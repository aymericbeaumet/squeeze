"""Build release archives and publish complete, retryable GitHub releases."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tomllib
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen
import zipfile


TARGETS = {
    "x86_64-unknown-linux-gnu": "linux-amd64",
    "aarch64-unknown-linux-gnu": "linux-arm64",
    "x86_64-apple-darwin": "macos-amd64",
    "aarch64-apple-darwin": "macos-arm64",
    "x86_64-pc-windows-msvc": "windows-amd64",
    "aarch64-pc-windows-msvc": "windows-arm64",
}


def api(method, path, data=None, allow_missing=False, content_type="application/json"):
    url = path if path.startswith("https://") else "https://api.github.com" + path
    payload = json.dumps(data).encode() if isinstance(data, dict) else data
    request = Request(url, data=payload, method=method, headers={
        "Authorization": "Bearer " + os.environ.get("GH_TOKEN", ""),
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": content_type,
    })
    try:
        with urlopen(request, timeout=120) as response:
            body = response.read()
            return json.loads(body) if body else None
    except HTTPError as error:
        if allow_missing and error.code == 404:
            return None
        raise


def endpoint(path):
    return f"/repos/{os.environ['GITHUB_REPOSITORY']}/{path}"


def output(name, value):
    with open(os.environ["GITHUB_OUTPUT"], "a") as stream:
        print(f"{name}={value}", file=stream)


def crate_version(root=Path(".")):
    versions = []
    for crate in ("squeeze", "squeeze-cli"):
        with (root / crate / "Cargo.toml").open("rb") as stream:
            versions.append(tomllib.load(stream)["package"]["version"])
    if versions[0] != versions[1]:
        raise ValueError(f"Crate versions differ: {versions}")
    if not re.fullmatch(r"\d+\.\d+\.\d+", versions[0]):
        raise ValueError("Automatic releases require a stable major.minor.patch version")
    return versions[0]


def validate_tag(version, ref_type, ref_name):
    tag = "v" + version
    if ref_type == "tag" and ref_name != tag:
        raise ValueError(f"Tag {ref_name} does not match crate version {version}")
    if ref_type != "tag" and ref_name != "main":
        raise ValueError("Releases must run from main or a version tag")
    return tag


def ensure_tag(tag, sha, create):
    ref = api("GET", endpoint(f"git/ref/tags/{tag}"), allow_missing=True)
    if ref is None:
        if create:
            api("POST", endpoint("git/refs"), {"ref": f"refs/tags/{tag}", "sha": sha})
        return
    target = ref["object"]
    while target["type"] == "tag":
        target = api("GET", endpoint(f"git/tags/{target['sha']}"))["object"]
    if target["type"] != "commit" or target["sha"] != sha:
        raise ValueError(f"Existing tag {tag} points to a different commit")


def prepare():
    version = crate_version()
    tag = validate_tag(version, os.environ.get("GITHUB_REF_TYPE", "branch"),
                       os.environ.get("GITHUB_REF_NAME", "main"))
    output("version", version)
    output("tag", tag)
    existing = api("GET", endpoint(f"releases/tags/{tag}"), allow_missing=True)
    if existing is not None and not existing["draft"]:
        output("should_release", "false")
        print(f"{tag} is already published")
        return
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    ensure_tag(tag, sha, create=False)
    output("sha", sha)
    output("should_release", "true")


def archive_name(tag, target):
    suffix = "zip" if "windows" in target else "tar.gz"
    return f"squeeze-{tag}-{TARGETS[target]}.{suffix}"


def package(tag, target, root=Path(".")):
    binary = "squeeze.exe" if "windows" in target else "squeeze"
    files = [(root / "target/release" / binary, binary),
             (root / "LICENSE", "LICENSE"), (root / "readme.md", "readme.md")]
    destination = root / "dist" / archive_name(tag, target)
    destination.parent.mkdir(exist_ok=True)
    if "windows" in target:
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path, name in files:
                archive.write(path, name)
    else:
        with tarfile.open(destination, "w:gz") as archive:
            for path, name in files:
                archive.add(path, arcname=name)
    return destination


def publish(tag, sha):
    expected = {archive_name(tag, target) for target in TARGETS}
    archives = sorted(path for path in Path("dist").iterdir() if path.name != "SHA256SUMS")
    if {path.name for path in archives} != expected:
        raise ValueError("Release requires exactly the six platform archives")
    checksums = Path("dist/SHA256SUMS")
    checksums.write_text("".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in archives
    ))
    ensure_tag(tag, sha, create=True)
    existing = api("GET", endpoint(f"releases/tags/{tag}"), allow_missing=True)
    if existing is not None and not existing["draft"]:
        raise ValueError(f"{tag} was published while building; refusing to replace its assets")
    if existing is None:
        existing = api("POST", endpoint("releases"), {
            "tag_name": tag, "target_commitish": sha, "name": tag,
            "draft": True, "generate_release_notes": True,
        })
    release_path = endpoint(f"releases/{existing['id']}")
    assets = api("GET", release_path + "/assets?per_page=100")
    for asset in assets:
        api("DELETE", endpoint(f"releases/assets/{asset['id']}"))
    upload_url = existing["upload_url"].split("{", 1)[0]
    for path in archives + [checksums]:
        api("POST", upload_url + "?name=" + quote(path.name), path.read_bytes(),
            content_type="application/octet-stream")
    # Compute Homebrew's source checksum before exposing the complete release.
    source_url = f"https://github.com/{os.environ['GITHUB_REPOSITORY']}/archive/refs/tags/{tag}.tar.gz"
    with urlopen(source_url, timeout=120) as response:
        source_sha = hashlib.sha256(response.read()).hexdigest()
    api("PATCH", release_path, {"draft": False, "make_latest": "true"})
    output("source_sha", source_sha)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("prepare", "package", "publish"))
    parser.add_argument("--tag")
    parser.add_argument("--target", choices=TARGETS)
    parser.add_argument("--sha")
    args = parser.parse_args()
    if args.command == "prepare":
        prepare()
    elif args.command == "package":
        package(args.tag, args.target)
    else:
        publish(args.tag, args.sha)
