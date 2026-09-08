import importlib.util
import io
from contextlib import chdir
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError


spec = importlib.util.spec_from_file_location("release", Path(__file__).with_name("release.py"))
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(release.os.environ, {
            "GITHUB_REPOSITORY": "owner/repo", "GITHUB_REF_TYPE": "branch", "GITHUB_REF_NAME": "main",
        })
        environment.start()
        self.addCleanup(environment.stop)

    def test_only_not_found_is_missing(self):
        for status in (401, 403, 429, 500):
            with self.subTest(status=status):
                error = HTTPError("https://api.github.com/test", status, "failed", {}, io.BytesIO())
                with patch.object(release, "urlopen", side_effect=error):
                    with self.assertRaises(HTTPError):
                        release.api("GET", "/test", allow_missing=True)
        error = HTTPError("https://api.github.com/test", 404, "missing", {}, io.BytesIO())
        with patch.object(release, "urlopen", side_effect=error):
            self.assertIsNone(release.api("GET", "/test", allow_missing=True))

    def test_manifests_must_agree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for crate, version in (("squeeze", "0.2.0"), ("squeeze-cli", "0.1.0")):
                (root / crate).mkdir()
                (root / crate / "Cargo.toml").write_text(f'[package]\nversion = "{version}"\n')
            with self.assertRaisesRegex(ValueError, "versions differ"):
                release.crate_version(root)

    def test_tag_must_match_manifests(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            release.validate_tag("0.2.0", "tag", "v0.1.0")
        self.assertEqual(release.validate_tag("0.2.0", "branch", "main"), "v0.2.0")

    def test_arbitrary_branch_cannot_publish(self):
        with self.assertRaisesRegex(ValueError, "main or a version tag"):
            release.validate_tag("0.2.0", "branch", "feature")

    def test_published_release_skips_without_retagging(self):
        with patch.object(release, "crate_version", return_value="0.2.0"), patch.object(
            release, "api", return_value={"draft": False}
        ) as api, patch.object(release, "output") as output:
            release.prepare()
        api.assert_called_once()
        output.assert_any_call("should_release", "false")

    def test_existing_tag_must_reference_tested_commit(self):
        with patch.object(release, "api", return_value={"object": {"type": "commit", "sha": "old"}}):
            with self.assertRaisesRegex(ValueError, "different commit"):
                release.ensure_tag("v0.2.0", "new", create=False)

    def test_package_contains_binary_license_and_readme(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target/release").mkdir(parents=True)
            (root / "target/release/squeeze.exe").write_bytes(b"binary")
            (root / "LICENSE").write_text("license")
            (root / "readme.md").write_text("readme")
            archive = release.package("v0.2.0", "aarch64-pc-windows-msvc", root)
            with release.zipfile.ZipFile(archive) as bundle:
                self.assertEqual(set(bundle.namelist()), {"squeeze.exe", "LICENSE", "readme.md"})

    def test_incomplete_build_cannot_create_tag_or_release(self):
        with tempfile.TemporaryDirectory() as directory, chdir(directory):
            Path("dist").mkdir()
            with patch.object(release, "api") as api:
                with self.assertRaisesRegex(ValueError, "six platform archives"):
                    release.publish("v0.2.0", "commit")
                api.assert_not_called()

    def test_failed_upload_stays_draft_and_retry_publishes_all_assets(self):
        calls = []
        uploaded = []
        draft = {"id": 42, "draft": True, "upload_url": "https://uploads.github.com/assets{?name}"}
        fail_upload = True

        def api(method, path, data=None, **kwargs):
            calls.append((method, path, data))
            if path.endswith("git/ref/tags/v0.2.0"):
                return {"object": {"type": "commit", "sha": "commit"}}
            if path.endswith("releases/tags/v0.2.0"):
                return draft
            if path.endswith("/assets?per_page=100"):
                return [{"id": 99, "name": "old-partial-asset"}]
            if method == "POST" and path.startswith("https://uploads.github.com"):
                if fail_upload:
                    raise RuntimeError("upload failed")
                uploaded.append(path)

        with tempfile.TemporaryDirectory() as directory, chdir(directory):
            Path("dist").mkdir()
            for target in release.TARGETS:
                Path("dist", release.archive_name("v0.2.0", target)).write_bytes(b"archive")
            with patch.object(release, "api", side_effect=api), patch.object(
                release, "urlopen", return_value=io.BytesIO(b"source archive")
            ), patch.object(release, "output"):
                with self.assertRaisesRegex(RuntimeError, "upload failed"):
                    release.publish("v0.2.0", "commit")
                self.assertFalse(any(method == "PATCH" for method, _, _ in calls))
                fail_upload = False
                release.publish("v0.2.0", "commit")
            self.assertEqual(len(uploaded), 7)
            self.assertEqual(calls[-1], ("PATCH", "/repos/owner/repo/releases/42", {
                "draft": False, "make_latest": "true",
            }))
            self.assertEqual(len(Path("dist/SHA256SUMS").read_text().splitlines()), 6)


if __name__ == "__main__":
    unittest.main()
