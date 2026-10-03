import importlib.util
import io
from contextlib import chdir
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError


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
            for crate, package, version in (("squeeze-lib", "squeeze-lib", "0.5.0"),
                                            ("squeeze-cli", "squeeze-cli", "0.4.0")):
                (root / crate).mkdir()
                (root / crate / "Cargo.toml").write_text(
                    f'[package]\nname = "{package}"\nversion = "{version}"\n')
            with self.assertRaisesRegex(ValueError, "versions differ"):
                release.crate_version(root)

    def test_cli_must_require_the_released_library(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "squeeze-lib").mkdir()
            (root / "squeeze-lib/Cargo.toml").write_text(
                '[package]\nname = "squeeze-lib"\nversion = "0.5.0"\n')
            (root / "squeeze-cli").mkdir()
            manifest = ('[package]\nname = "squeeze-cli"\nversion = "0.5.0"\n'
                        '[dependencies]\nsqueeze = {{ package = "squeeze-lib", version = "{}" }}\n')
            (root / "squeeze-cli/Cargo.toml").write_text(manifest.format("0.4.0"))
            with self.assertRaisesRegex(ValueError, "CLI requires 0.4.0"):
                release.crate_version(root)
            (root / "squeeze-cli/Cargo.toml").write_text(manifest.format("0.5.0"))
            self.assertEqual(release.crate_version(root), "0.5.0")
            (root / "squeeze-cli/Cargo.toml").write_text(
                manifest.format("0.5.0").replace('package = "squeeze-lib", ', ""))
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
            release, "crate_published", return_value=True
        ), patch.object(
            release, "api", return_value={"draft": False}
        ) as api, patch.object(release, "output") as output:
            release.prepare()
        api.assert_called_once()
        output.assert_any_call("should_release", "false")
        output.assert_any_call("publish_crates", "false")

    def test_unpublished_crates_need_a_token(self):
        for token in ("true", ""):
            with self.subTest(token=token), patch.dict(release.os.environ, {"HAS_CRATES_TOKEN": token}), \
                    patch.object(release, "crate_version", return_value="0.5.0"), \
                    patch.object(release, "crate_published", side_effect=lambda name, _: name == "squeeze-lib"), \
                    patch.object(release, "api", return_value={"draft": False}), \
                    patch.object(release, "tag_commit", return_value="tagged"), \
                    patch.object(release, "output") as output:
                if token:
                    release.prepare()
                    output.assert_any_call("publish_crates", "true")
                else:
                    with self.assertRaisesRegex(ValueError, "CARGO_REGISTRY_TOKEN is required"):
                        release.prepare()

    def test_crates_after_a_published_release_use_its_tagged_commit(self):
        def api(method, path, **kwargs):
            if path.endswith("releases/tags/v0.2.0"):
                return {"draft": False}
            if path.endswith("git/ref/tags/v0.2.0"):
                return {"object": {"type": "tag", "sha": "annotated"}}
            if path.endswith("git/tags/annotated"):
                return {"object": {"type": "commit", "sha": "tagged"}}
            raise AssertionError(path)

        with patch.dict(release.os.environ, {"HAS_CRATES_TOKEN": "true"}), \
                patch.object(release, "crate_version", return_value="0.2.0"), \
                patch.object(release, "crate_published", return_value=False), \
                patch.object(release, "api", side_effect=api), \
                patch.object(release, "output") as output:
            release.prepare()
        output.assert_any_call("should_release", "false")
        output.assert_any_call("publish_crates", "true")
        output.assert_any_call("sha", "tagged")

    def test_unreachable_crates_io_does_not_block_the_release(self):
        error = URLError("timed out")
        with patch.dict(release.os.environ, {"HAS_CRATES_TOKEN": "true"}), \
                patch.object(release, "crate_version", return_value="0.2.0"), \
                patch.object(release, "urlopen", side_effect=error), \
                patch.object(release, "api", return_value=None), \
                patch.object(release, "ensure_tag"), \
                patch.object(release.subprocess, "check_output", return_value="commit\n"), \
                patch.object(release, "output") as output:
            release.prepare()
        output.assert_any_call("should_release", "true")
        output.assert_any_call("publish_crates", "true")

    def test_crates_publish_in_dependency_order_and_skip_published(self):
        published = {"squeeze-lib"}
        with patch.object(release, "crate_published", side_effect=lambda name, _: name in published), \
                patch.object(release.subprocess, "run") as run:
            release.publish_crates("0.5.0")
        run.assert_called_once_with(["cargo", "publish", "--locked", "--package", "squeeze-cli"], check=True)
        self.assertEqual(release.PACKAGES, ("squeeze-lib", "squeeze-cli"))

    def test_crates_publish_core_before_cli(self):
        with patch.object(release, "crate_published", return_value=False), \
                patch.object(release.subprocess, "run") as run:
            release.publish_crates("0.5.0")
        self.assertEqual([call.args[0][-1] for call in run.call_args_list],
                         ["squeeze-lib", "squeeze-cli"])

    def test_registry_version_must_belong_to_this_repository(self):
        published = (b'{"version":{"crate":"squeeze-lib","num":"0.5.0",'
                     b'"repository":"https://example.com/other"}}')
        with patch.object(release, "urlopen", return_value=io.BytesIO(published)):
            with self.assertRaisesRegex(ValueError, "another repository"):
                release.crate_published("squeeze-lib", "0.5.0")

    def test_existing_tag_must_reference_tested_commit(self):
        with patch.object(release, "api", return_value={"object": {"type": "commit", "sha": "old"}}):
            with self.assertRaisesRegex(ValueError, "different commit"):
                release.ensure_tag("v0.2.0", "new", create=False)

    def test_package_contains_binary_license_and_readme(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target/aarch64-pc-windows-msvc/release").mkdir(parents=True)
            (root / "target/aarch64-pc-windows-msvc/release/squeeze.exe").write_bytes(b"binary")
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
            with patch.object(release, "api", side_effect=api):
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

    def test_homebrew_formula_installs_the_prebuilt_binaries(self):
        checksums = {release.archive_name("v0.2.0", target): target for target in release.TARGETS}
        formula = release.homebrew_formula("v0.2.0", checksums)
        self.assertIn('version "0.2.0"', formula)
        self.assertNotIn("cargo", formula)
        self.assertIn('bin.install "squeeze"', formula)
        self.assertIn('generate_completions_from_executable(bin/"squeeze", "--completions")', formula)
        for platform in ("macos-arm64", "macos-amd64", "linux-arm64", "linux-amd64"):
            name = f"squeeze-v0.2.0-{platform}.tar.gz"
            self.assertIn(f'url "https://github.com/owner/repo/releases/download/v0.2.0/{name}"', formula)
            self.assertIn(f'sha256 "{checksums[name]}"', formula)
        self.assertLess(formula.index("on_macos"), formula.index("on_linux"))

    def test_homebrew_update_is_idempotent(self):
        sums = "".join(f"{target}  {release.archive_name('v0.2.0', target)}\n" for target in release.TARGETS)
        formula = release.homebrew_formula("v0.2.0", {
            release.archive_name("v0.2.0", target): target for target in release.TARGETS
        })
        for current, writes in ((None, 1), ({"sha": "old", "content": "b2xk"}, 1),
                                ({"sha": "same", "content": release.base64.b64encode(formula.encode())}, 0)):
            with self.subTest(current=current), patch.object(
                release, "urlopen", return_value=io.BytesIO(sums.encode())
            ), patch.object(release, "api", return_value=current) as api:
                release.update_homebrew("v0.2.0", "owner/homebrew-tap")
            puts = [call for call in api.call_args_list if call.args[0] == "PUT"]
            self.assertEqual(len(puts), writes)
            if puts:
                body = puts[0].args[2]
                self.assertEqual(body["message"], "chore: update squeeze to 0.2.0")
                self.assertEqual(body.get("sha"), current and current["sha"])


if __name__ == "__main__":
    unittest.main()
