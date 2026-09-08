# Development and releases

## Tooling

`mise.toml` pins Rust 1.96.0 with rustfmt and Clippy. Run `mise trust`, then
`mise install`. The minimum supported Rust version remains 1.95; `mise run msrv`
installs and tests that toolchain independently of the development pin.

`mise run check` runs formatting, Clippy with warnings denied, all workspace
test targets, doctests, and documentation with warnings denied. `mise run release`
builds the optimized CLI. Cargo tasks use `--locked` so CI and release builds
use the committed dependency resolution. After changing crate versions or
dependencies, refresh `Cargo.lock` with Cargo and review the diff.

`mise run watch` and `mise run watch-check` use mise's watcher. The optional
`outdated` and `audit` tasks require the corresponding Cargo extensions.
The Makefile forwards existing commands to mise.

Mise manages Rust through rustup. Its Actions tool cache is disabled, while
`Swatinem/rust-cache` caches Cargo dependencies and build outputs; see the
[mise action's Rust cache guidance](https://github.com/jdx/mise-action#rust-cache).

## Releases

To release, bump the versions in both `squeeze/Cargo.toml` and
`squeeze-cli/Cargo.toml`, refresh `Cargo.lock`, and merge to `main`.
The release workflow automatically builds and publishes the corresponding
`v<version>` tag when that version has no published release. Ordinary pushes
with an already published version do not rebuild release artifacts.
Tag pushes and manual workflow dispatch also support release retries.

Each release is tested and built on six native
[GitHub runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners):

| Platform | Architecture | Rust target | Runner |
| --- | --- | --- | --- |
| Linux | amd64 | `x86_64-unknown-linux-gnu` | `ubuntu-24.04` |
| Linux | arm64 | `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` |
| macOS | amd64 | `x86_64-apple-darwin` | `macos-15-intel` |
| macOS | arm64 | `aarch64-apple-darwin` | `macos-15` |
| Windows | amd64 | `x86_64-pc-windows-msvc` | `windows-2025` |
| Windows | arm64 | `aarch64-pc-windows-msvc` | `windows-11-arm` |

Linux and macOS archives use `.tar.gz`; Windows archives use `.zip`. Each
contains the CLI, README, and license. For example, the Windows ARM64 archive
is `squeeze-v0.2.0-windows-arm64.zip`. `SHA256SUMS` accompanies the archives.
Linux binaries target glibc and are built on Ubuntu 24.04.

Publication waits for every build and test to pass. Assets are uploaded to a
draft before the release becomes public, and retries can resume an unpublished
release. The workflow uses the repository's `GITHUB_TOKEN` with `contents: write`.
The existing Homebrew tap update runs after publication and requires
`HOMEBREW_TAP_TOKEN` with write access to `aymericbeaumet/homebrew-tap`.

Release helpers use Python 3.11+ and the standard library. Run their tests with
`python3 -m unittest discover -s .github/scripts -p 'test_*.py'` and validate
workflow changes with `actionlint`. If publication fails after creating a tag,
rerun the failed workflow at its original commit or dispatch it on that tag.
An existing tag pointing at another commit is rejected. If only the Homebrew
update fails, rerun that failed job after fixing the tap token or permissions.
