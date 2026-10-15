# Development and releases

## Tooling

`mise.toml` pins Rust 1.99.1 with rustfmt and Clippy, plus Python 3.15.0.
Run `mise trust`, then `mise install`. The minimum supported Rust version remains
1.95; `mise run msrv` installs and tests that toolchain independently of the
development pin.
The MSRV task overrides `RUSTUP_TOOLCHAIN` so an inherited development
toolchain cannot silently replace the minimum-version check.

`mise run check` runs formatting, Clippy with warnings denied, all workspace
test targets, doctests, and documentation with warnings denied. `mise run release`
builds the optimized CLI. Cargo tasks use `--locked` so CI and release builds
use the committed dependency resolution. After changing crate versions or
dependencies, refresh `Cargo.lock` with Cargo and review the diff.

`squeeze-lib/iana.rs` embeds the IANA root-zone TLDs and registered URI schemes
that the domain and URI finders use to reject lookalikes such as `opts.all` or
`key:value`. Refresh it with `mise run update-iana` (Python 3, network
access) and review the diff; the registries change a few times a year.

`mise run watch` and `mise run watch-check` use mise's watcher. The optional
`outdated` and `audit` tasks install their pinned Cargo extensions through mise.
`mise tasks` lists every task: one-liners live in `mise.toml`, longer ones
such as `bench-cli` and `update-iana` are executable file tasks in
`mise-tasks/`.

Actions pins mise 2026.10.11, whose release assets cover all six platforms.
Verify those assets before updating the pin. Workflow action revisions and
container images are pinned to digests. Mise manages Rust through rustup. Its
Actions tool cache is disabled, while
`Swatinem/rust-cache` caches Cargo dependencies and build outputs; see the
[mise action's Rust cache guidance](https://github.com/jdx/mise-action#rust-cache).

## Releases

The root `Cargo.toml` defines the `squeeze-cli` package and the workspace;
`squeeze-lib/Cargo.toml` defines the library package. CLI sources and
integration tests remain in `squeeze-cli/`, with explicit Cargo target paths.
`cargo install --path . --locked` installs the local `squeeze` binary, and
`cargo test` defaults to both workspace packages.
Run `mise run package` from a clean checkout to build both publication
archives and verify the CLI against the packaged library. CI also checks
this and installs the CLI from the repository root.

To release, keep the `squeeze-lib` package in `squeeze-lib/Cargo.toml`, the
`squeeze-cli` package in `Cargo.toml`, and the CLI's library
dependency requirement at the same version. Refresh `Cargo.lock` and merge to
`main`.
The release workflow automatically builds and publishes the corresponding
`v<version>` tag when that version has no published release. Ordinary pushes
with an already published version do not rebuild release artifacts.
Tag pushes and manual workflow dispatch also support release retries.

Each release is tested and built on six native
[GitHub runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners):

| Platform | Architecture | Rust target | Runner |
| --- | --- | --- | --- |
| Linux | amd64 | `x86_64-unknown-linux-musl` | `ubuntu-24.04` |
| Linux | arm64 | `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` |
| macOS | amd64 | `x86_64-apple-darwin` | `macos-15-intel` |
| macOS | arm64 | `aarch64-apple-darwin` | `macos-15` |
| Windows | amd64 | `x86_64-pc-windows-msvc` | `windows-2025` |
| Windows | arm64 | `aarch64-pc-windows-msvc` | `windows-11-arm` |

Linux and macOS archives use `.tar.gz`; Windows archives use `.zip`. Each
contains the CLI, README, and license. For example, the Windows ARM64 archive
is `squeeze-v0.5.0-windows-arm64.zip`. `SHA256SUMS` accompanies the archives,
and each archive gets a build provenance attestation. Linux binaries link musl
statically, so they run on any distribution, and use mimalloc because musl's
allocator serializes the parallel scanner (up to 2.7 times slower); Windows binaries link the C
runtime statically (`.cargo/config.toml`), so they need no Visual C++
Redistributable. Archive names are a public contract for the Homebrew formula
and mise's GitHub backend.

Publication waits for every build and test to pass. Assets are uploaded to a
draft before the release becomes public, and retries can resume an unpublished
release. The workflow uses the repository's `GITHUB_TOKEN` with `contents: write`.

After publication, the Homebrew job writes `Formula/squeeze.rb` in
`aymericbeaumet/homebrew-tap` from the release's `SHA256SUMS`: the formula
installs the prebuilt macOS and Linux archives and generates shell
completions. It requires `HOMEBREW_TAP_TOKEN` with write access to the tap.
The crates job publishes `squeeze-lib` to crates.io first, waits for the
registry to serve that version, then publishes `squeeze-cli` with its matching
library dependency. If either crate version is unpublished, the prepare job
requires `CARGO_REGISTRY_TOKEN` before the new release can proceed. Because
crates.io publications are permanent, rerunning a failed crates job skips
versions that were already published.

`mise run demo` rebuilds the readme's `docs/demo/demo.gif` from
`docs/demo/demo.tape` with VHS in a container (Colima on macOS).

Release helpers use Python 3.11+ and the standard library. Run
`mise run release-check` to validate workflows with actionlint 1.7.12 and run
the helper tests with pinned Python 3.15.0. Release jobs use the same mise
environment and `mise run release-helper` to invoke the helper. If publication
fails after creating a tag,
rerun the failed workflow at its original commit or dispatch it on that tag.
An existing tag pointing at another commit is rejected. If only the Homebrew
or crates job fails, rerun it after fixing its token or permissions.
