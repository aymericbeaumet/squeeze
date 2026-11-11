# Development and releases

## Tooling

mise is the whole development environment: `mise.toml` pins Rust 1.99.1 with
rustfmt and Clippy, Python 3.15.0, and every tool a task needs, and
`mise tasks` lists every command. It also sets `min_version` to the mise
release CI pins, since older ones cannot enforce the committed lockfile
policy. Update mise through its original installation method when it
refuses to load the config.
Run `mise trust`, then `mise install`. Tasks declare their extra tools (the
MSRV toolchain, hyperfine, ripgrep, watchexec, cargo-outdated, cargo-audit,
ShellCheck, and the demo container CLI),
which mise installs on first use; with `auto_install = false`, install them
ahead of time with `mise install --include-task-tools`. The committed
`mise.lock` records resolved downloads and checksums for all six CI
platforms. `[tool_config] locked = true` makes project tools fail on missing
lock entries, including task tools, without changing the policy for your
global tools. The mise action also installs in locked mode. Run `mise lock`
when changing tools; `lockfile_platforms` keeps all six platforms covered. The minimum supported Rust
version is 1.95; `mise run msrv` installs and tests that toolchain
independently of the development pin.
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

`mise run watch` and `mise run watch-check` use mise's watcher with the
watchexec it pins. The optional
`outdated` and `audit` tasks use Cargo extensions pinned by mise.
One-liners live in `mise.toml`; longer ones such as `bench-cli`,
`update-iana`, and `release-helper` are executable file tasks in
`mise-tasks/`, which mise runs through their shebang on Windows too.

Actions pins mise 2026.11.6, whose release assets cover all six platforms.
Verify those assets before updating the pin, and move `min_version` in
`mise.toml` with it. Workflow action revisions and
container images are pinned to digests. Mise manages Rust through rustup, including extra targets via
`mise run rust-target -- <target>`. Native CI jobs give mise an isolated
rustup home and an explicit host triple so preinstalled toolchains cannot
select the wrong architecture on Windows ARM64. Its Actions tool cache is
disabled, while
`Swatinem/rust-cache` caches Cargo dependencies and build outputs; see the
[mise action's Rust cache guidance](https://github.com/jdx/mise-action#rust-cache).

A native linker and SDK remain operating-system prerequisites: Xcode Command
Line Tools on macOS, a C toolchain on Linux, or MSVC Build Tools on Windows.
Linux static-release jobs install the musl system libraries with apt.
`bench-cli` pins its required tools; optional GNU/BSD grep and ugrep are
comparisons against the versions on the host and are skipped when absent.

## Releases

The root `Cargo.toml` defines the `squeeze-cli` package and the workspace;
`squeeze-lib/Cargo.toml` defines the library package. CLI sources and
integration tests live in `squeeze-cli/`, with explicit Cargo target paths.
`cargo install --path . --locked` installs the local `squeeze` binary, and
`cargo test` defaults to both workspace packages.
Only `squeeze-lib` is published to crates.io. The CLI sets `publish = false`
and ships as the release archives (Homebrew, mise's GitHub backend) or builds
with `cargo install --locked --git https://github.com/aymericbeaumet/squeeze`.
Run `mise run package` from a clean checkout to build and verify the library's
crates.io archive. CI also checks this and installs the CLI from the
repository root.

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
is `squeeze-v1.0.0-windows-arm64.zip`. `SHA256SUMS` accompanies the archives,
and each archive gets a build provenance attestation. Linux binaries link musl
statically, so they run on any distribution, and use mimalloc because musl's
allocator serializes the parallel scanner (up to 2.7 times slower); Windows binaries link the C
runtime statically (`.cargo/config.toml`), so they need no Visual C++
Redistributable. Archive names are a public contract for the Homebrew formula
and mise's GitHub backend.

To verify an archive's build provenance, run
`gh attestation verify <archive> --repo aymericbeaumet/squeeze`.

Publication waits for every build and test to pass. Assets are uploaded to a
draft before the release becomes public, and retries can resume an unpublished
release. The workflow uses the repository's `GITHUB_TOKEN` with `contents: write`.

After publication, the Homebrew job writes `Formula/squeeze.rb` in
`aymericbeaumet/homebrew-tap` from the release's `SHA256SUMS`: the formula
installs the prebuilt macOS and Linux archives and generates shell
completions. The crates job publishes `squeeze-lib` to crates.io once every
platform's build and tests pass. Because crates.io publications are
permanent, rerunning a failed crates job skips a version that was already
published.

The three install paths of the readme map to these outputs: Homebrew to the
tap's formula, mise's `github:` backend to the release archives, and
`cargo install --git` to the repository itself. The release needs two
repository secrets, which the prepare job checks before building anything:

| Secret | Used by | Required when |
| --- | --- | --- |
| `HOMEBREW_TAP_TOKEN` | the Homebrew job and the nightly formula | a new release is built; needs contents write access to `aymericbeaumet/homebrew-tap` |
| `CARGO_REGISTRY_TOKEN` | the crates job | the `squeeze-lib` version is not on crates.io yet; needs the publish-update scope |

`mise run demo` rebuilds the readme's `docs/demo/demo.gif` from
`docs/demo/demo.tape` with VHS in a container on Linux or macOS. Mise pins
the container CLI and both images by digest. Start Colima on macOS or use
the native container engine on Linux before running the task.

The release helper, `mise-tasks/release-helper`, uses Python 3.11+ and the
standard library; `mise-tasks/test_release_helper.py` tests it. Run
`mise run release-check` to validate workflows with actionlint 1.7.12 and ShellCheck 0.11.0, and run
those tests with pinned Python 3.15.0. Release jobs use the same mise
environment and `mise run release-helper` to invoke the helper, and so does
the nightly workflow, whose `nightly` command points the tap's
`squeeze-nightly` formula, built from source, at every push to `main`. If publication
fails after creating a tag,
rerun the failed workflow at its original commit or dispatch it on that tag.
An existing tag pointing at another commit is rejected. If only the Homebrew
or crates job fails, rerun it after fixing its token or permissions.
