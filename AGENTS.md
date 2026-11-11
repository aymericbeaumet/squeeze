# Project workflow

- mise is the single dev environment. Use `mise install` (add
  `--include-task-tools` when `auto_install` is off) and `mise run check` for
  pinned Rust and Python, plus the formatting, Clippy, tests, doctests, and
  documentation checks used by CI. `min_version` in `mise.toml` tracks the mise
  version the workflows pin; bump them together.
- Update and commit `mise.lock` with `mise.toml` tool changes; lock all six CI
  platforms with `mise lock` (`lockfile_platforms` lists them). Project tools
  enforce the lockfile with `[tool_config] locked = true`; do not weaken it.
- Run `mise run release` and `mise run package` when changing build or packaging
  behavior, and `mise run msrv` when changing dependencies or the minimum supported
  Rust version.
- mise is the only task runner: add one-liners to `mise.toml` and longer
  scripts as executable file tasks in `mise-tasks/` (`#MISE description=...`,
  a shebang so Windows can run them); no Makefile or standalone `scripts/`.
  Workflows call `mise run` tasks instead of inline scripts, and tasks declare
  any tool they need beyond the global ones. Distribute through established package
  managers rather than repository install scripts.
- The library package is `squeeze-lib` (imported as `squeeze`); `squeeze`
  is taken on crates.io. The root manifest defines `squeeze-cli`; keep its
  explicit targets in `squeeze-cli/` registered when adding integration tests.
  Keep both crate versions, the CLI's requirement on
  the library, and their `Cargo.lock` entries synchronized. A new version on
  `main` publishes the release, the `squeeze-lib` crate, and the Homebrew
  formula; the CLI is not published to crates.io. See
  [release details](docs/development.md).
- Release archive names (`squeeze-vX.Y.Z-<os>-<arch>`) are a public contract
  shared by the Homebrew formula, cargo-binstall metadata, and
  mise's GitHub backend; change them everywhere together.
- Finders favor precision. After changing one, smoke-test false positives with
  `mise run run -- --all --with-kind readme.md squeeze-cli/main.rs` and pin
  intentional trade-offs in the `squeeze-lib/tests/hardening_*.rs` suites.
- Keep `readme.md` a short pitch (demo, install, examples, finders); the
  option reference lives in `docs/usage.md` and recipes in
  `docs/integrations.md`. When CLI output or flags change, update these
  docs and `--help`, and re-record `docs/demo/demo.gif` with `mise run demo`.
- Errors are typed. Fallible library configuration returns `squeeze::Error`
  (`squeeze-lib/error.rs`, with typo suggestions); the CLI turns those into
  clap usage errors and its own failures into `squeeze-cli/error.rs` variants
  printed as `squeeze: <path>: <reason>`. Every error exits 2; 1 is reserved
  for `--exit-code` finding nothing.
- CI and releases cover Linux, macOS, and Windows on both amd64 and arm64.
  Preserve all six native targets when changing workflows. Release binaries
  must run on a clean machine: Linux ones link musl statically, Windows ones
  the C runtime.
- After changing release automation, run `mise run release-check` for the
  pinned actionlint and Python helper tests.
- Performance work is measured, never guessed: `mise run bench -- --stats` reports
  throughput and finder operation counts per corpus (`--strategy all` compares
  scanner strategies interleaved, `--save`/`--compare` diff runs), and
  `mise run bench-cli` compares the CLI with ripgrep, grep and ugrep. Operation
  counts are the reliable signal on a loaded machine; see
  [performance](docs/performance.md) for the architecture and the rules
  finders must follow (gates, run rules, memo) with their property tests.
- The scanner has NEON and SSSE3 backends. After touching `squeeze-lib/classify.rs`
  or the block walk in `squeeze-lib/scanner.rs`, run the library tests for the other
  architecture as well: on Apple silicon
  `mise exec -- cargo test -p squeeze-lib --target x86_64-apple-darwin` runs the
  SSSE3 path under Rosetta and `mise exec -- cargo clippy -p squeeze-lib --target
  x86_64-apple-darwin --all-targets -- -D warnings` lints the code that only
  compiles there (`mise run rust-target -- x86_64-apple-darwin` once);
  CI covers both.
- Finder changes must keep `mise exec -- cargo test -p squeeze-lib` green: the
  fuzz suites check gate/rule contracts and strategy parity; `regex_parity`
  checks codetag/modeline/phone matchers against reference regexes, and
  `linear_scans` rejects quadratic rescans on adversarial lines.
