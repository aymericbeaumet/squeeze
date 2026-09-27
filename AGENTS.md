# Project workflow

- Use `mise install` and `mise run check` for the pinned Rust toolchain and the
  formatting, Clippy, tests, doctests, and documentation checks used by CI.
- Run `mise run release` when changing build or packaging behavior and
  `mise run msrv` when changing dependencies or the minimum supported Rust version.
- Keep both crate versions and their entries in `Cargo.lock` synchronized.
  A new version on `main` triggers publication; see [release details](docs/development.md).
- Finders favor precision. After changing one, smoke-test false positives with
  `mise run run -- --all --with-kind readme.md squeeze-cli/main.rs` and pin
  intentional trade-offs in the `squeeze/tests/hardening_*.rs` suites.
- CI and releases cover Linux, macOS, and Windows on both amd64 and arm64.
  Preserve all six native targets when changing workflows.
- After changing release automation, run `actionlint` and, with Python 3.11+,
  `python3 -m unittest discover -s .github/scripts -p 'test_*.py'`.
- Performance work is measured, never guessed: `mise run bench -- --stats` reports
  throughput and finder operation counts per corpus (`--strategy all` compares
  scanner strategies interleaved, `--save`/`--compare` diff runs), and
  `mise run bench-cli` compares the CLI with ripgrep, grep and ugrep. Operation
  counts are the reliable signal on a loaded machine; see
  [performance](docs/performance.md) for the architecture and the rules
  finders must follow (gates, run rules, memo) with their property tests.
- The scanner has NEON and SSSE3 backends. After touching `squeeze/classify.rs`
  or the block walk in `squeeze/scanner.rs`, run the library tests for the other
  architecture as well: on Apple silicon
  `cargo test -p squeeze --target x86_64-apple-darwin` runs the SSSE3 path under
  Rosetta and `cargo clippy -p squeeze --target x86_64-apple-darwin --all-targets
  -- -D warnings` lints the code that only compiles there (`rustup target add
  x86_64-apple-darwin` once); CI covers both.
- Finder changes must keep `cargo test -p squeeze` green: the fuzz suites check
  gate/rule contracts and strategy parity, `regex_parity` pins the hand-written
  codetag/modeline/phone matchers to the former regexes, and `linear_scans`
  rejects quadratic rescans on adversarial lines.
