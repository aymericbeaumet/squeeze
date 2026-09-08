# Project workflow

- Use `mise install` and `mise run check` for the pinned Rust toolchain and the
  formatting, Clippy, tests, doctests, and documentation checks used by CI.
- Run `mise run release` when changing build or packaging behavior and
  `mise run msrv` when changing dependencies or the minimum supported Rust version.
- Keep both crate versions and their entries in `Cargo.lock` synchronized.
  A new version on `main` triggers publication; see [release details](docs/development.md).
- CI and releases cover Linux, macOS, and Windows on both amd64 and arm64.
  Preserve all six native targets when changing workflows.
- After changing release automation, run `actionlint` and, with Python 3.11+,
  `python3 -m unittest discover -s .github/scripts -p 'test_*.py'`.
