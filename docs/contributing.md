# Contributing

Thanks for taking the time to help. Bug reports, wrong matches, and pull
requests are all welcome.

## Reporting a wrong or missing match

The most useful report is a small input that squeeze gets wrong. Open a
[wrong match issue](https://github.com/aymericbeaumet/squeeze/issues/new?template=wrong-match.yml)
with the input, the command, what squeeze printed, and what you expected.
Include `squeeze --version` and replace private data with a small synthetic
example that still reproduces the problem.
Finders favor precision over recall, so a format that is valid but rarely
seen in practice may be skipped on purpose; the issue is still the right
place to discuss it.

For crashes, installation problems, and anything else, open a
[bug report](https://github.com/aymericbeaumet/squeeze/issues/new?template=bug.yml).

## Development setup

Install [mise](https://mise.jdx.dev/getting-started.html): it provides the
pinned development tools and runs every task. Your OS also needs a native
linker and SDK; see [system prerequisites](development.md#tooling). Then run
the same checks as CI:

```shell
git clone https://github.com/aymericbeaumet/squeeze
cd squeeze
mise trust
mise install
mise run check
```

`mise run run -- <options>` runs the CLI from source, `mise run watch` reruns
the tests on every change, and `mise tasks` lists every task. If mise refuses
to load the project, update it the way you installed it (`mise self-update`,
or `brew upgrade mise`): the project needs the version CI uses.

## Repository layout

| Path | Contents |
|------|----------|
| `squeeze-cli/` | the `squeeze` command (`main.rs`) and its integration tests |
| `squeeze-lib/` | the `squeeze-lib` crate: one module per finder (`uri.rs`, `email.rs`, …) and the scanner that runs them |
| `squeeze-lib/tests/` | cross-finder suites: `hardening_*.rs` pin false positives and intentional trade-offs, `fuzz.rs` checks scanner contracts |
| `docs/` | usage, integrations, performance, and release documentation |
| `mise-tasks/` | longer tasks run by `mise run`: benchmarks, the IANA registry refresh, and the release helper |

## Changing a finder

1. Add a failing test for the input in the finder's module, or in the
   matching `squeeze-lib/tests/hardening_*.rs` suite when it is a trade-off
   worth pinning.
2. Fix the finder, then run `mise run check`.
3. Smoke-test false positives on real text:
   `mise run run -- --all --with-kind readme.md squeeze-cli/main.rs`.

Finders are hand-written rather than regex-based, and the scanner gates them
with SIMD classification. Read [performance](performance.md) for the
contracts a finder must follow and how to measure a change with
`mise run bench -- --stats`.

## Pull requests

Keep pull requests focused, and describe the behavior they change. Commit
messages follow [Conventional Commits](https://www.conventionalcommits.org/)
(`fix: …`, `feat: …`). [Development and releases](development.md) covers the
tooling, CI, and release process in more detail.
