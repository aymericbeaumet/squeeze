# Performance

squeeze aims to be the fastest structured-data extractor available. This
document describes how the scanner reaches that goal, how performance is
measured, and the rules a finder must follow to keep the guarantees.

## Architecture

A `Scanner` holds a list of finders and scans one line at a time. The work
per line is organised so that the expensive part, calling a finder, happens
only where a match can actually start.

1. **Prescan.** One pass computes which byte classes occur in the line
   (digits, hex letters, `@`, `$`, `:`, ...). Finders whose required classes
   are absent are disabled for the line (`required_classes` in
   `scanner.rs`). A line of prose disables the email, env, URI and CIDR
   finders in one table lookup per byte.
2. **Candidate positions.** Dispatch finders declare which byte can start a
   match (`could_start_at`) and, through *context gates*, which previous and
   next bytes rule it out (`could_start_after`, `could_continue_with`). The
   scanner folds these into two lookup tables indexed by a coarse class of
   the neighbouring byte, so a digit inside a number or a hex letter inside
   a word never reaches a finder. Trigger finders (email on `@`, URI on `:`)
   share the same tables without gates.
3. **Vector stage** (`Strategy::Vector`, the default). Sixteen bytes at a
   time, NEON or SSSE3 nibble lookups classify each byte into a category and
   test the start set; per-category rules on the previous and next byte
   (two alternatives, so an unconstrained finder such as keycap emoji on
   digits does not cancel the others) yield a bitmap that is a superset of
   the gated candidates. Only those lanes go through the exact tables.
   Scanners whose finders start at three bytes or fewer skip the prescan
   and the block classifier and use `memchr` instead (`squeeze --url` scans
   for `:` at memory speed); `Scanner::skip_to_candidate_line` extends that
   search across a whole buffer, so the CLI never visits a line that lacks
   the start bytes. Both paths are exact by construction: the block stage
   may only add candidates, never drop one, and property tests compare
   every strategy and backend against the original byte loop.
4. **Run rules.** At a candidate, the scanner measures the digit and hex
   runs once (`Runs::at`) and evaluates each finder's declarative
   `RunRule`s: a hash needs a hex run of 32 to 128, a UUID a hex run of
   exactly 8 followed by `-`, a datetime four digits then `-`. Finders
   sharing a run are gated together without a virtual call.
5. **Finder call.** What survives is handed to `try_at_memo` with a
   per-line `Memo`, a small cache a finder may use to remember a run that
   cannot match, so repeated candidates inside one line stay linear
   (modeline option runs, too-deep JSON bracket runs, IPv6-shaped runs).

Two other strategies remain selectable for comparison: `Legacy` (the
original per-byte dispatch tables) and `Gated` (the exact tables without
the vector stage).

The CLI reads input in 256 KiB blocks, splits lines with `memchr`, jumps
over lines a sparse scanner cannot match, validates UTF-8 once per block
and writes plain text results with `write_all`. With
`--jobs N` the input is cut into ~512 KiB chunks at newline boundaries,
scanned by N scoped threads, and written back in order through a reorder
buffer, so output is byte-identical to the sequential path.

## Contracts a finder must follow

Every optimisation above is only correct because finders keep a contract,
and every contract has a property test in `squeeze/tests/fuzz.rs`:

- If `could_start_after(prev, cur)` or `could_continue_with(cur, next)`
  returns `false`, `try_at` must return `None` in that context.
- If `RunRule::allow(rules, cur, runs)` returns `false`, `try_at` must
  return `None`.
- `try_at_memo` must return exactly what `try_at` returns; the memo is a
  cache, never an input.
- Strategies and backends must agree byte for byte; `linear_scans.rs`
  rejects quadratic rescans on adversarial 100 KB lines; `regex_parity.rs`
  pins the hand-written codetag, modeline and phone matchers to the regexes
  they replaced (kept as dev-dependencies only).

## Measuring

`mise run bench -- [options]` runs the `scanner` bench on deterministic
synthetic corpora (logs, prose, source, JSON lines, markdown, hex-dense,
unicode, plus the URI fixture and any `--corpus FILE`):

| option | purpose |
|---|---|
| `--stats` | operation counters: finder calls per KB, hit rate, coarse and exact candidate ratios, prescan skips, per-finder breakdown |
| `--strategy all` | time every strategy interleaved in one process |
| `--per-finder` | time each finder alone and compare the sum with the combined scan |
| `--save FILE` / `--compare FILE` | record a run and print throughput and call deltas against it |
| `--write-corpus DIR` | dump the corpora for external tools |

The bench pins itself to performance cores (macOS QoS) and keeps the best of
interleaved rounds. On a loaded machine wall-clock numbers still drift by
50% or more between runs; **operation counts are exact and load-independent**
and are the primary signal when comparing changes.

`mise run bench-cli` (`scripts/bench-cli.sh`) builds the release binary,
generates corpora at a chosen scale, and times the same extraction tasks
through squeeze, ripgrep, GNU/BSD grep and ugrep with hyperfine, recording
match counts next to the timings. Results land in `/tmp/squeeze-bench/summary.md`.

To profile: build with `CARGO_PROFILE_RELEASE_STRIP=false
CARGO_PROFILE_RELEASE_DEBUG=1 cargo build --release --target-dir target/prof`
and use `sample` (macOS) or `perf` (Linux) on the release binary.

## Results

Finder invocations per KB with every finder enabled, from `--stats`
(exact counts, unaffected by machine load):

| corpus | original | context gates | run rules | no regex |
|---|---|---|---|---|
| logs | 3154 | 704 | 179 | 220 |
| prose | 1157 | 127 | 11 | 6 |
| source | 979 | 181 | 93 | 93 |
| jsonl | 2588 | 519 | 147 | 234 |
| markdown | 1189 | 184 | 66 | 66 |
| hexdense | 2839 | 461 | 69 | 67 |
| unicode | 937 | 199 | 136 | 136 |
| nomatch | 800 | 57 | 0 | 0 |
| urls | 2029 | 364 | 98 | 118 |

The last column includes the former scan-mode finders, which now run as
gated dispatch finders instead of one regex pass per line: their calls are
counted where they used to be invisible. The hit rate of the remaining
calls went from about 1% to 20 to 30%; hash and UUID are now only ever
invoked on true matches.

Adversarial single lines that used to be quadratic (a 100 KB `1.1.1.1...`
run, `[` repeated, `ex:a ` repeated) scan at 85 to 150 MiB/s.

End-to-end, on a 55 MB log corpus (Apple M4 Pro, machine under external
load, best of five):

| command | before | after |
|---|---|---|
| `squeeze --all` | 1054 ms | 508 ms |
| `squeeze --all -j 4` | | 133 ms |
| `squeeze --all -j 10` | | 87 ms |
| `squeeze --url` | 164 ms | 61 ms |

See the readme for the comparison with other matchers produced by
`mise run bench-cli`.

## Known limits and next steps

- `env` still rescans to the end of the line for every `${` of an unclosed
  expression, and the URI finder rescans a token from each `:` when the
  greedy parse is rejected afterwards (`x?a:?a:?a:...`). Both are bounded
  by the token length and rare in practice; a memo can make them linear.
- `domain` is the last scan-mode finder; its `find` probes forward for an
  email local part and can rescan on `a.b+a.b+...` lines.
- The vector stage processes 16 bytes per step. An AVX2 backend (32 lanes)
  and a 64-byte NEON step would halve the per-block overhead.
- Trigger finders take no gates; the URI finder is called at every colon.
- `--jobs` defaults to 1. A parallel default for file inputs is a policy
  decision, not a performance one.
