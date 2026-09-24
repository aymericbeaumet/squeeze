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
   finders in one table lookup per byte. Scanners with a single gated
   finder, or whose finders start at three bytes or fewer, skip the prescan:
   their gates filter at least as well without the extra pass.
2. **Candidate positions.** Dispatch finders declare which byte can start a
   match (`could_start_at`) and, through *context gates*, which previous and
   next bytes rule it out (`could_start_after`, `could_continue_with`). The
   scanner folds these into two lookup tables indexed by a coarse class of
   the neighbouring byte, so a digit inside a number or a hex letter inside
   a word never reaches a finder. Trigger finders (email on `@`, URI on `:`)
   share the same tables and may declare gates too: the URI finder only
   fires on a colon preceded by a scheme byte and followed by a byte that
   can begin a URI body, and rejects in O(1) any colon that is neither
   followed by `/` nor preceded by the last two bytes of a registered
   scheme (lax mode needs one or the other).
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
   **Anchor plan.** A dispatch finder can also declare an *anchor*: bytes
   every match contains (`-` for UUIDs, `.` and `:` for IPs, `/` for CIDRs,
   `-` for datetimes, `.` for semver, the separators for MACs, `#` and `(`
   for colours) and the bytes that may precede the first of them. When
   every finder of a scanner is anchored or trigger-based and the anchor
   bytes number three or fewer, the scanner searches those bytes with
   `memchr`, walks back to where a match could start and tries the
   dispatch positions in order, never twice. The result is the dispatch
   result (a property test pins it), at memchr speed: `squeeze --uuid`
   never looks at a line without a dash.
4. **Run rules.** At a candidate, the scanner measures the digit and hex
   runs once and evaluates each finder's declarative `RunRule`s: a hash
   needs a hex run of 32 to 128, a UUID a hex run of exactly 8 followed by
   `-`, a datetime four digits then `-`. Finders sharing a run are gated
   together without a virtual call. The measurement stops one byte past the
   longest `max` any rule needs, and the hex run is cached per line so the
   digit-run starts inside a long hash never measure it again.
5. **Finder call.** What survives is handed to `try_at_memo` with a
   per-line `Memo`, a small cache a finder may use to remember a run that
   cannot match, so repeated candidates inside one line stay linear
   (modeline option runs, too-deep JSON bracket runs, IPv6-shaped runs).

6. **Whole-buffer scanning.** `Scanner::scan_buffer` runs the candidate
   search over an entire buffer of lines rather than a line at a time: the
   block stage processes 64 bytes per step (four independent blocks, one
   emptiness test, tables loaded once), and only when a candidate appears
   is its line resolved with `memchr`, the per-line state initialised and
   the exact gates consulted. Line terminators carry no category, so a
   candidate sees the same context as it would in a line scan, and the run
   lengths the rules need come from the block stage's hex and digit lane
   masks instead of a byte loop. A property test pins `scan_buffer` to
   per-line `scan_line` results, line offsets included.

Two other strategies remain selectable for comparison: `Legacy` (the
original per-byte dispatch tables) and `Gated` (the exact tables without
the vector stage).

The CLI memory-maps regular files (smaller ones are read whole) and scans
them from memory; streams are read in 256 KiB blocks. Each block of whole
lines is UTF-8 validated once with `simdutf8` (the standard validator was
the largest remaining cost of a sparse scan) and handed to `scan_buffer`;
only an invalid block is scanned line by line with lossy conversion.
Finders whose walks stop at whitespace (URI, email) are line-agnostic, so
their scanners probe the buffer with absolute positions and resolve a line
only around an actual match. Line numbers are counted lazily between emitted lines, and
plain text results are written with `write_all`. `--jobs` defaults to `auto`: files
of 8 MiB and more are cut into ~512 KiB chunks at newline boundaries
(slices of the mapping, nothing copied), scanned on every core by scoped
threads, and written back in order through a reorder buffer, so output is
byte-identical to the sequential path. Streams and smaller inputs stay
sequential unless a thread count is given; `-1` always is.

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

Library throughput per finder alone on the 56 MiB mixed corpus (Apple M4
Pro, `mise run bench -- --per-finder --only mixed`):

| finder | plan | MiB/s |
|---|---|---|
| email | anchors (`@`) | 2900 |
| color | anchors (`#`, `(`) | 2400 |
| cidr | anchors (`/`) | 2250 |
| datetime | anchors (`-`) | 1970 |
| uuid | anchors (`-`) | 1860 |
| uri | anchors (`:`) | 1670 |
| semver | anchors (`.`) | 1520 |
| hash | blocks + minimum run | 895 |
| ip | anchors (`.`, `:`) | 885 |
| mac | anchors (`:`, `-`, `.`) | 880 |

End to end against ripgrep 15 on that corpus, single-threaded, CPU time
(the stable figure on a loaded machine): url 34 vs 30 ms, email 23 vs 28,
ipv4 50 vs 96, sha256 54 vs 90, uuid 34 vs 51, the five finders together
189 vs 199. With the default `--jobs auto` squeeze finishes each task in 10
to 25 ms of wall time. See the readme for the full table produced by
`mise run bench-cli`.

## Known limits and next steps

- `env` still rescans to the end of the line for every `${` of an unclosed
  expression, and the URI finder rescans a token from each `:` when the
  greedy parse is rejected afterwards (`x?a:?a:?a:...`). Both are bounded
  by the token length and rare in practice; a memo can make them linear.
- `domain` is the last scan-mode finder; its `find` probes forward for an
  email local part and can rescan on `a.b+a.b+...` lines.
- The vector stage processes 64 bytes per step as four 16-byte blocks. An
  AVX2 backend (32 lanes) would halve the instruction count on x86.
- Hash has no anchor byte, so it stays on the block path, where a
  minimum-run filter on the hex lane masks (enabled only when every finder
  that starts at a hex digit needs a run of two or more) drops the short
  runs before any per-lane work; a 64-lane window instead of the current
  32 would sharpen it for `--sha512`.
- Mapped files are read by the kernel on demand; a file truncated by
  another process while it is being scanned raises SIGBUS, the same
  trade-off grep tools make.
