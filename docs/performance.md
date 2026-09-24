# Performance

squeeze aims to be the fastest structured-data extractor available. This
document describes how the scanner reaches that goal, how performance is
measured, and the rules a finder must follow to keep the guarantees.

## Architecture

A `Scanner` holds a list of finders and plans, once, how to search the input
for them. The work is organised so that the expensive part, calling a
finder, happens only where a match can actually start.

1. **Passes.** Each finder is searched either by `memchr` on up to three
   bytes or by the block classifier, and finders sharing a search form a
   pass (`Scanner::plan` prints them, e.g. `anchors(-.) + blocks`). A finder
   is found by a few bytes when its trigger bytes (`@` for email, `:` for
   URIs, `.` for domains), its start bytes (`$` for env, `{[` for JSON) or
   its *anchor* bytes number three or fewer. An anchor is a byte every
   match contains, with the set of bytes that may lie between the match
   start and the anchor (`-` for UUIDs, `.` and `:` for IP addresses, `/`
   for CIDR ranges): the scanner walks back from each anchor and tries the
   start positions in order, never twice. When a block pass runs anyway,
   it classifies extra start bytes for free, so finders join it unless they
   would disable its hex-run filter (below). Passes have disjoint finder
   sets; their matches are merged and grouped per line.
2. **Whole-buffer scanning.** `Scanner::scan_buffer` runs each pass over a
   whole buffer, not a line at a time. A pass whose finders are all
   *line-agnostic* (they treat `\n` and `\r` exactly like the end of the
   input, so a match never depends on its line) is probed with absolute
   positions and lines are resolved only around matches; the other passes
   resolve the line around each candidate lazily. The CLI validates UTF-8
   once per block and hands the block to `scan_buffer`, so a line without
   candidates is never visited.
3. **Block classifier.** Sixteen bytes at a time, NEON or SSSE3 nibble
   lookups classify each byte into a category and test the pass's start
   set; per-category rules on the previous and next byte (two alternatives,
   so an unconstrained finder does not cancel the others) yield a bitmap
   that is a superset of the exact gates. When every hex-starting finder of
   the pass needs a hex run of at least *k* bytes (a SHA-256 needs 64, a
   UUID 8), lane shifts drop every hex lane whose run is shorter, before the
   group of four blocks is even tested for candidates; a `--sha256` scan
   probes almost nothing but hashes.
4. **Exact gates.** Dispatch finders declare which byte can start a match
   (`could_start_at`) and, through *context gates*, which previous and next
   bytes rule it out (`could_start_after`, `could_continue_with`). The
   scanner folds these into two lookup tables indexed by a class of the
   neighbouring byte, so a digit inside a number or a hex letter inside a
   word never reaches a finder. Trigger finders share the tables.
5. **Run rules.** At a candidate, the scanner measures the digit and hex
   runs once (`Runs::at`, from the classifier's lanes when they cover the
   run) and evaluates each finder's declarative `RunRule`s. A rule can
   chain follow-up runs: an IPv4 address needs `d.d.`, a MAC address
   `aa:bb:cc:`, a date `YYYY-MM-`, a UUID `xxxxxxxx-xxxx-xxxx-`, a dashed
   phone number all three groups. Word rules measure the ASCII word at the
   candidate instead: a codetag mnemonic is a word of one of the mnemonic
   lengths followed by `:` or `(`, a modeline `vi`/`vim`/`ex` before `:`,
   a colour function `rgb`/`hsl` before `(`. Before any rule is visited,
   the byte after each run and the run's length are looked up in per-class
   tables of the finders whose rules can accept them, so a plain number
   rejects every rule of every finder with four loads.
6. **Finder call.** What survives is handed to `try_at_memo` with a
   per-line `Memo`, a small cache a finder may use to remember a run that
   cannot match, so repeated candidates inside one line stay linear
   (modeline option runs, too-deep JSON bracket runs, IPv6-shaped runs,
   dotted tokens for the domain finder).

Two other strategies remain selectable for comparison: `Legacy` (the
original per-byte dispatch tables) and `Gated` (the exact tables without
the vector stage).

The CLI memory-maps regular files of 64 KiB and more and reads everything
else in 256 KiB blocks, validates UTF-8 once per block or 1 MiB window with
`simdutf8`, scans it with `scan_buffer` and writes plain text results with
`write_all`. Files of 8 MiB and more are scanned on every core by default
(`--jobs auto`): the input is cut into ~512 KiB chunks at newline
boundaries, scanned by scoped threads, and written back in order through a
reorder buffer, so output is byte-identical to the sequential path.

## Contracts a finder must follow

Every optimisation above is only correct because finders keep a contract,
and every contract has a property test in `squeeze/tests/fuzz.rs`:

- If `could_start_after(prev, cur)` or `could_continue_with(cur, next)`
  returns `false`, `try_at` (or `try_trigger_at`) must return `None` in
  that context.
- If `RunRule::allow(rules, cur, runs, input, pos)` returns `false`, the
  attempt must return `None`; chained, word and length-restricted rules are
  checked the same way.
- Every match of a dispatch finder with an `anchor` contains an anchor
  byte, and only `walk` bytes lie between the match start and its first
  anchor byte.
- A `line_agnostic` finder gives the same answer on a whole buffer as on
  the line alone: `\n` and `\r` never belong to a match and end every walk
  like the end of the input does.
- `try_at_memo` must return exactly what `try_at` returns; the memo is a
  cache, never an input.
- Strategies and backends must agree byte for byte, `scan_buffer` must
  agree with per-line scanning for every plan, `linear_scans.rs` rejects
  quadratic rescans on adversarial 100 KB lines, and `regex_parity.rs`
  pins the hand-written codetag, modeline and phone matchers to the regexes
  they replaced (kept as dev-dependencies only). The domain finder's
  trigger path is compared with its `find` reference the same way.

## Measuring

`mise run bench -- [options]` runs the `scanner` bench on deterministic
synthetic corpora (logs, prose, source, JSON lines, markdown, hex-dense,
unicode, plus the URI fixture and any `--corpus FILE`):

| option | purpose |
|---|---|
| `--stats` | operation counters: finder calls per KB, hit rate, coarse and exact candidate ratios, prescan skips, per-finder breakdown, and the bytes at which the block classifier produced candidates the exact gates rejected |
| `--strategy all` | time every strategy interleaved in one process |
| `--per-finder` | time each finder alone and compare the sum with the combined scan |
| `--finders a,b` / `--only c,d` | restrict the finders and corpora |
| `--save FILE` / `--compare FILE` | record a run and print throughput and call deltas against it |
| `--write-corpus DIR` | dump the corpora for external tools |

The bench pins itself to performance cores (macOS QoS) and keeps the best of
interleaved rounds. On a loaded machine wall-clock numbers still drift by
50% or more between runs; **operation counts are exact and load-independent**
and are the primary signal when comparing changes. For end-to-end CPU time
prefer the minimum user time over many interleaved runs of each binary.

`mise run bench-cli` (`scripts/bench-cli.sh`) builds the release binary,
generates corpora at a chosen scale, and times the same extraction tasks
through squeeze, ripgrep, GNU/BSD grep and ugrep with hyperfine, recording
match counts next to the timings. Results land in `/tmp/squeeze-bench/summary.md`.

To profile: build with `CARGO_PROFILE_RELEASE_STRIP=false
CARGO_PROFILE_RELEASE_DEBUG=1 cargo build --release --target-dir target/prof`,
record with `samply record --save-only` and symbolicate the hot addresses
with `atos -i` against a `dsymutil` bundle (macOS), or use `perf` (Linux).
Note that the first pass over a memory-mapped file collects the page-touch
stalls of the whole run.

## Results

Finder invocations per KB with every finder enabled, from `--stats`
(exact counts, unaffected by machine load):

| corpus | original | context gates | run rules | no regex | passes and chained rules |
|---|---|---|---|---|---|
| logs | 3154 | 704 | 179 | 220 | 94 |
| prose | 1157 | 127 | 11 | 6 | 9 |
| source | 979 | 181 | 93 | 93 | 48 |
| jsonl | 2588 | 519 | 147 | 234 | 74 |
| markdown | 1189 | 184 | 66 | 66 | 47 |
| hexdense | 2839 | 461 | 69 | 67 | 46 |
| unicode | 937 | 199 | 136 | 136 | 111 |
| nomatch | 800 | 57 | 0 | 0 | 0 |
| urls | 2029 | 364 | 98 | 118 | 56 |

The `no regex` column counts the former scan-mode finders, which run as
gated dispatch or trigger finders instead of one regex pass per line: their
calls are counted where they used to be invisible. The last column adds
the pass planner, chained run rules and word rules; on the mixed corpus the
ip, phone, mac and cidr finders lost 50 to 80 percent of their calls and
codetag went from 26.7 to 1.8 calls per KB, while the hit rate of the
remaining calls is above 30 percent. Hash, UUID, MAC, datetime, colour, env
and handle are only ever invoked on true matches.

Adversarial single lines that used to be quadratic (a 100 KB `1.1.1.1...`
run, `[` repeated, `ex:a ` repeated, `a.b` repeated) scan at 85 to 150 MiB/s.

End-to-end, minimum user CPU time over 11 interleaved runs on the 56 MiB
mixed corpus (Apple M4 Pro, machine under external load), single-threaded:

| command | before this round | after |
|---|---|---|
| `squeeze --all` | 389 ms | 348 ms |
| `squeeze --url --email --ipv4 --sha256 --uuid` | 192 ms | 104 ms |
| `squeeze --sha256` | 51 ms | 30 ms |
| `squeeze --uuid --sha256` | 58 ms | 40 ms |
| `squeeze --ipv4` | 44 ms | 35 ms |
| `squeeze --domain` | 63 ms | 24 ms |
| `squeeze --codetag` | 135 ms | 104 ms |

See the readme for the comparison with other matchers produced by
`mise run bench-cli`.

## Known limits and next steps

- The block classifier distinguishes eight byte categories and keeps rules
  per category rather than per start byte, so on prose about a third of
  its candidates (words starting with `e`, `a`, `c`, `s`, `r`...) are
  rejected by the exact gates; `--stats` lists those bytes. A 16-row
  classifier indexed by a full byte lookup would remove most of them.
- The URI parser costs about 130 ns per matched URL: it walks the
  hier-part, query and fragment character by character and trims the
  result afterwards. A table-driven single pass would roughly halve it.
- `env` still rescans to the end of the line for every `${` of an unclosed
  expression; the scan now stops at line terminators, and a memo could make
  it linear.
- Trigger finders take no run rules by default; the URI finder is called at
  every colon whose neighbours are scheme bytes, which the IANA table check
  rejects in a few nanoseconds.
- The vector stage processes 16 bytes per step. An AVX2 backend (32 lanes)
  and a 64-byte NEON step would halve the per-block overhead.
