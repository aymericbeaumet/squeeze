# Performance

squeeze aims to be the fastest structured-data extractor available. This
document describes how the scanner reaches that goal, how performance is
measured, and the rules a finder must follow to keep the guarantees.

## Architecture

A `Scanner` holds a list of finders and plans, once, how to search the input
for them. The work is organised so that the expensive part, calling a
finder, happens only where a match can actually start.

1. **Passes.** Each finder is searched by up to three bytes, by a few
   literals, or by the block classifier, and finders sharing a search form
   a pass (`Scanner::plan` prints them, e.g. `anchors(-.) + blocks`). A
   finder is found by a few bytes when its trigger bytes (`@` for email,
   `:` for URIs, `.` for domains), its start bytes (`$` for env, `{[` for
   JSON) or its *anchor* bytes number three or fewer, whichever are rarer
   by a byte frequency table (a JWT is found by the `J` of `eyJ`, not by
   every `e`). An anchor is a byte every match contains, with the set of
   bytes that may lie between the match start and the anchor (`-` for
   UUIDs, `.` and `:` for IP addresses, `/` for CIDR ranges): the scanner
   walks back from each anchor and tries the start positions in order,
   never twice. An anchor may name bytes that confirm a match's first
   anchor byte at fixed offsets, at one of them (an IPv4 address's first
   `.` has another two to four bytes on) or at all of them (a UUID's first
   `-` has others 5, 10 and 15 bytes on, a MAC address's first `:` others
   3, 6, 9 and 12 bytes on, which timestamps never repeat), and the exact
   distance from the match start to that first anchor byte, in which case
   a confirmed anchor goes straight to the finder. A finder whose start
   bytes are as frequent as letters may instead name the literal prefixes
   of its candidates (`todo` for `--todo`, ASCII case ignored). When a
   block pass runs anyway, it classifies extra start bytes for free, so
   finders join it unless they would disable its hex-run filter (below).
   Passes have disjoint finder sets; their matches are merged and grouped
   per line.
2. **Byte and literal search.** A byte pass does not restart `memchr` at
   every hit, which dominates when hits are dense (the colons of a log's
   timestamps): NEON or SSSE3 compares 64 bytes at a time, and the pass
   walks the bits of the resulting mask. The same vectors test the byte
   before each hit against a nibble-table set (the "shufti" technique)
   built from the finders' gates and trigger contexts, so a colon after a
   digit never reaches the scanner when every finder of the pass needs a
   scheme letter there; anchor checks over searched bytes are tested on
   the masks too, one group of lookahead deep, so a timestamp's colon is
   rejected as a MAC address without a call. A literal pass probes each
   literal by its first and rarest byte in two vector loads that far
   apart and verifies the rare hits in full.
3. **Whole-buffer scanning.** `Scanner::scan_buffer` runs each pass over a
   whole buffer, not a line at a time. A pass whose finders are all
   *line-agnostic* (they treat `\n` and `\r` exactly like the end of the
   input, so a match never depends on its line) is probed with absolute
   positions and lines are resolved only around matches; the other passes
   resolve the line around each candidate lazily. The CLI validates UTF-8
   once per block and hands the block to `scan_buffer`, so a line without
   candidates is never visited; plain text output without locations goes
   through `scan_buffer_matches`, which reports ranges into the buffer and
   never resolves or counts lines at all.
4. **Block classifier.** Sixteen bytes at a time, NEON or SSSE3 nibble
   lookups classify each byte into one of eight categories; a per-byte
   lookup (a 128-entry table for ASCII, one entry per high nibble for
   high bytes) gives each start byte a *rule row*, and per-row rules on
   the categories of the previous and next byte yield a bitmap that is a
   superset of the exact gates. Each row holds two alternatives chosen to
   admit the fewest text contexts (measured neighbour-category
   frequencies), so the hex-run finders and the word finders starting at
   `e` keep their own constraints and the unconstrained keycap emoji does
   not let every digit inside a number through. The SSSE3 path, whose
   shuffles index 16 entries, keeps rules per category, a coarser
   superset. When every hex-starting finder of
   the pass needs a hex run of at least *k* bytes (a SHA-256 needs 64, a
   UUID 8), lane shifts drop every hex lane whose run is shorter, before the
   group of four blocks is even tested for candidates; a `--sha256` scan
   probes almost nothing but hashes.
5. **Exact gates.** Dispatch finders declare which byte can start a match
   (`could_start_at`) and, through *context gates*, which previous and next
   bytes rule it out (`could_start_after`, `could_continue_with`). The
   scanner folds these into two lookup tables indexed by a class of the
   neighbouring byte, so a digit inside a number or a hex letter inside a
   word never reaches a finder. Trigger finders share the tables and may
   add a *trigger context* over the two previous bytes and the class of
   the next one, tabulated once: the URI finder's rule that a colon not
   followed by `/` must end a registered scheme rejects timestamps and
   `key:value` pairs before any call (URI calls per KB on logs: 32 to 4).
6. **Run rules.** At a candidate, the scanner measures the digit and hex
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
7. **Finder call.** What survives is handed to `try_at_memo` with a
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
`write_all`. A mapped input is advised `MADV_WILLNEED` over a sliding
8 MiB window ahead of the scan: faulting pages in one at a time from the
scanning thread cost about half the user time of a sparse scan, and the
bounded window never requests an input larger than memory at once.
Newlines are only counted when the output shows line numbers. Files of 8 MiB and more and standard input are scanned on every
core by default (`--jobs auto`): the input is cut into ~512 KiB chunks at
newline boundaries, scanned by scoped threads, and written back in order by
a writer thread through a reorder buffer, so output is byte-identical to the
sequential path. Stream chunks are read straight into their own buffers,
and a short read (a live stream that paused) cuts the chunk early so
results are not held back waiting for a full block. The reader waits
while four chunks per worker are read but not written, so a blocked
stdout stops the reading instead of piling up results.

Directories are walked by the `ignore` crate, ripgrep's walker: hidden
entries, `.gitignore`, `.ignore` and git exclude rules are honoured, and a
file whose first 8 KiB contain a NUL byte is skipped as binary. Every walker
thread (at most twelve; beyond that file system locks, not the scan, set the
pace) scans whole files, reading them into a reused buffer without a stat
(only a file filling the first 256 KiB is stat'ed, and mapped from 4 MiB
on), and writes each file's results in one piece. An entry that cannot be
read is reported and skipped, and the exit status says so.

## Contracts a finder must follow

Every optimisation above is only correct because finders keep a contract,
and every contract has a property test in `squeeze/tests/fuzz.rs`:

- If `could_start_after(prev, cur)`, `could_continue_with(cur, next)` or,
  for a trigger finder whose next byte is not `trigger_context_exempt`,
  `trigger_context(prev2, prev1)` returns `false`, `try_at` (or
  `try_trigger_at`) must return `None` in that context.
- If `RunRule::allow(rules, cur, runs, input, pos)` returns `false`, the
  attempt must return `None`; chained, word and length-restricted rules are
  checked the same way.
- Every match of a dispatch finder with an `anchor` contains an anchor
  byte, only `walk` bytes lie between the match start and its first
  anchor byte, and that byte passes the anchor's checks.
- `try_at(input, pos)` only matches where one of the finder's `prefixes`
  starts at `pos`, ASCII case ignored.
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

`mise run bench-cli` (`mise-tasks/bench-cli`) builds the release binary,
generates corpora at a chosen scale, and times the same extraction tasks
through squeeze, ripgrep, GNU/BSD grep and ugrep with hyperfine, recording
match counts next to the timings. Results land in `/tmp/squeeze-bench/summary.md`,
ready to paste between the `bench-cli` markers of [CLI benchmarks](#cli-benchmarks).

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

End-to-end, minimum user CPU time over 7 interleaved runs on the 56 MiB
mixed corpus (Apple M4 Pro, machine under external load), single-threaded,
before and after the byte and literal search stage (masks, previous-byte
filter, anchor checks in the search, literal prefixes, mapped-page
prefetch):

| command | before | after |
|---|---|---|
| `squeeze --all` | 320 ms | 315 ms |
| `squeeze --url --email --ipv4 --sha256 --uuid` | 86 ms | 74 ms |
| `squeeze --url` | 25 ms | 15 ms |
| `squeeze --uuid` | 17 ms | 12 ms |
| `squeeze --datetime` | 18 ms | 12 ms |
| `squeeze --sha256` | 33 ms | 29 ms |
| `squeeze --ipv4` | 33 ms | 23 ms |
| `squeeze --mac` | 52 ms | 17 ms |
| `squeeze --domain` | 26 ms | 22 ms |
| `squeeze --todo` | 48 ms | 8 ms |
| `squeeze --codetag` | 112 ms | 108 ms |

On a 64 MB log, where the colons of timestamps dominate, `--url` went from
45 to 25 ms and `--mac` from 83 to 27 ms. Startup is 1.3 ms of user time.

See the readme for the comparison with other matchers produced by
`mise run bench-cli`.

## CLI benchmarks

`mise run bench-cli` reproduces the comparison below: deterministic corpora
generated by the library bench, the same extraction task given to each tool
(squeeze finder versus the closest POSIX regex for the others), files read
directly with `LC_ALL=C`, output discarded, timed with
[hyperfine](https://github.com/sharkdp/hyperfine). Match counts are reported
because the regexes are approximations of squeeze's grammars.

<!-- bench-cli:start -->
Mixed corpus of 56 MiB (logs, prose, source, JSON lines, markdown,
hex-dense and unicode text, scale 8), Apple M4 Pro (10 performance + 4
efficiency cores) while the machine was under heavy unrelated load, median
wall time and mean CPU time of 7 runs; ripgrep 15.2.0, ugrep 7.8.5, GNU grep 3.12. Output is piped away
rather than sent to `/dev/null`, which grep and ugrep detect to stop at the
first match. Wall time moves with load; CPU time is the stable figure.
Rerun `mise run bench-cli` to reproduce.

| task | squeeze -j 1 | squeeze | ripgrep | ugrep | gnu grep |
|---|---|---|---|---|---|
| url | 19 ms wall, 18 ms cpu (3011 MiB/s, 76840 matches) | 6 ms wall, 22 ms cpu (9408 MiB/s, 76840 matches) | 36 ms wall, 35 ms cpu (1542 MiB/s, 94584 matches) | 32 ms wall, 30 ms cpu (1737 MiB/s, 94584 matches) | 61 ms wall, 58 ms cpu (925 MiB/s, 94584 matches) |
| email | 15 ms wall, 14 ms cpu (3815 MiB/s, 144920 matches) | 5 ms wall, 18 ms cpu (11328 MiB/s, 144920 matches) | 30 ms wall, 29 ms cpu (1845 MiB/s, 144920 matches) | 92 ms wall, 88 ms cpu (611 MiB/s, 144920 matches) | 207 ms wall, 205 ms cpu (270 MiB/s, 144920 matches) |
| ipv4 | 53 ms wall, 29 ms cpu (1064 MiB/s, 139840 matches) | 32 ms wall, 32 ms cpu (1776 MiB/s, 139840 matches) | 246 ms wall, 111 ms cpu (228 MiB/s, 139840 matches) | 166 ms wall, 75 ms cpu (338 MiB/s, 139840 matches) | 556 ms wall, 247 ms cpu (101 MiB/s, 139840 matches) |
| sha256 | 31 ms wall, 30 ms cpu (1802 MiB/s, 29016 matches) | 6 ms wall, 36 ms cpu (9149 MiB/s, 29016 matches) | 96 ms wall, 94 ms cpu (586 MiB/s, 63880 matches) | 169 ms wall, 167 ms cpu (331 MiB/s, 63880 matches) | 156 ms wall, 154 ms cpu (358 MiB/s, 63880 matches) |
| uuid | 14 ms wall, 14 ms cpu (3937 MiB/s, 82856 matches) | 5 ms wall, 18 ms cpu (10935 MiB/s, 82856 matches) | 53 ms wall, 51 ms cpu (1054 MiB/s, 82856 matches) | 27 ms wall, 24 ms cpu (2081 MiB/s, 82856 matches) | 101 ms wall, 98 ms cpu (552 MiB/s, 82856 matches) |
| five kinds | 248 ms wall, 93 ms cpu (226 MiB/s, 473472 matches) | 26 ms wall, 96 ms cpu (2154 MiB/s, 473472 matches) | 166 ms wall, 167 ms cpu (337 MiB/s, 526080 matches) | 861 ms wall, 879 ms cpu (65 MiB/s, 526080 matches) | 1191 ms wall, 1198 ms cpu (47 MiB/s, 526080 matches) |
| everything | 394 ms wall, 352 ms cpu (142 MiB/s, 1162904 matches) | 50 ms wall, 373 ms cpu (1124 MiB/s, 1162904 matches) | n/a | n/a | n/a |

The same tasks on the log corpus alone (8 MiB):

| task | squeeze -j 1 | squeeze | ripgrep | ugrep | gnu grep |
|---|---|---|---|---|---|
| url | 5 ms wall, 5 ms cpu (1493 MiB/s, 11232 matches) | 4 ms wall, 6 ms cpu (2254 MiB/s, 11232 matches) | 9 ms wall, 7 ms cpu (863 MiB/s, 11232 matches) | 10 ms wall, 7 ms cpu (800 MiB/s, 11232 matches) | 11 ms wall, 8 ms cpu (696 MiB/s, 11232 matches) |
| email | 4 ms wall, 3 ms cpu (2142 MiB/s, 11248 matches) | 3 ms wall, 4 ms cpu (2622 MiB/s, 11248 matches) | 7 ms wall, 5 ms cpu (1067 MiB/s, 11248 matches) | 35 ms wall, 31 ms cpu (229 MiB/s, 11248 matches) | 34 ms wall, 31 ms cpu (234 MiB/s, 11248 matches) |
| ipv4 | 6 ms wall, 5 ms cpu (1342 MiB/s, 22440 matches) | 3 ms wall, 7 ms cpu (2360 MiB/s, 22440 matches) | 20 ms wall, 18 ms cpu (391 MiB/s, 22440 matches) | 19 ms wall, 13 ms cpu (428 MiB/s, 22440 matches) | 52 ms wall, 45 ms cpu (155 MiB/s, 22440 matches) |
| sha256 | 10 ms wall, 8 ms cpu (787 MiB/s, 11232 matches) | 7 ms wall, 8 ms cpu (1231 MiB/s, 11232 matches) | 20 ms wall, 17 ms cpu (404 MiB/s, 11232 matches) | 18 ms wall, 15 ms cpu (456 MiB/s, 11232 matches) | 30 ms wall, 27 ms cpu (266 MiB/s, 11232 matches) |
| uuid | 4 ms wall, 4 ms cpu (1828 MiB/s, 11248 matches) | 3 ms wall, 5 ms cpu (2411 MiB/s, 11248 matches) | 19 ms wall, 17 ms cpu (413 MiB/s, 11248 matches) | 9 ms wall, 6 ms cpu (845 MiB/s, 11248 matches) | 26 ms wall, 23 ms cpu (305 MiB/s, 11248 matches) |
| five kinds | 71 ms wall, 19 ms cpu (113 MiB/s, 67400 matches) | 9 ms wall, 18 ms cpu (920 MiB/s, 67400 matches) | 138 ms wall, 43 ms cpu (58 MiB/s, 67400 matches) | 504 ms wall, 203 ms cpu (16 MiB/s, 67400 matches) | 308 ms wall, 237 ms cpu (26 MiB/s, 67400 matches) |
| everything | 67 ms wall, 66 ms cpu (120 MiB/s, 302736 matches) | 23 ms wall, 77 ms cpu (346 MiB/s, 302736 matches) | n/a | n/a | n/a |

At scale, each tool with its default parallelism, 5 runs. The
mixed corpus repeated to 2 GiB, read from the file:

| task | squeeze | ripgrep | ugrep | gnu grep |
|---|---|---|---|---|
| url | 113 ms wall, 654 ms cpu (18271 MiB/s, 2843080 matches) | 2376 ms wall, 1270 ms cpu (872 MiB/s, 3499608 matches) | 1073 ms wall, 1055 ms cpu (1931 MiB/s, 3499608 matches) | 2691 ms wall, 2233 ms cpu (770 MiB/s, 3499608 matches) |
| ipv4 | 202 ms wall, 986 ms cpu (10272 MiB/s, 5174080 matches) | 6207 ms wall, 5381 ms cpu (334 MiB/s, 5174080 matches) | 15621 ms wall, 9889 ms cpu (133 MiB/s, 5174080 matches) | 46993 ms wall, 31494 ms cpu (44 MiB/s, 5174080 matches) |
| uuid | 106 ms wall, 532 ms cpu (19485 MiB/s, 3065672 matches) | 2436 ms wall, 1933 ms cpu (851 MiB/s, 3065672 matches) | 851 ms wall, 819 ms cpu (2434 MiB/s, 3065672 matches) | 5372 ms wall, 3803 ms cpu (386 MiB/s, 3065672 matches) |

The same 2 GiB piped through `cat`, as a stream of logs would be:

| task | squeeze | ripgrep | ugrep | gnu grep |
|---|---|---|---|---|
| url | 714 ms wall, 1469 ms cpu (2901 MiB/s, 2843080 matches) | 1543 ms wall, 1721 ms cpu (1343 MiB/s, 3499608 matches) | 1670 ms wall, 1582 ms cpu (1241 MiB/s, 3499608 matches) | 2815 ms wall, 2785 ms cpu (736 MiB/s, 3499608 matches) |
| ipv4 | 1538 ms wall, 1751 ms cpu (1347 MiB/s, 5174080 matches) | 6247 ms wall, 4013 ms cpu (332 MiB/s, 5174080 matches) | 2333 ms wall, 2707 ms cpu (888 MiB/s, 5174080 matches) | 13456 ms wall, 8649 ms cpu (154 MiB/s, 5174080 matches) |
| uuid | 1174 ms wall, 1351 ms cpu (1765 MiB/s, 3065672 matches) | 2321 ms wall, 2382 ms cpu (893 MiB/s, 3065672 matches) | 1231 ms wall, 1382 ms cpu (1683 MiB/s, 3065672 matches) | 10540 ms wall, 4386 ms cpu (197 MiB/s, 3065672 matches) |

A generated source tree of 20,000 files (175 MiB) with a `.gitignore`d
build directory as large again, walked by the tools that honour ignore
files (`--todo` against a case-insensitive `todo`):

| task | squeeze | ripgrep | ugrep |
|---|---|---|---|
| url | 216 ms wall, 962 ms cpu (809 MiB/s, 335710 matches) | 326 ms wall, 2858 ms cpu (535 MiB/s, 335710 matches) | 238 ms wall, 1022 ms cpu (734 MiB/s, 335710 matches) |
| todo | 219 ms wall, 842 ms cpu (797 MiB/s, 114565 matches) | 352 ms wall, 3525 ms cpu (496 MiB/s, 114565 matches) | 230 ms wall, 1009 ms cpu (759 MiB/s, 114565 matches) |

Single-threaded, squeeze uses less CPU than ripgrep, ugrep and GNU grep on
every task of both corpora, while parsing URIs per RFC 3986 with the IANA
scheme registry rather than matching `https?://[^\s]+`. The five finders
together take about half the CPU of ripgrep's five-pattern regex and a
ninth of ugrep's. At scale, the default parallel scan reads the 2 GiB file
at least eight times faster than ripgrep and ugrep, scans the same bytes
piped through `cat` faster than both on every task, and walks the source
tree, with the same ignore rules, ahead of both and with less CPU. Match
counts differ where the regexes are looser than squeeze's grammars (URLs
with trailing punctuation, 64-hex runs inside longer runs).
<!-- bench-cli:end -->

`squeeze -j 1` is the like-for-like single-threaded comparison; plain
`squeeze` is the default, which scans standard input and files of 8 MiB and
more on every core with output kept in order, and walks directories on
several threads. `five kinds` runs the five finders together
against the union of the five patterns; `everything` runs all 20 finders,
which no regex tool can do in one pass. CPU time is the number to compare
on a busy machine. Library-level throughput and operation counts per finder
come from `mise run bench -- --stats`, above.

## Known limits and next steps

- The block classifier's rules see eight neighbour categories, so a
  candidate whose exact gate depends on a finer class (`-` versus other
  punctuation, `y` versus other letters) still reaches the exact gates:
  about 130 per KB on prose and 50 per KB on logs, listed by `--stats`.
  Wider category vectors (two bytes per lane) would remove most of them.
- The URI parser costs about 130 ns per matched URL: it walks the
  hier-part, query and fragment character by character and trims the
  result afterwards. A table-driven single pass would roughly halve it.
- `env` still rescans to the end of the line for every `${` of an unclosed
  expression; the scan now stops at line terminators, and a memo could make
  it linear.
- The default codetag mnemonics (about seventy, some starting with `s`,
  which the long s folds onto) are too many for a literal pass and still
  go through the block classifier; a Teddy-style multi-literal search
  would cover them.
- The vector stage processes 16 bytes per step. An AVX2 backend (32 lanes)
  and a 64-byte NEON step would halve the per-block overhead.
