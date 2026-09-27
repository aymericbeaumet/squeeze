# squeeze 🍊

[![CI](https://github.com/aymericbeaumet/squeeze/actions/workflows/ci.yml/badge.svg)](https://github.com/aymericbeaumet/squeeze/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/aymericbeaumet/squeeze)](https://github.com/aymericbeaumet/squeeze/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Extract URLs, emails, IPs, hashes, TODOs, and 15 other kinds of data from any
text. Like `grep -o`, but it already knows what a URL looks like.

```console
$ cat notes.md
See [the docs](https://example.com/docs), or https://en.wikipedia.org/wiki/Squeeze_(disambiguation).
Ping ops@example.com, then check <https://status.example.com>.

$ grep -oE 'https?://[^ ]+' notes.md
https://example.com/docs),
https://en.wikipedia.org/wiki/Squeeze_(disambiguation).
https://status.example.com>.

$ squeeze --url notes.md
https://example.com/docs
https://en.wikipedia.org/wiki/Squeeze_(disambiguation)
https://status.example.com
```

- **Gets the edge cases right.** Each finder is a small parser following its
  format's spec (RFC 3986 URIs, IPv6, semver, JWTs, …), and it copes with the
  Markdown, JSON, HTML, and prose around a match: trailing punctuation,
  balanced parentheses, and quotes.
- **Plays well with pipes and repositories.** It reads stdin, files, globs,
  or whole directory trees (skipping what `.gitignore` ignores, like
  ripgrep), streams results as it finds them, and stops at the first one
  with `-1`.
- **Structured when you need it.** JSON, YAML, or CSV output with the kind,
  line, and column of each match, or `path:line:column:` prefixes your editor
  can jump to.
- **Fast.** SIMD byte classification finds the few positions where a match
  can start, so enabling many finders stays cheap, and big files, streams
  and directory trees are scanned on every core.
- **Also a Rust library.** Every finder is available as a
  [crate](#use-as-a-rust-library).

## Install

**Homebrew** (macOS, Linux):

```shell
brew install aymericbeaumet/tap/squeeze
```

**Prebuilt binaries**: download an archive for Linux, macOS, or Windows
(`amd64` or `arm64`) from
[GitHub Releases](https://github.com/aymericbeaumet/squeeze/releases/latest),
extract it, and put `squeeze` (`squeeze.exe` on Windows) on your `PATH`. Each
release includes SHA-256 checksums.

**Cargo** (requires [Rust](https://www.rust-lang.org/tools/install) 1.95+):

```shell
cargo install --locked --git https://github.com/aymericbeaumet/squeeze squeeze-cli
```

## Usage

Pick one or more finders. `squeeze` scans the files, directories, and quoted
glob patterns you pass after the options. Without a path it reads standard
input, or searches the current directory when standard input is a terminal.
Directories are walked recursively on every core, the way ripgrep walks
them: hidden entries, `.gitignore` and `.ignore` rules, and binary files are
skipped.

```shell
# Every link on a web page
curl -s https://news.ycombinator.com | squeeze --url --uniq

# Everyone who committed to a repository
git log --format='%an <%ae>' | squeeze --email --sort --uniq

# IPs, request IDs, and timestamps in logs, labeled by kind
kubectl logs deploy/api | squeeze --ip --uuid --datetime --with-kind

# TODOs and FIXMEs across a repository, with locations your editor understands
squeeze --todo --fixme --with-location

# Rust sources only
squeeze --todo --fixme --with-location 'src/**/*.rs'

# Everything squeeze can find, as JSON
squeeze --all --with-kind --output json notes.md
```

With several finders, results come out in the order they appear:

```console
$ echo '2026-01-15T10:30:00Z GET /health from 10.0.4.2 took 3ms' | squeeze --datetime --ip --with-kind
datetime	2026-01-15T10:30:00Z
ip	10.0.4.2
```

### Finders

| Finder | Flag | Examples |
|--------|------|----------|
| CIDR | `--cidr` | `192.168.1.0/24`, `2001:db8::/32` |
| Codetags | `--codetag`, `--todo`, `--fixme` | `TODO: fix this`, `FIXME(#42): bug` |
| Colors | `--color` | `#ff0000`, `rgb(255, 0, 0)`, `hsl(0, 100%, 50%)` |
| Datetimes | `--datetime` | `2024-01-15`, `2024-01-15T10:30:00Z` |
| Domains | `--domain` | `example.com`, `mail.example.co.uk` |
| Emails | `--email` | `user@example.com`, `first.last+tag@company.co.uk` |
| Emojis | `--emoji` | `😀`, `👨‍👩‍👧‍👦`, `1️⃣` |
| Env vars | `--env` | `$HOME`, `${PATH}`, `${VAR:-default}` |
| Handles | `--handle` | `@alice`, `@user@example.social` |
| Hashes | `--hash`, `--md5`, `--sha1`, `--sha256`, `--sha512` | `5d41402abc4b2a76b9719d911017c592` |
| IPs | `--ip`, `--ipv4`, `--ipv6` | `192.168.1.1`, `::1`, `2001:db8::1` |
| JSON | `--json` | `{"key": "value"}`, `[1, 2, 3]` |
| JWTs | `--jwt` | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln` |
| MACs | `--mac` | `00:1A:2B:3C:4D:5E`, `001A.2B3C.4D5E` |
| Modelines | `--modeline` | `vim: set ts=4 sw=4 et:` |
| Paths | `--path` | `/etc/hosts`, `./src/main.rs:42:10` |
| Phones | `--phone` | `+14155551234`, `(415) 555-1234` |
| Semver | `--semver` | `1.0.0`, `v2.3.1-rc.1+build.42` |
| URIs | `--uri`, `--url`, `--http`, `--https` | `https://example.com`, `mailto:hi@example.com` |
| UUIDs | `--uuid` | `550e8400-e29b-41d4-a716-446655440000` |

Some finders take a filter: `--codetag=todo,fixme`, `--hash=sha256`,
`--uri=https,ssh`. `--url` is shorthand for the schemes people usually mean
by a URL (`http`, `https`, `ftp`, `mailto`, …); `--uri` accepts any scheme.

Finders favor precision over recall. Use `--strict` to make `--uri` follow
RFC 3986 to the letter.

### Output options

| Flag | Description |
|------|-------------|
| `-1`, `--first` | stop after the first result |
| `--last` | only print the last result |
| `--sort` | sort the results |
| `--uniq` | deduplicate the results, keeping the first occurrence |
| `--with-kind` | print the finder name (`uri`, `email`, …) with each result |
| `--with-location` | print `path:line:column:` before each result |
| `--output <fmt>` | `text` (default), `json`, `yaml`, `csv`, or `none` |
| `--no-overlap` | drop matches that overlap an earlier one (`--precedence longest` keeps the longest instead) |
| `--copy` | copy the results to the clipboard |
| `--open` | open each result with the default application |
| `-j`, `--jobs <N>` | scanning threads; `auto` (default) uses every core for directories, stdin, and files of 8 MiB and more, output of a single input kept in order |

Walking a directory:

| Flag | Description |
|------|-------------|
| `--hidden` | also search hidden files and directories (`.git` is always skipped) |
| `--no-ignore` | do not respect `.gitignore`, `.ignore`, and git exclude rules |
| `--follow` | follow symbolic links |

In the structured formats, `--with-kind` and `--with-location` both switch
each result to an object with its kind, value, line, column, byte offsets, and
source file. Run `squeeze --help` for the full list.

## Integrations

### vim/nvim

Press `Enter` in visual mode to open the first URL in the selection:

```vim
" ~/.vimrc
vnoremap <silent> <CR> :<C-U>'<,'>w !squeeze -1 --url --open<CR><CR>
```

Load every TODO and FIXME of a project into the quickfix list:

```vim
:cexpr system("squeeze --todo --fixme --with-location 'src/**/*'")
```

### tmux

Press `Enter` in copy mode to open the first URL in the selection:

```tmux
# ~/.tmux.conf
bind -T copy-mode-vi enter send -X copy-pipe-and-cancel "squeeze -1 --url --open"
```

### fzf

Pick a URL from the scrollback of the current tmux pane and open it:

```shell
tmux capture-pane -pJ -S - | squeeze --url --uniq | fzf --tac | squeeze --url --open
```

### Shell

List the URLs from your shell history, most recent first:

```shell
# ~/.bashrc, ~/.zshrc
urls() { fc -rl 1 | squeeze --url --uniq; }
```

## Performance

squeeze is built to be the fastest structured-data extractor available:
SIMD searches and byte classification over whole buffers, per-finder
context gates and shared run measurements keep finder calls to the
positions where a match can start, every finder is linear on adversarial
input, and big files, streams and directory trees are scanned in parallel.
No regex engine is involved. The design, its contracts and the measurement tooling are described
in [docs/performance.md](docs/performance.md).

### Benchmarks

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
come from `mise run bench -- --stats`.

## Use as a Rust library

The finders live in the `squeeze` crate, which the CLI builds on:

```toml
[dependencies]
squeeze = { git = "https://github.com/aymericbeaumet/squeeze" }
```

```rust
use squeeze::{email::Email, scanner::Scanner, uri::URI};

let scanner = Scanner::new(vec![Box::new(URI::default()), Box::new(Email::default())]);

let line = "Ping ops@example.com about https://example.com/status";
for m in scanner.scan_line(line) {
    let kind = scanner.finders()[m.finder_index].id();
    println!("{kind}\t{}", &line[m.range]);
}
```

Build the API documentation with `cargo doc --open -p squeeze`.

## Development

Install [mise](https://mise.jdx.dev/getting-started.html), then run the same
checks as CI:

```shell
mise trust
mise install
mise run check
```

See [development and releases](docs/development.md) for the other tasks and
the release process. Bug reports with a sample input that squeeze gets wrong
are especially welcome.

## License

[MIT](LICENSE)
