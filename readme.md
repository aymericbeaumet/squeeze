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
- **Plays well with pipes.** It reads stdin, files, or globs, streams
  results as it finds them, and stops at the first one with `-1`.
- **Structured when you need it.** JSON, YAML, or CSV output with the kind,
  line, and column of each match, or `path:line:column:` prefixes your editor
  can jump to.
- **Fast.** A single pass over each line dispatches only the finders that
  can match there, so enabling many finders stays cheap.
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

Pick one or more finders. `squeeze` scans standard input, or the files and
quoted glob patterns you pass after the options:

```shell
# Every link on a web page
curl -s https://news.ycombinator.com | squeeze --url --uniq

# Everyone who committed to a repository
git log --format='%an <%ae>' | squeeze --email --sort --uniq

# IPs, request IDs, and timestamps in logs, labeled by kind
kubectl logs deploy/api | squeeze --ip --uuid --datetime --with-kind

# TODOs and FIXMEs, with locations your editor understands
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
| `-j`, `--jobs <N>` | scan input chunks in parallel on `N` threads, output kept in order |

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

squeeze is built to be the fastest structured-data extractor available: one
pass per line, SIMD byte classification, per-finder context gates and
shared run measurements keep finder calls to the positions where a match can
start, and every finder is linear on adversarial input. No regex engine is
involved. The design, its contracts and the measurement tooling are described
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
efficiency cores) while the machine was under heavy unrelated load, mean of
5 runs; ripgrep 15.2, GNU grep 3.x. Numbers move with load: rerun
`mise run bench-cli` on a quiet machine before quoting them.

| task | squeeze | squeeze -j 14 | ripgrep | gnu grep |
|---|---|---|---|---|
| url | 44 ms (1282 MiB/s, 76840 matches) | 12 ms (4850 MiB/s, 76840 matches) | 36 ms (1562 MiB/s, 94584 matches) | 329 ms (170 MiB/s, 94584 matches) |
| email | 71 ms (789 MiB/s, 144920 matches) | 42 ms (1349 MiB/s, 144920 matches) | 64 ms (871 MiB/s, 144920 matches) | 1915 ms (29 MiB/s, 144920 matches) |
| ipv4 | 244 ms (230 MiB/s, 139840 matches) | 25 ms (2221 MiB/s, 139840 matches) | 98 ms (570 MiB/s, 139840 matches) | 6183 ms (9 MiB/s, 139840 matches) |
| sha256 | 131 ms (427 MiB/s, 29016 matches) | 24 ms (2300 MiB/s, 29016 matches) | 104 ms (540 MiB/s, 63880 matches) | 12516 ms (4 MiB/s, 63880 matches) |
| uuid | 82 ms (681 MiB/s, 82856 matches) | 17 ms (3331 MiB/s, 82856 matches) | 59 ms (955 MiB/s, 82856 matches) | 6726 ms (8 MiB/s, 82856 matches) |
| all | 625 ms (90 MiB/s, 1361096 matches) | 65 ms (858 MiB/s, 1361096 matches) | 161 ms (349 MiB/s, 526080 matches) | 32695 ms (2 MiB/s, 526080 matches) |

Single-threaded, squeeze is on par with ripgrep for finders that start at a
few bytes (`--url`, `--email`) and 1.3 to 2.5x slower on digit- and hex-dense
tasks; with `-j` it is 2.5 to 4x faster than ripgrep, which does not
parallelise a single stream. GNU grep is 10 to 200x slower on these tasks.
<!-- bench-cli:end -->

`squeeze --all` extracts all 20 kinds at once; the regex tools run the union
of the five task patterns. `-j` scans chunks on several threads with output
kept in order. Library-level throughput and operation counts per finder come
from `mise run bench -- --stats`.

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
