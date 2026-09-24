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
| `-j`, `--jobs <N>` | scanning threads; `auto` (default) uses every core for files of 8 MiB and more, output kept in order |

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
7 runs; ripgrep 15.2.0, ugrep 7.8.5, GNU grep 3.12. Output is piped away
rather than sent to `/dev/null`, which grep and ugrep detect to stop at the
first match. Wall time moves with load; CPU time is the stable figure.
Rerun `mise run bench-cli` to reproduce.

| task | squeeze -j 1 | squeeze | ripgrep | ugrep | gnu grep |
|---|---|---|---|---|---|
| url | 29 ms wall, 28 ms cpu (1960 MiB/s, 76840 matches) | 10 ms wall, 30 ms cpu (5687 MiB/s, 76840 matches) | 37 ms wall, 34 ms cpu (1508 MiB/s, 94584 matches) | 33 ms wall, 30 ms cpu (1698 MiB/s, 94584 matches) | 65 ms wall, 60 ms cpu (866 MiB/s, 94584 matches) |
| email | 18 ms wall, 17 ms cpu (3111 MiB/s, 144920 matches) | 9 ms wall, 20 ms cpu (5954 MiB/s, 144920 matches) | 32 ms wall, 29 ms cpu (1775 MiB/s, 144920 matches) | 93 ms wall, 88 ms cpu (604 MiB/s, 144920 matches) | 212 ms wall, 207 ms cpu (265 MiB/s, 144920 matches) |
| ipv4 | 44 ms wall, 38 ms cpu (1277 MiB/s, 139840 matches) | 15 ms wall, 44 ms cpu (3785 MiB/s, 139840 matches) | 235 ms wall, 111 ms cpu (238 MiB/s, 139840 matches) | 208 ms wall, 79 ms cpu (269 MiB/s, 139840 matches) | 626 ms wall, 274 ms cpu (89 MiB/s, 139840 matches) |
| sha256 | 77 ms wall, 43 ms cpu (731 MiB/s, 29016 matches) | 12 ms wall, 39 ms cpu (4587 MiB/s, 29016 matches) | 96 ms wall, 93 ms cpu (584 MiB/s, 63880 matches) | 174 ms wall, 170 ms cpu (322 MiB/s, 63880 matches) | 156 ms wall, 151 ms cpu (359 MiB/s, 63880 matches) |
| uuid | 24 ms wall, 21 ms cpu (2360 MiB/s, 82856 matches) | 11 ms wall, 24 ms cpu (5281 MiB/s, 82856 matches) | 54 ms wall, 52 ms cpu (1040 MiB/s, 82856 matches) | 28 ms wall, 24 ms cpu (1985 MiB/s, 82856 matches) | 101 ms wall, 97 ms cpu (552 MiB/s, 82856 matches) |
| five kinds | 225 ms wall, 119 ms cpu (249 MiB/s, 473472 matches) | 79 ms wall, 125 ms cpu (710 MiB/s, 473472 matches) | 249 ms wall, 182 ms cpu (225 MiB/s, 526080 matches) | 1208 ms wall, 883 ms cpu (46 MiB/s, 526080 matches) | 1689 ms wall, 1218 ms cpu (33 MiB/s, 526080 matches) |
| everything | 679 ms wall, 403 ms cpu (83 MiB/s, 1162904 matches) | 77 ms wall, 427 ms cpu (730 MiB/s, 1162904 matches) | n/a | n/a | n/a |

The same tasks on the log corpus alone (8 MiB):

| task | squeeze -j 1 | squeeze | ripgrep | ugrep | gnu grep |
|---|---|---|---|---|---|
| url | 10 ms wall, 9 ms cpu (820 MiB/s, 11232 matches) | 5 ms wall, 10 ms cpu (1539 MiB/s, 11232 matches) | 9 ms wall, 7 ms cpu (872 MiB/s, 11232 matches) | 9 ms wall, 7 ms cpu (871 MiB/s, 11232 matches) | 11 ms wall, 8 ms cpu (752 MiB/s, 11232 matches) |
| email | 6 ms wall, 5 ms cpu (1371 MiB/s, 11248 matches) | 5 ms wall, 6 ms cpu (1689 MiB/s, 11248 matches) | 7 ms wall, 5 ms cpu (1143 MiB/s, 11248 matches) | 35 ms wall, 30 ms cpu (228 MiB/s, 11248 matches) | 34 ms wall, 30 ms cpu (232 MiB/s, 11248 matches) |
| ipv4 | 7 ms wall, 7 ms cpu (1084 MiB/s, 22440 matches) | 5 ms wall, 9 ms cpu (1513 MiB/s, 22440 matches) | 26 ms wall, 20 ms cpu (313 MiB/s, 22440 matches) | 22 ms wall, 16 ms cpu (363 MiB/s, 22440 matches) | 50 ms wall, 45 ms cpu (161 MiB/s, 22440 matches) |
| sha256 | 11 ms wall, 10 ms cpu (704 MiB/s, 11232 matches) | 5 ms wall, 10 ms cpu (1696 MiB/s, 11232 matches) | 19 ms wall, 17 ms cpu (425 MiB/s, 11232 matches) | 17 ms wall, 14 ms cpu (467 MiB/s, 11232 matches) | 30 ms wall, 26 ms cpu (266 MiB/s, 11232 matches) |
| uuid | 8 ms wall, 7 ms cpu (962 MiB/s, 11248 matches) | 5 ms wall, 8 ms cpu (1577 MiB/s, 11248 matches) | 19 ms wall, 16 ms cpu (421 MiB/s, 11248 matches) | 8 ms wall, 6 ms cpu (947 MiB/s, 11248 matches) | 26 ms wall, 23 ms cpu (308 MiB/s, 11248 matches) |
| five kinds | 59 ms wall, 24 ms cpu (135 MiB/s, 67400 matches) | 37 ms wall, 28 ms cpu (216 MiB/s, 67400 matches) | 90 ms wall, 43 ms cpu (89 MiB/s, 67400 matches) | 521 ms wall, 219 ms cpu (15 MiB/s, 67400 matches) | 412 ms wall, 255 ms cpu (19 MiB/s, 67400 matches) |
| everything | 92 ms wall, 91 ms cpu (87 MiB/s, 302736 matches) | 41 ms wall, 116 ms cpu (193 MiB/s, 302736 matches) | n/a | n/a | n/a |

On the mixed corpus, single-threaded squeeze uses less CPU than ripgrep,
ugrep and GNU grep on every task, while parsing URIs per RFC 3986 with the
IANA scheme registry rather than matching `https?://[^\s]+`. On the log
corpus ripgrep and ugrep are two milliseconds ahead on url (they search
for the literal `http`; squeeze visits every colon) and ugrep one
millisecond ahead on uuid. The five finders together beat the five-pattern
regex by a third in ripgrep and by 7x in ugrep and GNU grep, which no
longer have a literal to search for. With the default `--jobs auto`
squeeze finishes each task several times faster than ripgrep, which does
not parallelise a single stream.
<!-- bench-cli:end -->

`squeeze -j 1` is the like-for-like single-threaded comparison; plain
`squeeze` is the default, which scans files of 8 MiB and more on every core
with output kept in order. `five kinds` runs the five finders together
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
