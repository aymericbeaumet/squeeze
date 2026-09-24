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
| url | 31 ms wall, 30 ms cpu (1785 MiB/s, 76840 matches) | 11 ms wall, 35 ms cpu (5165 MiB/s, 76840 matches) | 37 ms wall, 35 ms cpu (1530 MiB/s, 94584 matches) | 32 ms wall, 29 ms cpu (1728 MiB/s, 94584 matches) | 169 ms wall, 74 ms cpu (330 MiB/s, 94584 matches) |
| email | 41 ms wall, 27 ms cpu (1364 MiB/s, 144920 matches) | 32 ms wall, 31 ms cpu (1777 MiB/s, 144920 matches) | 87 ms wall, 38 ms cpu (645 MiB/s, 144920 matches) | 235 ms wall, 104 ms cpu (238 MiB/s, 144920 matches) | 423 ms wall, 246 ms cpu (132 MiB/s, 144920 matches) |
| ipv4 | 42 ms wall, 41 ms cpu (1335 MiB/s, 139840 matches) | 12 ms wall, 49 ms cpu (4570 MiB/s, 139840 matches) | 97 ms wall, 94 ms cpu (580 MiB/s, 139840 matches) | 67 ms wall, 62 ms cpu (838 MiB/s, 139840 matches) | 234 ms wall, 221 ms cpu (239 MiB/s, 139840 matches) |
| sha256 | 34 ms wall, 33 ms cpu (1635 MiB/s, 29016 matches) | 10 ms wall, 39 ms cpu (5774 MiB/s, 29016 matches) | 96 ms wall, 93 ms cpu (586 MiB/s, 63880 matches) | 363 ms wall, 204 ms cpu (154 MiB/s, 63880 matches) | 464 ms wall, 191 ms cpu (121 MiB/s, 63880 matches) |
| uuid | 46 ms wall, 35 ms cpu (1206 MiB/s, 82856 matches) | 48 ms wall, 46 ms cpu (1158 MiB/s, 82856 matches) | 55 ms wall, 52 ms cpu (1020 MiB/s, 82856 matches) | 29 ms wall, 24 ms cpu (1958 MiB/s, 82856 matches) | 103 ms wall, 99 ms cpu (542 MiB/s, 82856 matches) |
| five kinds | 111 ms wall, 110 ms cpu (504 MiB/s, 473472 matches) | 18 ms wall, 125 ms cpu (3143 MiB/s, 473472 matches) | 265 ms wall, 172 ms cpu (212 MiB/s, 526080 matches) | 1342 ms wall, 915 ms cpu (42 MiB/s, 526080 matches) | 1905 ms wall, 1255 ms cpu (29 MiB/s, 526080 matches) |
| everything | 540 ms wall, 394 ms cpu (104 MiB/s, 1162904 matches) | 246 ms wall, 473 ms cpu (228 MiB/s, 1162904 matches) | n/a | n/a | n/a |

The same tasks on the log corpus alone (8 MiB):

| task | squeeze -j 1 | squeeze | ripgrep | ugrep | gnu grep |
|---|---|---|---|---|---|
| url | 28 ms wall, 13 ms cpu (289 MiB/s, 11232 matches) | 12 ms wall, 14 ms cpu (644 MiB/s, 11232 matches) | 19 ms wall, 10 ms cpu (411 MiB/s, 11232 matches) | 14 ms wall, 8 ms cpu (562 MiB/s, 11232 matches) | 28 ms wall, 12 ms cpu (284 MiB/s, 11232 matches) |
| email | 8 ms wall, 6 ms cpu (966 MiB/s, 11248 matches) | 9 ms wall, 8 ms cpu (929 MiB/s, 11248 matches) | 24 ms wall, 8 ms cpu (332 MiB/s, 11248 matches) | 75 ms wall, 39 ms cpu (107 MiB/s, 11248 matches) | 52 ms wall, 34 ms cpu (154 MiB/s, 11248 matches) |
| ipv4 | 46 ms wall, 14 ms cpu (175 MiB/s, 22440 matches) | 31 ms wall, 14 ms cpu (262 MiB/s, 22440 matches) | 21 ms wall, 18 ms cpu (383 MiB/s, 22440 matches) | 16 ms wall, 13 ms cpu (492 MiB/s, 22440 matches) | 47 ms wall, 43 ms cpu (171 MiB/s, 22440 matches) |
| sha256 | 10 ms wall, 9 ms cpu (794 MiB/s, 11232 matches) | 5 ms wall, 10 ms cpu (1721 MiB/s, 11232 matches) | 19 ms wall, 17 ms cpu (418 MiB/s, 11232 matches) | 18 ms wall, 15 ms cpu (446 MiB/s, 11232 matches) | 30 ms wall, 27 ms cpu (269 MiB/s, 11232 matches) |
| uuid | 11 ms wall, 10 ms cpu (739 MiB/s, 11248 matches) | 5 ms wall, 12 ms cpu (1623 MiB/s, 11248 matches) | 19 ms wall, 16 ms cpu (423 MiB/s, 11248 matches) | 8 ms wall, 5 ms cpu (998 MiB/s, 11248 matches) | 26 ms wall, 22 ms cpu (311 MiB/s, 11248 matches) |
| five kinds | 21 ms wall, 20 ms cpu (379 MiB/s, 67400 matches) | 6 ms wall, 24 ms cpu (1303 MiB/s, 67400 matches) | 37 ms wall, 34 ms cpu (214 MiB/s, 67400 matches) | 197 ms wall, 182 ms cpu (41 MiB/s, 67400 matches) | 290 ms wall, 208 ms cpu (28 MiB/s, 67400 matches) |
| everything | 217 ms wall, 91 ms cpu (37 MiB/s, 302736 matches) | 53 ms wall, 102 ms cpu (152 MiB/s, 302736 matches) | n/a | n/a | n/a |

On the mixed corpus, single-threaded squeeze uses less CPU than ripgrep
and GNU grep on every task, and less than ugrep on every task but uuid,
where ugrep's fixed-length matcher is ahead, and url, where the two are
level while squeeze parses URIs per RFC 3986 with the IANA scheme registry
rather than matching `https?://[^\s]+`. On the log corpus the tools are
within a few milliseconds of each other on url, ipv4 and uuid. The five
finders together beat the five-pattern regex by a third in ripgrep and by
8x in ugrep and GNU grep, which no longer have a literal to search for.
With the default `--jobs auto` squeeze finishes each task several times
faster than ripgrep, which does not parallelise a single stream.
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
