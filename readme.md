# squeeze [![CI](https://github.com/aymericbeaumet/squeeze/actions/workflows/ci.yml/badge.svg)](https://github.com/aymericbeaumet/squeeze/actions/workflows/ci.yml) [![Latest release](https://img.shields.io/github/v/release/aymericbeaumet/squeeze)](https://github.com/aymericbeaumet/squeeze/releases/latest) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

squeeze extracts 20 kinds of data from text, including URLs, emails, IPs,
hashes, and TODOs. Like `grep -o`, with the patterns built in.

![squeeze pulling timestamps, URLs, IPs, a UUID, an email, a version, a hash, and a handle out of a log file](docs/demo/demo.gif)

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

- Recognizes values in prose, Markdown, JSON, and HTML, handling surrounding
  punctuation and balanced parentheses in links.
- Reads pipes, files, globs, and directory trees, respecting ignore files.
- Prints one value per line, editor locations, or JSON, YAML, and CSV.
- Available as a CLI and a [Rust library](#use-as-a-rust-library).

## Install

**Homebrew** (macOS and Linux):

```shell
brew install aymericbeaumet/tap/squeeze
```

**mise** (Linux, macOS, and Windows):

```shell
mise use -g github:aymericbeaumet/squeeze
```

**Cargo** (Rust 1.95+):

```shell
cargo install --locked squeeze-cli
```

All three install the `squeeze` command. Prebuilt binaries support Linux,
macOS, and Windows on amd64 and arm64. You can also download them from
[GitHub Releases](https://github.com/aymericbeaumet/squeeze/releases/latest),
verify the archive against `SHA256SUMS`, and put the binary on your `PATH`.

**Shell completions**: `squeeze --completions <shell>` prints the script for
bash, zsh, fish, elvish, or PowerShell; Homebrew installs them for you.

## Usage

Pick one or more finders, or none to run all of them. Results contain one
matched value per line; use `--with-kind` to label them. With no path, or
with `-`, squeeze reads stdin. Paths can be files, directories, or quoted
glob patterns. Directory scans skip hidden entries, ignored paths, and
binary files.

```shell
# Everything squeeze recognizes in a file, one value per line
squeeze app.log

# Unique URLs on a web page
curl -s https://example.com | squeeze --url --uniq

# Everyone who committed to a repository
git log --format='%an <%ae>' | squeeze --email --sort --uniq

# IPs, request IDs, and timestamps in logs, labeled by kind
kubectl logs deploy/api | squeeze --ip --uuid --datetime --with-kind

# TODOs and FIXMEs across a repository, with locations your editor understands
squeeze --todo --fixme --with-location .

# Rust sources only
squeeze --todo --fixme --with-location 'src/**/*.rs'

# Extract URLs as JSON, with match locations
squeeze --url --with-location --output json notes.md
```

With several finders, results come out in the order they appear:

```console
$ echo '2026-01-15T10:30:00Z GET /health from 10.0.4.2 took 3ms' | squeeze --datetime --ip --with-kind
datetime  2026-01-15T10:30:00Z
ip        10.0.4.2
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

Finders favor precision over recall: they recognize common formats and may
skip unusual valid values. They extract candidates, without checking whether
a URL is reachable or an email address exists. Use `--strict` for URI
syntax following RFC 3986.

### Output options

| Flag | Description |
|------|-------------|
| `-1`, `--first` | stop after the first result |
| `--last` | only print the last result |
| `--sort` | sort the results |
| `--uniq` | deduplicate the results, keeping the first occurrence |
| `--with-kind` | print the finder name (`uri`, `email`, …) with each result, aligned in a terminal and tab-separated otherwise |
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

JSON and YAML return lists of values by default; CSV returns one value per
row. With `--with-kind` or `--with-location`, structured output includes
`kind`, `value`, `line`, `column`, `start`, `end`, and `source`. Lines and
columns start at 1; byte offsets start at 0 and the end is exclusive.

Matches can overlap: a URL can also contain a domain or an IP address.
Use `--no-overlap` to suppress overlapping results. Run `squeeze --help`
for the full list of options.

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

No regex engine is involved: SIMD searches and byte classification narrow the
positions where a match can start. Big files, streams, and directory trees can
be scanned across available cores; `-j 1` selects a single thread.

On a generated 56 MiB mixed corpus, single-threaded squeeze used 18 ms of CPU
to extract URLs versus ripgrep's 35 ms. The tools use different URL grammars
and return different match counts. See the [benchmarks](docs/performance.md#cli-benchmarks)
for the commands, data, results, and limitations.

## Use as a Rust library

Add `squeeze-lib`, imported as `squeeze`:

```toml
[dependencies]
squeeze = { package = "squeeze-lib", version = "1.0" }
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

See the [API documentation](https://docs.rs/squeeze-lib) for individual
finders and scanner options.

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
