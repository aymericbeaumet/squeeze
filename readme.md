# squeeze [![CI](https://github.com/aymericbeaumet/squeeze/actions/workflows/ci.yml/badge.svg)](https://github.com/aymericbeaumet/squeeze/actions/workflows/ci.yml) [![Latest release](https://img.shields.io/github/v/release/aymericbeaumet/squeeze)](https://github.com/aymericbeaumet/squeeze/releases/latest) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Extract URLs, emails, IPs, hashes, TODOs, and 15 other kinds of data from any
text. Like `grep -o`, but it already knows what a URL looks like.

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
- **Fast.** It uses less CPU than ripgrep, ugrep, and GNU grep on every
  [benchmarked task](#performance), even single-threaded, and scans big
  files, streams, and directory trees on every core.
- **Also a Rust library.** Every finder is available as a
  [crate](#use-as-a-rust-library).

## Install

**macOS and Linux**:

```shell
curl -fsSL https://raw.githubusercontent.com/aymericbeaumet/squeeze/main/install.sh | sh
```

**Windows** (PowerShell):

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/aymericbeaumet/squeeze/main/install.ps1 | iex"
```

The scripts download the latest release for your platform, check its SHA-256
checksum, and install `squeeze` in `~/.local/bin` (`%LOCALAPPDATA%\Programs\squeeze\bin`
on Windows) without admin rights. Read them first:
[install.sh](install.sh), [install.ps1](install.ps1).

**Homebrew** (macOS, Linux): `brew install aymericbeaumet/tap/squeeze`

**Cargo**: `cargo binstall squeeze-cli` fetches the prebuilt binary;
`cargo install --locked squeeze-cli` builds it (Rust 1.95+).

**mise**: `mise use -g github:aymericbeaumet/squeeze`

**Manually**: download the archive for your platform (Linux, macOS, or
Windows; `amd64` or `arm64`) from
[GitHub Releases](https://github.com/aymericbeaumet/squeeze/releases/latest)
and put `squeeze` on your `PATH`. Linux binaries are static and run on any
distribution. Every release lists SHA-256 checksums and carries build
provenance you can check with
`gh attestation verify <archive> --repo aymericbeaumet/squeeze`.

**Shell completions**: `squeeze --completions <shell>` prints the script for
bash, zsh, fish, elvish, or PowerShell; Homebrew installs them for you.

## Usage

Pick one or more finders, or none to run all of them with each result
labeled by kind. `squeeze` scans the files, directories, and quoted glob
patterns you pass after the options. Without a path it reads standard
input, or searches the current directory when standard input is a terminal.
Directories are walked recursively on every core, the way ripgrep walks
them: hidden entries, `.gitignore` and `.ignore` rules, and binary files are
skipped.

```shell
# Everything squeeze recognizes in a file, labeled by kind
squeeze app.log

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

Finders favor precision over recall. Use `--strict` to make `--uri` follow
RFC 3986 to the letter.

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

No regex engine is involved: SIMD searches and byte classification find the
few positions where a match can start, every finder is linear on adversarial
input, and big files, streams, and directory trees are scanned on every core.

CPU time to extract each kind from a 56 MiB mixed corpus (logs, prose,
source, JSON, Markdown), single-threaded, lower is better:

| task | squeeze | ripgrep | ugrep | GNU grep |
|---|---|---|---|---|
| URLs | **18 ms** | 35 ms | 30 ms | 58 ms |
| emails | **14 ms** | 29 ms | 88 ms | 205 ms |
| IPv4 | **29 ms** | 111 ms | 75 ms | 247 ms |
| SHA-256 | **30 ms** | 94 ms | 167 ms | 154 ms |
| UUIDs | **14 ms** | 51 ms | 24 ms | 98 ms |
| all five at once | **93 ms** | 167 ms | 879 ms | 1198 ms |

The regex tools get the closest POSIX pattern, which is looser than
squeeze's grammars (it keeps trailing punctuation, for one). With its
default parallelism, squeeze reads a 2 GiB file at least eight times faster
than ripgrep and ugrep. Methodology, wall times, streams, directory trees,
and how to reproduce with `mise run bench-cli` are in
[docs/performance.md](docs/performance.md#cli-benchmarks).

## Use as a Rust library

The finders live in the [`squeeze-core`](https://crates.io/crates/squeeze-core)
crate, which the CLI builds on and which is imported as `squeeze`:

```toml
[dependencies]
squeeze = { package = "squeeze-core", version = "0.4" }
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

The API documentation is on [docs.rs](https://docs.rs/squeeze-core), or run
`cargo doc --open -p squeeze-core` in a clone.

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
