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
- Fast: no regex engine, SIMD scanning, and every core on large inputs.
- Available as a CLI and a [Rust library](#rust-library).

## Install

**Homebrew** (macOS and Linux):

```shell
brew install aymericbeaumet/tap/squeeze
```

**mise** (Linux, macOS, and Windows):

```shell
mise use -g github:aymericbeaumet/squeeze
```

**Cargo** (Rust 1.95+), from source:

```shell
cargo install --locked --git https://github.com/aymericbeaumet/squeeze
```

All three install the `squeeze` command. Prebuilt binaries for Linux, macOS,
and Windows on amd64 and arm64 are also on
[GitHub Releases](https://github.com/aymericbeaumet/squeeze/releases/latest).

## Usage

Pick one or more finders, or none to run all of them. With no path, squeeze
reads stdin.

```shell
# Everything squeeze recognizes in a file
squeeze app.log

# Unique links on a web page
curl -s https://news.ycombinator.com | squeeze --url --uniq

# Everyone who committed to a repository
git log --format='%an <%ae>' | squeeze --email --sort --uniq

# IPs, request IDs, and timestamps in logs, labeled by kind
kubectl logs deploy/api | squeeze --ip --uuid --datetime --with-kind

# TODOs and FIXMEs across a repository, with locations your editor understands
squeeze --todo --fixme --with-location .

# URLs as JSON, with their kind and position
squeeze --url --with-kind --output json notes.md
```

The [usage guide](docs/usage.md) covers every option, and
[integrations](docs/integrations.md) has recipes for vim, tmux, fzf, and your
shell.

## What it finds

| Finder | Flag | Examples |
|--------|------|----------|
| CIDR | `--cidr` | `192.168.1.0/24`, `2001:db8::/32` |
| Codetags | `--codetag`, `--todo`, `--fixme` | `TODO: fix this`, `FIXME(#42): bug` |
| Colors | `--css-color` | `#ff0000`, `rgb(255, 0, 0)`, `hsl(0, 100%, 50%)` |
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

Finders favor precision over recall: they recognize common formats and may
skip unusual valid values. Found something squeeze gets wrong?
[Report it](https://github.com/aymericbeaumet/squeeze/issues/new?template=wrong-match.yml)
with a sample input.

## Performance

No regex engine is involved: SIMD searches and byte classification narrow the
positions where a match can start, and large files, streams, and directory
trees are scanned across every core. On a generated 56 MiB mixed corpus,
single-threaded squeeze used 18 ms of CPU to extract URLs versus ripgrep's
35 ms, while parsing URIs per RFC 3986 rather than matching a loose regex.
See the [benchmarks](docs/performance.md#cli-benchmarks) for the commands,
data, and limitations.

## Rust library

The finders are available as the `squeeze-lib` crate, imported as `squeeze`:

```shell
cargo add squeeze-lib
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

Configuring a finder returns a typed `squeeze::Error`, such as an unknown
hash algorithm with a suggested fix; scanning never fails. See the
[API documentation](https://docs.rs/squeeze-lib) for individual finders and
scanner options.

## Contributing

Bug reports, wrong matches, and pull requests are welcome. The
[contributing guide](docs/contributing.md) explains how to set up the
project, where things live, and how to change a finder.

## License

[MIT](LICENSE)
