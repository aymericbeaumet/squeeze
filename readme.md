# squeeze [![GitHub Actions](https://github.com/aymericbeaumet/squeeze/actions/workflows/ci.yml/badge.svg)](https://github.com/aymericbeaumet/squeeze/actions/workflows/ci.yml)

[squeeze](https://github.com/aymericbeaumet/squeeze) enables to extract rich
information from any text (raw, JSON, HTML, YAML, etc).

Currently supported:

| Finder | Flag | Examples |
|--------|------|----------|
| CIDR | `--cidr` | `192.168.1.0/24`, `2001:db8::/32` |
| Codetags | `--codetag`, `--todo`, `--fixme` | `TODO: fix this`, `FIXME(#42): bug` |
| Colors | `--color` | `#ff0000`, `rgb(255, 0, 0)`, `hsl(0, 100%, 50%)` |
| Datetimes | `--datetime` | `2024-01-15`, `2024-01-15T10:30:00Z` |
| Emails | `--email` | `user@example.com`, `first.last+tag@company.co.uk` |
| Env vars | `--env` | `$HOME`, `${PATH}` |
| Hashes | `--hash`, `--md5`, `--sha256` | `5d41402abc4b2a76b9719d911017c592` |
| IPs | `--ip`, `--ipv4`, `--ipv6` | `192.168.1.1`, `::1`, `2001:db8::1` |
| JSON | `--json` | `{"key": "value"}`, `[1, 2, 3]` |
| JWTs | `--jwt` | `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOi...` |
| MACs | `--mac` | `00:1A:2B:3C:4D:5E`, `001A.2B3C.4D5E` |
| Paths | `--path` | `/etc/hosts`, `./src/main.rs:42:10` |
| Phones | `--phone` | `+14155551234`, `(415) 555-1234` |
| Semver | `--semver` | `1.0.0`, `v2.3.1-rc.1+build.42` |
| URIs | `--uri`, `--url`, `--http`, `--https` | `https://example.com`, `ftp://host/file` |
| UUIDs | `--uuid` | `550e8400-e29b-41d4-a716-446655440000` |

See [integrations](#integrations) for some practical uses. Continue reading for
the install and getting started instructions.

## Install

### Using Homebrew (macOS/Linux)

```shell
brew tap aymericbeaumet/tap
brew install squeeze
```

### Using Cargo

_This method requires the [Rust
toolchain](https://www.rust-lang.org/tools/install) to be installed on your
machine._

```shell
cargo install --git https://github.com/aymericbeaumet/squeeze squeeze-cli
```

### From source

```shell
git clone --depth=1 https://github.com/aymericbeaumet/squeeze.git /tmp/squeeze
cargo install --path=/tmp/squeeze/squeeze-cli
```

## Getting Started

Let's start by extracting a URL, `squeeze` expects the text to be searched on
its standard input, with the results being placed on its standard output:

```shell
echo 'lorem https://github.com ipsum' | squeeze -1 --url
```

```
https://github.com
```

> The `-1` flag allows to immediately abort after one result has been found.

If you want to print all the URLs, just omit the `-1` flag:

```shell
squeeze --url << EOF
this a domain: github.com, but this is a url: https://aymericbeaumet.com
this is some markdown: [link](https://wikipedia.com)
EOF
```

```
https://aymericbeaumet.com
https://wikipedia.com
```

Extract other types of information the same way:

```shell
echo '2024-01-15T10:30:00Z server at 192.168.1.0/24' | squeeze --datetime --cidr
```

```
2024-01-15T10:30:00Z
192.168.1.0/24
```

Enable several finders at the same time:

```shell
squeeze --url --email --todo << EOF
// TODO: email alice@example.com about https://example.com
http://localhost
EOF
```

```
TODO: email alice@example.com about https://example.com
alice@example.com
https://example.com
http://localhost
```

Some finders support sub-filters. For example `--codetag=todo` or its alias
`--todo`, `--uri=https`, `--hash=sha256`, etc.

See all the possibilities with `squeeze --help`.

## Integrations

Integrations with some popular tools.

### vim/nvim

Press `Enter` in visual mode to extract the first URL from the current
selection and open it:

```vim
" ~/.vimrc
vnoremap <silent> <CR> :<C-U>'<,'>w !squeeze -1 --url --open<CR><CR>
```

### tmux

Press `Enter` in copy mode to extract the first URL from the current selection
and open it:

```tmux
# ~/.tmux.conf
bind -T copy-mode-vi enter send -X copy-pipe-and-cancel "squeeze -1 --url --open"
```

### shell (bash, zsh)

Define convenience functions:

```shell
# ~/.bashrc ~/.zshrc
urls() { fc -rl 1 | squeeze --url | sort -u; }
ips() { squeeze --ip; }
```

## Development

### Run binary

```shell
echo 'http://localhost' | cargo run -- --url
```

### Run tests

```shell
cargo test
watchexec --clear --restart 'cargo test'
```
