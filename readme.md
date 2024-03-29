# squeeze [![GitHub Actions](https://github.com/aymericbeaumet/squeeze/actions/workflows/ci.yml/badge.svg)](https://github.com/aymericbeaumet/squeeze/actions/workflows/ci.yml)

[squeeze](https://github.com/aymericbeaumet/squeeze) enables to extract rich
information from any text (raw, JSON, HTML, YAML, etc).

Currently supported:

- Codetags (as defined per [PEP 350](https://www.python.org/dev/peps/pep-0350/))
- URIs/URLs/URNs (as defined per [RFC 3986](https://tools.ietf.org/html/rfc3986/))

See [integrations](#integrations) for some practical uses. Continue reading for
the install and getting started instructions.

## Install

### Using git

_This method requires the [Rust
toolchain](https://www.rust-lang.org/tools/install) to be installed on your
machine._

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

It is also possible to extract other types of information, like codetags
(`TODO:`, `FIXME:`, etc). The usage remains very similar:

```shell
squeeze --codetag=todo << EOF
// TODO: implement the main function
fn main {}
EOF
```

```
TODO: implement the main function
```

> Note that for convenience some aliases are defined. In this case, you can use
`--todo` instead of `--codetag=todo`. In the same vein, `--url` is an alias to
limit the search to specific URI schemes.

It is possible to enable several finders at the same time, they will be run
sequentially for each line:

```shell
squeeze --uri=http,https --codetag=todo,fixme << EOF
// TODO: update with a better example
// FIXME: all of https://github.com/aymericbeaumet/squeeze/issues
// Some random comment to be ignored
ftp://localhost
http://localhost
EOF
```

```
TODO: update with a better example
FIXME: all of https://github.com/aymericbeaumet/squeeze/issues
https://github.com/aymericbeaumet/squeeze/issues
http://localhost
```

This getting started should give you an overview of what's possible with
`squeeze`. Have a look at all the possibilities with `squeeze --help`.

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

Define a `urls` function to list all the URLs in your shell history:

```shell
# ~/.bashrc ~/.zshrc
urls() { fc -rl 1 | squeeze --url | sort -u; }
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
