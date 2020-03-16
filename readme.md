# squeeze

[![travis](https://img.shields.io/travis/aymericbeaumet/squeeze?style=flat-square&logo=travis)](https://travis-ci.org/aymericbeaumet/squeeze)
[![github](https://img.shields.io/github/issues/aymericbeaumet/squeeze?style=flat-square&logo=github)](https://github.com/aymericbeaumet/squeeze/issues)

[squeeze](https://github.com/aymericbeaumet/squeeze) enables to extract rich
information from any text (raw, JSON, HTML, YAML, man pages, etc).

Currently supported:

- Codetags (as defined per [PEP 350](https://www.python.org/dev/peps/pep-0350/))
- URIs (as defined per [RFC 3986](https://tools.ietf.org/html/rfc3986/))

See [integrations](#integrations) for some practical uses. Continue reading for
the install and getting started instructions.

## Install

### Using git

_This method requires the [Rust
toolchain](https://www.rust-lang.org/tools/install) to be installed._

```shell
git clone https://github.com/aymericbeaumet/squeeze.git /tmp/squeeze
cargo install --path=/tmp/squeeze/src/squeeze-cli
```

## Getting Started

Let's start by extracting a URL:

```shell
echo 'lorem https://github.com ipsum' | squeeze -1 --url
```

```
https://github.com
```

> The `-1` flag allows to immediately abort after one result has been found.

If you want to print all the URLs, just omit the flag:

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
(`TODO:`, `FIXME:`, etc):

```shell
squeeze --codetag=todo << EOF
// TODO: implement the main function
fn main {}
EOF
```

```
TODO: implement the main function
```

> Note that for convenience you can use `--todo` instead of `--codetag=todo`. In
the same vein, `--url` is an alias to limit the search to specific url schemes:
`--uri=http,https,...`.

You can mix it up all together, the finders will be run sequentially for each
line:

```shell
squeeze --uri=https --codetag==todo << EOF
// TODO: fix all https://github.com/aymericbeaumet/squeeze/issues
EOF
```

```
TODO: fix all https://github.com/aymericbeaumet/squeeze/issues
https://github.com/aymericbeaumet/squeeze
```

Get an idea of all the possibilities by looking at `squeeze --help`.

## Integrations

### shell (bash, zsh)

Define a `urls` function to list all the URLs in your shell history. You can
even pair it with [fzf](https://github.com/junegunn/fzf) to fuzzy-search it and
copy the result into your clipboard:

```shell
# ~/.bashrc ~/.zshrc
urls() { fc -rl 1 | squeeze --url | sort -u; }
furls() { urls | fzf | pbcopy; }
```

### tmux

Press `Enter` in copy mode to extract the first URL from the current selection
and open it:

```tmux
# ~/.tmux.conf
bind -T copy-mode-vi enter send -X copy-pipe-and-cancel "squeeze -1 --url | xargs open"
```

### vim/nvim

Press `Enter` in visual mode to extract the first URL from the current
selection and open it:

```vim
" ~/.vimrc
vnoremap <silent> <CR> :<C-U>'<,'>w !squeeze -1 --url \| xargs open<CR><CR>
```

### pager (man, etc)

Search the output of any command supporting the `$PAGER` environment variable:

```shell
env PAGER='squeeze --url' man git
```
