# squeeze

[![travis](https://img.shields.io/travis/aymericbeaumet/squeeze?style=flat-square&logo=travis)](https://travis-ci.org/aymericbeaumet/squeeze)
[![github](https://img.shields.io/github/issues/aymericbeaumet/squeeze?style=flat-square&logo=github)](https://github.com/aymericbeaumet/squeeze/issues)

[squeeze](https://github.com/aymericbeaumet/squeeze) enables to extract rich
information (URIs, Codetags) from any text (raw, JSON, HTML, YAML, etc).

It has proven to be particularly useful to optimize a work environment. It is
meant to be orthogonal to tools like xargs(1) and open(1). See
[integrations](#integrations) for some practical uses.

## Install

### Using git

_This method requires the [Rust
toolchain](https://www.rust-lang.org/tools/install) to be installed._

```shell
git clone https://github.com/aymericbeaumet/squeeze.git /tmp/squeeze
cargo install --path=/tmp/squeeze/src/squeeze-cli
```

## Examples

- Extract the first URL:

```shell
echo 'lorem https://github.com ipsum' | squeeze -1 --url
```

```
https://github.com
```

- Extract all the URLs:

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

- Extract the TODO codetags:

```shell
squeeze --todo << EOF
// TODO: implement the main function
fn main {}
EOF
```

```
TODO: implement the main function
```

## Integrations

### vim/nvim

- Press _Enter_ in visual mode to extract the first URL from the current
  selection and open it:

```vim
" ~/.vimrc
vnoremap <silent> <CR> :<C-U>'<,'>w !squeeze -1 --url \| xargs open<CR><CR>
```

### tmux

- Press _Enter_ in copy mode to extract the first URL from the current
  selection and open it:

```tmux
# ~/.tmux.conf
bind -T copy-mode-vi enter send -X copy-pipe-and-cancel "squeeze -1 --url | xargs open"
```
