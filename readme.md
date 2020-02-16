# squeeze

[![travis](https://img.shields.io/travis/aymericbeaumet/squeeze?style=flat-square&logo=travis)](https://travis-ci.org/aymericbeaumet/squeeze)
[![github](https://img.shields.io/github/issues/aymericbeaumet/squeeze?style=flat-square&logo=github)](https://github.com/aymericbeaumet/squeeze/issues)

[squeeze](https://github.com/aymericbeaumet/squeeze) enables to extract rich
data from text. It is meant to be orthogonal to tools like xargs(1) and
open(1).

## Install

```shell
go install github.com/aymericbeaumet/squeeze
```

## Examples

- Extract a single URL:

```shell
echo 'lorem https://github.com ipsum' | squeeze -1 --url

# https://github.com
```

- Extract all the URLs:

```shell
squeeze --url << EOF
this is a url: https://github.com
this is not: github.com
this is markdown [link](https://wikipedia.com)
EOF

# https://github.com
# https://wikipedia.com
```

## Integrations

### Vim

- Open the first URL extracted from a selection in visual mode:

```vim
" ~/.vimrc
vnoremap <silent> <CR> :<C-U>'<,'>w !squeeze -1 --url \| xargs open<CR><CR>
```

### Tmux

- Open the first URL extracted from selection in copy mode:

```tmux
# ~/.tmux.conf
bind -T copy-mode-vi enter send -X copy-pipe-and-cancel "squeeze -1 --url | xargs open"
```
