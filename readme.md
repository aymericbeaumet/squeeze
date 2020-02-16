# squeeze

[![travis](https://img.shields.io/travis/aymericbeaumet/squeeze?style=flat-square&logo=travis)](https://travis-ci.org/aymericbeaumet/squeeze)
[![github](https://img.shields.io/github/issues/aymericbeaumet/squeeze?style=flat-square&logo=github)](https://github.com/aymericbeaumet/squeeze/issues)

[squeeze](https://github.com/aymericbeaumet/squeeze) enables out to filter out
urls from texts. It is meant to be orthogonal to tools like xargs(1) and
open(1).

## Install

```shell
go install github.com/aymericbeaumet/squeeze
```

## Examples

- Extract a single URL:

```shell
echo 'lorem https://github.com ipsum' | squeeze --url

# output
https://github.com
```

- Extract several URLs:

```shell
squeeze --all --url << EOF
this is a url: https://github.com
this is not: github.com
this is markdown [link](https://wikipedia.com)
EOF

# output
https://github.com
https://wikipedia.com
```

## Integrations

### Vim

- Open the first URL from your visual mode selection:

```vim
" ~/.vimrc
vnoremap <silent> <CR> :<C-U>'<,'>w !squeeze --url \| xargs open<CR><CR>
```

### Tmux

- Open the first URL from your copy mode selection:

```tmux
# ~/.tmux.conf
bind -T copy-mode-vi enter send -X copy-pipe-and-cancel "squeeze --url | xargs open"
```
