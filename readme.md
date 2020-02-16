# squeeze

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

```
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

### Tmux

- Open the first URL you currently have in your selection:

```
# ~/.tmux.conf
bind -T copy-mode-vi enter send -X copy-pipe-and-cancel "squeeze --url | xargs open"
```
