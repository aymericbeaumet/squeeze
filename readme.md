# squeeze

squeeze enables out to filter out urls from texts. It is meant to be orthogonal
to tools like xargs(1) and open(1).

## Install

```shell
go install github.com/aymericbeaumet/squeeze
```

## Examples

```shell
echo 'lorem https://github.com ipsum' | squeeze
# https://github.com
```

## Integrations

### Tmux

Open the first URL of each line you have currently selected with tmux:

```
# ~/.tmux.conf
bind -T copy-mode-vi enter send -X copy-pipe-and-cancel "squeeze | xargs open"
```
