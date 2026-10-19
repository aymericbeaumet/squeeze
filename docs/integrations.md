# Integrations

squeeze reads stdin and prints one value per line, so it fits anywhere text
flows through a pipe.

## vim/nvim

Press `Enter` in visual mode to open the first URL in the selection:

```vim
" ~/.vimrc
vnoremap <silent> <CR> :<C-U>'<,'>w !squeeze -1 --url --open<CR><CR>
```

Load every TODO and FIXME of a project into the quickfix list:

```vim
:cexpr system("squeeze --todo --fixme --with-location .")
```

## tmux

Press `Enter` in copy mode to open the first URL in the selection:

```tmux
# ~/.tmux.conf
bind -T copy-mode-vi enter send -X copy-pipe-and-cancel "squeeze -1 --url --open"
```

## fzf

Pick a URL from the scrollback of the current tmux pane and open it:

```shell
tmux capture-pane -pJ -S - | squeeze --url --uniq | fzf --tac | squeeze --url --open
```

## Shell

List the URLs from your shell history, most recent first:

```shell
# ~/.bashrc, ~/.zshrc
urls() { fc -rl 1 | squeeze --url --uniq; }
```

Copy the first URL a command prints, such as a deploy preview link:

```shell
make deploy 2>&1 | squeeze -1 --url --copy
```
