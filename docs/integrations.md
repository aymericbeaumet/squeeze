# Integrations

squeeze reads stdin and prints one value per line, so it fits anywhere text
flows through a pipe.

## Data pipelines

Find the ten IP addresses mentioned most often in a log. Each occurrence
counts, including repeated addresses on the same line.

```shell
squeeze --ip app.log | sort | uniq -c | sort -nr | head -10
```

List distinct HTTPS links from the commit messages in a release. Replace the
two tags with the range you want to inspect.

```shell
git log v1.0.0..v2.0.0 --format=%B | squeeze --https --uniq
```

Export distinct URLs from local Markdown files as a JSON array:

```shell
squeeze --url --sort --uniq --output json '**/*.md' > links.json
```

Use `--with-location` to export objects with the source path, line, column,
and matched value instead. Quote the glob so squeeze expands it consistently
across shells. Directory and glob scans respect ignore files by default.

For a web page, squeeze finds absolute URLs present in the response:

```shell
curl --fail --silent --show-error https://example.com | squeeze --http --https --uniq
```

Relative links such as `/about` need an HTML parser and a base URL; squeeze
does not resolve them or execute JavaScript.

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
mise run deploy 2>&1 | squeeze -1 --url --copy
```
