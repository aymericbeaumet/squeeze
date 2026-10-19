# Usage

```shell
squeeze [OPTIONS] [PATH]...
```

Run `squeeze --help` for the same reference in your terminal.

## Inputs

With no path, or with `-`, squeeze reads stdin. Paths can be files,
directories, or quoted glob patterns such as `'src/**/*.rs'`. Directories are
walked recursively, like ripgrep does: hidden entries, ignored paths, and
binary files are skipped.

| Flag | Description |
|------|-------------|
| `--hidden` | also search hidden files and directories (`.git` is always skipped) |
| `--no-ignore` | do not respect `.gitignore`, `.ignore`, and git exclude rules |
| `--follow` | follow symbolic links |

## Finders

Pick one or more finders, or none to run all of them (`--all` does the same
explicitly). The [readme](../readme.md#what-it-finds) lists every finder with
examples.

Some finders take a filter:

| Filter | Matches |
|--------|---------|
| `--codetag=todo,fixme` | only the given codetag mnemonics; `--todo` and `--fixme` are shorthands |
| `--hash=sha256` | only the given algorithms (`md5`, `sha1`, `sha256`, `sha512`); `--md5`, `--sha1`, `--sha256`, and `--sha512` are shorthands |
| `--uri=https,ssh` | only the given schemes; `--http` and `--https` are shorthands |

`--url` is shorthand for the schemes people usually mean by a URL (`data`,
`ftp`, `ftps`, `http`, `https`, `mailto`, `sftp`, `ws`, `wss`); `--uri`
accepts any scheme. `--strict` matches URIs exactly as
RFC 3986 allows, keeping trailing `'` and `)` that are usually prose
punctuation. `--hide-mnemonic` prints a codetag's text without its `TODO:`
prefix.

Finders favor precision over recall: they recognize common formats and may
skip unusual valid values. They extract candidates, without checking whether a
URL is reachable or an email address exists. If squeeze extracts something it
should not, or misses something it should, please
[report it](https://github.com/aymericbeaumet/squeeze/issues/new?template=wrong-match.yml).

## Output

Results contain one matched value per line, in the order they appear in the
input.

| Flag | Description |
|------|-------------|
| `--with-kind` | print the finder name (`uri`, `email`, …) with each result, aligned in a terminal and tab-separated otherwise |
| `--with-location` | print `path:line:column:` before each result (`line:column:` for stdin), a format editors and quickfix lists understand |
| `--output <fmt>` | `text` (default), `json`, `yaml`, `csv`, or `none` |

```console
$ echo '2026-01-15T10:30:00Z GET /health from 10.0.4.2 took 3ms' | squeeze --datetime --ip --with-kind
datetime  2026-01-15T10:30:00Z
ip        10.0.4.2
```

JSON and YAML return lists of values by default; CSV returns one value per
row. With `--with-kind` or `--with-location`, structured output includes
`kind`, `value`, `line`, `column`, `start`, `end`, and `source`. Lines and
columns start at 1; byte offsets start at 0 and the end is exclusive.

```console
$ echo 'ping ops@example.com' | squeeze --email --with-kind --output json
[{"kind":"email","value":"ops@example.com","line":1,"column":6,"start":5,"end":20,"source":null}]
```

`--output none` prints nothing, which is useful with `--copy` or `--open`.

### Selecting results

| Flag | Description |
|------|-------------|
| `-1`, `--first` | stop after the first result |
| `--last` | only print the last result |
| `--sort` | sort the results |
| `--uniq` | deduplicate the results, keeping the first occurrence |
| `--no-overlap` | drop matches that overlap an earlier one |
| `--precedence longest` | with `--no-overlap`, keep the longest of overlapping matches instead of the first |

Matches can overlap: a URL can also contain an IP address or a version, and
each finder reports it. Use `--no-overlap` to keep one of them.

### Acting on results

| Flag | Description |
|------|-------------|
| `--copy` | copy the results to the clipboard |
| `--open` | open each result with the default application |

## Parallelism

`-j`, `--jobs <N>` sets the number of scanning threads. The default, `auto`,
uses every core for directories, stdin, and files of 8 MiB and more, and
keeps the output of a single input in order. `-j 1` scans on a single thread.
`--first`, `--last`, and `--open` always scan sequentially.

## Shell completions

`squeeze --completions <shell>` prints the completion script for `bash`,
`zsh`, `fish`, `elvish`, or `powershell`. Homebrew installs them for you.

```shell
# bash
squeeze --completions bash > ~/.local/share/bash-completion/completions/squeeze

# zsh, with ~/.zfunc in your fpath
squeeze --completions zsh > ~/.zfunc/_squeeze

# fish
squeeze --completions fish > ~/.config/fish/completions/squeeze.fish
```

## Exit status

squeeze exits with `0` when it ran successfully, whether or not it found
anything, `1` when an input could not be read, and `2` on invalid usage. To
test for matches in a script, check the output: `[ -n "$(squeeze
--url notes.md)" ]`.
