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
| `--codetag=todo,fixme` | only the given [PEP 350](https://peps.python.org/pep-0350/) mnemonics; `--todo` and `--fixme` are shorthands |
| `--hash=sha256` | only the given algorithms (`md5`, `sha1`, `sha256`, `sha512`); `--md5`, `--sha1`, `--sha256`, and `--sha512` are shorthands |
| `--uri=https,ssh` | only the given schemes; `--http` and `--https` are shorthands |

The value can also follow the flag, as in `--hash sha256 notes.md`, when it
names known algorithms, mnemonics, or registered schemes; any other word
stays a path. An unknown value is an error that suggests the closest valid
one:

```console
$ squeeze --codetag=tood .
error: unknown codetag mnemonic 'tood', did you mean 'TODO'?
```

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
| `--color <when>` | color kinds and locations: `auto` (default, in a terminal), `always`, or `never` |

```console
$ echo '2026-01-15T10:30:00Z GET /health from 10.0.4.2 took 3ms' | squeeze --datetime --ip --with-kind
datetime  2026-01-15T10:30:00Z
ip        10.0.4.2
```

JSON and YAML return lists of values by default; CSV returns one value per
row. With `--with-kind` or `--with-location`, structured output includes
`kind`, `value`, `line`, `column`, `start`, `end`, and `source`. Lines and
columns start at 1; byte offsets start at 0 and the end is exclusive.

`--color=auto` honors [`NO_COLOR`](https://no-color.org/), `CLICOLOR=0`,
and `CLICOLOR_FORCE`. Values are never colored, and structured output never
is.

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
| `--precedence longest` | keep the longest of overlapping matches instead of the first; implies `--no-overlap` |

Matches can overlap: a URL can also contain an IP address or a version, and
each finder reports it. Use `--no-overlap` to keep one of them.

### Acting on results

| Flag | Description |
|------|-------------|
| `--copy` | copy the results to the clipboard |
| `--open` | open each URL with the default application (the schemes of `--url`) |
| `--open=<kinds>` | open the given kinds instead: `url`, `uri` (any scheme), and `path` |

`--open` never opens paths or other schemes such as `file:` unless asked to,
so piping untrusted text into it only ever opens web, mail, and FTP links.

## Parallelism

`-j`, `--jobs <N>` sets the number of scanning threads. The default, `auto`,
uses every core for directories, stdin, and files of 8 MiB and more, and
keeps the output of a single input in order. `-j 1` scans on a single thread.
`--first` always scans on one thread, and `--last` and `--open` walk
directories on one thread, so results come in a predictable order.

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

| Status | Meaning |
|--------|---------|
| `0` | squeeze ran, whether or not it found anything |
| `1` | nothing was found, only with `--exit-code` |
| `2` | an error: invalid usage, or an input that could not be read |

Finding nothing is not an error by default, so pipelines under
`set -o pipefail` keep going on empty input. Pass `--exit-code` to test for
matches, like `git diff --exit-code` or grep:

```shell
if squeeze --exit-code --url notes.md > /dev/null; then echo "has links"; fi
```

Errors are reported on stderr as `squeeze: <path>: <reason>`; invalid
arguments print a usage error instead.
