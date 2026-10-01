#!/bin/sh
# Install squeeze (https://github.com/aymericbeaumet/squeeze) on Linux or macOS
# from its GitHub releases:
#
#   curl -fsSL https://raw.githubusercontent.com/aymericbeaumet/squeeze/main/install.sh | sh
#
# Pass options after `sh -s --`, or set the matching environment variables:
#
#   curl -fsSL https://raw.githubusercontent.com/aymericbeaumet/squeeze/main/install.sh | sh -s -- --version 0.3.0 --to ~/bin
#
#   --version VERSION  SQUEEZE_VERSION      release to install (default: latest)
#   --to DIR           SQUEEZE_INSTALL_DIR  install directory (default: ~/.local/bin)
#
# The archive is checked against the release's SHA256SUMS before it is
# extracted. Nothing outside the install directory is modified, and no root
# access is needed. On Windows, use install.ps1 instead.

set -eu

REPO=https://github.com/aymericbeaumet/squeeze
SOURCE_INSTALL="cargo install --locked squeeze-cli"

usage() {
	cat <<EOF
Install squeeze from $REPO/releases

Usage: install.sh [--version VERSION] [--to DIR]

Options:
  --version VERSION  release to install, e.g. 0.3.0 (default: latest)
                     [env: SQUEEZE_VERSION]
  --to DIR           install directory (default: ~/.local/bin)
                     [env: SQUEEZE_INSTALL_DIR]
  -h, --help         show this help
EOF
}

say() {
	printf '%s\n' "$*"
}

die() {
	printf 'error: %s\n' "$*" >&2
	exit 1
}

has() {
	command -v "$1" >/dev/null 2>&1
}

# Prints the asset suffix for this machine, e.g. linux-amd64 or macos-arm64.
detect_platform() {
	os=$(uname -s)
	arch=$(uname -m)
	case $os in
	Linux) os=linux ;;
	Darwin)
		os=macos
		# A shell running under Rosetta sees x86_64; prefer the native build.
		if [ "$arch" = x86_64 ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || true)" = 1 ]; then
			arch=arm64
		fi
		;;
	MINGW* | MSYS* | CYGWIN*)
		die "on Windows, use the PowerShell installer instead:
  powershell -ExecutionPolicy ByPass -c \"irm https://raw.githubusercontent.com/aymericbeaumet/squeeze/main/install.ps1 | iex\""
		;;
	*) unsupported ;;
	esac
	case $arch in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) unsupported ;;
	esac
	printf '%s-%s\n' "$os" "$arch"
}

unsupported() {
	die "no prebuilt squeeze binary for $(uname -s) on $(uname -m).
Build it from source with Rust instead:
  $SOURCE_INSTALL
or see $REPO/releases"
}

# download URL FILE
download() {
	if has curl; then
		curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$2" "$1"
	else
		wget -q -O "$2" "$1"
	fi
}

# GitHub redirects /releases/latest to /releases/tag/vX.Y.Z. Reading that
# redirect avoids the rate-limited API.
latest_version() {
	if has curl; then
		headers=$(curl --proto '=https' --tlsv1.2 -fsSI --retry 3 "$REPO/releases/latest")
	else
		# wget follows the redirect; -S prints every response's headers.
		headers=$(wget -S --spider "$REPO/releases/latest" 2>&1)
	fi || die "could not reach $REPO/releases/latest"
	tag=$(printf '%s\n' "$headers" | tr -d '\r' | sed -n 's|^ *[Ll]ocation: .*/releases/tag/\([^/ ]*\).*|\1|p' | tail -n 1)
	[ -n "$tag" ] || die "could not determine the latest release from $REPO/releases/latest"
	printf '%s\n' "${tag#v}"
}

sha256() {
	if has sha256sum; then
		sum=$(sha256sum "$1")
	else
		sum=$(shasum -a 256 "$1")
	fi
	printf '%s\n' "${sum%% *}"
}

# verify FILE SUMS: checks FILE against its entry in the SHA256SUMS file SUMS.
verify() {
	name=${1##*/}
	expected=
	while read -r hash file || [ -n "$hash" ]; do
		if [ "$file" = "$name" ]; then
			expected=$hash
			break
		fi
	done <"$2"
	[ -n "$expected" ] || die "$name is not listed in SHA256SUMS"
	actual=$(sha256 "$1")
	[ "$actual" = "$expected" ] || die "checksum mismatch for $name (expected $expected, got $actual); not installing"
}

# Prints how to add DIR to PATH for the user's login shell.
path_hint() {
	entry=$1
	if [ -n "${HOME:-}" ]; then
		case $1 in "$HOME"/*) entry="\$HOME/${1#"$HOME"/}" ;; esac
	fi
	say ""
	say "$1 is not on your PATH. To add it, run:"
	shell=${SHELL:-}
	case ${shell##*/} in
	fish)
		say "  fish_add_path '$1'"
		return
		;;
	zsh) rc=${ZDOTDIR:-\~}/.zshrc ;;
	bash) if [ "$(uname -s)" = Darwin ]; then rc=\~/.bash_profile; else rc=\~/.bashrc; fi ;;
	*) rc=\~/.profile ;;
	esac
	say "  echo 'export PATH=\"$entry:\$PATH\"' >> $rc"
	say "then open a new terminal."
}

main() {
	version=${SQUEEZE_VERSION:-}
	dir=${SQUEEZE_INSTALL_DIR:-}
	while [ $# -gt 0 ]; do
		case $1 in
		--version | --to)
			[ $# -ge 2 ] || die "$1 requires a value"
			if [ "$1" = --version ]; then version=$2; else dir=$2; fi
			shift 2
			;;
		--version=*) version=${1#*=} && shift ;;
		--to=*) dir=${1#*=} && shift ;;
		-h | --help) usage && exit 0 ;;
		*) die "unknown option: $1 (see --help)" ;;
		esac
	done

	if [ -z "$dir" ]; then
		[ -n "${HOME:-}" ] || die "HOME is not set; choose a directory with --to DIR"
		dir=$HOME/.local/bin
	fi
	case $dir in
	"~") dir=$HOME ;;
	"~"/*) dir=$HOME/${dir#"~"/} ;;
	/*) ;;
	*) dir=$(pwd)/$dir ;;
	esac
	[ "$dir" = / ] || dir=${dir%/}

	has curl || has wget || die "curl or wget is required"
	has sha256sum || has shasum || die "sha256sum or shasum is required to verify the download"
	has tar || die "tar is required"

	platform=$(detect_platform)
	if [ -z "$version" ]; then
		version=$(latest_version)
	fi
	version=${version#v}
	case $version in
	*[!0-9A-Za-z.+-]* | "") die "invalid version: $version" ;;
	esac
	tag=v$version
	asset=squeeze-$tag-$platform.tar.gz
	url=$REPO/releases/download/$tag

	tmp=$(mktemp -d "${TMPDIR:-/tmp}/squeeze.XXXXXX")
	staged=
	trap 'rm -rf "$tmp" ${staged:+"$staged"}' EXIT
	trap 'exit 1' HUP INT TERM

	say "Installing squeeze $tag ($platform) to $dir"
	download "$url/SHA256SUMS" "$tmp/SHA256SUMS" ||
		die "could not download $url/SHA256SUMS; does release $tag exist? See $REPO/releases"
	download "$url/$asset" "$tmp/$asset" || die "could not download $url/$asset"
	verify "$tmp/$asset" "$tmp/SHA256SUMS"
	say "Verified SHA-256 checksum of $asset"

	mkdir "$tmp/x"
	tar -xzf "$tmp/$asset" -C "$tmp/x"
	[ -f "$tmp/x/squeeze" ] || die "squeeze binary not found in $asset"

	# Stage next to the target, then rename: replacing the binary is atomic
	# and works even while an older squeeze is running.
	if ! mkdir -p "$dir" || [ ! -w "$dir" ]; then
		die "cannot write to $dir; choose another directory with --to DIR"
	fi
	# mktemp creates the file exclusively, so a planted symlink cannot redirect the copy.
	staged=$(mktemp "$dir/.squeeze.XXXXXX") || die "cannot write to $dir; choose another directory with --to DIR"
	cp "$tmp/x/squeeze" "$staged"
	chmod 755 "$staged"
	mv -f "$staged" "$dir/squeeze"
	staged=

	if ! installed=$("$dir/squeeze" --version </dev/null 2>&1); then
		die "installed $dir/squeeze, but it failed to run:
$installed
Please report this at $REPO/issues, or build from source instead:
  $SOURCE_INSTALL"
	fi
	say "Installed $installed to $dir/squeeze"

	case ":${PATH:-}:" in
	*":$dir:"*)
		found=$(command -v squeeze || true)
		if [ "$found" != "$dir/squeeze" ]; then
			say "Note: 'squeeze' currently resolves to $found, which comes first on your PATH."
		fi
		;;
	*) path_hint "$dir" ;;
	esac
	say ""
	say "Try it: echo 'see https://example.com' | squeeze --url"
}

main "$@"
