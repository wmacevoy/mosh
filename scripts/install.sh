#!/bin/sh
#
# Installs mosh with port forwarding (https://wmacevoy.github.io/mosh/)
# from a prebuilt release, into your home directory.  No root needed.
#
#     curl -fsSL https://raw.githubusercontent.com/wmacevoy/mosh/master/scripts/install.sh | sh
#
# Run it on your own machine and on each server you connect to: port
# forwarding needs this build at both ends.
#
# Environment:
#     MOSH_VERSION   release to install, e.g. 1.4.0-pf.1 [the newest]
#     PREFIX         where to install [$HOME/.local]
#     MOSH_RELEASES  where releases are downloaded from, for mirrors
#                    [https://github.com/wmacevoy/mosh/releases/download]
#

set -eu

repo="wmacevoy/mosh"
version="${MOSH_VERSION:-@VERSION@}"
prefix="${PREFIX:-$HOME/.local}"

say() { printf '%s\n' "$*"; }
fail() { say "install.sh: $*" >&2; exit 1; }

fetch() { # URL [FILE]
    if command -v curl >/dev/null 2>&1; then
        if [ $# -gt 1 ]; then curl -fsSL -o "$2" "$1"; else curl -fsSL "$1"; fi
    elif command -v wget >/dev/null 2>&1; then
        if [ $# -gt 1 ]; then wget -q -O "$2" "$1"; else wget -q -O - "$1"; fi
    else
        fail "need curl or wget"
    fi
}

# What are we running on?
case "$(uname -s)" in
    Linux) os=linux ;;
    Darwin) os=macos ;;
    MSYS*|MINGW*|CYGWIN*) fail "on Windows, download the mosh-*-msys2.zip from https://github.com/$repo/releases" ;;
    *) fail "no prebuilt package for $(uname -s); build from source: https://wmacevoy.github.io/mosh/usage.html" ;;
esac
case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) fail "no prebuilt package for $(uname -m); build from source: https://wmacevoy.github.io/mosh/usage.html" ;;
esac
[ "$os" = macos ] && arch=universal

# Which release?  (A copy of this script published with a release knows its own.)
case "$version" in
    @*)
        # The newest release, including pre-releases, which is all there are so far.
        version=$(fetch "https://api.github.com/repos/$repo/releases?per_page=20" \
                  | sed -n 's/.*"tag_name": *"mosh-\([^"]*\)".*/\1/p' | head -n 1)
        [ -n "$version" ] || fail "could not find a release at https://github.com/$repo/releases"
        ;;
esac

name="mosh-$version-$os-$arch"
base="${MOSH_RELEASES:-https://github.com/$repo/releases/download}/mosh-$version"

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t mosh-install)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading $name ..."
fetch "$base/$name.tar.gz" "$tmp/$name.tar.gz" || fail "could not download $base/$name.tar.gz"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || fail "could not download $base/SHA256SUMS"

# Check that we got what was published.
want=$(sed -n "s/^\([0-9a-f]\{64\}\) [ *]$name\.tar\.gz\$/\1/p" "$tmp/SHA256SUMS")
[ -n "$want" ] || fail "$name.tar.gz is not listed in SHA256SUMS"
if command -v sha256sum >/dev/null 2>&1; then
    have=$(sha256sum "$tmp/$name.tar.gz" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
    have=$(shasum -a 256 "$tmp/$name.tar.gz" | cut -d' ' -f1)
else
    fail "need sha256sum or shasum to check the download"
fi
[ "$want" = "$have" ] || fail "checksum mismatch for $name.tar.gz (expected $want, got $have)"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
"$tmp/$name/bin/mosh-client" --version >/dev/null 2>&1 \
    || fail "the downloaded mosh-client does not run on this system; build from source: https://wmacevoy.github.io/mosh/usage.html"

mkdir -p "$prefix/bin" "$prefix/share/man/man1"
for f in mosh mosh-client mosh-server; do
    # install over a running copy safely: replace the file, don't write into it
    cp "$tmp/$name/bin/$f" "$prefix/bin/.$f.new"
    chmod 755 "$prefix/bin/.$f.new"
    mv -f "$prefix/bin/.$f.new" "$prefix/bin/$f"
done
cp "$tmp/$name"/share/man/man1/*.1 "$prefix/share/man/man1/" 2>/dev/null || true

say "Installed $("$prefix/bin/mosh-client" --version | head -n 1) in $prefix/bin"

case ":$PATH:" in
    *":$prefix/bin:"*) ;;
    *)
        say ""
        say "$prefix/bin is not on your PATH.  To use this mosh from this machine, add it:"
        say "    export PATH=\"$prefix/bin:\$PATH\""
        say "(As a server it needs nothing more: this mosh looks for mosh-server in ~/.local/bin.)"
        ;;
esac
command -v perl >/dev/null 2>&1 || say "Note: the mosh command needs perl, which was not found.  (mosh-server does not.)"
