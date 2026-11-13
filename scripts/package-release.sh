#!/bin/sh
#
# Collects a built tree into a release tarball:
#
#     scripts/package-release.sh OUTPUT_DIRECTORY
#
# Run from the top of a built tree.  Writes
# mosh-VERSION-linux-ARCH.tar.gz or mosh-VERSION-macos-universal.tar.gz,
# and refuses if the programs need any library that does not come with
# the operating system, since the point is that they can be copied to
# another machine and run.
#

set -eu

out=${1:?usage: package-release.sh OUTPUT_DIRECTORY}
version=$(sed -n 's/^AC_INIT(\[[^]]*\], \[\([^]]*\)\].*/\1/p' configure.ac)
programs="src/frontend/mosh-client src/frontend/mosh-server"

case "$(uname -s)" in
    Linux)
        case "$(uname -m)" in
            x86_64|amd64) arch=x86_64 ;;
            aarch64|arm64) arch=aarch64 ;;
            *) arch=$(uname -m) ;;
        esac
        name="mosh-$version-linux-$arch"
        for program in $programs; do
            # Only the C library and its companions.
            if ldd "$program" | grep '=>' \
                | grep -v -E 'linux-vdso|libc\.so|libm\.so|ld-linux|libpthread\.so|libdl\.so|librt\.so|libutil\.so' \
                | grep -q .; then
                echo "package-release.sh: $program is not self-contained:" >&2
                ldd "$program" >&2
                exit 1
            fi
        done
        ;;
    Darwin)
        name="mosh-$version-macos-universal"
        for program in $programs; do
            # Only what ships with macOS.
            if otool -L "$program" | tail -n +2 | grep -v -E '^[[:space:]]*(/usr/lib/|/System/Library/)' \
                | grep -v -E '^[^[:space:]].*:$' | grep -q .; then
                echo "package-release.sh: $program is not self-contained:" >&2
                otool -L "$program" >&2
                exit 1
            fi
            lipo -archs "$program"
        done
        ;;
    *)
        echo "package-release.sh: don't know how to package for $(uname -s)" >&2
        exit 1
        ;;
esac

stage=$(mktemp -d 2>/dev/null || mktemp -d -t mosh-package)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$name/bin" "$stage/$name/share/man/man1" "$out"

cp scripts/mosh "$stage/$name/bin/mosh.pl" # (the Perl script the mosh command used to be)
for program in mosh-client mosh-server; do
    cp "src/frontend/$program" "$stage/$name/bin/$program"
    if [ "$(uname -s)" = Darwin ]; then
        strip -x "$stage/$name/bin/$program"
        # Apple Silicon runs nothing unsigned, and stripping breaks the linker's signature.
        codesign --force --sign - "$stage/$name/bin/$program"
    else
        strip "$stage/$name/bin/$program"
    fi
done
chmod 755 "$stage/$name/bin/"*
# the mosh and mocp commands are mosh-client under those names
ln -s mosh-client "$stage/$name/bin/mosh"
ln -s mosh-client "$stage/$name/bin/mocp"
cp man/mosh.1 man/mocp.1 man/mosh-client.1 man/mosh-server.1 "$stage/$name/share/man/man1/"
cp COPYING README.md "$stage/$name/"

"$stage/$name/bin/mosh-client" --version | head -n 1
"$stage/$name/bin/mosh-server" --version | head -n 1
"$stage/$name/bin/mosh" --version | head -n 1
"$stage/$name/bin/mocp" --help | head -n 1

tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
echo "$out/$name.tar.gz"
