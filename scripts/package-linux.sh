#!/bin/sh
#
# Collects a built tree into a release tarball:
#
#     scripts/package-linux.sh OUTPUT_DIRECTORY
#
# Run from the top of a tree configured with --enable-static-libraries
# and built.  Writes mosh-VERSION-linux-ARCH.tar.gz, whose programs
# depend on nothing but the C library.
#

set -eu

out=${1:?usage: package-linux.sh OUTPUT_DIRECTORY}
version=$(sed -n 's/^AC_INIT(\[[^]]*\], \[\([^]]*\)\].*/\1/p' configure.ac)
case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) arch=$(uname -m) ;;
esac
name="mosh-$version-linux-$arch"

for program in src/frontend/mosh-client src/frontend/mosh-server; do
    # Anything but the C library (and its maths and loader) would have to be on the machine it is copied to.
    if ldd "$program" | grep -v -E 'linux-vdso|libc\.so|libm\.so|ld-linux|libpthread\.so|libdl\.so|librt\.so|libutil\.so' | grep -q '=>'; then
        echo "package-linux.sh: $program is not self-contained:" >&2
        ldd "$program" >&2
        exit 1
    fi
done

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$name/bin" "$stage/$name/share/man/man1" "$out"

cp scripts/mosh "$stage/$name/bin/"
for program in mosh-client mosh-server; do
    strip -o "$stage/$name/bin/$program" "src/frontend/$program"
done
chmod 755 "$stage/$name/bin/"*
cp man/mosh.1 man/mosh-client.1 man/mosh-server.1 "$stage/$name/share/man/man1/"
cp COPYING README.md "$stage/$name/"

"$stage/$name/bin/mosh-client" --version | head -n 1
"$stage/$name/bin/mosh-server" --version | head -n 1

tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
echo "$out/$name.tar.gz"
