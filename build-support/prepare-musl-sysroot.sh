#!/usr/bin/env bash
# Run as root INSIDE the noble builder (or a disposable CI runner), never on the host.
# This installs native development libraries only. Rust builds remain offline and unprivileged.
set -euo pipefail
sysroot=/opt/zffacquire-musl
archive=alpine-minirootfs-3.22.5-x86_64.tar.gz
sha256=4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282
[[ $(uname -m) == x86_64 ]] || { echo 'This sysroot targets x86_64 only.' >&2; exit 1; }
[[ $EUID == 0 ]] || { echo 'Run as root inside the builder.' >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [[ ! -x $sysroot/sbin/apk ]]; then
    curl --fail --location --retry 3 "https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/$archive" -o "$work/$archive"
    printf '%s  %s\n' "$sha256" "$work/$archive" | sha256sum --check
    mkdir -p "$sysroot"
    tar xzf "$work/$archive" -C "$sysroot"
fi
cp /etc/resolv.conf "$sysroot/etc/resolv.conf"
# apk verifies repository and package signatures using the keys in the pinned rootfs.
chroot "$sysroot" /sbin/apk add --no-cache eudev-dev acl-dev acl-static attr-dev attr-static gcc musl-dev binutils
for lib in udev acl attr; do
    test -s "$sysroot/usr/lib/lib$lib.a"
    # Alpine ships GCC LTO archives. Materialize machine code with its matching
    # compiler so Ubuntu's linker does not need the Alpine GCC LTO plugin.
    # Compilation runs as nobody, and only its temporary directory is writable.
    native_work=$(chroot --userspec=65534:65534 "$sysroot" /bin/mktemp -d)
    chroot --userspec=65534:65534 "$sysroot" /usr/bin/gcc -nostdlib -r \
        -flinker-output=nolto-rel -Wl,--whole-archive "/usr/lib/lib$lib.a" \
        -Wl,--no-whole-archive -o "$native_work/native.o"
    chroot --userspec=65534:65534 "$sysroot" /usr/bin/ar rcs "$native_work/lib$lib.a" "$native_work/native.o"
    install -m 0644 "$sysroot$native_work/lib$lib.a" "$sysroot/usr/lib/lib$lib.a"
    rm -rf "$sysroot$native_work"
done
printf 'Musl native libraries ready in %s\n' "$sysroot"
