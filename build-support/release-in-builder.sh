#!/usr/bin/env bash
# Invoked by the project's hardened cargo-build-musl unit, inside noble.
set -euo pipefail
sysroot=/opt/zffacquire-musl
for lib in udev acl attr; do
    test -s "$sysroot/usr/lib/lib$lib.a" || {
        echo "Missing musl lib$lib.a. Run build-support/prepare-musl-sysroot.sh inside noble first." >&2
        exit 1
    }
done
export PKG_CONFIG_SYSROOT_DIR_x86_64_unknown_linux_musl="$sysroot"
export PKG_CONFIG_LIBDIR_x86_64_unknown_linux_musl="$sysroot/usr/lib/pkgconfig"
export PKG_CONFIG_ALL_STATIC=1
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-L native=$sysroot/usr/lib -l static=udev"
cargo build --frozen --release -p zffacquire --target x86_64-unknown-linux-musl
binary="$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/zffacquire"
if readelf -d "$binary" | grep -q NEEDED || readelf -l "$binary" | grep -q INTERP; then
    echo 'Release CLI unexpectedly requires shared libraries.' >&2
    exit 1
fi
"$binary" --version
cargo test --frozen --release -p zffacquire --target x86_64-unknown-linux-musl --test acquire_readback
unset PKG_CONFIG_ALL_STATIC
cargo build --frozen --release -p zffacquire-gui --target x86_64-unknown-linux-gnu
