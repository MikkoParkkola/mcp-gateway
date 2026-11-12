#!/bin/sh
# Linker driver for aarch64 Linux: cc, with the lld that rustup ships when the
# toolchain has one. The lib test binary's code has outgrown the 128 MB reach of
# a single aarch64 branch, and GNU ld then fails with "relocation truncated to
# fit: R_AARCH64_CALL26"; lld inserts range-extension thunks instead.
# Without a rustup lld this is plain cc, so nothing is required to be installed.
root="$(rustc --print sysroot 2>/dev/null)"
# Only the wildcard expands: a sysroot path with a space stays one word.
for d in "$root"/lib/rustlib/aarch64-*-linux-gnu/bin/gcc-ld; do
    if [ -x "$d/ld.lld" ]; then
        exec cc -B"$d" -fuse-ld=lld "$@"
    fi
done
exec cc "$@"
