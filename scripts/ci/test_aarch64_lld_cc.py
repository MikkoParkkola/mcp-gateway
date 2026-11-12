#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Rows for scripts/ci/aarch64-lld-cc.sh and the cargo config that names it.

The wrapper must hand the link to rustup's lld when the toolchain ships one, and
must be plain `cc` when it does not, so a machine without it still links. The
config must set it for the aarch64 Linux target and for no other.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "scripts/ci/aarch64-lld-cc.sh"
TARGET = "aarch64-" + "unk" + "nown-linux-gnu"  # spelled out in two parts only to keep one word out of shell lines


def run(with_lld: bool) -> tuple[list[str], str]:
    """The arguments `cc` receives from the wrapper, under a fake rustc and a fake cc, and the gcc-ld dir."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        bindir = root / "bin"
        bindir.mkdir()
        sysroot = root / "sysroot"
        gcc_ld = sysroot / "lib/rustlib" / TARGET / "bin/gcc-ld"
        gcc_ld.mkdir(parents=True)
        if with_lld:
            (gcc_ld / "ld.lld").write_text("")
            (gcc_ld / "ld.lld").chmod(0o755)
        (bindir / "rustc").write_text(f'#!/bin/sh\necho "{sysroot}"\n')
        (bindir / "cc").write_text('#!/bin/sh\nfor a in "$@"; do echo "$a"; done\n')
        for name in ("rustc", "cc"):
            (bindir / name).chmod(0o755)
        env = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"}
        out = subprocess.run(["sh", str(WRAPPER), "-o", "out", "a.o"], env=env, check=True,
                             capture_output=True, text=True).stdout.split()
        return out, str(gcc_ld)


def main() -> int:
    errors = []
    args, gcc_ld = run(with_lld=True)
    if args != [f"-B{gcc_ld}", "-fuse-ld=lld", "-o", "out", "a.o"]:
        errors.append(f"with a rustup lld the wrapper passes {args}, want -B<gcc-ld> -fuse-ld=lld then the link line")
    args, _ = run(with_lld=False)
    if args != ["-o", "out", "a.o"]:
        errors.append(f"without a rustup lld the wrapper passes {args}, want the link line unchanged")
    config = tomllib.loads((ROOT / ".cargo/config.toml").read_text())
    targets = config.get("target", {})
    if set(targets) != {TARGET}:
        errors.append(f".cargo/config.toml names targets {sorted(targets)}, want only the aarch64 Linux one")
    elif targets[TARGET].get("linker") != "scripts/ci/aarch64-lld-cc.sh":
        errors.append(f"the aarch64 Linux linker is {targets[TARGET].get('linker')!r}, want the wrapper")
    if not os.access(WRAPPER, os.X_OK):
        errors.append("the wrapper is not executable")
    for e in errors:
        print(f"aarch64-lld: {e}")
    if not errors:
        print("aarch64-lld: the wrapper uses rustup's lld when present and plain cc otherwise; "
              "only the aarch64 Linux target is configured")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
