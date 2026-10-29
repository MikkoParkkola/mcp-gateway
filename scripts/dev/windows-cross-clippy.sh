#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Clippy for Windows from a Linux or macOS host: a cheap early signal for a
# change that touches cfg(windows) code, a Windows-only path, or adds a boxed
# or large future, before the merge train's Windows jobs judge it.
#
#   scripts/dev/windows-cross-clippy.sh [extra cargo args...]
#   CROSS_CARGO=<wrapper> scripts/dev/windows-cross-clippy.sh   (e.g. a remote build
#     wrapper on a host that has the target; the local target check is skipped)
#
# A signal, not a gate. It targets x86_64-pc-windows-gnu, so it covers
# neither cfg(target_env = "msvc") code nor any Windows test or guard; the
# train's Windows shards and Windows clippy (MSVC) stay the gate.
set -euo pipefail

target=x86_64-pc-windows-gnu
if [ -z "${CROSS_CARGO:-}" ] && ! rustup target list --installed 2>/dev/null | grep -x "$target" >/dev/null; then
  echo "windows-cross-clippy: the $target target is not installed." >&2
  echo "  rustup target add $target   (and a mingw-w64 toolchain for C dependencies)" >&2
  exit 2
fi
if [ -z "${CROSS_CARGO:-}" ] && ! command -v x86_64-w64-mingw32-gcc >/dev/null; then
  echo "windows-cross-clippy: no x86_64-w64-mingw32-gcc; crates with C code will fail to build (install mingw-w64)." >&2
fi
exec "${CROSS_CARGO:-cargo}" clippy --target "$target" --all-targets --all-features "$@" -- -D warnings
