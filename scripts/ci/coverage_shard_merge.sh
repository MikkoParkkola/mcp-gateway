#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Unpacks every coverage shard's bundle into target/llvm-cov-target for one
# `cargo llvm-cov report`. Fails when an expected shard's bundle is missing, or when two
# shards built different binaries under one name: report would read one of them, and the
# other's counters would no longer match it. Usage: coverage_shard_merge.sh <shard>...
set -euo pipefail
t=target/llvm-cov-target
mkdir -p "$t"
declare -A seen
for shard in "$@"; do
  b="shards/cov-shard-$shard"
  [ -f "$b/files.tar" ] && [ -f "$b/manifest.txt" ] || {
    echo "::error::shard $shard: bundle missing"; exit 1; }
  while read -r sum path; do
    if [ -n "${seen[$path]:-}" ] && [ "${seen[$path]}" != "$sum" ]; then
      echo "::error::$path differs between shards (${seen[$path]} vs $sum)"; exit 1
    fi
    seen[$path]=$sum
  done < <(grep -E '^[0-9a-f]{64}  ' "$b/manifest.txt")
  tar -C "$t" -xf "$b/files.tar"
  mv "$t"/profraw/*.profraw "$t"/
  rmdir "$t/profraw"
  head -4 "$b/manifest.txt" | tr '\n' ' ' | sed 's/^/::notice::/'; echo
done
echo "::notice::profiles $(ls "$t"/*.profraw | wc -l), executables ${#seen[@]}"
