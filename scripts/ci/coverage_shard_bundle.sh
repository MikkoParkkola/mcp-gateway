#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Packs one coverage shard for the merge job: its raw profiles, renamed with the shard's
# name so two runners' files never collide (a profile is named by binary and process id),
# and every instrumented executable `cargo llvm-cov report` would read, in a tar that keeps
# the executable bit report needs. Writes bundle/: files.tar, run.log, manifest.txt
# (sizes, the executables' sha256). Usage: coverage_shard_bundle.sh <shard>
set -euo pipefail
shard=$1
t=target/llvm-cov-target
rm -rf bundle && mkdir -p bundle/profraw
n=0
for f in "$t"/*.profraw; do
  [ -e "$f" ] || continue
  cp "$f" "bundle/profraw/$shard-$(basename "$f")"
  n=$((n + 1))
done
[ "$n" -gt 0 ] || { echo "::error::shard $shard: no profiles in $t"; exit 1; }
# The executables report reads: regular files with an execute bit, outside build-script,
# incremental and fingerprint output, which report skips too.
(cd "$t" && find . -type f -perm -u+x \
    -not -path '*/build/*' -not -path '*/incremental/*' -not -path '*/.fingerprint/*' \
    -print0 | sort -z) > bundle/executables.list
tar -C "$t" --null -T bundle/executables.list -cf bundle/files.tar
tar -C bundle -rf bundle/files.tar profraw
rm -rf bundle/profraw
cp run.log bundle/run.log
{
  echo "shard $shard"
  echo "profiles $n"
  echo "executables $(tr -cd '\0' < bundle/executables.list | wc -c)"
  echo "tar_bytes $(wc -c < bundle/files.tar | tr -d ' ')"
  (cd "$t" && xargs -0 sha256sum < "$OLDPWD/bundle/executables.list")
} > bundle/manifest.txt
rm bundle/executables.list
head -4 bundle/manifest.txt | sed "s/^/::notice::/"
