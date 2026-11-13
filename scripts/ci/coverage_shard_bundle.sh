#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Packs one coverage shard for the merge job: its raw profiles, renamed with the shard's
# name so two runners' files never collide (a profile is named by binary and process id),
# and every instrumented executable `cargo llvm-cov report` would read, in a tar that keeps
# the executable bit report needs. Writes bundle/: files.tar, run.log, tests.tsv, manifest.txt
# (sizes, each executable's coverage digest from coverage_shards.py).
# Usage: coverage_shard_bundle.sh <shard>
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
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
# The executables report reads: regular files with an execute bit, except build scripts and incremental and
# fingerprint output, which report skips too. Build scripts are named, not found by folder: cargo 1.100 builds
# every crate's outputs, test binaries included, under build/<package>/<hash>/out/, so a `*/build/*` filter
# (right for the old layout, where build/ held only build scripts) dropped every test binary.
(cd "$t" && find . -type f -perm -u+x \
    -not -name 'build_script_build*' -not -name 'build-script-build*' \
    -not -path '*/incremental/*' -not -path '*/.fingerprint/*' \
    -print0 | sort -z) > bundle/executables.list
# Fail closed: a part with profiles but no executables cannot be graded (it graded every function at 0%).
[ -s bundle/executables.list ] || { echo "::error::shard $shard: no instrumented executables under $t"; exit 1; }
tar -C "$t" --null -T bundle/executables.list -cf bundle/files.tar
# cargo-llvm-cov's report tells cargo 1.100's layout from a `fingerprint` folder beside each `out`; without it it
# reads build/<package>/<hash>/out as build-script output and skips every test binary there (it passed only the two
# uplifted bins). Carry those folders, empty: the marker is all the report needs.
(cd "$t" && find . -type d -path '*/build/*/fingerprint' -print0 | sort -z) > bundle/fingerprints.list
[ ! -s bundle/fingerprints.list ] || tar -C "$t" --null --no-recursion -T bundle/fingerprints.list -rf bundle/files.tar
rm bundle/fingerprints.list
tar -C bundle -rf bundle/files.tar profraw
rm -rf bundle/profraw
cp run.log bundle/run.log
# Each test's binary, name and outcome, from coverage_shards.py's listing: the
# equivalence check compares these between the parts and a single job.
[ -s tests.tsv ] || { echo "::error::shard $shard: no tests.tsv"; exit 1; }
cp tests.tsv bundle/tests.tsv
{
  echo "shard $shard"
  echo "profiles $n"
  echo "executables $(tr -cd '\0' < bundle/executables.list | wc -c)"
  echo "tar_bytes $(wc -c < bundle/files.tar | tr -d ' ')"
  # The compiler that built these executables: the merge refuses a part built by another.
  rustc -Vv | sed -n 's/^release: /rustc_release /p; s/^commit-hash: /rustc_commit /p'
  (cd "$t" && xargs -0 python3 "$here/coverage_shards.py" digest < "$OLDPWD/bundle/executables.list")
} > bundle/manifest.txt
rm bundle/executables.list
head -6 bundle/manifest.txt | sed "s/^/::notice::/"
