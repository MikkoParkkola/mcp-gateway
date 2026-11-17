#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# lib-parts.sh export PARTS DEST: build the lib test binary for each part in PARTS (one, or a comma list for the
# grouped rollback legs) and write DEST/pK/lib-tests-pK and DEST/pK/list.txt (its unfiltered --list) for each.
#
# The one place MCP_GATEWAY_TEST_PART is set: only as a prefix on the command that compiles part K, never exported
# to the caller (workflow lines may not name it; scripts/release/test_grep_no_test_hook.py). Every part is checked
# against 1..N, N read from the build script, before anything builds. A part whose binary lists no test fails.
set -euo pipefail

# lib-parts.sh cov PLAN PART: validate lib-K, run coverage under the compile gate with the part prefix,
# then rename the sole lib executable to mcp_gateway-HASH-pK for bundling. Other parts run with the
# part variable removed, without the gate or rename. A failed run keeps its status and renames nothing.
mode="${1:-}"
if { [ "$mode" != export ] && [ "$mode" != cov ]; } || [ $# -ne 3 ]; then
  echo "usage: $0 export PARTS DEST | cov PLAN PART" >&2
  exit 2
fi
if [ "$mode" = cov ]; then
  plan="$2"
  part="$3"
  root="$(cd "$(dirname "$0")/../.." && pwd)"
  if [[ "$part" = lib-* ]]; then
    k="${part#lib-}"
    n="$(sed -nE 's/.*const[[:space:]]+N[[:space:]]*:[[:space:]]*u32[[:space:]]*=[[:space:]]*([0-9]+)[[:space:]]*;.*/\1/p' \
      "$root/scripts/dev/test-parts-build.rs")"
    if [ -z "$n" ]; then
      echo "::error::lib-parts: the build script declares no const N: u32" >&2
      exit 1
    fi
    if ! [[ "$k" =~ ^[1-9][0-9]*$ ]] || [ "${#k}" -gt "${#n}" ] || [ "$k" -gt "$n" ]; then
      echo "::error::lib-parts: part '$k' is outside 1..$n" >&2
      exit 1
    fi
    MCP_GATEWAY_TEST_PART="$k" "$root/scripts/ci/compile-cgroup.sh" \
      python3 "$root/scripts/ci/coverage_shards.py" run "$plan" "$part"
    executables=()
    while IFS= read -r -d '' executable; do
      executables+=("$executable")
    done < <(find target/llvm-cov-target/debug/deps -maxdepth 1 -type f -perm -u+x \
      -name 'mcp_gateway-*' ! -name '*.*' -print0)
    if [ "${#executables[@]}" -ne 1 ]; then
      echo "::error::lib-parts: expected one lib test executable, found ${#executables[@]}" >&2
      exit 1
    fi
    mv "${executables[0]}" "${executables[0]}-p$k"
  else
    env -u MCP_GATEWAY_TEST_PART python3 "$root/scripts/ci/coverage_shards.py" run "$plan" "$part"
  fi
  exit 0
fi
parts="$2"
dest="$3"
root="$(cd "$(dirname "$0")/../.." && pwd)"
n="$(sed -nE 's/.*const[[:space:]]+N[[:space:]]*:[[:space:]]*u32[[:space:]]*=[[:space:]]*([0-9]+)[[:space:]]*;.*/\1/p' \
  "$root/scripts/dev/test-parts-build.rs")"
if [ -z "$n" ]; then
  echo "::error::lib-parts: the build script declares no const N: u32" >&2
  exit 1
fi
IFS=, read -r -a list <<< "$parts"
for k in "${list[@]}"; do
  if ! [[ "$k" =~ ^[1-9][0-9]*$ ]] || [ "$k" -gt "$n" ]; then
    echo "::error::lib-parts: part '$k' is outside 1..$n" >&2
    exit 1
  fi
done
for k in "${list[@]}"; do
  out="$dest/p$k"
  MCP_GATEWAY_TEST_PART="$k" python3 "$root/scripts/ci/shard_tests.py" export-lib "$out"
  mv "$out/lib-tests" "$out/lib-tests-p$k"
  "$out/lib-tests-p$k" --list > "$out/list.txt"
  if ! grep -q ': test$' "$out/list.txt"; then
    echo "::error::lib-parts: part $k's binary lists no test" >&2
    exit 1
  fi
  echo "lib-parts: part $k: $(grep -c ': test$' "$out/list.txt") tests"
done
