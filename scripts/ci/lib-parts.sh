#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# lib-parts.sh export PARTS DEST: build the lib test binary for each part in PARTS (one, or a comma list for the
# grouped rollback legs) and write DEST/pK/lib-tests-pK and DEST/pK/list.txt (its unfiltered --list) for each.
#
# lib-parts.sh cov PLAN PART: run one coverage part (scripts/ci/coverage_shards.py run PLAN PART). A lib part, lib-K,
# runs with its test part set and under the memory gate (scripts/ci/compile-cgroup.sh), then its lib test executable
# is moved to deps/pK/mcp_gateway-HASH so the merge keeps each part's executable apart. Any other part runs with
# the part variable removed, without the gate or the move. A failed run keeps its status and moves nothing.
#
# lib-parts.sh run [CARGO_FLAGS...] -- [TEST_ARGS...]: run the test suite of the crate in the current directory the
# way `cargo test CARGO_FLAGS -- TEST_ARGS` would, with the lib test binary one part at a time: parts 1..N (N from
# that crate's build script), then every other test target, then the doctests, each with --no-fail-fast. Every phase
# runs even after one fails; the exit status is 1 when any failed. The packaged suite runs it from the unpacked crate,
# release verify from the checkout.
#
# The one place MCP_GATEWAY_TEST_PART is set: only as a prefix on the command that compiles part K, never exported
# to the caller (workflow lines may not name it; scripts/release/test_grep_no_test_hook.py), and removed from the
# other targets' and the doctests' calls even when the caller set it. Every part is checked against 1..N, N read from
# the build script, before anything builds. A part whose binary lists no test fails.
set -euo pipefail

usage() {
  echo "usage: $0 export PARTS DEST | cov PLAN PART | run [CARGO_FLAGS...] -- [TEST_ARGS...]" >&2
  exit 2
}
root="$(cd "$(dirname "$0")/../.." && pwd)"

# N from a build script (the checkout's by default), the one place it is declared. Refuses a script with no N and N=0.
part_count() {
  local file="${1:-$root/scripts/dev/test-parts-build.rs}" n
  n="$(sed -nE 's/.*const[[:space:]]+N[[:space:]]*:[[:space:]]*u32[[:space:]]*=[[:space:]]*([0-9]+)[[:space:]]*;.*/\1/p' \
    "$file" 2>/dev/null || true)"
  if [ -z "$n" ]; then
    echo "::error::lib-parts: the build script declares no const N: u32" >&2
    return 1
  fi
  if [ "$n" -lt 1 ]; then
    echo "::error::lib-parts: the build script declares N=$n; a lib test split needs at least one part" >&2
    return 1
  fi
  echo "$n"
}

mode="${1:-}"
if [ "$mode" = run ] && [ -z "${MCP_GATEWAY_TEST_HOME_DIR:-}" ]; then
  # Tests that resolve the gateway home in-process refuse to run without a private one: run the whole suite once
  # more inside a home of its own (the shards' implementation, removed afterwards). A home the caller set is kept.
  exec python3 "$root/scripts/ci/shard_tests.py" with-home -- bash "$0" "$@"
fi
if [ "$mode" = run ]; then
  shift
  flags=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do
    flags+=("$1")
    shift
  done
  [ $# -gt 0 ] || usage
  shift
  # The `${a[@]+...}` form keeps an empty array legal under `set -u` on every bash this runs on.
  n="$(part_count ./scripts/dev/test-parts-build.rs)"
  status=0
  for k in $(seq 1 "$n"); do
    MCP_GATEWAY_TEST_PART="$k" cargo test ${flags[@]+"${flags[@]}"} --no-fail-fast --lib -- ${@+"$@"} || status=1
  done
  env -u MCP_GATEWAY_TEST_PART cargo test ${flags[@]+"${flags[@]}"} --no-fail-fast --bins --test '*' --examples \
    -- ${@+"$@"} || status=1
  env -u MCP_GATEWAY_TEST_PART cargo test ${flags[@]+"${flags[@]}"} --no-fail-fast --doc -- ${@+"$@"} || status=1
  exit "$status"
fi

if { [ "$mode" != export ] && [ "$mode" != cov ]; } || [ $# -ne 3 ]; then
  usage
fi

# Both modes check a part number the same way, before anything builds: digits with no leading zero, and 1..N. The
# length check keeps a huge number out of the arithmetic comparison.
check_part() {
  local k="$1" n="$2"
  if ! [[ "$k" =~ ^[1-9][0-9]*$ ]] || [ "${#k}" -gt "${#n}" ] || [ "$k" -gt "$n" ]; then
    echo "::error::lib-parts: part '$k' is outside 1..$n" >&2
    return 1
  fi
}

if [ "$mode" = cov ]; then
  plan="$2"
  part="$3"
  deps=target/llvm-cov-target/debug/deps
  if [[ "$part" = lib-* ]]; then
    k="${part#lib-}"
    n="$(part_count)"
    check_part "$k" "$n"
  fi
  # cargo llvm-cov clean leaves these folders; a restored cache would put an earlier run's part executable
  # into this run's bundle. Match the whole directory name so p256 crate artifacts survive.
  for directory in "$deps"/p[0-9]*/; do
    name="${directory%/}"
    name="${name##*/}"
    if [[ -d "$directory" && "$name" =~ ^p[0-9]+$ ]]; then
      rm -rf -- "$directory"
    fi
  done
  if [[ "$part" = lib-* ]]; then
    mkdir -p "$deps"
    # mktemp creates the marker now, so its mtime is this run's start.
    marker="$(mktemp "$deps/.coverage-start.XXXXXX")"
    trap 'rm -f "$marker"' EXIT
    MCP_GATEWAY_TEST_PART="$k" "$root/scripts/ci/compile-cgroup.sh" \
      python3 "$root/scripts/ci/coverage_shards.py" run "$plan" "$part"
    # The one lib test executable this run built: an executable mcp_gateway-HASH with no extension. A binary already
    # in a per-part subdirectory, or older than this run's marker, is never a candidate even in a reused target dir.
    executables=()
    while IFS= read -r -d '' executable; do
      executables+=("$executable")
    done < <(find "$deps" -maxdepth 1 -type f -perm -u+x -newer "$marker" \
      -name 'mcp_gateway-*' ! -name '*.*' -print0)
    if [ "${#executables[@]}" -ne 1 ]; then
      hint=""
      # In a reused target dir cargo may not relink an unchanged binary, so it stays older than the marker.
      if [ "${#executables[@]}" -eq 0 ]; then
        hint=" (only executables newer than this run's start count; delete stale $deps/mcp_gateway-* and rerun)"
      fi
      echo "::error::lib-parts: expected one lib test executable, found ${#executables[@]}$hint" >&2
      exit 1
    fi
    # cargo llvm-cov report only reads executables named like cargo names them (mcp_gateway-HASH).
    # It searches deps recursively, so a per-part folder keeps the five executables apart.
    mkdir -p "$deps/p$k"
    mv "${executables[0]}" "$deps/p$k/"
  else
    env -u MCP_GATEWAY_TEST_PART python3 "$root/scripts/ci/coverage_shards.py" run "$plan" "$part"
  fi
  exit 0
fi

parts="$2"
dest="$3"
n="$(part_count)"
IFS=, read -r -a list <<< "$parts"
for k in "${list[@]}"; do
  check_part "$k" "$n"
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
