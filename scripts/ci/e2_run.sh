#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# E2 (throwaway only, never merged): e2_run.sh verify|packaged OUT. The split side only: builds each part and lists
# it right after its own build (a later part may overwrite the binary), then the other targets, lists the doctests,
# and runs the job's new split command end to end, logging every phase. The unsplit oracle is built on Spark (the
# whole lib test binary loses hosted runners); e2_parity.py compares the two afterwards.
set -euo pipefail
shape="$1"
mkdir -p "$2"
out="$(cd "$2" && pwd)"
root="$(cd "$(dirname "$0")/../.." && pwd)"
sdk=a_real_sdk_job_outlives_the_gateway_and_its_owner_reads_the_result
lib_exe() { python3 -c 'import json,sys
for l in open(sys.argv[1]):
    try: m = json.loads(l)
    except ValueError: continue
    if m.get("reason") == "compiler-artifact" and m.get("profile", {}).get("test") and m["target"]["kind"] == ["lib"]:
        print(m["executable"])' "$1" | tail -1; }

if [ "$shape" = packaged ]; then
  cd "$root"
  cargo package --locked --no-verify
  version="$(cargo metadata --format-version 1 --no-deps --locked \
    | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "mcp-gateway"))')"
  work="$(mktemp -d)"
  tar -xzf "${CARGO_TARGET_DIR:-$root/target}/package/mcp-gateway-$version.crate" -C "$work"
  cd "$work/mcp-gateway-$version"
  flags=(--all-features --locked)
  skips=(--skip "$sdk" --skip mik_7479_full_burst)
else
  cd "$root"
  flags=(--all-features)
  skips=(--skip "$sdk")
fi
n="$(sed -nE 's/.*const[[:space:]]+N[[:space:]]*:[[:space:]]*u32[[:space:]]*=[[:space:]]*([0-9]+)[[:space:]]*;.*/\1/p' \
  scripts/dev/test-parts-build.rs)"
echo "e2 $shape: N=$n in $(pwd)"

: > "$out/hashes.txt"

for k in $(seq 1 "$n"); do
  MCP_GATEWAY_TEST_PART="$k" cargo test "${flags[@]}" --no-run --lib --message-format=json > "$out/p$k.json"
  exe="$(lib_exe "$out/p$k.json")"
  "$exe" --list > "$out/p$k.txt"
  sha256sum "$exe" >> "$out/hashes.txt"
done
env -u MCP_GATEWAY_TEST_PART cargo test "${flags[@]}" --no-run --bins --test '*' --examples --message-format=json \
  > "$out/rest.json"
env -u MCP_GATEWAY_TEST_PART cargo test "${flags[@]}" --doc -- --list > "$out/split-doc.txt"

status=0

if [ "$shape" = packaged ]; then
  "$root/scripts/ci/packaged-tests.sh" run 2>&1 | tee "$out/run.log" || status=1
else
  "$root/scripts/ci/lib-parts.sh" run "${flags[@]}" -- "${skips[@]}" 2>&1 | tee "$out/run.log" || status=1
fi
python3 "$root/scripts/ci/e2_parity.py" counts "$out" "${skips[@]}" || status=1
# The evidence lives in this log: each binary's hash and each list's size.
cat "$out/hashes.txt"
for f in "$out"/p[0-9]*.txt "$out/split-doc.txt"; do
  echo "e2 $shape: $(basename "$f"): $(grep -c ': test$' "$f" || true) tests"
done
echo "e2 $shape: status $status"
exit "$status"
