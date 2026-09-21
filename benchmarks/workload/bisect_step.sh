#!/usr/bin/env bash
# NFR.WORKLOAD.1 bisect predicate. Called by `git bisect run` from inside the
# dedicated bisect worktree on Spark. Builds the candidate commit's binary and
# measures it INTERLEAVED against the already-built B (3.5.1) binary, on the
# same port, sharing machine conditions across time -- an absolute threshold
# against a 4ms margin does not survive Spark drift, so every step reproduces
# the gate's own relative formula locally: bad if candidate p50 > B p50 * 1.05.
#
# Exit codes (git bisect semantics):
#   0    good (fast)  -- median(candidate) <= median(B) * 1.05
#   1    bad (slow)   -- median(candidate) >  median(B) * 1.05
#   125  skip         -- build failed, or no clean measurement obtained
set -uo pipefail   # NOT -e: this script must reach its own logging/exit lines
                    # even when a step of the pipeline fails or classifies bad.

WORKTREE="$HOME/perf-workload/arms/bisect"
HARNESS="$HOME/perf-workload/arms/C/benchmarks/workload"   # fixed, byte-identical every step
B_BIN="$HOME/perf-workload/arms/B/target/release/mcp-gateway"
FEATURES="a2a,webui,config-export,cost-governance,firewall,discovery,semantic-search,tool-profiles,metrics"
K6_IMAGE="grafana/k6@sha256:1f40432b1cbe7234e977f96c362c9bc550a2d2b583d014dd8669fe40d3e9e755"
PORT=39425
BUDGET=1.05   # eval_workload.py P50_BUDGET
BACKEND_NAME="workload"
TOOL_NAME="workload_probe"
EXPECT_TEXT="WORKLOAD_OK case=042 bundle=deterministic"
PROTOCOL_VERSION="2025-06-18"   # legacy era; matches how A/B/C were all measured

cd "$WORKTREE" || exit 125
SHA="$(git rev-parse HEAD)"
RUNROOT="$HOME/perf-workload/results/bisect-2026-09-21/$SHA"
mkdir -p "$RUNROOT"

[[ -x "$B_BIN" ]] || { echo "[bisect-step] $SHA: reference B binary missing at $B_BIN -> skip"; exit 125; }

echo "[bisect-step] $SHA: building..."
if ! cargo build --release --locked --features "$FEATURES" > "$RUNROOT/build.log" 2>&1; then
  echo "[bisect-step] $SHA: BUILD FAILED -> skip"
  exit 125
fi

CAND_BIN="$WORKTREE/target/release/mcp-gateway"
[[ -x "$CAND_BIN" ]] || { echo "[bisect-step] $SHA: no binary produced -> skip"; exit 125; }

CONFIG_DIR="$RUNROOT/config"
mkdir -p "$CONFIG_DIR"
python3 - "$HARNESS/gateway.workload.yaml" "$CONFIG_DIR/gateway.workload.yaml" "$HARNESS/mcp_backend.py" <<'PY'
import sys
src, dst, fixture = sys.argv[1:4]
text = open(src).read()
open(dst, "w").write(text.replace("${WORKLOAD_FIXTURE}", fixture))
PY
CONFIG="$CONFIG_DIR/gateway.workload.yaml"

GW_PID=""
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&- 2>/dev/null || true; return 0; }; return 1; }
stop_gateway() {
  if [[ -n "$GW_PID" ]] && kill -0 "$GW_PID" 2>/dev/null; then
    kill "$GW_PID" 2>/dev/null || true
    wait "$GW_PID" 2>/dev/null || true
  fi
  GW_PID=""
  local waited=0
  while port_open "$PORT"; do sleep 0.2; waited=$((waited+1)); [[ $waited -lt 100 ]] || break; done
}
# A bug in this predicate must never read as a bad commit. Only the verdict
# branch at the end may exit non-zero-and-not-125; anything else becomes a skip.
on_exit() {
  local rc=$?
  stop_gateway
  if [[ $rc -ne 0 && $rc -ne 125 && "${VERDICT_READY:-0}" != 1 ]]; then
    echo "[bisect-step] ${SHA:-?}: unclassified failure rc=$rc -> skip"
    exit 125
  fi
  exit "$rc"
}
trap on_exit EXIT

# run_rep <bin> <label>. Prints "OK <p50>" or "VOID <reason>" on its last line.
run_rep() {
  local bin="$1" label="$2"
  local gwhome="$RUNROOT/home-$label"
  rm -rf "$gwhome"; mkdir -p "$gwhome"
  WORKLOAD_FIXTURE="$HARNESS/mcp_backend.py" \
  HOME="$gwhome" RUST_LOG=error \
    "$bin" --config "$CONFIG" --port "$PORT" \
    > "$RUNROOT/$label.gateway.stdout" 2> "$RUNROOT/$label.gateway.stderr" &
  GW_PID=$!

  local waited=0
  until curl -fsS "http://127.0.0.1:$PORT/health" > "$RUNROOT/$label.health.json" 2>/dev/null; do
    sleep 0.2; waited=$((waited+1))
    if [[ $waited -ge 150 ]]; then echo "VOID gateway-never-healthy"; stop_gateway; return 1; fi
    kill -0 "$GW_PID" 2>/dev/null || { echo "VOID gateway-died-at-startup"; stop_gateway; return 1; }
  done

  docker run --rm --network host \
    --user "$(id -u):$(id -g)" \
    -v "$HARNESS:/scripts:ro" \
    -v "$RUNROOT:/out" \
    -e BASE_URL="http://127.0.0.1:$PORT" \
    -e BACKEND_NAME="$BACKEND_NAME" \
    -e TOOL_NAME="$TOOL_NAME" \
    -e EXPECT_TEXT="$EXPECT_TEXT" \
    -e PROTOCOL_VERSION="$PROTOCOL_VERSION" \
    -e SCENARIO=load \
    "$K6_IMAGE" run \
      --summary-trend-stats="avg,min,med,p(50),p(90),p(95),p(99),max" \
      --summary-export="/out/$label.summary.json" \
      /scripts/k6_workload.js \
      > "$RUNROOT/$label.k6.txt" 2> "$RUNROOT/$label.k6.err"
  local k6_rc=$?
  stop_gateway
  if [[ $k6_rc -ne 0 ]]; then echo "VOID k6-exit-$k6_rc"; return 1; fi
  [[ -s "$RUNROOT/$label.summary.json" ]] || { echo "VOID no-summary-export"; return 1; }

  python3 - "$RUNROOT/$label.summary.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
m = s.get("metrics", {})
def rate(name):
    node = m.get(name) or {}
    for k in ("rate", "value"):
        if k in node and node[k] is not None:
            return float(node[k])
    return None
herr, sass, chk = rate("http_error_rate"), rate("semantic_assertion_rate"), rate("checks")
if herr is None or sass is None or chk is None:
    print("VOID missing-metric"); sys.exit(0)
if herr > 0 or sass < 1.0 or chk < 0.99:
    print(f"VOID herr={herr} sass={sass} chk={chk}"); sys.exit(0)
lat = m.get("mcp_tools_call_latency") or {}
p50 = lat.get("p(50)")
print(f"OK {p50}" if p50 is not None else "VOID no-p50")
PY
}

# Warm both binaries once, discarded, so a first-hit-cache effect does not
# land on whichever side happens to run first in the interleave below.
run_rep "$B_BIN" "w-b0" >/dev/null
run_rep "$CAND_BIN" "w-cand0" >/dev/null

CAND_P50S=(); B_P50S=()
for n in 1 2 3; do
  cout="$(run_rep "$CAND_BIN" "cand$n")"
  echo "[bisect-step] $SHA: cand$n -> $cout"
  [[ "$cout" == OK\ * ]] || { echo "[bisect-step] $SHA: cand$n $cout -> skip"; exit 125; }
  CAND_P50S+=("${cout#OK }")

  bout="$(run_rep "$B_BIN" "b$n")"
  echo "[bisect-step] $SHA: b$n -> $bout"
  [[ "$bout" == OK\ * ]] || { echo "[bisect-step] $SHA: b$n $bout -> skip"; exit 125; }
  B_P50S+=("${bout#OK }")
done

read -r CAND_MED B_MED RATIO <<<"$(python3 -c "
import statistics, sys
cand = [float(x) for x in sys.argv[1].split(',')]
b = [float(x) for x in sys.argv[2].split(',')]
cm, bm = statistics.median(cand), statistics.median(b)
print(cm, bm, cm / bm)
" "$(IFS=,; echo "${CAND_P50S[*]}")" "$(IFS=,; echo "${B_P50S[*]}")")"

# p50 reps=... line printed unconditionally, BEFORE the bad/good branch, so a
# monitor grepping for it never goes silent on a bad step.
echo "[bisect-step] $SHA: p50 cand=${CAND_P50S[*]} (median $CAND_MED) b=${B_P50S[*]} (median $B_MED) ratio=$RATIO budget=$BUDGET"

VERDICT="$(python3 -c "print('BAD' if $RATIO > $BUDGET else 'GOOD')")"
echo "[bisect-step] $SHA: $VERDICT (ratio $RATIO vs budget $BUDGET)"
VERDICT_READY=1
[[ "$VERDICT" == "GOOD" ]]
exit $?
