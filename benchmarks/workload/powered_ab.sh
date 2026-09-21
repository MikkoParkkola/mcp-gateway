#!/usr/bin/env bash
# NFR.PERF.1 — powered, counterbalanced A/B against the arm the criterion names.
#
# The criterion (docs/requirements/RELEASE-4.0.0-requirements.md:230) reads
# "against 3.5.0". Earlier runs of this harness interleaved v3.5.1, so their
# ratios answered a question the criterion did not ask. BASE_BIN is v3.5.0.
#
# Three procedure controls, each of which a prior run lacked:
#
#  1. PRE-REGISTERED VOID GATE. A rep that delivers fewer iterations than the
#     scenario offers spent that time blocked: the host was busy, and the rep's
#     tail is host noise. The threshold is registered by `--calibrate` BEFORE
#     any scored rep and read from disk afterwards, so it cannot be re-derived
#     from the scored data. Gate and measurement are nearly uncoupled --
#     iteration duration is 200ms of scheduled sleep plus ~107ms of fixed
#     overhead, so a 9% latency regression moves it 0.09%.
#  2. VOID THE PAIR, NEVER ONE ARM. Dropping one side destroys the pairing that
#     cancels common-mode host drift, which is the whole reason the arms are
#     interleaved.
#  3. COUNTERBALANCED WITHIN ONE RUN. Odd pairs run rel first, even pairs run
#     base first, so position is balanced inside a single CSV instead of being
#     reconciled across two runs.
#
# Rep count: registered by `--calibrate` from the calibration pairs -- enough
# that the 95% halfwidth fits inside a third of the budget -- and floored at
# MIN_PAIRS, capped at MAX_PAIRS. The scored run READS that count from the gate
# file; it never re-derives it from the data it is scoring, and it never stops
# early on the verdict, so it cannot shop for significance.
set -uo pipefail

WORKTREE="$HOME/perf-workload/arms/bisect"
HARNESS="$HOME/perf-workload/arms/C/benchmarks/workload"
BASE_BIN="$HOME/perf-workload/arms/A/target/release/mcp-gateway"   # v3.5.0, 32f135a61
BASE_LABEL="v3.5.0"
FEATURES="a2a,webui,config-export,cost-governance,firewall,discovery,semantic-search,tool-profiles,metrics"
K6_IMAGE="grafana/k6@sha256:1f40432b1cbe7234e977f96c362c9bc550a2d2b583d014dd8669fe40d3e9e755"
PORT=39425
BASE_PORT=39425          # v3.5.0 arm
REL_PORT=39426           # candidate arm -- separate ports so a stale listener
                         # from the previous rep cannot silently serve the next
STOP_PORT=$PORT
PORT_STUCK=0
BACKEND_NAME="workload"
TOOL_NAME="workload_probe"
EXPECT_TEXT="WORKLOAD_OK case=042 bundle=deterministic"
PROTOCOL_VERSION="2025-06-18"
RELREF="${RELREF:-origin/main}"

CALIB_REPS=4          # per arm, discarded from scoring
MIN_PAIRS=52          # floor from the pre-registration; see its Amendment 1.3
MAX_PAIRS=60
RUNROOT="${RUNROOT:-$HOME/perf-workload/results/perf1-v350-$(date +%Y%m%d)}"
GATE_FILE="$RUNROOT/registered_gate.json"
SCORER="$HARNESS/powered_ab_score.py"

MODE="${1:---score}"
mkdir -p "$RUNROOT"
CSV="$RUNROOT/reps.csv"

cd "$WORKTREE" || exit 1
git fetch origin -q 2>/dev/null
git checkout -q --detach "$RELREF" || { echo "[ab] cannot check out $RELREF"; exit 1; }
REL_SHA="$(git rev-parse HEAD)"
echo "[ab] release line $RELREF = $REL_SHA"
[[ -x "$BASE_BIN" ]] || { echo "[ab] baseline binary missing at $BASE_BIN"; exit 1; }
echo "[ab] baseline $BASE_LABEL = $BASE_BIN"
echo "[ab] building release line..."
if ! cargo build --release --locked --features "$FEATURES" > "$RUNROOT/build.log" 2>&1; then
  echo "[ab] BUILD FAILED -- see $RUNROOT/build.log"; exit 1
fi
REL_BIN="$WORKTREE/target/release/mcp-gateway"
[[ -x "$REL_BIN" ]] || { echo "[ab] no binary produced"; exit 1; }

CONFIG_DIR="$RUNROOT/config"; mkdir -p "$CONFIG_DIR"
python3 - "$HARNESS/gateway.workload.yaml" "$CONFIG_DIR/gateway.workload.yaml" "$HARNESS/mcp_backend.py" <<'PY'
import sys
src, dst, fixture = sys.argv[1:4]
open(dst, "w").write(open(src).read().replace("${WORKLOAD_FIXTURE}", fixture))
PY
CONFIG="$CONFIG_DIR/gateway.workload.yaml"

GW_PID=""
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && { exec 3>&- 2>/dev/null || true; return 0; }; return 1; }
stop_gateway() {
  if [[ -n "$GW_PID" ]] && kill -0 "$GW_PID" 2>/dev/null; then
    kill "$GW_PID" 2>/dev/null || true; wait "$GW_PID" 2>/dev/null || true
  fi
  GW_PID=""
  local waited=0
  while port_open "$STOP_PORT"; do
    sleep 0.2; waited=$((waited+1))
    # A3.2: a port that never frees means the next rep would measure the previous
    # arm's listener. That is a VOID with a reason, never a silent `break`.
    [[ $waited -lt 100 ]] || { PORT_STUCK=1; return 0; }
  done
  PORT_STUCK=0
}
trap 'stop_gateway' EXIT

# run_rep <bin> <label>. Last line: "OK <p50> <p90> <p95> <p99> <max> <reqs> <iters>"
# or "VOID <reason>". Semantic validation is inside: a rep with any http error,
# any failed semantic assertion, or a missing metric is VOID, never a sample.
run_rep() {
  local bin="$1" label="$2" port="${3:-$PORT}"
  STOP_PORT="$port"
  local gwhome="$RUNROOT/home-$label"
  rm -rf "$gwhome"; mkdir -p "$gwhome"
  WORKLOAD_FIXTURE="$HARNESS/mcp_backend.py" HOME="$gwhome" RUST_LOG=error \
    "$bin" --config "$CONFIG" --port "$port" \
    > "$RUNROOT/$label.gateway.stdout" 2> "$RUNROOT/$label.gateway.stderr" &
  GW_PID=$!
  local waited=0
  until curl -fsS "http://127.0.0.1:$port/health" > "$RUNROOT/$label.health.json" 2>/dev/null; do
    sleep 0.2; waited=$((waited+1))
    if [[ $waited -ge 150 ]]; then echo "VOID gateway-never-healthy"; stop_gateway; return 1; fi
    kill -0 "$GW_PID" 2>/dev/null || { echo "VOID gateway-died-at-startup"; stop_gateway; return 1; }
  done
  # A3.2 -- the listening socket must be owned by the PID we launched. A free
  # port is a fact with a shelf life; this is what makes it durable.
  local own
  own="$(ss -ltnp 2>/dev/null | grep -c "\:$port .*pid=$GW_PID," || true)"
  echo "$label port=$port pid=$GW_PID owned=$own" >> "$RUNROOT/port-ownership.txt"
  [[ "$own" == "1" ]] || { echo "VOID port-$port-not-owned-by-launched-pid"; stop_gateway; return 1; }
  rm -f "$RUNROOT/$label.samples.csv"
  docker run --rm --network host --user "$(id -u):$(id -g)" \
    -v "$HARNESS:/scripts:ro" -v "$RUNROOT:/out" \
    -e BASE_URL="http://127.0.0.1:$port" -e BACKEND_NAME="$BACKEND_NAME" \
    -e TOOL_NAME="$TOOL_NAME" -e EXPECT_TEXT="$EXPECT_TEXT" \
    -e PROTOCOL_VERSION="$PROTOCOL_VERSION" -e SCENARIO=load \
    "$K6_IMAGE" run --summary-export="/out/$label.summary.json" \
      --out "csv=/out/$label.samples.csv" \
      /scripts/k6_workload.js > "$RUNROOT/$label.k6.txt" 2> "$RUNROOT/$label.k6.err"
  local k6_rc=$?
  stop_gateway
  [[ "${PORT_STUCK:-0}" == "0" ]] || { echo "VOID port-$port-never-released"; return 1; }
  [[ $k6_rc -eq 0 ]] || { echo "VOID k6-exit-$k6_rc"; return 1; }
  [[ -s "$RUNROOT/$label.summary.json" ]] || { echo "VOID no-summary-export"; return 1; }
  [[ -s "$RUNROOT/$label.samples.csv" ]] || { echo "VOID no-raw-samples"; return 1; }
  # Order statistics come from the raw per-request samples, never from the
  # summary's percentiles -- the summary is read only for the error/check rates.
  python3 "$SCORER" --read-rep "$RUNROOT/$label.summary.json" \
    --samples "$RUNROOT/$label.samples.csv"
}

# ---------------------------------------------------------------------------
# Arms are rebuilt from source on this box, in this session, minutes apart, so
# neither number is inherited from an older binary with an older toolchain.
# ---------------------------------------------------------------------------
BASE_WORKTREE="${BASE_WORKTREE:-$HOME/perf-workload/arms/A}"
BASE_SHA_EXPECT="32f135a61fb50c20a044fb4c2347bc1cf8015d89"
BASE_SHA="$(git -C "$BASE_WORKTREE" rev-parse HEAD 2>/dev/null || echo none)"
if [[ "$BASE_SHA" != "$BASE_SHA_EXPECT" ]]; then
  echo "[ab] STOP: baseline tree is $BASE_SHA, not v3.5.0 ($BASE_SHA_EXPECT)"; exit 2
fi
if [[ "${REBUILD_BASE:-1}" == "1" ]]; then
  echo "[ab] building baseline $BASE_LABEL ..."
  if ! (cd "$BASE_WORKTREE" && cargo build --release --locked --features "$FEATURES") \
       > "$RUNROOT/build.base.log" 2>&1; then
    echo "[ab] BASELINE BUILD FAILED -- see $RUNROOT/build.base.log"; exit 1
  fi
fi
[[ -x "$BASE_BIN" ]] || { echo "[ab] baseline binary missing after build"; exit 1; }

digest() { sha256sum "$1" | cut -d' ' -f1; }
BASE_DIGEST="$(digest "$BASE_BIN")"
REL_DIGEST="$(digest "$REL_BIN")"
RUSTC="$(rustc --version)"
K6_DIGEST="$K6_IMAGE"

cat > "$RUNROOT/run_record.json" <<JSON
{
  "criterion": "NFR.PERF.1",
  "started_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "host": "$(hostname)",
  "arch": "$(uname -m)",
  "cores": "$(nproc)",
  "rustc": "$RUSTC",
  "k6_image": "$K6_DIGEST",
  "features": "$FEATURES",
  "baseline": {
    "label": "$BASE_LABEL",
    "sha": "$BASE_SHA",
    "binary": "$BASE_BIN",
    "sha256": "$BASE_DIGEST",
    "port": $BASE_PORT
  },
  "candidate": {
    "ref": "$RELREF",
    "sha": "$REL_SHA",
    "binary": "$REL_BIN",
    "sha256": "$REL_DIGEST",
    "port": $REL_PORT
  }
}
JSON
echo "[ab] baseline  $BASE_SHA  sha256=$BASE_DIGEST"
echo "[ab] candidate $REL_SHA  sha256=$REL_DIGEST"
if [[ "$BASE_DIGEST" == "$REL_DIGEST" ]]; then
  echo "[ab] STOP: both arms are the same binary -- nothing to compare"; exit 2
fi

# ---------------------------------------------------------------------------
# One pair = one base rep and one rel rep, adjacent, order counterbalanced.
# A VOID on either side voids the PAIR (control 2): dropping one arm destroys
# the pairing that cancels common-mode host drift.
# ---------------------------------------------------------------------------
[[ -f "$CSV" ]] || echo "pair,order,arm,sha,p50_ms,p99_ms,reqs,iters,status,reason" > "$CSV"

emit() { # <pair> <order> <arm> <sha> <result-line>
  local pair="$1" order="$2" arm="$3" sha="$4"; shift 4
  local line="$*"
  if [[ "$line" == OK\ * ]]; then
    read -r _ p50 p90 p95 p99 mx reqs iters <<<"$line"
    echo "$pair,$order,$arm,$sha,$p50,$p99,$reqs,$iters,OK," >> "$CSV"
    echo "$p50 $p99 $iters"
  else
    local reason="${line#VOID }"
    echo "$pair,$order,$arm,$sha,,,,,VOID,$reason" >> "$CSV"
    echo ""
  fi
}

run_pair() { # <pair-index> -> writes two CSV rows, echoes "VOID" or "OK"
  local pair="$1"
  local first second
  if (( pair % 2 == 1 )); then first=rel; second=base; else first=base; second=rel; fi
  local ok=1
  for slot in 1 2; do
    local arm; [[ $slot == 1 ]] && arm="$first" || arm="$second"
    local bin port sha
    if [[ "$arm" == base ]]; then bin="$BASE_BIN"; port="$BASE_PORT"; sha="$BASE_SHA"
    else bin="$REL_BIN"; port="$REL_PORT"; sha="$REL_SHA"; fi
    local label="p${pair}-${arm}"
    local out; out="$(run_rep "$bin" "$label" "$port" | tail -1)"
    gzip -f "$RUNROOT/$label.samples.csv" 2>/dev/null || true
    local got; got="$(emit "$pair" "$slot" "$arm" "$sha" "$out")"
    [[ -n "$got" ]] || ok=0
    echo "[ab] pair $pair slot $slot $arm: ${out:0:72}" >&2
  done
  (( ok == 1 )) && echo OK || echo VOID
}

case "$MODE" in
--calibrate)
  echo "[ab] CALIBRATION -- $CALIB_REPS pairs, discarded from scoring"
  for i in $(seq 1 "$CALIB_REPS"); do run_pair "$i" > /dev/null; done
  # The gate, the rep count and the thresholds are DERIVED HERE and written to
  # disk. The scored run reads them back; it never recomputes them from its own
  # data. That is the whole point of calibrating first.
  python3 "$SCORER" --register --csv "$CSV" --out "$GATE_FILE" \
    --p50-budget 0.05 --p99-budget 0.10 --min-pairs "$MIN_PAIRS" --max-pairs "$MAX_PAIRS" \
    || { echo "[ab] calibration could not register a gate"; exit 3; }
  echo "[ab] registered gate -> $GATE_FILE"
  cat "$GATE_FILE"
  ;;
--score)
  [[ -s "$GATE_FILE" ]] || { echo "[ab] STOP: no pre-registered gate at $GATE_FILE. Run --calibrate first."; exit 3; }
  TARGET_PAIRS="$(python3 "$SCORER" --read-gate "$GATE_FILE" --field pairs)"
  echo "[ab] SCORED RUN -- pre-registered gate says $TARGET_PAIRS pairs"
  # Scored pairs are numbered from 1000 so calibration rows can never be scored.
  voids=0
  for i in $(seq 1 "$TARGET_PAIRS"); do
    r="$(run_pair "$((1000+i))")"
    [[ "$r" == OK ]] || voids=$((voids+1))
    if (( voids > TARGET_PAIRS / 4 )); then
      echo "[ab] STOP: $voids voided pairs -- the host is not quiet enough to measure"; break
    fi
  done
  python3 "$SCORER" --verdict --csv "$CSV" --gate "$GATE_FILE" \
    --run-record "$RUNROOT/run_record.json" --out "$RUNROOT/verdict.json" | tee "$RUNROOT/verdict.txt"
  ;;
*)
  echo "usage: powered_ab.sh [--calibrate|--score]"; exit 64 ;;
esac
