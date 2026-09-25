#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# NFR.DEMO.1 scenario 5 -- error-budget diagnosis/recovery.
#
# A peer starts failing. The recording shows the gateway's error budget
# noticing, the operator DIAGNOSING it from the gateway's own numbers
# (gateway_get_stats: killed, error_rate, window counts), and RECOVERING with
# gateway_revive_server once the peer is healthy again.
#
# A broken build shows the peer failing past the threshold with the backend
# still live (killed=false), or a revive that does not restore service.
#
# Usage: BIN=/path/to/mcp-gateway bash scripts/release/demo/5-error-budget.sh
SCENARIO_ID="5-error-budget"
# shellcheck source=scripts/release/demo/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

PEER="$REPO_ROOT/scripts/release/demo/fixtures/demo_flaky_peer.py"
FAIL_MARKER="$RUN_DIR/peer-is-sick"
THRESHOLD="0.5"
MIN_SAMPLES="3"

echo "== NFR.DEMO.1 scenario 5: error-budget diagnosis/recovery =="
echo "gateway:    $("$BIN" --version)"
echo "peer:       fails every tool call while $FAIL_MARKER exists"
echo "budget:     threshold $THRESHOLD, min_samples $MIN_SAMPLES (tuned so the recording is short)"
echo "run dir:    $RUN_DIR"

cat > "$CONFIG_PATH" <<YAML
server:
  host: "127.0.0.1"
  port: $PORT

auth:
  enabled: true
  single_user: true
  api_keys:
    - key_sha256: "$(printf %s "$API_KEY" | "$BIN" hash-key)"
      name: "Demo Operator"
      rate_limit: 0
      backends: ["flaky_peer"]
      admin: true

meta_mcp:
  enabled: true

# Off on purpose: a cached response would answer a call the sick peer never
# saw, and the budget would never see a failure. The recording needs every
# call to reach the peer.
cache:
  enabled: false

error_budget:
  threshold: $THRESHOLD
  window_size: 10
  window_duration: 5m
  min_samples: $MIN_SAMPLES

backends:
  flaky_peer:
    command: "python3 $PEER $FAIL_MARKER"
    description: "NFR.DEMO.1 scenario 5 fault-injecting peer"
    enabled: true
YAML

start_gateway scenario5 || exit 1

ping_peer() {
  rpc "tools/call" \
    '{"name":"gateway_invoke","arguments":{"server":"flaky_peer","tool":"budget_ping","arguments":{"text":"hello"}}}'
}
contains() { case "$2" in *"$1"*) echo "$1 present";; *) echo "absent: $2";; esac; }
safety_field() { # dotted.path
  printf '%s' "$STATS" | python3 -c '
import json, sys
payload = json.loads(sys.stdin.read() or "{}")
for entry in payload.get("server_safety", []):
    if entry.get("server") == "flaky_peer":
        value = entry
        for key in sys.argv[1].split("."):
            value = (value or {}).get(key)
        print(json.dumps(value))
        break
else:
    print("<no safety entry for flaky_peer>")
' "$1"
}

echo
echo "-- healthy: the peer answers --"
HEALTHY="$(ping_peer | meta_payload)"
echo "flaky_peer -> $HEALTHY"
record "S5.HEALTHY_CALL_SUCCEEDS" "budget_ping ok present" "$(contains "budget_ping ok" "$HEALTHY")"

echo
echo "-- the peer goes sick; the operator does nothing --"
touch "$FAIL_MARKER"
for i in 1 2 3 4; do
  echo "call $i -> $(ping_peer | head -c 200)"
done

echo
echo "-- diagnosis: the gateway's own numbers, through gateway_get_stats --"
STATS="$(rpc "tools/call" '{"name":"gateway_get_stats","arguments":{}}' | meta_payload)"
printf '%s' "$STATS" | python3 -c 'import json,sys; print(json.dumps(json.load(sys.stdin).get("server_safety"), indent=2))'

# The expected numbers are ARITHMETIC from the config above, not copied from a
# run: the window holds the one healthy call plus the failures, and the budget
# is only evaluated once it holds min_samples=3 calls. The second failure is
# therefore the first evaluation, and it is already over the line -- 2/3 =
# 66.7% > threshold 0.5. So the kill lands with successes=1, failures=2, and
# calls 3 and 4 above are refused rather than forwarded to a peer known sick.
record "S5.BUDGET_KILLED_THE_BACKEND" "true" "$(safety_field killed)"
record "S5.ERROR_RATE_AT_KILL" '"66.7%"' "$(safety_field error_rate)"
record "S5.WINDOW_SUCCESSES_AT_KILL" "1" "$(safety_field window.successes)"
record "S5.WINDOW_FAILURES_AT_KILL" "2" "$(safety_field window.failures)"

echo
echo "-- while killed, the gateway refuses rather than retrying a sick peer --"
REFUSAL="$(ping_peer)"
echo "refusal -> $(printf '%s' "$REFUSAL" | head -c 300)"
record "S5.REFUSED_WHILE_KILLED" \
  "is currently disabled by operator kill switch present" \
  "$(contains "is currently disabled by operator kill switch" "$REFUSAL")"

echo
echo "-- recovery: the peer is fixed, then the operator revives it --"
mv "$FAIL_MARKER" "$RUN_DIR/peer-was-sick"
REVIVE="$(rpc "tools/call" '{"name":"gateway_revive_server","arguments":{"server":"flaky_peer"}}' | meta_payload)"
echo "revive -> $REVIVE"
record "S5.REVIVE_SAW_A_KILLED_SERVER" "true" \
  "$(printf '%s' "$REVIVE" | python3 -c 'import json,sys; print(json.dumps(json.loads(sys.stdin.read() or "{}").get("was_killed")))')"

RECOVERED="$(ping_peer | meta_payload)"
echo "flaky_peer -> $RECOVERED"
record "S5.CALL_SUCCEEDS_AFTER_REVIVE" "budget_ping ok present" "$(contains "budget_ping ok" "$RECOVERED")"

echo
echo "results: $RESULTS_JSON"
echo "transcript: $TRANSCRIPT"
