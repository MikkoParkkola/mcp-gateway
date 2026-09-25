# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Shared skeleton for the NFR.DEMO.1 scenario drivers, lifted from
# scripts/release/nfr_upgrade_1_rehearsal.sh: isolated RUN_DIR/HOME, free-port
# selection, explicit result rows, results.json on exit.
#
# One difference from the rehearsal, and it is the point of this criterion:
# `record` takes an EXPECTED and an ACTUAL and derives PASS/FAIL by comparing
# them. The criterion asks each recording to carry "expected observations and
# actual outcomes"; deriving the status makes expected != actual a real failure
# rather than a label the driver author chose.
#
# Sourced, not executed. Callers set SCENARIO_ID before sourcing.
# shellcheck shell=bash

set -uo pipefail
# 4.0 refuses a config or env file other users can read (UPGRADING-4.0 item 35).
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
BIN="${BIN:?set BIN to the mcp-gateway binary under test}"
RUN_DIR="${RUN_DIR:-$(mktemp -d "/tmp/nfr-demo-1-${SCENARIO_ID}.XXXXXX")}"
RESULTS_JSON="${RESULTS_JSON:-$RUN_DIR/results.json}"
TRANSCRIPT="${TRANSCRIPT:-$RUN_DIR/transcript.txt}"

HOME_DIR="$RUN_DIR/home"
DATA_DIR="$HOME_DIR/.mcp-gateway"
CONFIG_PATH="$DATA_DIR/gateway.yaml"
LOG_DIR="$RUN_DIR/logs"
mkdir -p "$DATA_DIR" "$LOG_DIR"

# Everything below this point is on camera and in the transcript.
exec > >(tee "$TRANSCRIPT") 2>&1

RESULTS=()
record() { # id expected actual
  local id="$1" expected="$2" actual="$3" status="FAIL"
  [ "$expected" = "$actual" ] && status="PASS"
  RESULTS+=("$(python3 -c 'import json,sys; print(json.dumps({"id":sys.argv[1],"expected":sys.argv[2],"actual":sys.argv[3],"status":sys.argv[4]}))' \
    "$id" "$expected" "$actual" "$status")")
  echo "[$status] $id"
  echo "        expected: $expected"
  echo "        actual:   $actual"
}
write_results() {
  printf '[\n  %s\n]\n' "$(IFS=,$'\n  '; echo "${RESULTS[*]}")" > "$RESULTS_JSON"
}
trap 'stop_gateway; write_results' EXIT

pick_free_port() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}
PORT="$(pick_free_port)"
API_KEY="demo-key-$(python3 -c 'import secrets; print(secrets.token_hex(8))')"

GW_PID=""
start_gateway() { # label
  local label="${1:-gateway}"
  HOME="$HOME_DIR" MCP_GATEWAY_CONFIG="$CONFIG_PATH" \
    "$BIN" serve > "$LOG_DIR/$label.stdout.log" 2> "$LOG_DIR/$label.stderr.log" &
  GW_PID=$!
  local i
  for i in $(seq 1 60); do
    if curl -s -o /dev/null -m 1 "http://127.0.0.1:$PORT/health"; then
      echo "gateway up (pid $GW_PID, port $PORT)"
      return 0
    fi
    if ! kill -0 "$GW_PID" 2>/dev/null; then
      echo "FATAL: gateway exited before opening $PORT" >&2
      tail -20 "$LOG_DIR/$label.stderr.log" >&2
      return 1
    fi
    sleep 0.2
  done
  echo "FATAL: gateway never answered /health" >&2
  return 1
}
stop_gateway() {
  [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null
  [ -n "$GW_PID" ] && wait "$GW_PID" 2>/dev/null
  GW_PID=""
  return 0
}

rpc() { # method params_json [api_key] -> response body
  local method="$1" params="$2" key="${3:-$API_KEY}"
  curl -s -m 10 -X POST "http://127.0.0.1:$PORT/mcp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $key" \
    -H "mcp-protocol-version: ${MCP_PROTOCOL_VERSION:-2025-06-18}" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}"
}

# The meta-tool responses wrap their payload in result.content[0].text as JSON.
meta_payload() { # response -> the inner payload, or the envelope on error
  python3 -c '
import json, sys
env = json.loads(sys.stdin.read() or "{}")
text = (env.get("result") or {}).get("content", [{}])[0].get("text")
print(text if text is not None else json.dumps(env))
'
}
