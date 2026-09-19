#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# NFR.DEMO.1 scenario 2 -- reconnectable task.
#
# A client starts a task, drops the session, and comes back on a NEW session.
# The recording shows the task surviving the disconnect and being readable by
# its owner, not readable by another account, and cancellable to a terminal
# state.
#
# A broken build loses the record with the session (tasks/get finds nothing on
# the new session), or hands the task to whoever asks.
#
# Usage: BIN=/path/to/mcp-gateway bash scripts/release/demo/2-reconnectable-task.sh
SCENARIO_ID="2-reconnectable-task"
# shellcheck source=scripts/release/demo/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

PEER="$REPO_ROOT/scripts/release/demo/fixtures/demo_era_peer.py"
OWNER_KEY="owner-$API_KEY"
OTHER_KEY="other-$API_KEY"
CLIENT_VERSION="2026-07-28"

echo "== NFR.DEMO.1 scenario 2: reconnectable task =="
echo "gateway:  $("$BIN" --version)"
echo "client:   protocol $CLIENT_VERSION"
echo "run dir:  $RUN_DIR"

cat > "$CONFIG_PATH" <<YAML
server:
  host: "127.0.0.1"
  port: $PORT

auth:
  enabled: true
  api_keys:
    - key: "$OWNER_KEY"
      name: "Task Owner"
      rate_limit: 0
      backends: ["work_peer"]
    - key: "$OTHER_KEY"
      name: "Someone Else"
      rate_limit: 0
      backends: ["work_peer"]

meta_mcp:
  enabled: true

cache:
  enabled: false

backends:
  work_peer:
    command: "python3 $PEER work_peer 2025-06-18 not_modern"
    description: "NFR.DEMO.1 scenario 2 work peer"
    enabled: true
YAML

start_gateway scenario2 || exit 1

# _common.sh's rpc() sends no session header; a reconnect is a DIFFERENT
# session id on the same credential, so this scenario needs its own.
# The modern path also wants the method (and, for tools/call, the tool name) in
# headers mirroring the body: src/protocol/headers.rs:159, and the router
# rejects a mismatch with -32020 before dispatch.
rpc_sess() { # session_id method params_json [api_key] [tool_name]
  local key="${4:-}" extra=()
  [ -n "${5:-}" ] && extra=(-H "Mcp-Name: $5")
  curl -s -m 10 -X POST "http://127.0.0.1:$PORT/mcp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${key:-$OWNER_KEY}" \
    -H "mcp-protocol-version: $CLIENT_VERSION" \
    -H "Mcp-Session-Id: $1" \
    -H "Mcp-Method: $2" \
    "${extra[@]}" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}"
}
# The task surface requires MCP request metadata; without it every task call is
# -32602 "missing required request metadata". Carried on each params object
# rather than injected by rpc_sess, so the transcript shows what was sent.
# The tasks extension must be DECLARED in clientCapabilities, or a task-augmented
# call is -32021 "requires the 'io.modelcontextprotocol/tasks' extension".
META="\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"$CLIENT_VERSION\",\"io.modelcontextprotocol/clientCapabilities\":{\"extensions\":{\"io.modelcontextprotocol/tasks\":{}}}}"

jfield() { python3 -c '
import json, sys
node = json.loads(sys.stdin.read() or "{}")
for key in sys.argv[1].split("."):
    if isinstance(node, list):
        node = node[int(key)] if key.isdigit() and int(key) < len(node) else None
    else:
        node = (node or {}).get(key)
print(node if node is not None else "<absent>")
' "$1"; }
contains() { case "$2" in *"$1"*) echo "$1 present";; *) echo "absent";; esac; }

echo
echo "-- session A starts a task --"
CREATED="$(rpc_sess session-A "tools/call" \
  "{\"name\":\"gateway_invoke\",\"arguments\":{\"server\":\"work_peer\",\"tool\":\"work_peer_ping\",\"arguments\":{\"text\":\"long job\"}},\"task\":{},$META}" "" gateway_invoke)"
echo "created -> $(printf '%s' "$CREATED" | head -c 400)"
TASK_ID="$(printf '%s' "$CREATED" | jfield result.task.taskId)"
echo "task id: $TASK_ID"
record "S2.TASK_CREATED_WITH_AN_ID" "true" \
  "$(case "$TASK_ID" in ""|"<absent>") echo false;; *) echo true;; esac)"

echo
echo "-- session A is gone; the owner comes back on session B --"
RECONNECT="$(rpc_sess session-B "tasks/get" "{\"taskId\":\"$TASK_ID\",$META}")"
echo "reconnect -> $(printf '%s' "$RECONNECT" | head -c 400)"
record "S2.TASK_SURVIVES_A_NEW_SESSION" "$TASK_ID" \
  "$(printf '%s' "$RECONNECT" | jfield result.taskId)"
record "S2.RECONNECT_IS_NOT_AN_ERROR" "absent" \
  "$(contains '"error"' "$RECONNECT")"

echo
echo "-- another account asks for the same task id --"
STRANGER="$(rpc_sess session-C "tasks/get" "{\"taskId\":\"$TASK_ID\",$META}" "$OTHER_KEY")"
echo "stranger -> $(printf '%s' "$STRANGER" | head -c 300)"
record "S2.ANOTHER_ACCOUNT_DOES_NOT_GET_THE_TASK" "absent" \
  "$(contains "\"taskId\":\"$TASK_ID\"" "$STRANGER")"

echo
echo "-- the owner cancels, on a third session --"
CANCEL="$(rpc_sess session-D "tasks/cancel" "{\"taskId\":\"$TASK_ID\",$META}")"
echo "cancel -> $(printf '%s' "$CANCEL" | head -c 300)"
AFTER="$(rpc_sess session-D "tasks/get" "{\"taskId\":\"$TASK_ID\",$META}")"
echo "after -> $(printf '%s' "$AFTER" | head -c 300)"
record "S2.CANCELLED_IS_TERMINAL" "cancelled" \
  "$(printf '%s' "$AFTER" | jfield result.status)"

echo
echo "results: $RESULTS_JSON"
echo "transcript: $TRANSCRIPT"
