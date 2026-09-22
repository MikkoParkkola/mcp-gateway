#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# NFR.DEMO.1 scenario 2 -- a reconnectable task.
#
# A client starts a task on a long-running peer, drops the session, and comes
# back on a NEW session. The gateway is then killed while the task is still in
# flight and restarted from the same durable store. The recording shows the
# task surviving both the session change and the process restart, the peer
# never being asked to do the work twice, and the task reaching a terminal
# state on cancel.
#
# Scope note, verified at source: with auth ENABLED, task creation refuses with
# -32600 "task creation requires a verified caller identity" unless the request
# carries a VerifiedIdentity (src/gateway/router/handlers/tasks.rs:145). A plain
# API key does not produce one -- the static-key branch of the auth middleware
# inserts AuthenticatedClient and ApiKey into the request extensions and no
# identity (src/gateway/auth.rs:991-1002); only key_server_credential does
# (:1006-1014). That is the claim doing the work here.
#
# An earlier draft of this header blamed OIDC's HTTPS requirement. That was
# WRONG and is corrected rather than carried: a non-HTTPS issuer only logs a
# warning (src/key_server/oidc.rs:377), and an explicit provider.jwks_uri
# bypasses discovery and its HTTPS check entirely (:399), so a local issuer is
# configurable. Minting a local JWKS and a signed JWT was simply not built in
# this pass. The consequence is unchanged and stated plainly: this driver runs
# with auth DISABLED, so the recording proves cross-SESSION and cross-RESTART
# reconnect, and nothing about cross-ACCOUNT isolation -- that is
# MIK-7311.LIFECYCLE.2's Rust ACs, not this criterion.
#
# A broken build loses the record with the session or with the process
# (tasks/get finds nothing), replays the side effect on recovery (the peer's
# submission counter reaches two), or leaves the task not cancellable.
#
# Usage: BIN=/path/to/mcp-gateway bash scripts/release/demo/2-reconnectable-task.sh
SCENARIO_ID="2-reconnectable-task"
# shellcheck source=scripts/release/demo/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

PEER="$REPO_ROOT/scripts/release/demo/fixtures/demo_task_peer.py"
CLIENT_VERSION="2026-07-28"
SUBMISSIONS="$RUN_DIR/peer-submissions.txt"
PEER_DELAY_SECS=20
: > "$SUBMISSIONS"

echo "== NFR.DEMO.1 scenario 2: reconnectable task =="
echo "gateway:  $("$BIN" --version)"
echo "client:   protocol $CLIENT_VERSION"
echo "run dir:  $RUN_DIR"
echo "peer:     one tool call takes ${PEER_DELAY_SECS}s and appends to $SUBMISSIONS"
echo "auth:     disabled (see script header -- task creation needs a"
echo "          VerifiedIdentity that the static API-key path never inserts)"

cat > "$CONFIG_PATH" <<YAML
server:
  host: "127.0.0.1"
  port: $PORT

auth:
  enabled: false

meta_mcp:
  enabled: true

cache:
  enabled: false

# Left at the shipped default on purpose. tasks.store_dir defaults to
# ~/.mcp-gateway/tasks and "a process that cannot open it does not start; there
# is no volatile fallback" (src/config/features/tasks.rs:23-32). _common.sh
# points HOME at the run directory, so the store is inside \$RUN_DIR and the
# restart below reopens the same one. Nothing in this recording configures
# durability into existence.

backends:
  work_peer:
    command: "python3 $PEER work_peer $SUBMISSIONS $PEER_DELAY_SECS"
    description: "NFR.DEMO.1 scenario 2 long-running work peer"
    enabled: true
YAML

start_gateway scenario2-first || exit 1

# A reconnect is a DIFFERENT session id on the same run; _common.sh's rpc()
# sends no session header, so this scenario needs its own. The modern path also
# wants the method (and, for a named method, the name) mirrored in headers:
# src/protocol/headers.rs:66 -- tools/call mirrors "name", tasks/get|update|cancel
# mirror "taskId" -- and the router rejects a mismatch with -32020 before dispatch.
rpc_sess() { # session_id method params_json mcp_name
  curl -s -m 30 -X POST "http://127.0.0.1:$PORT/mcp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -H "mcp-protocol-version: $CLIENT_VERSION" \
    -H "Mcp-Session-Id: $1" \
    -H "Mcp-Method: $2" \
    -H "Mcp-Name: $4" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}"
}
# The task surface requires MCP request metadata; without it every task call is
# -32602 "missing required request metadata". The tasks extension must be
# DECLARED in clientCapabilities, or a task-augmented call is -32021 "requires
# the 'io.modelcontextprotocol/tasks' extension". Task creation additionally
# requires an idempotency key, carried in params._meta under the gateway's own
# key (src/protocol/mrtr.rs:33, IDEMPOTENCY_KEY_META) -- not an HTTP header.
IDEMPOTENCY_KEY="demo-task-$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
META_BASE="\"io.modelcontextprotocol/protocolVersion\":\"$CLIENT_VERSION\",\"io.modelcontextprotocol/clientCapabilities\":{\"extensions\":{\"io.modelcontextprotocol/tasks\":{}}}"
CREATE_META="\"_meta\":{$META_BASE,\"io.mcp-gateway/idempotency-key\":\"$IDEMPOTENCY_KEY\"}"
META="\"_meta\":{$META_BASE}"

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
submission_count() { wc -l < "$SUBMISSIONS" | tr -d ' '; }
# The five values TaskStatus can take (src/protocol/tasks.rs:22-33), lower_snake
# on the wire. The row below asserts membership, not a particular one: what
# MIK-7311.LIFECYCLE.4 forbids is silence, and either a resumed result or an
# explicit interrupted outcome satisfies it.
explicit_status() { # status -> explicit | <the raw value>
  case "$1" in
    working|input_required|completed|failed|cancelled) echo "explicit";;
    *) echo "$1";;
  esac
}
# Working and InputRequired are the non-terminal pair the store itself selects
# for startup recovery (src/gateway/task_service/store.rs:993-1003); everything
# else is settled.
terminal_status() { # status -> terminal | <the raw value>
  case "$1" in
    completed|failed|cancelled) echo "terminal";;
    *) echo "$1";;
  esac
}
# _common.sh's stop_gateway sends SIGTERM, and this gateway DRAINS on SIGTERM:
# the first run of this driver saw the 20-second job finish during shutdown, so
# the restarted process read an already-terminal record and the recording
# proved only that a completed record survives. A recording of a mid-flight
# restart has to leave the process no chance to settle the record first.
hard_kill_gateway() {
  [ -n "$GW_PID" ] && kill -9 "$GW_PID" 2>/dev/null
  [ -n "$GW_PID" ] && wait "$GW_PID" 2>/dev/null
  GW_PID=""
  return 0
}

echo
echo "-- session A starts a task --"
CREATED="$(rpc_sess session-A "tools/call" \
  "{\"name\":\"gateway_invoke\",\"arguments\":{\"server\":\"work_peer\",\"tool\":\"work_peer_ping\",\"arguments\":{\"text\":\"long job\"}},\"task\":{},$CREATE_META}" \
  gateway_invoke)"
echo "created -> $(printf '%s' "$CREATED" | head -c 400)"
TASK_ID="$(printf '%s' "$CREATED" | jfield result.taskId)"
echo "task id: $TASK_ID"
record "S2.TASK_CREATED_WITH_AN_ID" "true" \
  "$(case "$TASK_ID" in ""|"<absent>") echo false;; *) echo true;; esac)"

echo
echo "-- session A is gone; the owner comes back on session B --"
RECONNECT="$(rpc_sess session-B "tasks/get" "{\"taskId\":\"$TASK_ID\",$META}" "$TASK_ID")"
echo "reconnect -> $(printf '%s' "$RECONNECT" | head -c 400)"
record "S2.TASK_SURVIVES_A_NEW_SESSION" "$TASK_ID" \
  "$(printf '%s' "$RECONNECT" | jfield result.taskId)"
record "S2.RECONNECT_IS_NOT_AN_ERROR" "absent" \
  "$(contains '"error"' "$RECONNECT")"

echo
echo "-- the peer has been asked to do the work once --"
SUBMISSIONS_BEFORE="$(submission_count)"
echo "peer submissions so far -> $SUBMISSIONS_BEFORE"
record "S2.PEER_WAS_ASKED_ONCE_BEFORE_THE_RESTART" "1" "$SUBMISSIONS_BEFORE"

echo
echo "-- the gateway is killed while the task is still in flight, then restarted --"
# Still in flight by construction: the peer sleeps PEER_DELAY_SECS per call and
# the submission above is already on disk, so the work started and cannot have
# finished. This is the half the criterion's word "reconnectable" rests on: a
# session-header swap against a live process cannot tell a durable record from
# a process-local map.
echo "status before the kill -> $(printf '%s' "$RECONNECT" | jfield result.status)"
hard_kill_gateway
echo "gateway SIGKILLed; the durable store it left on disk:"
printf '  %s\n' "$DATA_DIR"/tasks/* 2>/dev/null | head -5
echo "record on disk says status:"
python3 -c '
import glob, json, sys
for path in glob.glob(sys.argv[1] + "/tasks/*.json"):
    doc = json.load(open(path))
    print("  ", path.rsplit("/", 1)[-1], "->", json.dumps(doc.get("task", doc)).__len__(), "bytes")
' "$DATA_DIR" 2>/dev/null
start_gateway scenario2-restarted || exit 1

AFTER_RESTART="$(rpc_sess session-C "tasks/get" "{\"taskId\":\"$TASK_ID\",$META}" "$TASK_ID")"
echo "after restart -> $(printf '%s' "$AFTER_RESTART" | head -c 400)"
record "S2.TASK_SURVIVES_A_GATEWAY_RESTART" "$TASK_ID" \
  "$(printf '%s' "$AFTER_RESTART" | jfield result.taskId)"
RESTART_STATUS="$(printf '%s' "$AFTER_RESTART" | jfield result.status)"
echo "status after the restart -> $RESTART_STATUS"
record "S2.STATUS_AFTER_RESTART_IS_EXPLICIT_NOT_SILENCE" "explicit" \
  "$(explicit_status "$RESTART_STATUS")"

echo
echo "-- recovery did not replay the side effect --"
SUBMISSIONS_AFTER="$(submission_count)"
echo "peer submissions after the restart -> $SUBMISSIONS_AFTER"
cat "$SUBMISSIONS"
record "S2.RESTART_DID_NOT_REPLAY_THE_SUBMISSION" "1" "$SUBMISSIONS_AFTER"

echo
echo "-- a fourth session cancels the task --"
CANCEL="$(rpc_sess session-D "tasks/cancel" "{\"taskId\":\"$TASK_ID\",$META}" "$TASK_ID")"
echo "cancel -> $(printf '%s' "$CANCEL" | head -c 300)"
AFTER="$(rpc_sess session-E "tasks/get" "{\"taskId\":\"$TASK_ID\",$META}" "$TASK_ID")"
echo "after -> $(printf '%s' "$AFTER" | head -c 300)"
# Membership, not a single value. Whether the restarted gateway resumed the
# work or left it interrupted decides whether cancel settles the record or
# arrives after it is already settled, and both are correct; what the criterion
# needs is that the task does not sit non-terminal forever.
record "S2.CANCEL_LEAVES_A_TERMINAL_STATE" "terminal" \
  "$(terminal_status "$(printf '%s' "$AFTER" | jfield result.status)")"

echo
echo "results: $RESULTS_JSON"
echo "transcript: $TRANSCRIPT"
