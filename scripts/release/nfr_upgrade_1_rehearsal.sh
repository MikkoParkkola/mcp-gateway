#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# NFR.UPGRADE.1 rehearsal: upgrade a realistic 3.5.1 deployment to 4.0.0,
# verify config/credentials/permissions/mounts/active-callers survive, flip
# modern-off, roll back to 3.5.1, and re-verify the same five properties.
#
# Requires two pre-built binaries (paths given via env or flags):
#   BIN_351 - a mcp-gateway 3.5.1 binary
#   BIN_400 - the mcp-gateway binary under test (this tree's target/debug)
#
# Everything runs inside an isolated HOME so no fixture or token file ever
# touches the operator's real ~/.mcp-gateway. The five properties and why
# they are the right ones: docs/requirements/RELEASE-4.0.0-scope-tests.md
# (NFR.UPGRADE.1 row) and docs/requirements/RELEASE-4.0.0-scope-update.md.
# Results are graded in docs/release/nfr-upgrade-1-rehearsal-results.md.
# Deliberately no `-e`: this script records PASS/FAIL per conjunct rather
# than aborting on the first non-zero exit (a refused-request curl or a
# refused-protocol-version response is an expected outcome in some phases,
# not a script bug). Fatal setup problems (missing binary, busy port, a
# gateway that never opens its port) still call `exit 1` explicitly, and the
# script exits 1 at the end when any recorded check is FAIL, so CI can gate
# on the exit status (the ci.yml `upgrade-rehearsal` job).
set -uo pipefail
# 4.0 refuses a config or env file other users can read (UPGRADING-4.0 item 35),
# so every file this rehearsal writes is owner-only, as the documented step asks.
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIXTURE_STUB="$REPO_ROOT/scripts/release/fixtures/nfr_upgrade_1_mount_stub.py"

BIN_351="${BIN_351:?set BIN_351 to a 3.5.1 mcp-gateway binary}"
BIN_400="${BIN_400:?set BIN_400 to the 4.0.0 mcp-gateway binary under test}"
RUN_DIR="${RUN_DIR:-$(mktemp -d /tmp/nfr-upgrade-1.XXXXXX)}"
RESULTS_JSON="${RESULTS_JSON:-$RUN_DIR/results.json}"

HOME_DIR="$RUN_DIR/home"
DATA_DIR="$HOME_DIR/.mcp-gateway"
CONFIG_PATH="$DATA_DIR/gateway.yaml"
STAMP_PATH="$DATA_DIR/version.stamp"
OAUTH_DIR="$DATA_DIR/oauth"
LOG_DIR="$RUN_DIR/logs"
mkdir -p "$HOME_DIR" "$DATA_DIR" "$OAUTH_DIR" "$LOG_DIR"

# ── result recording ────────────────────────────────────────────────────────
RESULTS=()
record() { # id status detail
  RESULTS+=("{\"id\":\"$1\",\"status\":\"$2\",\"detail\":$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$3")}")
  echo "[$2] $1 -- $3"
}
write_results() {
  printf '[\n  %s\n]\n' "$(IFS=,$'\n  '; echo "${RESULTS[*]}")" > "$RESULTS_JSON"
}
trap write_results EXIT

echo "== NFR.UPGRADE.1 rehearsal =="
echo "RUN_DIR=$RUN_DIR"
echo "BIN_351=$BIN_351 ($("$BIN_351" --version))"
echo "BIN_400=$BIN_400 ($("$BIN_400" --version))"
# The stamp the 4.0 binary writes is its own version (4.0.0-beta.1, 4.0.0, ...).
VERSION_400="$("$BIN_400" --version | awk '{print $2}')"
if [[ -z "$VERSION_400" ]]; then
  echo "FATAL: could not read a version from $BIN_400 --version" >&2
  exit 1
fi

# ── port selection: bind a random high port, confirm nothing is listening ──
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
if lsof -i "TCP:$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "FATAL: port $PORT already listening, pick again" >&2
  exit 1
fi
echo "PORT=$PORT"

API_KEY="rehearsal-key-$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
ISSUER="https://rehearsal.invalid/issuer"
BACKEND_NAME="echo_mount"

# ── synthetic OAuth token, keyed exactly like TokenStorage::storage_key ────
TOKEN_KEY="$(python3 - "$BACKEND_NAME" "$ISSUER" <<'PY'
import hashlib, sys
backend, issuer = sys.argv[1], sys.argv[2]
h = hashlib.sha256((backend + ":" + issuer).encode()).digest()
print(h[:8].hex())
PY
)"
TOKEN_FILE="$OAUTH_DIR/${TOKEN_KEY}_tokens.json"
cat > "$TOKEN_FILE" <<JSON
{
  "access_token": "rehearsal-access-token-351",
  "token_type": "Bearer",
  "refresh_token": "rehearsal-refresh-token-351",
  "expires_at": 4102444800,
  "scope": "rehearsal.read"
}
JSON
TOKEN_SHA_BEFORE="$(shasum -a 256 "$TOKEN_FILE" | awk '{print $1}')"

# ── gateway.yaml (config + data_dir share one path: see migration contract) ─
cat > "$CONFIG_PATH" <<YAML
server:
  host: "127.0.0.1"
  port: $PORT

auth:
  enabled: true
  single_user: true
  api_keys:
    - key: "$API_KEY"
      name: "Rehearsal Client A"
      rate_limit: 0
      backends: ["$BACKEND_NAME"]
      admin: false

meta_mcp:
  enabled: true

backends:
  $BACKEND_NAME:
    command: "python3 $FIXTURE_STUB"
    description: "NFR.UPGRADE.1 rehearsal mount (offline stdio stub)"
    enabled: true
YAML
CONFIG_SHA_BEFORE="$(shasum -a 256 "$CONFIG_PATH" | awk '{print $1}')"

# ── process control ─────────────────────────────────────────────────────────
GW_PID=""
start_gateway() { # binary label
  local bin="$1" label="$2"
  HOME="$HOME_DIR" MCP_GATEWAY_CONFIG="$CONFIG_PATH" \
    "$bin" serve \
    > "$LOG_DIR/$label.stdout.log" 2> "$LOG_DIR/$label.stderr.log" &
  GW_PID=$!
  for _ in $(seq 1 50); do
    if curl -s -o /dev/null -m 1 "http://127.0.0.1:$PORT/health"; then
      echo "  $label started, pid=$GW_PID"
      return 0
    fi
    if ! kill -0 "$GW_PID" 2>/dev/null; then
      echo "FATAL: $label exited before opening $PORT; see $LOG_DIR/$label.stderr.log" >&2
      cat "$LOG_DIR/$label.stderr.log" >&2
      return 1
    fi
    sleep 0.2
  done
  echo "FATAL: $label never answered /health" >&2
  return 1
}
stop_gateway() {
  local label="${1:-gateway}"
  if [[ -n "$GW_PID" ]] && kill -0 "$GW_PID" 2>/dev/null; then
    kill "$GW_PID" 2>/dev/null || true
    for _ in $(seq 1 30); do
      kill -0 "$GW_PID" 2>/dev/null || break
      sleep 0.2
    done
    kill -9 "$GW_PID" 2>/dev/null || true
  fi
  GW_PID=""
  echo "  $label stopped"
}

rpc() { # method params_json  -> prints response body
  local method="$1" params="$2"
  curl -s -m 5 -X POST "http://127.0.0.1:$PORT/mcp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -H "mcp-protocol-version: ${MCP_PROTOCOL_VERSION:-2025-06-18}" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}"
}

# A modern (2026-07-28) request declares itself in params._meta, per
# src/protocol/meta.rs -- there is no initialize handshake in this era, so
# both header and body must agree. See PROTOCOL-ARCH-VERDICT for the wire
# shape this mirrors.
rpc_modern() { # method -> prints response body
  local method="$1"
  curl -s -m 5 -X POST "http://127.0.0.1:$PORT/mcp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -H "mcp-protocol-version: 2026-07-28" \
    -H "mcp-method: $method" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}"
}

call_echo_tool() {
  MCP_PROTOCOL_VERSION="2025-06-18" rpc "tools/call" \
    "{\"name\":\"gateway_invoke\",\"arguments\":{\"server\":\"$BACKEND_NAME\",\"tool\":\"echo\",\"arguments\":{\"text\":\"hello-351\"}}}"
}

echo "-- phase 1: baseline on 3.5.1 --"
start_gateway "$BIN_351" "phase1-351-baseline"
INIT_351="$(MCP_PROTOCOL_VERSION="2025-06-18" rpc "initialize" '{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"rehearsal","version":"1"}}')"
echo "$INIT_351" > "$LOG_DIR/phase1-initialize.json"
if echo "$INIT_351" | python3 -c 'import json,sys; d=json.load(sys.stdin); exit(0 if "result" in d else 1)'; then
  record "PHASE1.BASELINE_INITIALIZE" "PASS" "3.5.1 initialize succeeded"
else
  record "PHASE1.BASELINE_INITIALIZE" "FAIL" "3.5.1 initialize did not return a result: $INIT_351"
fi

ECHO_351="$(call_echo_tool)"
echo "$ECHO_351" > "$LOG_DIR/phase1-echo-call.json"
if echo "$ECHO_351" | python3 -c 'import json,sys; d=json.load(sys.stdin); r=json.dumps(d); exit(0 if "rehearsal-echo: hello-351" in r else 1)'; then
  record "PHASE1.ACTIVE_CALLER_BASELINE" "PASS" "API key invoked mounted backend tool through gateway_invoke on 3.5.1"
else
  record "PHASE1.ACTIVE_CALLER_BASELINE" "FAIL" "gateway_invoke did not return the expected echo payload: $ECHO_351"
fi
stop_gateway "phase1-351-baseline"

STAMP_AFTER_351="$(cat "$STAMP_PATH" 2>/dev/null || echo '<missing>')"
if [[ "$STAMP_AFTER_351" == "3.5.1" ]]; then
  record "PHASE1.STAMP_WRITTEN" "PASS" "version.stamp == 3.5.1 after fresh-install run"
else
  record "PHASE1.STAMP_WRITTEN" "FAIL" "version.stamp == '$STAMP_AFTER_351', expected 3.5.1"
fi

echo "-- phase 2: upgrade 3.5.1 -> 4.0.0, same data dir --"
UPGRADE_OUT="$(HOME="$HOME_DIR" "$BIN_400" upgrade --data-dir "$DATA_DIR" 2>"$LOG_DIR/phase2-upgrade.stderr.log")"
UPGRADE_EXIT=$?
echo "$UPGRADE_OUT" > "$LOG_DIR/phase2-upgrade.stdout.log"
STAMP_AFTER_UPGRADE="$(cat "$STAMP_PATH" 2>/dev/null || echo '<missing>')"
if [[ "$UPGRADE_EXIT" -eq 0 && "$STAMP_AFTER_UPGRADE" == "$VERSION_400" ]]; then
  record "PHASE2.STAMP_ADVANCED" "PASS" "upgrade exited 0, stamp 3.5.1 -> $VERSION_400"
else
  record "PHASE2.STAMP_ADVANCED" "FAIL" "exit=$UPGRADE_EXIT stamp='$STAMP_AFTER_UPGRADE'"
fi

CONFIG_SHA_AFTER_UPGRADE="$(shasum -a 256 "$CONFIG_PATH" | awk '{print $1}')"
if [[ "$CONFIG_SHA_AFTER_UPGRADE" == "$CONFIG_SHA_BEFORE" ]]; then
  record "PHASE2.CONFIG_PRESERVED" "PASS" "gateway.yaml sha256 unchanged across upgrade ($CONFIG_SHA_BEFORE)"
else
  record "PHASE2.CONFIG_PRESERVED" "FAIL" "gateway.yaml sha256 changed: before=$CONFIG_SHA_BEFORE after=$CONFIG_SHA_AFTER_UPGRADE"
fi

TOKEN_SHA_AFTER_UPGRADE="$(shasum -a 256 "$TOKEN_FILE" 2>/dev/null | awk '{print $1}' || echo '<missing>')"
if [[ "$TOKEN_SHA_AFTER_UPGRADE" == "$TOKEN_SHA_BEFORE" ]]; then
  record "PHASE2.CREDENTIALS_PRESERVED" "PASS" "OAuth token file byte-identical across upgrade ($TOKEN_SHA_BEFORE)"
else
  record "PHASE2.CREDENTIALS_PRESERVED" "FAIL" "token file sha changed or missing: before=$TOKEN_SHA_BEFORE after=$TOKEN_SHA_AFTER_UPGRADE"
fi

if python3 -c "
import yaml, sys
before = open('$CONFIG_PATH').read()
d = yaml.safe_load(before)
keys = d.get('auth', {}).get('api_keys', [])
backends = d.get('backends', {})
ok = (
    len(keys) == 1 and keys[0]['key'] == '$API_KEY' and keys[0]['backends'] == ['$BACKEND_NAME']
    and '$BACKEND_NAME' in backends and backends['$BACKEND_NAME']['enabled'] is True
)
sys.exit(0 if ok else 1)
"; then
  record "PHASE2.PERMISSIONS_AND_MOUNTS_PRESERVED" "PASS" "api_keys[0] scoping and backend mount both intact post-upgrade"
else
  record "PHASE2.PERMISSIONS_AND_MOUNTS_PRESERVED" "FAIL" "post-upgrade gateway.yaml no longer parses to the expected api_key/backend shape"
fi

echo "-- phase 2a: migrate the API key to its digest (UPGRADING-4.0 item 41) --"
# 4.0 refuses a plaintext auth.api_keys[].key at load. The documented step:
# hash the SAME key with hash-key and store it as key_sha256. The 3.x config is
# kept for the rollback in phase 4, since 3.x cannot read key_sha256.
cp "$CONFIG_PATH" "$CONFIG_PATH.3x"
KEY_DIGEST="$(printf %s "$API_KEY" | "$BIN_400" hash-key 2>"$LOG_DIR/phase2a-hash-key.stderr.log")"
python3 - "$CONFIG_PATH" "$KEY_DIGEST" <<'PY'
import sys, yaml
path, digest = sys.argv[1], sys.argv[2]
with open(path) as f:
    d = yaml.safe_load(f)
for key in d["auth"]["api_keys"]:
    key.pop("key")
    key["key_sha256"] = digest
with open(path, "w") as f:
    yaml.safe_dump(d, f, sort_keys=False)
PY
if printf %s "$API_KEY" | "$BIN_400" hash-key --verify "$KEY_DIGEST" 2>/dev/null \
  && ! grep -q "$API_KEY" "$CONFIG_PATH"; then
  record "PHASE2.API_KEY_MIGRATED_TO_DIGEST" "PASS" "key_sha256 verifies against the same key; the plaintext is gone from gateway.yaml"
else
  record "PHASE2.API_KEY_MIGRATED_TO_DIGEST" "FAIL" "hash-key migration did not produce a verifying digest, or the plaintext key is still in gateway.yaml"
fi

echo "-- phase 2a': enable the audit log (UPGRADING-4.0 item 43) --"
# 4.0 refuses an auth-enabled config without security.transparency_log at
# load. The documented step: turn the log on with a writable path. The 3.x
# copy taken above stays without it for the rollback.
AUDIT_LOG="$DATA_DIR/audit/transparency.jsonl"
mkdir -p "$(dirname "$AUDIT_LOG")"
python3 - "$CONFIG_PATH" "$AUDIT_LOG" <<'PY'
import sys, yaml
path, log = sys.argv[1], sys.argv[2]
with open(path) as f:
    d = yaml.safe_load(f)
d.setdefault("security", {})["transparency_log"] = {"enabled": True, "path": log}
with open(path, "w") as f:
    yaml.safe_dump(d, f, sort_keys=False)
PY

echo "-- phase 2b: active caller on 4.0.0 (modern-off default: true) --"
start_gateway "$BIN_400" "phase2-400-post-upgrade"
INIT_400="$(rpc_modern "initialize")"
echo "$INIT_400" > "$LOG_DIR/phase2-initialize-modern.json"
if echo "$INIT_400" | python3 -c 'import json,sys; d=json.load(sys.stdin); exit(0 if "result" in d else 1)'; then
  record "PHASE2.MODERN_INITIALIZE_ON" "PASS" "2026-07-28 initialize accepted with modern_protocol default (true)"
else
  record "PHASE2.MODERN_INITIALIZE_ON" "FAIL" "2026-07-28 initialize refused while modern_protocol should default true: $INIT_400"
fi

DISCOVER_400="$(rpc_modern "server/discover")"
echo "$DISCOVER_400" > "$LOG_DIR/phase2-discover-modern.json"
if echo "$DISCOVER_400" | python3 -c 'import json,sys; d=json.load(sys.stdin); exit(0 if "2026-07-28" in json.dumps(d) else 1)'; then
  record "PHASE2.MODERN_DISCOVER_ADVERTISES" "PASS" "server/discover advertises 2026-07-28 with modern on"
else
  record "PHASE2.MODERN_DISCOVER_ADVERTISES" "FAIL" "server/discover did not mention 2026-07-28: $DISCOVER_400"
fi

ECHO_400="$(call_echo_tool)"
echo "$ECHO_400" > "$LOG_DIR/phase2-echo-call.json"
if echo "$ECHO_400" | python3 -c 'import json,sys; d=json.load(sys.stdin); r=json.dumps(d); exit(0 if "rehearsal-echo: hello-351" in r else 1)'; then
  record "PHASE2.ACTIVE_CALLER_POST_UPGRADE" "PASS" "same API key invoked same mounted tool successfully on 4.0.0"
else
  record "PHASE2.ACTIVE_CALLER_POST_UPGRADE" "FAIL" "gateway_invoke failed post-upgrade: $ECHO_400"
fi
stop_gateway "phase2-400-post-upgrade"
# A parsed record, not a byte pattern: schema_version 2 with an `ok` outcome
# is the echo call succeeding on 4.0 and being audited.
if python3 - "$AUDIT_LOG" <<'PY'
import json, sys
try:
    rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
except (OSError, ValueError):
    sys.exit(1)
sys.exit(0 if any(r.get("schema_version") == 2 and r.get("outcome") == "ok" for r in rows) else 1)
PY
then
  record "PHASE2.AUDIT_LOG_WRITTEN" "PASS" "the tool call wrote a schema_version 2, outcome ok record to $AUDIT_LOG"
else
  record "PHASE2.AUDIT_LOG_WRITTEN" "FAIL" "no schema_version 2 record with outcome ok in $AUDIT_LOG"
fi

echo "-- phase 3: modern-off --"
cp "$CONFIG_PATH" "$CONFIG_PATH.pre-modern-off"
python3 - "$CONFIG_PATH" <<'PY'
import sys, yaml
path = sys.argv[1]
with open(path) as f:
    d = yaml.safe_load(f)
d.setdefault("server", {})["modern_protocol"] = False
with open(path, "w") as f:
    yaml.safe_dump(d, f, sort_keys=False)
PY
start_gateway "$BIN_400" "phase3-400-modern-off"
INIT_OFF="$(rpc_modern "initialize")"
echo "$INIT_OFF" > "$LOG_DIR/phase3-initialize-modern-off.json"
# Assert the specific era-refusal code (-32022, unsupported protocol version),
# not just "error" in d -- a well-formed request refused for the wrong reason
# (e.g. -32602 malformed-metadata) would satisfy the weaker check without
# proving server.modern_protocol: false is what caused the refusal.
if echo "$INIT_OFF" | python3 -c 'import json,sys; d=json.load(sys.stdin); exit(0 if d.get("error",{}).get("code") == -32022 else 1)'; then
  record "PHASE3.MODERN_OFF_INITIALIZE_REFUSED" "PASS" "2026-07-28 initialize refused with -32022 (unsupported protocol version) once server.modern_protocol: false"
else
  record "PHASE3.MODERN_OFF_INITIALIZE_REFUSED" "FAIL" "2026-07-28 initialize did not get the expected -32022 era-refusal with modern_protocol: false: $INIT_OFF"
fi

# Legacy (2025-06-18) shape deliberately, not rpc_modern: a modern-shaped
# request never reaches server/discover's handler when modern_protocol is
# off (the era gate refuses it before dispatch -- see
# PHASE3.MODERN_OFF_INITIALIZE_REFUSED above, which already covers that
# path). This call is the one that actually exercises
# discover_document(modern_enabled=false) and proves *that* function hides
# 2026-07-28, which is what this check is named for.
DISCOVER_OFF="$(MCP_PROTOCOL_VERSION="2025-06-18" rpc "server/discover" '{}')"
echo "$DISCOVER_OFF" > "$LOG_DIR/phase3-discover-modern-off.json"
if echo "$DISCOVER_OFF" | python3 -c '
import json, sys
d = json.load(sys.stdin)
# Do not string-match the whole payload: an unsupported-version error echoes
# the *rejected* "2026-07-28" back in its message, which is not advertising
# it. What "advertised" means is a supportedVersions list, on either the
# success path (result.supportedVersions) or the refusal path
# (error.data.supportedVersions) -- check only that.
supported = (d.get("result") or d.get("error", {}).get("data") or {}).get(
    "supportedVersions", []
)
sys.exit(0 if "2026-07-28" not in supported else 1)
'; then
  record "PHASE3.MODERN_OFF_DISCOVER_HIDES" "PASS" "server/discover no longer advertises 2026-07-28"
else
  record "PHASE3.MODERN_OFF_DISCOVER_HIDES" "FAIL" "server/discover still advertises 2026-07-28: $DISCOVER_OFF"
fi
stop_gateway "phase3-400-modern-off"
cp "$CONFIG_PATH.pre-modern-off" "$CONFIG_PATH"
rm -f "$CONFIG_PATH.pre-modern-off"

echo "-- phase 4: rollback to 3.5.1 against the 4.0.0-stamped data dir --"
# 3.x reads `key`, not key_sha256: a rollback restores the kept 3.x config.
cp "$CONFIG_PATH.3x" "$CONFIG_PATH"
CONFIG_SHA_BEFORE_ROLLBACK="$(shasum -a 256 "$CONFIG_PATH" | awk '{print $1}')"
TOKEN_SHA_BEFORE_ROLLBACK="$(shasum -a 256 "$TOKEN_FILE" | awk '{print $1}')"
start_gateway "$BIN_351" "phase4-351-rollback"
STAMP_AFTER_ROLLBACK="$(cat "$STAMP_PATH" 2>/dev/null || echo '<missing>')"
ROLLBACK_WARNED="$(rg -c 'Downgrade detected' "$LOG_DIR/phase4-351-rollback.stderr.log" 2>/dev/null || echo 0)"
if [[ "$STAMP_AFTER_ROLLBACK" == "$VERSION_400" ]]; then
  record "PHASE4.STAMP_UNCHANGED" "PASS" "stamp still $VERSION_400 after starting the 3.5.1 binary (installed.cmp(current)==Greater leaves the stamp alone)"
else
  record "PHASE4.STAMP_UNCHANGED" "FAIL" "stamp changed to '$STAMP_AFTER_ROLLBACK' when it should stay $VERSION_400"
fi
if [[ "$ROLLBACK_WARNED" != "0" ]]; then
  record "PHASE4.DOWNGRADE_WARNING_LOGGED" "PASS" "'Downgrade detected' warning present in 3.5.1 stderr"
else
  record "PHASE4.DOWNGRADE_WARNING_LOGGED" "FAIL" "no downgrade warning found in $LOG_DIR/phase4-351-rollback.stderr.log"
fi

INIT_ROLLBACK="$(MCP_PROTOCOL_VERSION="2025-06-18" rpc "initialize" '{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"rehearsal","version":"1"}}')"
echo "$INIT_ROLLBACK" > "$LOG_DIR/phase4-initialize.json"
if echo "$INIT_ROLLBACK" | python3 -c 'import json,sys; d=json.load(sys.stdin); exit(0 if "result" in d else 1)'; then
  record "PHASE4.GATEWAY_STARTS_NORMALLY" "PASS" "rolled-back 3.5.1 gateway answers initialize"
else
  record "PHASE4.GATEWAY_STARTS_NORMALLY" "FAIL" "rolled-back gateway did not answer initialize: $INIT_ROLLBACK"
fi

ECHO_ROLLBACK="$(call_echo_tool)"
echo "$ECHO_ROLLBACK" > "$LOG_DIR/phase4-echo-call.json"
if echo "$ECHO_ROLLBACK" | python3 -c 'import json,sys; d=json.load(sys.stdin); r=json.dumps(d); exit(0 if "rehearsal-echo: hello-351" in r else 1)'; then
  record "PHASE4.ACTIVE_CALLER_POST_ROLLBACK" "PASS" "same API key invoked same mounted tool successfully after rollback"
else
  record "PHASE4.ACTIVE_CALLER_POST_ROLLBACK" "FAIL" "gateway_invoke failed after rollback: $ECHO_ROLLBACK"
fi
stop_gateway "phase4-351-rollback"

CONFIG_SHA_AFTER_ROLLBACK="$(shasum -a 256 "$CONFIG_PATH" | awk '{print $1}')"
TOKEN_SHA_AFTER_ROLLBACK="$(shasum -a 256 "$TOKEN_FILE" | awk '{print $1}')"
if [[ "$CONFIG_SHA_AFTER_ROLLBACK" == "$CONFIG_SHA_BEFORE_ROLLBACK" && "$TOKEN_SHA_AFTER_ROLLBACK" == "$TOKEN_SHA_BEFORE_ROLLBACK" ]]; then
  record "PHASE4.CONFIG_AND_CREDENTIALS_STILL_INTACT" "PASS" "config and token sha256 unchanged by running the rollback"
else
  record "PHASE4.CONFIG_AND_CREDENTIALS_STILL_INTACT" "FAIL" "config or token changed: config before=$CONFIG_SHA_BEFORE_ROLLBACK after=$CONFIG_SHA_AFTER_ROLLBACK; token before=$TOKEN_SHA_BEFORE_ROLLBACK after=$TOKEN_SHA_AFTER_ROLLBACK"
fi

echo "== done. Results: $RESULTS_JSON =="
echo "Logs: $LOG_DIR"
FAILED=0
for r in "${RESULTS[@]}"; do
  [[ "$r" == *'"status":"PASS"'* ]] || FAILED=$((FAILED + 1))
done
echo "${#RESULTS[@]} checks, $FAILED failed"
if (( FAILED > 0 )); then
  exit 1
fi
