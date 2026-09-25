#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# NFR.DEMO.1 scenario 1 -- mixed-era interaction.
#
# One gateway build, two backends of different protocol eras mounted side by
# side. The recording shows the gateway's own era fields classifying each peer
# from a probe, and the same kind of tool call succeeding through both.
#
# A broken build shows era_source=assumed / era_evidence=never_probed on a
# backend that WAS probed (the unprobed default leaking into a probed backend),
# or the modern revision echoed to the legacy peer.
#
# Usage: BIN=/path/to/mcp-gateway bash scripts/release/demo/1-mixed-era.sh
SCENARIO_ID="1-mixed-era"
# shellcheck source=scripts/release/demo/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

PEER="$REPO_ROOT/scripts/release/demo/fixtures/demo_era_peer.py"
MODERN_VERSION="2026-07-28"
LEGACY_VERSION="2025-06-18"

echo "== NFR.DEMO.1 scenario 1: mixed-era interaction =="
echo "gateway:        $("$BIN" --version)"
echo "modern peer:    protocolVersion $MODERN_VERSION, server/discover names a modern revision"
echo "legacy peer:    protocolVersion $LEGACY_VERSION, server/discover names none"
echo "run dir:        $RUN_DIR"

cat > "$CONFIG_PATH" <<YAML
server:
  host: "127.0.0.1"
  port: $PORT

# 4.0 refuses auth without an audit log (UPGRADING-4.0 item 43).
security:
  transparency_log:
    enabled: true
    path: "$RUN_DIR/audit/transparency.jsonl"

auth:
  enabled: true
  single_user: true
  api_keys:
    - key_sha256: "$(printf %s "$API_KEY" | "$BIN" hash-key)"
      name: "Demo Client"
      rate_limit: 0
      backends: ["modern_peer", "legacy_peer"]
      admin: true

meta_mcp:
  enabled: true

backends:
  modern_peer:
    command: "python3 $PEER modern_peer $MODERN_VERSION modern"
    description: "NFR.DEMO.1 scenario 1 modern-era peer"
    enabled: true
  legacy_peer:
    command: "python3 $PEER legacy_peer $LEGACY_VERSION not_modern"
    description: "NFR.DEMO.1 scenario 1 legacy-era peer"
    enabled: true
YAML

start_gateway scenario1 || exit 1

call_through() { # backend tool
  rpc "tools/call" \
    "{\"name\":\"gateway_invoke\",\"arguments\":{\"server\":\"$1\",\"tool\":\"$2\",\"arguments\":{\"text\":\"mixed-era\"}}}" \
    | meta_payload
}

echo
echo "-- the same call through both eras, from one client --"
# Also the warm-up: backends start lazily, and the era probe runs on the start
# path (src/backend/lifecycle.rs:322, resolve_era_after_start). Reading the era
# fields before any backend has started reports never_probed, which is the
# unprobed default and not a classification.
MODERN_CALL="$(call_through modern_peer modern_peer_ping)"
LEGACY_CALL="$(call_through legacy_peer legacy_peer_ping)"
echo "modern_peer -> $MODERN_CALL"
echo "legacy_peer -> $LEGACY_CALL"

contains() { case "$2" in *"$1"*) echo "$1 present";; *) echo "absent: $2";; esac; }
record "S1.MODERN_CALL_SUCCEEDS" \
  "modern_peer answered: mixed-era present" \
  "$(contains "modern_peer answered: mixed-era" "$MODERN_CALL")"
record "S1.LEGACY_CALL_SUCCEEDS" \
  "legacy_peer answered: mixed-era present" \
  "$(contains "legacy_peer answered: mixed-era" "$LEGACY_CALL")"

echo
echo "-- the gateway's own era fields, read through gateway_list_servers --"
SERVERS="$(rpc "tools/call" '{"name":"gateway_list_servers","arguments":{}}' | meta_payload)"
echo "$SERVERS" | python3 -m json.tool 2>/dev/null | head -60

era_field() { # backend field
  printf '%s' "$SERVERS" | python3 -c '
import json, sys
payload = json.loads(sys.stdin.read() or "{}")
for s in payload.get("servers", []):
    if s.get("name") == sys.argv[1]:
        print(s.get(sys.argv[2], "<absent>"))
        break
else:
    print("<no such backend>")
' "$1" "$2"
}

echo
record "S1.MODERN_ERA" "modern" "$(era_field modern_peer era)"
record "S1.MODERN_ERA_SOURCE" "probed" "$(era_field modern_peer era_source)"
record "S1.MODERN_ERA_EVIDENCE" "discover_modern" "$(era_field modern_peer era_evidence)"
record "S1.LEGACY_ERA" "legacy" "$(era_field legacy_peer era)"
record "S1.LEGACY_ERA_SOURCE" "probed" "$(era_field legacy_peer era_source)"
record "S1.LEGACY_ERA_EVIDENCE" "discover_not_modern" "$(era_field legacy_peer era_evidence)"

echo
echo "-- negotiation: the legacy client must not be answered in a modern revision --"
NEGOTIATED="$(MCP_PROTOCOL_VERSION="$LEGACY_VERSION" rpc "initialize" \
  "{\"protocolVersion\":\"$LEGACY_VERSION\",\"capabilities\":{},\"clientInfo\":{\"name\":\"legacy-client\",\"version\":\"1\"}}" \
  | python3 -c 'import json,sys; print((json.loads(sys.stdin.read() or "{}").get("result") or {}).get("protocolVersion","<absent>"))')"
echo "legacy client negotiated: $NEGOTIATED"
record "S1.NEGOTIATED_VERSION_FOR_LEGACY_CLIENT" "$LEGACY_VERSION" "$NEGOTIATED"

echo
echo "results: $RESULTS_JSON"
echo "transcript: $TRANSCRIPT"
