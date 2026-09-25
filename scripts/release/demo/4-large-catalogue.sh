#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# NFR.DEMO.1 scenario 4 -- large-catalogue discovery.
#
# The gateway is pointed at the repository's own production capability
# catalogue (capabilities/, minus capabilities/examples/) -- no live backend,
# no credentials, the same directory tests/mik_3274_ranking_3_baseline.rs
# loads for ranking regression. The recording shows the three claims design
# section "Scenario 4" asks for, in one frame: the served meta surface stays
# compact while the reachable catalogue is in the hundreds; a keyword search
# surfaces the one relevant tool at rank 1; and a restricted caller's search
# omits a forbidden tool that an unrestricted caller sees at rank 1 --
# authorization before disclosure, ranking before truncation.
#
# A broken build shows the catalogue undercounted against the files on disk (a
# scan that gave up early, or a warm-up race not actually closed), the targeted
# query missing the Gmail-send tool from rank 1 (ranking regressed to
# no-better-than-random), a result set truncated before ranking (visible as a
# returned count above MAX_SEARCH_LIMIT while the candidate pool is larger), or
# the forbidden tool present for the restricted caller.
#
# The restriction is a ROUTING PROFILE, not an API-key denylist: the search
# path filters on profile.tool_allowed (src/gateway/meta_mcp/search.rs:663,
# :726, :755), while an API key's denied_tools is an invocation-time control
# reached only from authorize_tool_call (src/gateway/router/authorization.rs:179)
# and does not filter discovery. A recording that used the key denylist would
# assert a control the discovery path never consults.
#
# Usage: BIN=/path/to/mcp-gateway bash scripts/release/demo/4-large-catalogue.sh
SCENARIO_ID="4-large-catalogue"
# shellcheck source=scripts/release/demo/_common.sh
source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

CAP_ROOT="$REPO_ROOT/capabilities"
CLAIMS="$REPO_ROOT/benchmarks/public_claims.json"
# src/gateway/meta_mcp_helpers.rs:626 -- the ceiling a search response clamps to.
MAX_SEARCH_LIMIT=25
FORBIDDEN_TOOL="gws_gmail_send"

# Real subdirectories only -- capabilities/examples/ holds template files, not
# production capabilities, and the ranking baseline test excludes it the same
# way (tests/mik_3274_ranking_3_baseline.rs:111).
CAP_DIRS_YAML="$(
  for d in "$CAP_ROOT"/*/; do
    name="$(basename "$d")"
    [ "$name" = "examples" ] && continue
    printf '    - "%s"\n' "${d%/}"
  done
)"
CAP_COUNT="$(python3 - "$CAP_ROOT" <<'PY'
import sys, glob, os, yaml
root = sys.argv[1]
n = 0
for f in glob.glob(os.path.join(root, "**", "*.yaml"), recursive=True):
    if f"{os.sep}examples{os.sep}" in f:
        continue
    try:
        doc = yaml.safe_load(open(f))
    except Exception:
        continue
    if isinstance(doc, dict) and doc.get("name"):
        n += 1
print(n)
PY
)"
# Not typed in: the repo's own machine-readable claim for the served surface.
# The shipped claim is a BAND, not a point -- "a compact meta-surface of 9 to 17
# tools" (README.md:21, docs/ARCHITECTURE.md:13, docs/BENCHMARKS.md:65). The
# lower bound is machine-readable; the upper bound is not, so it is spelled
# here with its citation. The point value in public_claims.json
# (meta_tools.readme_benchmark) describes the DEFAULT deployment; this scenario
# configures routing profiles, which add gateway_set_profile, gateway_get_profile
# and gateway_list_profiles, so the band is the claim this config can answer.
META_TOOLS_MIN="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["meta_tools"]["minimum"])' "$CLAIMS")"
META_TOOLS_MAX=17

echo "== NFR.DEMO.1 scenario 4: large-catalogue discovery =="
echo "gateway:     $("$BIN" --version)"
echo "catalogue:   $CAP_ROOT (production capabilities/, examples/ excluded)"
echo "catalogue size counted on disk: $CAP_COUNT capability files"
echo "claimed served meta-tool band: $META_TOOLS_MIN-$META_TOOLS_MAX tools (README.md:21; lower bound from benchmarks/public_claims.json)"
echo "run dir:     $RUN_DIR"

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
      backends: ["catalogue"]
      admin: true

meta_mcp:
  enabled: true

cache:
  enabled: false

# Two profiles, so the restricted caller is restricted by the mechanism the
# search path actually consults. New sessions start on "open"; the restricted
# session switches itself with gateway_set_profile.
default_routing_profile: "open"
routing_profiles:
  open:
    description: "Unrestricted discovery"
  restricted:
    description: "No outbound mail"
    deny_tools: ["$FORBIDDEN_TOOL"]

capabilities:
  enabled: true
  name: "catalogue"
  directories:
$CAP_DIRS_YAML
YAML

start_gateway scenario4 || exit 1

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

# A session id is what carries a routing profile (src/gateway/meta_mcp/mod.rs:1397,
# active_profile). _common.sh's rpc() sends none, so profile-scoped calls need
# their own sender.
rpc_sess() { # session_id method params_json
  curl -s -m 20 -X POST "http://127.0.0.1:$PORT/mcp" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $API_KEY" \
    -H "mcp-protocol-version: ${MCP_PROTOCOL_VERSION:-2025-06-18}" \
    -H "Mcp-Session-Id: $1" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}"
}
search_json() { # session_id -> the search payload for the shared query
  rpc_sess "$1" "tools/call" \
    '{"name":"gateway_search_tools","arguments":{"query":"send an email through gmail","limit":5}}' \
    | meta_payload
}

echo
echo "-- the served meta surface a client sees on tools/list --"
SERVED="$(rpc "tools/list" '{}' | python3 -c '
import json, sys
tools = (json.loads(sys.stdin.read() or "{}").get("result") or {}).get("tools") or []
print(len(tools))
print(",".join(sorted(t.get("name","") for t in tools)))
')"
SERVED_COUNT="$(printf '%s' "$SERVED" | head -1)"
echo "tools/list -> $SERVED_COUNT tools: $(printf '%s' "$SERVED" | tail -1)"
record "S4.SERVED_SURFACE_IS_IN_THE_COMPACT_BAND" "true" \
  "$([ "$SERVED_COUNT" -ge "$META_TOOLS_MIN" ] && [ "$SERVED_COUNT" -le "$META_TOOLS_MAX" ] 2>/dev/null && echo true || echo false)"

echo
echo "-- how big is the catalogue the gateway actually loaded? --"
# The capability directory scan is not finished the instant /health answers
# (same lesson scenario 1 documents for era probes: readiness on the HTTP port
# is not readiness of everything behind it). An earlier draft polled for the
# first NONZERO count and read 18 of 119 -- a partially-filled scan, not a
# product defect. Poll until the count is STABLE instead: three identical
# nonzero reads in a row.
TOTAL=0
STABLE=0
LAST=-1
for _ in $(seq 1 60); do
  LIST="$(rpc "tools/call" '{"name":"gateway_list_tools","arguments":{}}' | meta_payload)"
  TOTAL="$(printf '%s' "$LIST" | jfield total)"
  case "$TOTAL" in ''|*[!0-9]*) TOTAL=0;; esac
  if [ "$TOTAL" -gt 0 ] && [ "$TOTAL" = "$LAST" ]; then
    STABLE=$((STABLE + 1))
    [ "$STABLE" -ge 2 ] && break
  else
    STABLE=0
  fi
  LAST="$TOTAL"
  sleep 0.3
done
echo "gateway_list_tools total -> $TOTAL tools ($STABLE repeat reads), $CAP_COUNT capability files on disk"
record "S4.CATALOGUE_MATCHES_DISK_COUNT" "$CAP_COUNT" "$TOTAL"
# The criterion's own sentence, as one comparison: the surface the client is
# served is far smaller than the catalogue it can still reach through it.
record "S4.SERVED_SURFACE_IS_SMALLER_THAN_THE_CATALOGUE" "true" \
  "$([ "$SERVED_COUNT" -lt "$TOTAL" ] 2>/dev/null && echo true || echo false)"

echo
echo "-- a caller who does not know the catalogue searches for one job --"
SEARCH="$(search_json session-open)"
echo "gateway_search_tools -> $(printf '%s' "$SEARCH" | head -c 400)"
TOP_TOOL="$(printf '%s' "$SEARCH" | jfield matches.0.tool)"
TOP_DESC="$(printf '%s' "$SEARCH" | jfield matches.0.description)"
echo "top match -> $TOP_TOOL"
RELEVANT="$(python3 -c '
import sys
name, desc = sys.argv[1].lower(), sys.argv[2].lower()
print("true" if "gmail" in name and "send" in (name + " " + desc) else "false")
' "$TOP_TOOL" "$TOP_DESC")"
record "S4.SEARCH_SURFACES_THE_RELEVANT_TOOL_FIRST" "true" "$RELEVANT"

echo
echo "-- the same caller asks for far more results than the ceiling allows --"
# Ranking before truncation is only observable when the candidate pool is
# bigger than the ceiling; a query that happens to match fewer tools than
# MAX_SEARCH_LIMIT cannot tell a clamp from a small result set. total_available
# is the PRE-truncation count (src/gateway/meta_mcp/search.rs:409, emitted at
# src/gateway/meta_mcp_helpers.rs:619), so it is asserted alongside.
GREEDY="$(rpc "tools/call" '{"name":"gateway_search_tools","arguments":{"query":"a","limit":9999}}' | meta_payload)"
GREEDY_AVAILABLE="$(printf '%s' "$GREEDY" | jfield total_available)"
GREEDY_COUNT="$(printf '%s' "$GREEDY" | python3 -c 'import json,sys; d=json.loads(sys.stdin.read() or "{}"); print(len(d.get("matches") or []))')"
echo "requested limit 9999, candidates -> $GREEDY_AVAILABLE, matches returned -> $GREEDY_COUNT"
record "S4.SEARCH_CANDIDATES_EXCEED_THE_CEILING" "true" \
  "$([ "$GREEDY_AVAILABLE" -gt "$MAX_SEARCH_LIMIT" ] 2>/dev/null && echo true || echo false)"
record "S4.SEARCH_LIMIT_IS_CLAMPED" "$MAX_SEARCH_LIMIT" "$GREEDY_COUNT"

echo
echo "-- a restricted caller runs the identical query --"
SET_PROFILE="$(rpc_sess session-restricted "tools/call" \
  '{"name":"gateway_set_profile","arguments":{"profile":"restricted"}}' | meta_payload)"
echo "gateway_set_profile -> $(printf '%s' "$SET_PROFILE" | head -c 200)"
RESTRICTED="$(search_json session-restricted)"
echo "restricted matches -> $(printf '%s' "$RESTRICTED" | python3 -c 'import json,sys; print([m.get("tool") for m in (json.loads(sys.stdin.read() or "{}").get("matches") or [])])')"
record "S4.RESTRICTED_CALLER_DOES_NOT_SEE_THE_FORBIDDEN_TOOL" "absent" \
  "$(contains "\"$FORBIDDEN_TOOL\"" "$RESTRICTED")"
# Without this control the row above would pass on an empty result set, which
# proves nothing about authorization (RANKING.2 pins its denial tests the same
# way, src/gateway/meta_mcp/search_ranking_authz_tests.rs:788).
record "S4.OPEN_CALLER_SEES_THE_SAME_TOOL_AT_RANK_1" "$FORBIDDEN_TOOL" "$TOP_TOOL"

echo
echo "results: $RESULTS_JSON"
echo "transcript: $TRANSCRIPT"
