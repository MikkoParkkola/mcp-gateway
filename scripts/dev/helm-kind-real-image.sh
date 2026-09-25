#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# The chart runs the real gateway: load a locally built image into kind, install
# the chart with probes on under Pod Security `restricted`, and require Ready
# plus /livez 200, then an MCP `initialize` and `tools/list` answered with a
# JSON-RPC result.
#
# helm-kind-lifecycle.sh drives `pause` and so tests rollout mechanics only. That
# is how the chart shipped from #292 unable to start at all: `serve --host` exits
# 2, a `backends` sequence fails the map-typed config, and the task store under a
# read-only HOME is fatal. Every failure dumps the pod state and the gateway's
# own log, so a red run names the defect rather than a wait timeout.
#
# Usage: helm-kind-real-image.sh <image-ref with a tag>
set -euo pipefail

IMAGE="${1:?usage: helm-kind-real-image.sh <registry/repository:tag>}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART="$ROOT_DIR/deploy/helm/mcp-gateway"
CLUSTER="${MCP_GATEWAY_KIND_CLUSTER:-mcp-gateway-real-image}"
NAMESPACE="${MCP_GATEWAY_HELM_NAMESPACE:-mcp-gateway-real}"
RELEASE="${MCP_GATEWAY_HELM_RELEASE:-gw}"
KIND="${KIND:-kind}"
HELM="${HELM:-helm}"
KUBECTL="${KUBECTL:-kubectl}"
KEEP="${MCP_GATEWAY_KIND_KEEP:-0}"
TIMEOUT="${MCP_GATEWAY_ROLLOUT_TIMEOUT:-180s}"
# The chart's default is credential mode: the Secret below and the MCP requests
# at the end carry the same bearer.
TOKEN="kind-real-image-not-a-real-credential-0123456789"

# ghcr.io/owner/repo:tag -> registry, repository, tag (the chart's three values).
REGISTRY="${IMAGE%%/*}"
rest="${IMAGE#*/}"
REPOSITORY="${rest%:*}"
TAG="${rest##*:}"
[ "$REPOSITORY" != "$rest" ] || { echo "FAIL: $IMAGE has no tag" >&2; exit 1; }

command -v "$KIND" >/dev/null 2>&1
command -v "$HELM" >/dev/null 2>&1
command -v "$KUBECTL" >/dev/null 2>&1

created_cluster=0
pf_pid=""
cleanup() {
  [ -z "$pf_pid" ] || kill "$pf_pid" 2>/dev/null || true
  if [ "$KEEP" != "1" ] && [ "$created_cluster" = "1" ]; then
    "$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

diagnose() {
  echo "== diagnostics ==" >&2
  "$KUBECTL" get pods -n "$NAMESPACE" -o wide >&2 || true
  # Warning events carry the kubelet's own reason (e.g. a non-numeric image
  # user under runAsNonRoot), which a truncated describe can cut off.
  "$KUBECTL" get events -n "$NAMESPACE" --field-selector type=Warning \
    -o custom-columns=REASON:.reason,MESSAGE:.message 2>/dev/null | sort -u | tail -20 >&2 || true
  for pod in $("$KUBECTL" get pods -n "$NAMESPACE" -l "app.kubernetes.io/instance=$RELEASE" \
      -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    echo "-- $pod (previous) --" >&2
    "$KUBECTL" logs -n "$NAMESPACE" "$pod" --previous --tail=50 >&2 2>/dev/null || true
    echo "-- $pod (current) --" >&2
    "$KUBECTL" logs -n "$NAMESPACE" "$pod" --tail=50 >&2 2>/dev/null || true
  done
}

if ! "$KIND" get clusters | grep -qx "$CLUSTER"; then
  "$KIND" create cluster --name "$CLUSTER"
  created_cluster=1
fi
"$KUBECTL" config use-context "kind-$CLUSTER" >/dev/null
"$KIND" load docker-image "$IMAGE" --name "$CLUSTER"

"$KUBECTL" create namespace "$NAMESPACE" --dry-run=client -o yaml | "$KUBECTL" apply -f -
"$KUBECTL" label --overwrite namespace "$NAMESPACE" \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/enforce-version=latest
"$KUBECTL" create secret generic mcp-gateway-auth -n "$NAMESPACE" \
  --from-literal=token="$TOKEN" \
  --dry-run=client -o yaml | "$KUBECTL" apply -f -

echo "== install $IMAGE with probes on =="
if ! "$HELM" upgrade --install "$RELEASE" "$CHART" \
    --namespace "$NAMESPACE" \
    --set image.registry="$REGISTRY" \
    --set image.repository="$REPOSITORY" \
    --set image.tag="$TAG" \
    --set image.pullPolicy=Never \
    --set probes.enabled=true \
    --wait --timeout "$TIMEOUT"; then
  echo "FAIL: the chart's pods never became Ready on the real image" >&2
  diagnose
  exit 1
fi

echo "== /livez answers 200 through the Service =="
svc="$("$KUBECTL" get svc -n "$NAMESPACE" -l "app.kubernetes.io/instance=$RELEASE" \
  -o jsonpath='{.items[0].metadata.name}')"
port="$("$KUBECTL" get svc -n "$NAMESPACE" "$svc" -o jsonpath='{.spec.ports[0].port}')"
"$KUBECTL" port-forward -n "$NAMESPACE" "svc/$svc" "39499:$port" >/dev/null 2>&1 &
pf_pid=$!
code=""
for _ in $(seq 1 30); do
  code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:39499/livez || true)"
  [ "$code" = "200" ] && break
  sleep 1
done
if [ "$code" != "200" ]; then
  echo "FAIL: /livez answered '$code', want 200" >&2
  diagnose
  exit 1
fi

echo "== MCP initialize then tools/list through the Service =="
# Ready and /livez say the process is up, not that it serves MCP. port-forward
# pins one pod, so the session initialize mints is the one tools/list presents.
# Each answer must be a JSON-RPC result for the id sent: an `error` member, a
# 401, or an HTML page all fail, where a bare "contains jsonrpc" would not.
mcp() { # id-or-empty method params_json [session] -> headers, body, HTTP_STATUS=<code>
  local id="$1" method="$2" params="$3" sess="${4:-}" body
  if [ -n "$id" ]; then
    body="{\"jsonrpc\":\"2.0\",\"id\":$id,\"method\":\"$method\",\"params\":$params}"
  else
    body="{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params}"
  fi
  curl -sS --max-time 10 -w '\nHTTP_STATUS=%{http_code}\n' -D - -X POST "http://127.0.0.1:39499/mcp" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    ${sess:+-H "Mcp-Session-Id: $sess"} \
    -d "$body"
}
assert_result() { # id want_key <<<response
  # The response arrives on stdin, not argv: a large body cannot hit ARG_MAX.
  # shellcheck disable=SC2016 # a Python program, not a shell expansion
  python3 -c '
import json, sys
want_id, key, raw = int(sys.argv[1]), sys.argv[2], sys.stdin.read()
status = [l for l in raw.splitlines() if l.startswith("HTTP_STATUS=")]
if status != ["HTTP_STATUS=200"]:
    sys.exit(f"want HTTP 200, got {status}: {raw[:600]!r}")
# Plain JSON after the headers, or SSE framing where it rides a `data:` line.
for line in raw.splitlines():
    line = line[5:].strip() if line.startswith("data:") else line.strip()
    if not line.startswith("{"):
        continue
    try:
        msg = json.loads(line)
    except ValueError:
        continue
    if msg.get("jsonrpc") == "2.0" and msg.get("id") == want_id \
            and "error" not in msg and key in (msg.get("result") or {}):
        sys.exit(0)
sys.exit(f"no JSON-RPC result with id={want_id} carrying {key!r}: {raw[:600]!r}")
' "$1" "$2"
}
init="$(mcp 1 initialize '{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"helm-kind-real-image","version":"0"}}' || true)"
if ! assert_result 1 protocolVersion <<<"$init"; then
  echo "FAIL: initialize did not return a JSON-RPC result" >&2
  diagnose
  exit 1
fi
session="$(tr -d '\r' <<<"$init" | awk -F': ' 'tolower($1)=="mcp-session-id" {print $2; exit}' || true)"
mcp "" notifications/initialized '{}' "$session" >/dev/null || true
tools="$(mcp 2 tools/list '{}' "$session" || true)"
if ! assert_result 2 tools <<<"$tools"; then
  echo "FAIL: tools/list did not return a JSON-RPC result" >&2
  diagnose
  exit 1
fi

echo "helm kind real image passed: $IMAGE Ready, /livez 200, initialize + tools/list answered on $CLUSTER"
