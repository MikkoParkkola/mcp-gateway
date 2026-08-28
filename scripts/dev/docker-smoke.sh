#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
set -euo pipefail

# Container smoke for MIK-6552.
# Builds or reuses an mcp-gateway image, mounts a freshly generated local
# profile, checks /health, and invokes one zero-key capability through the
# containerized gateway.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="${MCP_GATEWAY_DOCKER_IMAGE:-mcp-gateway:smoke}"
build_image="${MCP_GATEWAY_DOCKER_BUILD:-1}"
bin="${MCP_GATEWAY_BIN:-$repo_root/target/debug/mcp-gateway}"

if [[ "$build_image" != "0" ]]; then
  docker build -t "$image" "$repo_root"
fi

if [[ ! -x "$bin" ]]; then
  (cd "$repo_root" && cargo build --quiet --bin mcp-gateway)
fi

tmp="${MCP_GATEWAY_DOCKER_SMOKE_DIR:-$(mktemp -d)}"
work="$tmp/work"
home="$tmp/home"
mkdir -p "$work" "$home"

port="$(
  python3 - <<'PY'
import socket

sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
)"

container="mcp-gateway-smoke-$$"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

(
  cd "$work"
  HOME="$home" "$bin" init --profile local --output gateway.yaml >/dev/null
)

# Mirrors deploy/single-node/docker-compose.yaml, including the reason. A
# container must bind 0.0.0.0 to receive anything, and the init config keeps
# /mcp public so tool calls work — which is a reachable surface needing no
# credential, and the gateway refuses to serve it. The boundary here is the
# publish above: 127.0.0.1 only, so nothing off this host reaches the port.
# Without this the smoke exits instead of proving health and a tool call.
docker run -d \
  --name "$container" \
  -p "127.0.0.1:$port:39400" \
  -e MCP_GATEWAY_SERVER__ALLOW_UNAUTHENTICATED_NETWORK_BIND=true \
  -v "$work/gateway.yaml:/config.yaml:ro" \
  -v "$work/capabilities:/capabilities:ro" \
  "$image" \
  --config /config.yaml --host 0.0.0.0 --port 39400 >/dev/null

health_url="http://127.0.0.1:$port/health"
mcp_url="http://127.0.0.1:$port/mcp"

for _ in $(seq 1 150); do
  if curl -fsS "$health_url" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

if ! curl -fsS "$health_url" >/dev/null; then
  docker logs "$container" >&2 || true
  exit 1
fi

# /health reports "healthy" as soon as the listener binds; capabilities load in
# a background task that deliberately waits for that bind. Invoking on health
# alone races the load and fails with "Not found: 'gateway'". Wait for the
# readiness the admin health view reports — a backend that never loads still
# fails this smoke.
admin_token="$(sed -n 's/^ *bearer_token: *"\(.*\)"/\1/p' "$work/gateway.yaml" | head -1)"
capabilities_ready=""
for _ in $(seq 1 150); do
  if curl -fsS -H "Authorization: Bearer $admin_token" "$health_url" 2>/dev/null \
    | python3 -c 'import json,sys
try:
    b = json.load(sys.stdin).get("capability_backend") or {}
except Exception:
    sys.exit(1)
sys.exit(0 if b.get("capabilities_count", 0) > 0 else 1)'; then
    capabilities_ready="yes"
    break
  fi
  sleep 0.2
done
if [ -z "$capabilities_ready" ]; then
  echo "capability backend never reported a loaded capability" >&2
  docker logs "$container" >&2 || true
  exit 1
fi

cat >"$tmp/invoke.json" <<'JSON'
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "gateway_invoke",
    "arguments": {
      "server": "gateway",
      "tool": "weather_current",
      "arguments": {
        "latitude": 60.1699,
        "longitude": 24.9384
      }
    }
  }
}
JSON

curl -fsS \
  -H "Content-Type: application/json" \
  --data-binary "@$tmp/invoke.json" \
  "$mcp_url" >"$tmp/response.json"

python3 "$repo_root/scripts/dev/assert_capability_response.py" "$tmp/response.json"

echo "docker smoke passed on http://127.0.0.1:$port"
echo "workdir: $tmp"
