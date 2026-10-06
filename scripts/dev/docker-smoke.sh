#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
set -euo pipefail

# Container smoke for MIK-6552.
# Builds or reuses an mcp-gateway image, mounts a freshly generated local
# profile, checks /health, and invokes one zero-key capability through the
# containerized gateway. The routed call goes to a fixture container on a
# private network, reached as the gateway's HTTP proxy, never the public
# internet (#1543).

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
image="${MCP_GATEWAY_DOCKER_IMAGE:-mcp-gateway:smoke}"
build_image="${MCP_GATEWAY_DOCKER_BUILD:-1}"
bin="${MCP_GATEWAY_BIN:-$repo_root/target/debug/mcp-gateway}"
# 1: write the profile with the image itself, so no host build is needed (CI).
init_in_image="${MCP_GATEWAY_INIT_IN_IMAGE:-0}"
fixture_image="${MCP_GATEWAY_FIXTURE_IMAGE:-python:3.13-alpine@sha256:79e7a9b9ff1cbceff819f856fb374477792a5967759d94df266de7b7b4120e6f}"

if [[ "$build_image" != "0" ]]; then
  docker build --target runtime -t "$image" "$repo_root"
fi

if [[ "$init_in_image" != "1" && ! -x "$bin" ]]; then
  (cd "$repo_root" && cargo build --quiet --bin mcp-gateway)
fi

tmp="${MCP_GATEWAY_DOCKER_SMOKE_DIR:-$(mktemp -d)}"
work="$tmp/work"
home="$tmp/home"
mkdir -p "$work" "$home"

container="mcp-gateway-smoke-$$"
fixture="mcp-gateway-smoke-fixture-$$"
network="mcp-gateway-smoke-$$"
cleanup() {
  docker rm -f "$container" "$fixture" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ "$init_in_image" == "1" ]]; then
  docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$work:/work" -w /work \
    "$image" init --profile local --output gateway.yaml >/dev/null
else
  (
    cd "$work"
    HOME="$home" "$bin" init --profile local --output gateway.yaml >/dev/null
  )
fi

# The fixture listens only on this private network; it is not published.
docker network create "$network" >/dev/null
docker run -d --name "$fixture" --network "$network" \
  -v "$repo_root/scripts/dev/smoke_fixture_server.py:/fixture.py:ro" \
  "$fixture_image" python3 /fixture.py /tmp/fixture.port 0.0.0.0 8080 >/dev/null
fixture_up=""
for _ in $(seq 1 50); do
  if docker exec "$fixture" test -s /tmp/fixture.port 2>/dev/null; then
    fixture_up="yes"
    break
  fi
  sleep 0.2
done
if [[ -z "$fixture_up" ]]; then
  echo "smoke fixture container did not start ($fixture_image)" >&2
  docker logs "$fixture" >&2 || true
  exit 1
fi
# The fixture's address on the private network, named as the gateway's
# capability proxy below.
fixture_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$fixture")"
[[ -n "$fixture_ip" ]] || { echo "smoke fixture container has no address" >&2; exit 1; }
"$repo_root/scripts/dev/smoke-fixture-capability.sh" "$work" "http://$fixture_ip:8080"

# Mirrors deploy/single-node/docker-compose.yaml, including the reason. A
# container must bind 0.0.0.0 to receive anything, and the init config keeps
# /mcp public so tool calls work — which is a reachable surface needing no
# credential, and the gateway refuses to serve it. The boundary here is the
# publish above: 127.0.0.1 only, so nothing off this host reaches the port.
# Without this the smoke exits instead of proving health and a tool call.
#
# The config init just wrote is mode 600 and owned by this user, and the
# gateway refuses one other users can read. The image's own UID 1001 cannot
# read it unless this user is 1001, so the container runs as this user, with a
# writable HOME. (A deployment makes a 1001-owned copy instead; see
# docs/DEPLOYMENT.md. A throwaway smoke has no sudo to do that.)
docker run -d \
  --name "$container" \
  --network "$network" \
  --user "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -p "127.0.0.1::39400" \
  -e MCP_GATEWAY_SERVER__ALLOW_UNAUTHENTICATED_NETWORK_BIND=true \
  -e MCP_GATEWAY_SERVER__CLEARTEXT_HTTP=host_local_publish \
  -v "$work/gateway.yaml:/config.yaml:ro" \
  -v "$work/capabilities:/capabilities:ro" \
  "$image" \
  --config /config.yaml --host 0.0.0.0 --port 39400 >/dev/null

# Docker chose the host port, so none was picked and freed for another
# process to take first.
port="$(docker port "$container" 39400/tcp | head -n1)"
port="${port##*:}"
[[ -n "$port" ]] || { echo "no published port for $container" >&2; exit 1; }

health_url="http://127.0.0.1:$port/health"
mcp_url="http://127.0.0.1:$port/mcp"

for _ in $(seq 1 150); do
  if curl -fsS --max-time 10 "$health_url" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

if ! curl -fsS --max-time 10 "$health_url" >/dev/null; then
  docker logs "$container" >&2 || true
  exit 1
fi

# /health reports "healthy" as soon as the listener binds; capabilities load in
# a background task that deliberately waits for that bind. Invoking on health
# alone races the load and fails with "Not found: 'gateway'". Wait for the
# readiness the admin health view reports — a backend that never loads still
# fails this smoke. The product gap making it necessary is MIK-7268.
admin_token="$(sed -n 's/^ *bearer_token: *"\(.*\)"/\1/p' "$work/gateway.yaml" | head -1)"
[[ -n "$admin_token" ]] || { echo "could not read admin token from gateway.yaml" >&2; exit 1; }
capabilities_ready=""
for _ in $(seq 1 150); do
  if curl -fsS --max-time 10 -H "Authorization: Bearer $admin_token" "$health_url" 2>/dev/null \
    | python3 -c 'import json,sys
try:
    b = json.load(sys.stdin).get("capability_backend") or {}
except Exception:
    sys.exit(1)
caps = b.get("capabilities") or []
sys.exit(0 if {"weather_current", "first_run_fixture"} <= set(caps) else 1)'; then
    capabilities_ready="yes"
    break
  fi
  sleep 0.2
done
if [ -z "$capabilities_ready" ]; then
  echo "capability backend never exposed weather_current and first_run_fixture" >&2
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
      "tool": "first_run_fixture",
      "arguments": {
        "latitude": 60.1699,
        "longitude": 24.9384
      }
    }
  }
}
JSON

curl -fsS --max-time 60 \
  -H "Content-Type: application/json" \
  --data-binary "@$tmp/invoke.json" \
  "$mcp_url" >"$tmp/response.json"

if ! python3 "$repo_root/scripts/dev/assert_capability_response.py" "$tmp/response.json" \
  --expect-temperature 21.25; then
  docker logs "$container" 2>&1 | tail -40 >&2 || true
  exit 1
fi

echo "docker smoke passed on http://127.0.0.1:$port"
echo "workdir: $tmp"
