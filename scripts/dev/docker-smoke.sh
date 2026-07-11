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

docker run -d \
  --name "$container" \
  -p "127.0.0.1:$port:39400" \
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

cat >"$tmp/invoke.json" <<'JSON'
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "gateway_invoke",
    "arguments": {
      "server": "capabilities",
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

python3 - "$tmp/response.json" <<'PY'
import json
import sys

payload = json.load(open(sys.argv[1], encoding="utf-8"))
if "error" in payload:
    raise SystemExit(f"JSON-RPC error: {payload['error']}")
content = payload.get("result", {}).get("content", [])
if not content:
    raise SystemExit("missing MCP result content")
text = content[0].get("text")
if not text:
    raise SystemExit("missing MCP text content")
inner = json.loads(text)
if not isinstance(inner, dict):
    raise SystemExit("weather_current returned non-object payload")
PY

echo "docker smoke passed on http://127.0.0.1:$port"
echo "workdir: $tmp"
