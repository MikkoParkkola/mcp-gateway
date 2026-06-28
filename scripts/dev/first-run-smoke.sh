#!/usr/bin/env bash
set -euo pipefail

# Clean first-run smoke for MIK-6552.
# Creates a disposable HOME/workdir, generates the local profile, starts the
# gateway, and proves one routed zero-key capability call through gateway_invoke.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bin="${MCP_GATEWAY_BIN:-$repo_root/target/debug/mcp-gateway}"
max_seconds="${MCP_GATEWAY_SMOKE_MAX_SECONDS:-300}"

if [[ ! -x "$bin" ]]; then
  (cd "$repo_root" && cargo build --quiet --bin mcp-gateway)
fi

tmp="${MCP_GATEWAY_SMOKE_DIR:-$(mktemp -d)}"
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

server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

start_epoch="$(date +%s)"

(
  cd "$work"
  HOME="$home" "$bin" init --profile local --output gateway.yaml >/dev/null
)

(
  cd "$work"
  HOME="$home" "$bin" --config gateway.yaml --host 127.0.0.1 --port "$port" \
    >"$tmp/gateway.log" 2>&1 &
  echo "$!" >"$tmp/gateway.pid"
)
server_pid="$(cat "$tmp/gateway.pid")"

health_url="http://127.0.0.1:$port/health"
mcp_url="http://127.0.0.1:$port/mcp"

for _ in $(seq 1 100); do
  if curl -fsS "$health_url" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
curl -fsS "$health_url" >/dev/null

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

elapsed="$(( $(date +%s) - start_epoch ))"
if (( elapsed > max_seconds )); then
  echo "first-run smoke exceeded ${max_seconds}s: ${elapsed}s" >&2
  echo "workdir: $tmp" >&2
  exit 1
fi

echo "first-run smoke passed in ${elapsed}s"
echo "workdir: $tmp"
