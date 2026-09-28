#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
set -euo pipefail

# Clean first-run smoke for MIK-6552.
# Creates a disposable HOME/workdir, generates the local profile, starts the
# gateway, and proves one routed zero-key capability call through gateway_invoke.
# The routed call goes to a loopback fixture server, never the public internet,
# so a third-party outage cannot turn this smoke red (#1543).

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
fixture_pid=""
cleanup() {
  for pid in "$server_pid" "$fixture_pid"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT

start_epoch="$(date +%s)"

(
  cd "$work"
  HOME="$home" "$bin" init --profile local --output gateway.yaml >/dev/null
)

# The fixture server picks its own port and writes it once it is listening.
# The file is named for this run, so one left in a reused MCP_GATEWAY_SMOKE_DIR
# cannot stand in for this server's.
port_file="$tmp/fixture.$$.port"
python3 "$repo_root/scripts/dev/smoke_fixture_server.py" "$port_file" &
fixture_pid="$!"
for _ in $(seq 1 50); do
  [[ -s "$port_file" ]] && break
  kill -0 "$fixture_pid" 2>/dev/null || break
  sleep 0.1
done
if [[ ! -s "$port_file" ]]; then
  echo "smoke fixture server did not start (scripts/dev/smoke_fixture_server.py)" >&2
  exit 1
fi
fixture_port="$(cat "$port_file")"

"$repo_root/scripts/dev/smoke-fixture-capability.sh" "$work"

(
  cd "$work"
  HOME="$home" HTTP_PROXY="http://127.0.0.1:$fixture_port" NO_PROXY="" \
    "$bin" --config gateway.yaml --host 127.0.0.1 --port "$port" \
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

# /health answers 200 only once the startup capability scan has finished
# (MIK-7268), so the loop above already waits for the catalogue. This check
# still confirms the bundled sample and the fixture the smoke invokes are in it.
admin_token="$(sed -n 's/^ *bearer_token: *"\(.*\)"/\1/p' "$work/gateway.yaml" | head -1)"
[[ -n "$admin_token" ]] || { echo "could not read admin token from gateway.yaml" >&2; exit 1; }
capabilities_ready=""
for _ in $(seq 1 100); do
  if curl -fsS -H "Authorization: Bearer $admin_token" "$health_url" 2>/dev/null \
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
  sleep 0.1
done
if [ -z "$capabilities_ready" ]; then
  echo "capability backend never exposed weather_current and first_run_fixture" >&2
  tail -40 "$tmp/gateway.log" >&2 || true
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

curl -fsS \
  -H "Content-Type: application/json" \
  --data-binary "@$tmp/invoke.json" \
  "$mcp_url" >"$tmp/response.json"

if ! python3 "$repo_root/scripts/dev/assert_capability_response.py" "$tmp/response.json" \
  --expect-temperature 21.25; then
  tail -40 "$tmp/gateway.log" >&2 || true
  exit 1
fi

elapsed="$(( $(date +%s) - start_epoch ))"
if (( elapsed > max_seconds )); then
  echo "first-run smoke exceeded ${max_seconds}s: ${elapsed}s" >&2
  echo "workdir: $tmp" >&2
  exit 1
fi

echo "first-run smoke passed in ${elapsed}s"
echo "workdir: $tmp"
