#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
set -euo pipefail

# Service-template smoke for MIK-6552.
# Validates the checked-in single-node templates and proves the generated local
# profile starts from systemd-like and launchd-like working directories without
# requiring root, Docker, systemd, or launchd.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
bin="${MCP_GATEWAY_BIN:-$repo_root/target/debug/mcp-gateway}"

if [[ ! -x "$bin" ]]; then
  (cd "$repo_root" && cargo build --quiet --bin mcp-gateway)
fi

tmp="${MCP_GATEWAY_SERVICE_SMOKE_DIR:-$(mktemp -d)}"
home="$tmp/home"
source_layout="$tmp/source"
mkdir -p "$home" "$source_layout"

(
  cd "$source_layout"
  HOME="$home" "$bin" init --profile local --output gateway.yaml >/dev/null
)

test -f "$source_layout/gateway.yaml"
test -f "$source_layout/capabilities/knowledge/weather_current.yaml"
test -f "$source_layout/capabilities/knowledge/public_holidays.yaml"

docker_template="$repo_root/deploy/single-node/docker-compose.yaml"
systemd_template="$repo_root/deploy/single-node/mcp-gateway.service"
launchd_template="$repo_root/deploy/single-node/com.mikkoparkkola.mcp-gateway.plist"

grep -Fq '${PWD}/gateway.yaml:/config.yaml:ro' "$docker_template"
grep -Fq '${PWD}/capabilities:/capabilities:ro' "$docker_template"
grep -Fq '["--config", "/config.yaml", "--host", "0.0.0.0", "--port", "39400"]' "$docker_template"
grep -Fq "http://localhost:39400/health" "$docker_template"
if docker compose version >/dev/null 2>&1; then
  (cd "$source_layout" && docker compose -f "$docker_template" config >/dev/null)
else
  echo "WARN: docker compose not available; skipped compose config validation" >&2
fi

grep -Fq "WorkingDirectory=/etc/mcp-gateway" "$systemd_template"
grep -Fq "ExecStart=/usr/local/bin/mcp-gateway --config /etc/mcp-gateway/gateway.yaml --host 127.0.0.1 --port 39400" "$systemd_template"
grep -Fq "ReadOnlyPaths=/etc/mcp-gateway" "$systemd_template"

python3 - "$launchd_template" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as handle:
    plist = plistlib.load(handle)

expected_args = [
    "/usr/local/bin/mcp-gateway",
    "--config",
    "/usr/local/etc/mcp-gateway/gateway.yaml",
    "--host",
    "127.0.0.1",
    "--port",
    "39400",
]
if plist.get("ProgramArguments") != expected_args:
    raise SystemExit("launchd ProgramArguments do not match the documented config path")
if plist.get("WorkingDirectory") != "/usr/local/etc/mcp-gateway":
    raise SystemExit("launchd WorkingDirectory does not match the config directory")
if plist.get("RunAtLoad") is not True or plist.get("KeepAlive") is not True:
    raise SystemExit("launchd template must run at load and keep the gateway alive")
PY

run_layout_smoke() {
  local label="$1"
  local layout_dir="$2"
  local port
  port="$(
    python3 - <<'PY'
import socket

sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
  )"

  (
    cd "$layout_dir"
    HOME="$home" "$bin" --config gateway.yaml --host 127.0.0.1 --port "$port" \
      >"$tmp/$label.log" 2>&1 &
    echo "$!" >"$tmp/$label.pid"
  )

  local pid
  pid="$(cat "$tmp/$label.pid")"
  trap 'kill "$pid" >/dev/null 2>&1 || true' RETURN

  local health_url="http://127.0.0.1:$port/health"
  for _ in $(seq 1 100); do
    if curl -fsS "$health_url" >/dev/null 2>&1; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
      trap - RETURN
      return 0
    fi
    sleep 0.1
  done

  cat "$tmp/$label.log" >&2 || true
  kill "$pid" >/dev/null 2>&1 || true
  wait "$pid" >/dev/null 2>&1 || true
  trap - RETURN
  echo "$label service-layout smoke failed" >&2
  return 1
}

systemd_layout="$tmp/systemd/etc/mcp-gateway"
launchd_layout="$tmp/launchd/usr/local/etc/mcp-gateway"
mkdir -p "$systemd_layout" "$launchd_layout"
cp "$source_layout/gateway.yaml" "$systemd_layout/gateway.yaml"
cp -R "$source_layout/capabilities" "$systemd_layout/capabilities"
cp "$source_layout/gateway.yaml" "$launchd_layout/gateway.yaml"
cp -R "$source_layout/capabilities" "$launchd_layout/capabilities"

run_layout_smoke "systemd" "$systemd_layout"
run_layout_smoke "launchd" "$launchd_layout"

echo "service template smoke passed"
echo "workdir: $tmp"
