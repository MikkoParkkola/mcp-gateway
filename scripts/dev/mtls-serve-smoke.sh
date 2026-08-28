#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# mTLS serve smoke: prove the gateway actually starts and serves over mTLS.
#
# WHY THIS EXISTS. `Gateway::run` bound the listening address unconditionally
# and `serve_tls` then bound the same address again, so EVERY mTLS gateway died
# on "address already in use". The bug was certain, shipped, and invisible:
# nothing in the test suite calls `Gateway::run`, so the whole serve path had no
# coverage at all. A unit test cannot see this — the two binds are in different
# functions and each is correct alone. Only starting the process shows it.
#
# Deliberately narrow: this asserts the process SERVES, not that mTLS is
# correctly enforced. Certificate verification has its own unit tests; what had
# no check was "does it come up".
set -euo pipefail

bin="${1:-./target/debug/mcp-gateway}"
if [[ ! -x "$bin" ]]; then
  echo "usage: $0 [path-to-mcp-gateway]  (default ./target/debug/mcp-gateway)" >&2
  exit 2
fi
bin="$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")"

tmp="$(mktemp -d)"
server_pid=""
cleanup() {
  [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

# A fixed port, not 0. The defect was binding the SAME address twice, and two
# ephemeral binds get two different ports — which would pass while broken.
port=39471

"$bin" tls init-ca --cn "smoke CA" --out "$tmp/tls" >/dev/null
"$bin" tls issue-server --cn localhost --san-dns localhost \
  --ca-cert "$tmp/tls/ca.crt" --ca-key "$tmp/tls/ca.key" --out "$tmp/tls" >/dev/null

cat >"$tmp/gateway.yaml" <<YAML
server:
  host: "127.0.0.1"
  port: $port
auth:
  enabled: true
  bearer_token: "smoke-token"
  public_paths: ["/health", "/mcp"]
mtls:
  enabled: true
  server_cert: "$tmp/tls/server.crt"
  server_key: "$tmp/tls/server.key"
  ca_cert: "$tmp/tls/ca.crt"
  require_client_cert: false
YAML

"$bin" --config "$tmp/gateway.yaml" >"$tmp/gateway.log" 2>&1 &
server_pid=$!

# It either serves or it is gone. Poll the process rather than the port: the
# failure being guarded against is an immediate exit, and a dead process is the
# signal.
for _ in $(seq 1 100); do
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "FAIL: the gateway exited instead of serving over mTLS" >&2
    echo "--- log ---" >&2
    cat "$tmp/gateway.log" >&2
    exit 1
  fi
  if grep -q "mTLS listener starting" "$tmp/gateway.log" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

# Still running after the listener started is the property. A double bind fails
# here, because axum_server::bind returns its error after that log line.
sleep 1
if ! kill -0 "$server_pid" 2>/dev/null; then
  echo "FAIL: the gateway died after starting its mTLS listener" >&2
  echo "--- log ---" >&2
  cat "$tmp/gateway.log" >&2
  exit 1
fi

if grep -qi "address already in use\|AddrInUse" "$tmp/gateway.log"; then
  echo "FAIL: the gateway bound its address twice" >&2
  cat "$tmp/gateway.log" >&2
  exit 1
fi

# Staying up is necessary and not sufficient. The listening socket is handed
# from tokio to axum-server through into_std(), which leaves it NONBLOCKING; a
# socket in the wrong mode can leave a process alive that accepts nothing. Only
# completing a request proves the handover produced a working listener.
code="$(curl -sS --cacert "$tmp/tls/ca.crt" --resolve "localhost:$port:127.0.0.1" \
  -o /dev/null -w '%{http_code}' --max-time 10 \
  "https://localhost:$port/health" 2>"$tmp/curl.err" || true)"
if [[ "$code" != "200" ]]; then
  echo "FAIL: the gateway is up but did not answer over TLS (got '${code:-none}')" >&2
  cat "$tmp/curl.err" >&2
  cat "$tmp/gateway.log" >&2
  exit 1
fi

echo "mTLS serve smoke passed (served HTTP $code over TLS on port $port)"
