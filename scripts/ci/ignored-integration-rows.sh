#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Mikko Parkkola
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# ignored-integration-rows.sh: the #[ignore] rows of tests/integration_tests.rs against a live gateway, run after the
# Linux int-a shard has built both the gateway binary and that test target (so nothing is rebuilt here).
#
# The rows talk to a gateway on 127.0.0.1:39400 and the stats rows need an admin caller. This starts one with an
# admin key made here (random per run, masked, never written to disk: the config names only its digest), waits for
# /readyz, and runs the rows with TESTS_REQUIRE_ALL=1, so a row that cannot reach what it needs fails instead of
# passing as a skip. /readyz, not an open port: the listener binds before the capability scan finishes, and a row
# asking during the scan sees a half-loaded catalogue.
#
# test_invoke_caching stays out: it calls the live Open-Meteo API, and an outside outage must not redden a pull
# request (its #[ignore] reason). Run it by hand against this script's gateway with the same key.
#
# Usage (from the repository root): scripts/ci/ignored-integration-rows.sh
set -euo pipefail

# A fresh home and required mode, as every shard gets them: run again inside shard_tests.py with-home, which sets
# MCP_GATEWAY_TEST_HOME_DIR (so the second pass goes on).
if [ -z "${MCP_GATEWAY_TEST_HOME_DIR:-}" ]; then
  exec python3 scripts/ci/shard_tests.py with-home -- "$0"
fi

# The rows this job owns. A row added, removed or renamed fails the count check until this number and the file agree.
ROWS=4
PORT=39400
GATEWAY=target/debug/mcp-gateway
if [ ! -x "$GATEWAY" ]; then
  echo "::error::$GATEWAY is missing: the int-a shard should have built it"
  exit 1
fi

work=$(mktemp -d)
admin_key=$(openssl rand -hex 32)
echo "::add-mask::$admin_key"
export MCP_GATEWAY_TEST_ADMIN_KEY="$admin_key"
export MCP_GATEWAY_TEST_ADMIN_KEY_SHA256="sha256:$(printf %s "$admin_key" | sha256sum | awk '{print $1}')"

# The digest reaches the gateway through env:, so the key itself is in no file.
cat > "$work/gateway.yaml" <<YAML
server:
  host: 127.0.0.1
  port: $PORT
meta_mcp:
  enabled: true
auth:
  enabled: true
  api_keys:
    - name: ci-admin
      admin: true
      backends: ["*"]
      key_sha256: env:MCP_GATEWAY_TEST_ADMIN_KEY_SHA256
capabilities:
  enabled: true
  name: capabilities
  directories:
    - $PWD/capabilities
YAML
chmod 600 "$work/gateway.yaml"   # 4.0 refuses a config other users can read

"$GATEWAY" --config "$work/gateway.yaml" serve > "$work/gateway.log" 2>&1 &
gateway_pid=$!
trap 'kill "$gateway_pid" 2>/dev/null || true; wait "$gateway_pid" 2>/dev/null || true' EXIT

# Up to 60 s for the capability scan; a gateway that exits stops the wait at once.
deadline=$((SECONDS + 60))
until curl -fsS --max-time 2 -o /dev/null "http://127.0.0.1:$PORT/readyz"; do
  if ! kill -0 "$gateway_pid" 2>/dev/null || [ "$SECONDS" -ge "$deadline" ]; then
    echo "::error::no /readyz 200 from the gateway (exited, or not ready within 60 s)"
    tail -80 "$work/gateway.log"
    exit 1
  fi
  sleep 0.2
done

# --all-features: the shard's own build (shard_tests.py BASE), so this reuses it instead of rebuilding.
TESTS_REQUIRE_ALL=1 cargo test --locked --all-features --test integration_tests -- --ignored --skip test_invoke_caching \
  --test-threads=1 2>&1 | tee "$work/rows.log" || true   # the result line below is the verdict
if ! grep -Eq "^test result: ok\. $ROWS passed; 0 failed; 0 ignored" "$work/rows.log"; then
  echo "::error::expected exactly $ROWS ignored integration rows to pass (see the result line above)"
  echo "=== gateway log tail"
  tail -40 "$work/gateway.log"
  exit 1
fi
