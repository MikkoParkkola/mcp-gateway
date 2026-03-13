# MCP Gateway — HTTP Load Tests

Two complementary tools cover different needs:

| Tool | File | Purpose |
|------|------|---------|
| k6   | `k6_gateway.js`  | Multi-scenario load testing with thresholds, custom metrics, and CI integration |
| wrk  | `wrk_basic.lua`  | Fast single-command throughput baseline |

## Prerequisites

### k6

```bash
# macOS
brew install k6

# Linux
sudo gpg --no-default-keyring --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
  --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] https://dl.k6.io/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/k6.list
sudo apt-get update && sudo apt-get install k6

# Docker (no installation needed)
docker run --rm -i grafana/k6 run - < tests/load/k6_gateway.js
```

### wrk

```bash
brew install wrk          # macOS
sudo apt-get install wrk  # Debian/Ubuntu
```

## Running the Gateway

Start a local gateway with at least one backend registered so `tools/list`
returns results:

```bash
cargo run -- serve --config mcp-gateway.yaml
# or
./mcp-gateway serve
```

The default listen address is `http://127.0.0.1:39400`.

## k6 Scenarios

All scenarios run against `http://127.0.0.1:39400` by default.

### Smoke (1 VU, 10 s) — sanity check

```bash
cd tests/load
k6 run k6_gateway.js
```

Verifies all endpoints are reachable and return valid JSON-RPC responses.
Run this before every deployment.

### Load (50 VU, 60 s) — steady-state production

```bash
k6 run -e SCENARIO=load k6_gateway.js
```

Ramps to 50 virtual users over 10 s, holds for 40 s, ramps back down.
Validates the p95 < 500 ms SLO under normal concurrency.

### Stress (200 VU, 120 s) — find the ceiling

```bash
k6 run -e SCENARIO=stress k6_gateway.js
```

Ramps through 50 → 100 → 200 VUs in stages. Identifies where latency
climbs above thresholds or error rate breaks the 1 % budget.

### Spike (0 → 300 VU burst)

```bash
k6 run -e SCENARIO=spike k6_gateway.js
```

Simulates a sudden traffic burst from zero to 300 VUs in 10 s, holds for
20 s, then drops back to zero. Tests how the gateway handles cold bursts
(connection establishment, queueing, circuit-breaker behaviour).

### Custom base URL and authentication

```bash
k6 run \
  -e BASE_URL=http://10.0.1.50:39400 \
  -e API_KEY=my-bearer-token \
  -e SCENARIO=load \
  k6_gateway.js
```

`API_KEY` is sent as `Authorization: Bearer <value>`. Leave it unset for
open (unauthenticated) gateways.

## k6 Thresholds

The script fails the run (non-zero exit code) if any of these are violated:

| Metric | Threshold |
|--------|-----------|
| `http_error_rate` | < 1 % |
| `mcp_initialize_latency` p95 | < 500 ms |
| `mcp_tools_list_latency` p95 | < 500 ms |
| `mcp_tools_call_latency` p95 | < 500 ms |
| `health_latency` p95 | < 100 ms |
| `dashboard_latency` p95 | < 300 ms |
| `ui_status_latency` p95 | < 300 ms |
| `http_req_duration` p95 / p99 | < 500 ms / < 2 000 ms |
| `checks` pass rate | > 99 % |

## Interpreting k6 Results

After each run k6 prints a summary table. Key columns:

- **avg / p(90) / p(95) / p(99)** — latency percentiles in milliseconds
- **rate** — requests per second
- **✓ / ✗** — passed / failed check counts

Custom per-endpoint Trend metrics (`mcp_initialize_latency`, etc.) let you
identify which specific operation is slow rather than aggregating everything
into a single `http_req_duration` bucket.

A run exits with code 0 only if all thresholds pass.

## wrk Throughput Baseline

```bash
# 4 threads, 50 connections, 30 seconds
wrk -t4 -c50 -d30s -s tests/load/wrk_basic.lua http://127.0.0.1:39400

# 8 threads, 200 connections, 60 seconds, with authentication
wrk -t8 -c200 -d60s -s tests/load/wrk_basic.lua http://127.0.0.1:39400 -- my-bearer-token
```

The Lua script cycles through `initialize` (20 %), `tools/list` (60 %),
and `tools/call gateway_status` (20 %) to approximate realistic traffic
distribution.

The `done()` callback prints:

```
=== MCP Gateway wrk Report ===
  Total requests   : 142871
  HTTP errors      : 0 (0.00%)
  RPC errors (est) : 0
  Requests/sec     : 2381.18
  Latency p50      : 18.42 ms
  Latency p90      : 31.07 ms
  Latency p99      : 58.13 ms
  Latency max      : 312.00 ms
==============================
```

wrk does not support thresholds; use it for absolute throughput numbers and
feed those into capacity-planning calculations.

## CI Integration

### GitHub Actions

```yaml
name: Load Test

on:
  workflow_dispatch:
  schedule:
    - cron: "0 4 * * 1"   # weekly on Monday at 04:00 UTC

jobs:
  load-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install k6
        run: |
          sudo gpg --no-default-keyring \
            --keyring /usr/share/keyrings/k6-archive-keyring.gpg \
            --keyserver hkp://keyserver.ubuntu.com:80 \
            --recv-keys C5AD17C747E3415A3642D57D77C6C491D6AC1D69
          echo "deb [signed-by=/usr/share/keyrings/k6-archive-keyring.gpg] \
            https://dl.k6.io/deb stable main" \
            | sudo tee /etc/apt/sources.list.d/k6.list
          sudo apt-get update && sudo apt-get install -y k6

      - name: Start gateway
        run: |
          cargo build --release
          ./target/release/mcp-gateway serve &
          sleep 2   # allow server to bind

      - name: Smoke test
        run: k6 run tests/load/k6_gateway.js
        env:
          BASE_URL: http://127.0.0.1:39400

      - name: Load test
        run: k6 run -e SCENARIO=load tests/load/k6_gateway.js
        env:
          BASE_URL: http://127.0.0.1:39400
```

### Saving results to Grafana Cloud k6

```bash
k6 run \
  -e SCENARIO=load \
  --out cloud \
  tests/load/k6_gateway.js
```

Requires `k6 login cloud --token <token>` first. Results are stored in the
k6 Cloud dashboard with historical trend charts.

### Saving results as JSON

```bash
k6 run --out json=results.json -e SCENARIO=load tests/load/k6_gateway.js
```

Useful for diffing regressions between releases: compare `p(95)` values
across the `mcp_tools_list_latency` metric in the two JSON files.

## Endpoint Reference

| Method | Path | Auth | Notes |
|--------|------|------|-------|
| `GET`  | `/health` | None | Returns `{"status":"healthy","version":"...","backends":{...}}` |
| `POST` | `/mcp` | Optional | Meta-MCP JSON-RPC 2.0 hub |
| `GET`  | `/mcp` | Optional | SSE notification stream (streaming must be enabled) |
| `DELETE` | `/mcp` | Optional | Terminate SSE session (`mcp-session-id` header) |
| `POST` | `/mcp/{name}` | Optional | Direct backend proxy (bypass meta-mcp) |
| `GET`  | `/dashboard` | Optional | Operator HTML dashboard (webui feature) |
| `GET`  | `/ui` | None | Single-page web UI (webui feature) |
| `GET`  | `/ui/api/status` | Admin | JSON gateway health snapshot |
| `GET`  | `/ui/api/tools` | Admin | Flat tool list with search |
| `GET`  | `/ui/api/config` | Admin | Sanitized gateway config |
| `POST` | `/ui/api/reload` | Admin | Trigger config hot-reload |
| `GET`  | `/.well-known/jwks.json` | None | Gateway RSA public key (JWKS) |
| `GET`  | `/api/costs` | Optional | Token cost estimates |
| `GET`/`POST` | `/sse` | — | Returns 410 Gone (deprecated SSE transport) |

The key-server endpoints (`/auth/token`, `/auth/keys/*`) are registered only
when `key_server.enabled = true` in the gateway configuration.
