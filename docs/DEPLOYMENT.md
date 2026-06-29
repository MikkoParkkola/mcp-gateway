# Production Deployment Guide

For quick-start and development usage, see the [README](../README.md). For every config option with defaults, see [`examples/gateway-full.yaml`](../examples/gateway-full.yaml).

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **Rust** | 1.88+ (edition 2024) | Latest stable |
| **OS** | Linux (x86_64, aarch64), macOS (ARM64) | Linux for production |
| **Memory** | 64 MB | 256 MB+ (scales with backends) |
| **Disk** | 50 MB (binary + config) | 200 MB (with capabilities) |

The gateway is a single binary with no runtime dependencies beyond libc. Rustls is compiled in. Node.js is only required for stdio backends that use `npx`.

## Building from Source

```bash
git clone https://github.com/MikkoParkkola/mcp-gateway
cd mcp-gateway
cargo build --release
# Binary: target/release/mcp-gateway (~7 MB, stripped with LTO)
```

The release profile applies: `lto = "thin"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`.

### Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `webui` | Yes | Embedded web dashboard at `/ui` and `/dashboard` |
| `metrics` | No | Prometheus metrics endpoint at `/metrics` |

```bash
cargo build --release --features metrics       # Add metrics
cargo build --release --no-default-features    # Minimal (no web UI)
```

## Docker Deployment

```bash
docker build -t mcp-gateway:latest .

docker run -d --name mcp-gateway \
  -p 39400:39400 \
  -v ./gateway.yaml:/config.yaml:ro \
  -v ./capabilities:/capabilities:ro \
  -e TAVILY_API_KEY=tvly-xxx \
  mcp-gateway:latest
```

### Docker Compose

```yaml
services:
  mcp-gateway:
    image: ghcr.io/mikkoparkkola/mcp-gateway:latest
    restart: unless-stopped
    ports: ["39400:39400"]
    volumes:
      - ./gateway.yaml:/config.yaml:ro
      - ./capabilities:/capabilities:ro
    environment:
      MCP_GATEWAY_LOG_LEVEL: info
      MCP_GATEWAY_LOG_FORMAT: json
    healthcheck:
      test: ["CMD", "wget", "--spider", "-q", "http://localhost:39400/health"]
      interval: 30s
      timeout: 5s
      retries: 3
    deploy:
      resources:
        limits: { memory: 512M, cpus: "1.0" }
```

Stdio backends spawn child processes. If those backends use `npx`, install Node.js in the image or run them as HTTP sidecar containers.

### Container Verification

Use the same doctor command for local and container deployments:

```bash
mcp-gateway doctor --config gateway.yaml --format json
curl -sf http://localhost:39400/health > /dev/null
scripts/dev/docker-smoke.sh  # repo checkout: container health + routed tool call
scripts/dev/usability-smoke.sh  # repo checkout: no prompts + safe export + routed tool call
```

Client configs are still generated on the host, not inside the container:

```bash
mcp-gateway setup export --target all --dry-run --config gateway.yaml
mcp-gateway setup export --target all --config gateway.yaml
```

Applied exports print any backup file and a rollback command. Use that rollback command before deleting or hand-editing a generated client config.

## Kubernetes Enterprise Alpha

The enterprise-alpha Kubernetes package lives in
[`deploy/kubernetes/enterprise-alpha`](../deploy/kubernetes/enterprise-alpha/README.md).
It currently covers CRD shape, Helm-style values, least-privilege base
resources, network policy defaults, HA probes, read-only preflight checks,
local manifest tests, a deterministic reconcile plan, a server-side dry-run
wrapper, a disposable kind smoke fixture, and sensitive-data-free evidence
exports for Kubernetes status, Events, OTel, and SIEM adapters. It also includes
a deterministic controller-manager loop for bounded CI cycles or continuous
operator reconciliation over a reviewed resource stream, plus a gated cluster
apply command plan and opt-in executor for preflight, server-side dry-run,
apply, verification, evidence export, and rollback handles.

```bash
mcp-gateway kubernetes plan \
  deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml \
  --namespace mcp-gateway

mcp-gateway kubernetes controller \
  deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml \
  --namespace mcp-gateway \
  --cycles 2

mcp-gateway kubernetes apply-plan \
  deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml \
  --namespace mcp-gateway

mcp-gateway kubernetes apply-plan \
  deploy/kubernetes/enterprise-alpha/base/example-gateway.yaml \
  --namespace mcp-gateway \
  --execute \
  --format plain

deploy/kubernetes/enterprise-alpha/scripts/server-dry-run.sh mcp-gateway
deploy/kubernetes/enterprise-alpha/scripts/kind-smoke.sh
```

Free/core deployment remains Docker, Docker Compose, and single-node service
templates. Kubernetes HA, cluster policy reconciliation, managed rollout,
multi-tenant namespaces, controller-manager operation, gated cluster apply
planning and execution, kind-based cluster validation, and fleet evidence export
adapters are enterprise scope.

## Configuration Loading Order

Config merges from three sources (later overrides earlier):

1. YAML config file (`--config` or `MCP_GATEWAY_CONFIG`)
2. Environment variables (`MCP_GATEWAY_` prefix, `__` for nesting)
3. CLI flags (`--port`, `--host`, `--no-meta-mcp`)

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_GATEWAY_CONFIG` | -- | Config file path |
| `MCP_GATEWAY_PORT` | `39400` | Listen port |
| `MCP_GATEWAY_HOST` | `127.0.0.1` | Bind address |
| `MCP_GATEWAY_LOG_LEVEL` | `info` | trace/debug/info/warn/error |
| `MCP_GATEWAY_LOG_FORMAT` | `text` | `text` or `json` |

Nested values: `MCP_GATEWAY_SERVER__PORT=8080` sets `server.port`.

Config values support `${VAR}` and `${VAR:-default}` expansion. Use `env_files:` in config to load `.env` files (supports `~` expansion; missing files silently skipped).

## TLS / mTLS

The gateway includes a built-in certificate manager:

```bash
# Generate root CA
mcp-gateway tls init-ca --cn "MCP Gateway Root CA" --out /etc/mcp-gateway/tls

# Issue server certificate
mcp-gateway tls issue-server \
  --ca-cert /etc/mcp-gateway/tls/ca.crt --ca-key /etc/mcp-gateway/tls/ca.key \
  --cn gateway.company.com --san-dns "gateway.company.com,localhost" \
  --out /etc/mcp-gateway/tls

# Issue client certificate (for mTLS)
mcp-gateway tls issue-client \
  --ca-cert /etc/mcp-gateway/tls/ca.crt --ca-key /etc/mcp-gateway/tls/ca.key \
  --cn "claude-code-agent" --out /etc/mcp-gateway/tls/clients
```

Enable mTLS in config:

```yaml
mtls:
  enabled: true
  ca_cert: /etc/mcp-gateway/tls/ca.crt
  server_cert: /etc/mcp-gateway/tls/server.crt
  server_key: /etc/mcp-gateway/tls/server.key
  require_client_cert: true
```

## Reverse Proxy

Bind the gateway to `127.0.0.1` (default) and proxy from the public-facing server. SSE streaming requires disabled response buffering.

### Nginx

```nginx
upstream mcp_gateway {
    server 127.0.0.1:39400;
    keepalive 32;
}
server {
    listen 443 ssl http2;
    server_name gateway.example.com;
    ssl_certificate     /etc/ssl/certs/gateway.crt;
    ssl_certificate_key /etc/ssl/private/gateway.key;

    location /mcp {
        proxy_pass http://mcp_gateway;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;          # Required for SSE
        proxy_cache off;
        proxy_set_header Connection "";
        proxy_read_timeout 300s;
    }
    location /health  { proxy_pass http://mcp_gateway; }
    location /ui      { proxy_pass http://mcp_gateway; }
    location /metrics {
        allow 10.0.0.0/8; deny all;
        proxy_pass http://mcp_gateway;
    }
}
```

### Caddy

```
gateway.example.com {
    reverse_proxy 127.0.0.1:39400 {
        flush_interval -1
    }
}
```

Caddy auto-provisions TLS via Let's Encrypt. `flush_interval -1` disables buffering for SSE.

## Systemd Service

```ini
# /etc/systemd/system/mcp-gateway.service
[Unit]
Description=MCP Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=mcp-gateway
Group=mcp-gateway
ExecStart=/usr/local/bin/mcp-gateway --config /etc/mcp-gateway/gateway.yaml
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
Environment=MCP_GATEWAY_LOG_LEVEL=info
Environment=MCP_GATEWAY_LOG_FORMAT=json
EnvironmentFile=-/etc/mcp-gateway/env
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/etc/mcp-gateway
LimitNOFILE=65536
MemoryMax=1G

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /usr/sbin/nologin mcp-gateway
sudo cp target/release/mcp-gateway /usr/local/bin/
sudo mkdir -p /etc/mcp-gateway
sudo cp gateway.yaml /etc/mcp-gateway/
sudo chown -R mcp-gateway:mcp-gateway /etc/mcp-gateway
sudo systemctl daemon-reload
sudo systemctl enable --now mcp-gateway
```

## Client Configuration Safety

`mcp-gateway setup export` is the supported way to write Claude Code, Claude Desktop, Cursor, VS Code Copilot, Windsurf, Cline, and Zed client configs.

```bash
# Preview the exact entry first
mcp-gateway setup export --target all --dry-run --config /etc/mcp-gateway/gateway.yaml

# Apply with backup and post-write verification
mcp-gateway setup export --target all --config /etc/mcp-gateway/gateway.yaml

# Restore one client config from the printed backup path
mcp-gateway setup export --rollback /path/to/client.json.mcp-gateway.bak.123456789
```

The exporter preserves unrelated client settings, creates a sibling backup before updating an existing file, verifies the gateway entry after writing, and prints the rollback command. For managed team deployments, generate and review the client entry once, then distribute it through your MDM, dotfile manager, or configuration-management system instead of asking each user to hand-edit JSON.

## Health Checks

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No (public by default) | Backend status, circuit breaker state |
| `/ui/api/status` | GET | Depends on config | JSON API for dashboards |

Circuit breaker states: `Closed` (healthy), `Open` (failing), `HalfOpen` (testing recovery).

```bash
# Load balancer probe
curl -sf http://localhost:39400/health > /dev/null
# Alert on broken backends
curl -s http://localhost:39400/health | jq '.backends | to_entries[] | select(.value.circuit_state != "Closed")'
```

## Monitoring and Observability

### Structured Logging

JSON logs for aggregation (ELK, Loki, Datadog):

```bash
MCP_GATEWAY_LOG_FORMAT=json MCP_GATEWAY_LOG_LEVEL=info mcp-gateway --config gateway.yaml
```

Includes: timestamp, level, span context, backend name, request ID, latency, circuit breaker transitions.

### Prometheus Metrics

Build with `--features metrics`, scrape `/metrics`:

- `mcp_gateway_requests_total` -- count per backend/tool
- `mcp_gateway_request_duration_seconds` -- latency histogram
- `mcp_gateway_circuit_breaker_state` -- state gauge
- `mcp_gateway_rate_limiter_rejections_total` -- rejection count
- `mcp_gateway_active_connections` -- current connections

### Live Statistics / Web Dashboard

```bash
mcp-gateway stats --url http://127.0.0.1:39400 --price 15.0
```

Built-in dashboards: `/ui` (tool list, health, config) and `/dashboard` (health matrix, cache rates, top tools). Auto-refresh every 5s.

## Authentication for Production

**Never run without auth on a network-accessible port.** Default bind (`127.0.0.1`) limits to localhost. For networked deployments:

```yaml
server:
  host: "0.0.0.0"
auth:
  enabled: true
  bearer_token: "env:MCP_GATEWAY_TOKEN"
  public_paths: ["/health"]
```

`env:VAR_NAME` references for auth, agent auth, and key-server admin secrets must be present at startup; missing secret variables fail configuration validation.

For multi-client setups with per-client tool scoping, see the [README auth section](../README.md#authentication).

## Backup and Recovery

| Item | Location |
|------|----------|
| Config file | `/etc/mcp-gateway/gateway.yaml` |
| Capabilities | `capabilities/` directory |
| Secrets | `/etc/mcp-gateway/env` |
| TLS certs | `/etc/mcp-gateway/tls/` |

The gateway is **stateless**. No database. Redeploy the binary with the same config to restore full functionality. Startup takes ~8ms; backends reconnect automatically; tool caches repopulate on first request.

## Scaling

A single instance handles thousands of RPS with sub-2ms routing overhead. This is sufficient for virtually all use cases.

For horizontal scaling (organizational isolation, not throughput): each instance is independent with no shared state. Sticky sessions are not required. Stdio backends run per-instance; HTTP/SSE backends can be shared across instances.

### Resource Tuning

```yaml
failsafe:
  rate_limit:
    requests_per_second: 100   # Per-backend; adjust for backend capacity
    burst_size: 50
  circuit_breaker:
    failure_threshold: 5       # Lower = faster isolation
    reset_timeout: 30s
cache:
  default_ttl: 60s             # Higher = fewer calls, staler data
  max_entries: 10000           # In-memory; scale with available RAM
```

Each stdio backend uses 3 file descriptors. Set `LimitNOFILE=65536` in systemd for large deployments.
