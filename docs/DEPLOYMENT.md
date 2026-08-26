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
| `metrics` | Yes | Prometheus metrics endpoint at `/metrics`, unauthenticated (see [Prometheus Metrics](#prometheus-metrics)) |

```bash
cargo build --release                          # Default features, including metrics
cargo build --release --no-default-features    # Minimal (no web UI, no metrics)
```

## Single-Node Templates

Reusable templates for Docker Compose, Linux systemd, and macOS launchd live in
[`deploy/single-node`](../deploy/single-node/README.md). They all consume the
same `gateway.yaml` and `capabilities/` directory emitted by
`mcp-gateway init --profile local`.

From a repo checkout, validate the template paths and native start behavior:

```bash
scripts/dev/service-template-smoke.sh
```

## Docker Deployment

```bash
mcp-gateway init --profile local
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
scripts/dev/service-template-smoke.sh  # repo checkout: service template paths + native start smoke
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

## macOS launchd

The launch daemon template is
[`deploy/single-node/com.mikkoparkkola.mcp-gateway.plist`](../deploy/single-node/com.mikkoparkkola.mcp-gateway.plist).
It uses `/usr/local/etc/mcp-gateway/gateway.yaml` and starts from that
directory, so the generated `capabilities/` directory works without editing
the config.

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
| `/health` | GET | No (public by default) | Redacted backend health by default; authenticated admin callers also see backend status, circuit breaker state, and runtime profile lifecycle state |
| `/ui/api/status` | GET | Redacted unless admin | JSON API for dashboards; counts only without an admin credential |

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

Included in a default build. Scrape `/metrics`. The endpoint is unauthenticated,
because Prometheus scrapers do not send auth headers — keep it off the public
internet with a firewall rule or a reverse-proxy allow-list.

- `mcp_gateway_requests_total` -- count per backend/tool
- `mcp_gateway_request_duration_seconds` -- latency histogram
- `mcp_gateway_circuit_breaker_state` -- state gauge
- `mcp_gateway_rate_limiter_rejections_total` -- rejection count
- `mcp_gateway_active_connections` -- current connections
- `mcp_backend_idle_stop_close_failures` -- per backend, counts backends stopped
  for idleness that did not shut down cleanly (see below)

#### Alerting on a backend that would not stop

`stop_when_idle_for` stops a backend the gateway started once it goes unused. If
that shutdown fails or runs past its budget, the gateway gives up on the close so
the sweep keeps running, and increments `mcp_backend_idle_stop_close_failures`.
The child process may still be alive. Nothing else reports this, so an
unmonitored gateway leaks one process per occurrence and the first symptom is
memory pressure on the host, days later.

```yaml
# prometheus rules
- alert: McpBackendIdleStopCloseFailures
  expr: increase(mcp_backend_idle_stop_close_failures[15m]) > 0
  labels: { severity: warning }
  annotations:
    summary: "Backend {{ $labels.backend }} did not stop cleanly when idle"
```

Every occurrence is worth knowing about, because each one may be a process that
outlives the gateway's tracking and never comes back on its own. So the
threshold is zero rather than a rate, and there is no `for` clause: the
expression stays true for the whole 15-minute window after a single increment,
which means `for` would delay the notification without ever suppressing an
isolated failure. Warning rather than page — the damage is one leaked process,
not an outage.

When it fires: check for an orphaned child process of the gateway
(`pgrep -P $(pgrep -f mcp-gateway)`) and kill what the gateway no longer tracks.
Then look at that backend's shutdown path — a server ignoring SIGTERM is the
usual cause. Setting a longer `stop_when_idle_for` does not help; removing the
setting for that backend stops the leak at the cost of keeping it resident.

### Live Statistics / Web Dashboard

```bash
mcp-gateway stats --url http://127.0.0.1:39400 --price 15.0
```

Built-in dashboards: `/ui` (tool list, health, read-only control plane, config) and `/dashboard` (health matrix, cache rates, top tools). Auto-refresh every 5s.

## Authentication for Production

**The gateway refuses to start without auth on a network-accessible port.** The
default bind (`127.0.0.1`) limits it to the local machine. Binding anywhere else
with `auth.enabled = false` is refused before a listener is opened, because any
caller reaching that address could invoke every configured backend with the
gateway's credentials. For networked deployments:

```yaml
server:
  host: "0.0.0.0"
auth:
  enabled: true
  bearer_token: "env:MCP_GATEWAY_TOKEN"
  public_paths: ["/health"]
```

`env:VAR_NAME` references for auth, agent auth, and key-server admin secrets must be present at startup; missing secret variables fail configuration validation.

If authentication terminates in front of the gateway — a sidecar, a service
mesh, or a reverse proxy that authenticates before forwarding — the gateway
itself may serve unauthenticated on a network address:

```yaml
server:
  host: "0.0.0.0"
  allow_unauthenticated_network_bind: true
```

This is logged at WARN on every start while it remains set. Set it only when
that fronting layer exists; without one it restores the exposure the refusal
prevents.

Config files are written with mode `0600` on Unix, including the temporary file
used during the write, since a config can hold a bearer token or API keys. An
existing config with wider permissions is reported at startup and is tightened
by the next write that replaces it.

### Browser access to the gateway port

A loopback bind stops remote callers. It does not stop a web page: a site the
operator visits can rebind a hostname to `127.0.0.1`, and a cross-origin POST
reaches a JSON endpoint without a preflight. The gateway therefore refuses a
request whose `Origin`, `Host` or HTTP/2 `:authority` does not name it, and refuses any request a
browser marks `Sec-Fetch-Site: cross-site` or `same-site`.

A request with no `Origin` is allowed, because a non-browser MCP client never
sends one. That is what keeps command-line clients, Prometheus scrapes of
`/metrics`, and health probes working unchanged.

The allow list is the loopback spellings of the bind address **at the bind
port**, the configured bind address itself, and the `server.public_url` origin,
which is re-read on every request so a config reload takes effect at once. A
page served from `http://localhost:3000` is refused: being local does not make
it trusted.

There is deliberately no setting for allowing extra browser origins. A
cross-origin browser client also needs CORS preflight responses, which this
gateway does not serve, so such a setting would name origins that still could
not call it. Serve the page from the gateway's own origin, or use a non-browser
client.

When the bind is not loopback and no `public_url` is set, a `Host` naming a
domain is refused and a numeric address is accepted. Such a gateway answers at
an address it cannot predict, so the name cannot be checked, but rebinding
always needs a hostname while a network client dials an address. Set
`public_url` if clients legitimately reach the gateway by name.

### What a config reload applies

Most settings are read once at startup. A reload reports which changed fields
are **not yet applied** and keeps reporting them on every reload until the
process is restarted, rather than saying so once and forgetting.

Enabling `auth.enabled` is the case that matters: it takes effect on restart, so
a reload reports `NOT YET APPLIED, restart required for: auth`. Fields are
treated as restart-required unless proven otherwise, so an occasional needless
restart is possible; being told a security change took effect when it did not
is not.

Applied without a restart: backends, `server.public_url`, and
`control_plane.role_mapping`.

### Capabilities that register an address with a third party

A capability that hands a caller-chosen destination to a third party which then
calls it — a webhook registration is the shape — creates persistent state
outside the gateway, addressed by the caller and authorised by the operator's
credential. It needs no readable response to be useful, so the browser and
network gates do not constrain it. Those capabilities require an admin
credential.

The rule is derived from each capability's own definition: it is not read-only,
and it takes a caller-supplied destination — a URL, but also a topic, queue or
channel, since a delivery address need not be a URL. A capability can declare
`metadata.registers_external_callback` explicitly where its shape is not
obvious from the name. Posting a URL as data —
archiving a page, attaching a link — is not covered, because nothing calls back
and requiring a credential there would take an ordinary tool away for no gain.
A capability added later inherits the rule rather than needing to be remembered
on a list.

### Opening the dashboard

`mcp-gateway init` generates an admin credential for the install and writes it
into `gateway.yaml`, which is created readable only by you. Tools work without
it; managing the gateway and reading the dashboard need it.

A browser cannot attach an `Authorization` header to a navigation, so `serve`
prints a link:

```
DASHBOARD (opens once, then remembered in this browser):
  http://127.0.0.1:39400/dashboard?bootstrap=...
```

Opening it exchanges a single-use value for a session cookie and redirects, so
nothing stays in the address bar. The value in the link is **not** the admin
credential — a query string reaches this gateway's own request log, which
outlives the browser tab. It works once and dies with the process, so a link
left in a shell history is spent.

The cookie carries an opaque handle, never the admin credential: a bearer token
in a cookie is long-lived and recoverable from the wire without TLS, while a
handle means nothing outside the running process and dies with it. It is
`HttpOnly` and `SameSite=Strict`, so script cannot read it and it is never sent
cross-site, and it is marked `Secure` when the listener speaks TLS.

### Admin requires a credential

With `auth.enabled = false` every caller is anonymous and holds **no admin**.
Ordinary tools work, so a local MCP client needs no configuration. These do not:

- `gateway_kill_server`, `gateway_revive_server`, `gateway_set_profile`,
  `gateway_set_state`, `gateway_reload_config`, `gateway_reload_capabilities`
- `/dashboard` and the management endpoints under `/ui/api/`, which return
  `403`. `/ui/api/status` still answers, with counts rather than backend names

Set `auth.enabled = true` with a bearer token to get them back; that token is
admin. An unauthenticated gateway cannot tell its operator apart from a web page
or from any other process running as the same user, so admin is a grant that
follows a credential.

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
