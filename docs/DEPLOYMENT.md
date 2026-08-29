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
# Linux bind mounts: prepare a dedicated owner-only copy for container UID 1001.
install -m 600 gateway.yaml gateway.container.yaml
sudo chown 1001:1001 gateway.container.yaml

docker run -d --name mcp-gateway \
  -p 39400:39400 \
  -v ./gateway.container.yaml:/config.yaml:ro \
  -v ./capabilities:/capabilities:ro \
  -e TAVILY_API_KEY=tvly-xxx \
  mcp-gateway:latest
```

On Linux, the image runs as UID/GID 1001. Bind-mount an owner-only deployment
copy that this identity can read; do not change ownership on your working
config or make a credential-bearing config world-readable. The same
requirement applies to the Compose example below: create its `gateway.yaml`
deployment copy with `install -m 600 <working-config> gateway.yaml && sudo chown
1001:1001 gateway.yaml`. Docker Desktop handles bind-mount identity differently
on macOS and Windows.

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

## Replica Count and `server.modern_protocol`

**Run a single replica while `server.modern_protocol` is on.** The
consumed-continuation ledger and the mint counter are process-local, so two
replicas can each accept the same continuation and each issue the same counter
value. Neither is detected at runtime — the second spend simply succeeds.

This constraint binds only on the modern protocol path. `server.modern_protocol`
is off by default, and with it off there is no such limit: scale horizontally as
the rest of this document describes.

The shipped Helm chart and Kubernetes manifests default to two replicas, which is
correct for the default configuration. Turning the switch on is what makes that count
wrong, so the change to one replica belongs with the change that enables it.

If you need both horizontal scale and the 2026-07-28 revision, wait for the
shared insert-if-absent store tracked as MIK-7312. Do not work around it with a
sticky-session load balancer: continuations are presented by whichever client
holds one, and session affinity does not constrain which replica that reaches.

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

A **malformed** line in an env file is not skipped: it fails startup, naming the file,
the line number and the category of fault. The offending line is never echoed, because
the offending line is the secret. A `~` in an `env_files` path resolves once, at startup,
against the home directory in force at that moment; each file is applied before the next
is expanded, so a file that sets `HOME` moves where a later `~` points.

Env files supply values to configuration references. They do **not** supply the
attestation signing key: `ATTESTATION_SIGNING_KEY` and `ATTESTATION_KEY_ID` are read
directly from the process environment under those fixed names, and are expected to be
injected by the deployment — a systemd unit, a Kubernetes secret — rather than named in a
config file. Putting them in an env file has no effect.

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

Built-in dashboards: `/ui` (tool list, health, read-only control plane, config) and `/dashboard` (health matrix, cache rates, top tools), which is admin-only — see [Opening the dashboard](#opening-the-dashboard). Auto-refresh every 5s.

## Authentication for Production

**The gateway refuses to start when its tools can be called without a
credential and it can be reached from off this machine.** The refusal happens
before a listener is opened, because any caller who reaches such a gateway can
invoke every configured backend with the gateway's own credentials.

Both halves have to be true for it to fire:

**Reachable** — either of:

- a bind other than loopback; the default `127.0.0.1` is not one
- a `server.public_url` naming a non-loopback host, because a tunnel or proxy
  reaches the gateway by that name

**AND tools open** — either of:

- `auth.enabled = false`, where every path is open regardless of any list
- an `auth.public_paths` entry covering `/mcp`. Entries match by prefix, so
  `""`, `/`, `/m` and `/mcp` all count; `/health` and `/metrics` do not

Both columns, not one. The pairing that surprises people is a wide bind with
the `init` config's public `/mcp` — authentication is on, and the tools are
still open.

`auth.enabled = true` on its own is therefore not enough: authentication with
`/mcp` left public is a gateway that reads as protected and serves every backend
to whoever reaches it. The message names whichever half fired and the fix for
that one.

For networked deployments:

```yaml
server:
  host: "0.0.0.0"
auth:
  enabled: true
  bearer_token: "env:MCP_GATEWAY_TOKEN"
  public_paths: ["/health"]
```

`env:VAR_NAME` references for auth, agent auth, and key-server admin secrets must be present at startup; missing secret variables fail configuration validation.

A gateway whose tools already require a native credential is not refused, even
with `auth.enabled = false`: mTLS with `require_client_cert`, mTLS with a
non-empty policy — which denies any call arriving without a verified identity —
and `agent_auth` each mean the tool surface admits nobody without one. The
refusal asks whether the tools can be invoked without a credential, not whether
one particular setting is on.

`scripts/dev/mtls-serve-smoke.sh` starts a real gateway over mTLS and asserts it
stays up; run it after changing anything on the serve path.

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

There is deliberately no setting for allowing extra browser origins, and the
reason is not the one it looks like. It is tempting to say such a setting would
be inert because the gateway serves no CORS preflight responses — that is
wrong. A form POST is a simple request and skips the preflight entirely, which
is the very shape the origin check exists to refuse. An extra-origin setting
would therefore be a real grant: every page on that origin could drive the
gateway with whatever credentials it holds, and one cross-site scripting flaw
on that origin would inherit them.

Serve the page from the gateway's own origin, or use a non-browser client.

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

One reload is refused outright rather than applied: one that would leave the
tools reachable without a credential — see the tunnel section below, which is
where this is met in practice.

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

### An existing config written before this release

Config files are created `0600` now, but one written by an earlier version may
still be readable by other local accounts — and it can hold a bearer token or
API keys. The gateway reports it at startup rather than changing a file you own:

```
CONFIG READABLE BY OTHER LOCAL USERS: it holds this gateway's credentials.
Fix with: chmod 600 <path>
```

### Inbound webhooks

Webhook deliveries pass the same Host check as everything else, and a delivery
arriving through a tunnel carries the tunnel's hostname. On a loopback bind that
name is neither loopback nor declared, so it is refused.

Declare the address the provider actually posts to:

```yaml
server:
  public_url: "https://your-tunnel.example.com"
```

The Host check already admits `public_url`, and it is re-read on each request,
so a reload applies it without a restart. Without it the provider sees a `403`
and the gateway logs `Request blocked: Host does not name this gateway`, naming
the hostname it refused.

**Declare authentication in the same breath, and restart.** A `public_url`
naming a tunnel says the gateway is reached from off this machine. Over tools
that need no credential, that is the gateway serving every configured backend
to whoever reaches the tunnel — so the reload is refused. No backend is started
or stopped and no configuration is published:

```
config reload refused: refusing to serve HTTP, reachable at the declared
public_url host your-tunnel.example.com: ...
```

The refusal names two things it did not do — no backend was started or stopped,
and no configuration was published — and claims nothing beyond them. Reading a
config file no longer leaks its `env_files` into the process environment. A
refused reload leaves the environment exactly as the last accepted configuration
left it, so a capability that resolves its credential from an environment
variable still resolves the value it had before the refused edit. Earlier
releases applied env files before validating the file, which made a refused
reload a partial no-op; that is fixed.

Enabling `auth.enabled` in the same edit does not get it through, and that is
deliberate rather than an oversight: authentication is applied at startup, so
until a restart the request path is still running without it while the tunnel
hostname would already be admitted.

**Enabling it is not sufficient either.** A config `init` wrote already has
authentication on and lists `/mcp` under `auth.public_paths`, so its tools need
no credential — and that, plus a declared hostname, is exactly what is refused.
Publishing such a gateway means closing the tool paths and giving clients the
credential, or fronting it with something that authenticates and setting
`server.allow_unauthenticated_network_bind`. The refusal says which of the two
a restart would do with the file in front of it, so follow that rather than
guessing. Set both, then restart — the same start
that applies the authentication is the one that admits the hostname.

### Managing the gateway from your MCP client

`mcp-gateway setup export` writes the gateway entry into each AI client's own
config. Ordinary tools need no credential, so the entry works as written.

Management tools do need one, and the exporter deliberately writes no
credential. Three of the supported clients keep their config inside a working
tree — Cursor, VS Code and Cline — and an exporter that writes a secret into
some destinations and not others gets that decision wrong the first time
somebody exports to all of them at once. It also has to print what it wrote.

So management runs through the dashboard, or through stdio, where the client
spawns the gateway itself and is the operator by construction.

To manage from a proxy-mode client anyway, add the header yourself to a config
that is not in a working tree:

```json
{ "mcpServers": { "gateway": {
    "url": "http://127.0.0.1:39400/mcp",
    "headers": { "Authorization": "Bearer <the token in gateway.yaml>" }
} } }
```

### Opening the dashboard

`mcp-gateway init` generates an admin credential for the install and writes it
into `gateway.yaml`, which is created readable only by you on Unix (Windows
takes the directory's inherited permissions). Tools work without
it; managing the gateway and reading the dashboard need it.

A browser cannot attach an `Authorization` header to a navigation, so `serve`
prints a link — **on a loopback bind only**, and redeemable only from this
machine. That is checked against the connection's own peer address, not against
a header the caller writes: a request forwarded from elsewhere carries whatever
`Host` the proxy chose, and the peer is the socket the kernel accepted.

A reverse proxy running on this same machine connects from loopback too, so a
request carrying a forwarding header (`X-Forwarded-For`, `Forwarded`,
`X-Forwarded-Host`) is refused as well. **Residual, stated rather than implied
away**: a proxy that strips those headers would still be indistinguishable from
a local browser. Treat the printed value as sensitive. A gateway bound to a network address prints none, because a link that
grants an admin session should not travel in a log that leaves the host.

There is therefore no link to use on such a gateway, and a port-forward does not
produce one: the value is never emitted, so nothing arrives to redeem. Manage a
network-bound gateway through `/ui`, which can present the bearer token, or
through the meta-tools with that same credential. `/dashboard` is for the
loopback case.

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

With `auth.enabled = false` every caller **over HTTP** is anonymous and holds
**no admin**. A stdio caller is treated as admin: the client spawned the
process, so it already holds whatever the operator holds.
Ordinary tools work, so a local MCP client needs no configuration. These do not:

- `gateway_kill_server`, `gateway_revive_server`, `gateway_reload_config`,
  `gateway_reload_capabilities` — the four that change the gateway for every
  session. Choosing a routing profile or a discovery state writes only the
  caller's own session, so those stay available without a credential
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
