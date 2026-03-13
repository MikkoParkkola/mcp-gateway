# MCP Gateway

[![CI](https://github.com/MikkoParkkola/mcp-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/MikkoParkkola/mcp-gateway/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/mcp-gateway.svg)](https://crates.io/crates/mcp-gateway)
[![Downloads](https://img.shields.io/crates/d/mcp-gateway.svg)](https://crates.io/crates/mcp-gateway)
[![Rust](https://img.shields.io/badge/rust-1.85+-blue.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests](https://img.shields.io/badge/tests-2000%2B-brightgreen.svg)](https://github.com/MikkoParkkola/mcp-gateway)
[![MCP Servers](https://img.shields.io/badge/MCP%20servers-48%20built--in-blue.svg)](https://github.com/MikkoParkkola/mcp-gateway/wiki/Getting-Started)
[![Capabilities](https://img.shields.io/badge/REST%20capabilities-70%2B-purple.svg)](https://github.com/MikkoParkkola/mcp-gateway/wiki/Capabilities)
[![MCP Protocol](https://img.shields.io/badge/MCP-2025--11--25-green.svg)](https://modelcontextprotocol.io)
[![Glama](https://glama.ai/mcp/servers/badge)](https://glama.ai/mcp/servers)

**Give your AI access to every tool it needs -- without burning your context window or building MCP servers.**

![demo](demo.gif)

MCP Gateway sits between your AI client and your tools. Instead of loading hundreds of tool definitions into every request, the AI gets 4 meta-tools and discovers the right one on demand -- like searching an app store instead of installing every app.

## Why

**The context window is the bottleneck.** Every MCP tool you connect costs ~150 tokens of context overhead. Connect 20 servers with 100+ tools and you've burned 15,000 tokens before the conversation starts -- on tool definitions the AI probably won't use this turn.

Worse: context limits force you to **choose** which tools to connect. You leave tools out because they don't fit -- and your AI makes worse decisions because it can't reach the right data.

MCP Gateway removes that tradeoff entirely.

| | Without Gateway | With Gateway |
|---|----------------|--------------|
| **Tools in context** | Every definition, every request | 4 meta-tools (~400 tokens) |
| **Token overhead** | ~15,000 tokens (100 tools) | ~400 tokens -- **97% savings** |
| **Cost at scale** | ~$0.22/request (Opus input) | ~$0.006/request -- **$219 saved per 1K** |
| **Practical tool limit** | 20-50 tools (context pressure) | **Unlimited** -- discovered on demand |
| **Connect a new REST API** | Build an MCP server (days) | Drop a YAML file or import an OpenAPI spec (minutes) |
| **Changing MCP config** | Restart AI session, lose context | Restart gateway (~8ms), session stays alive |
| **When one tool breaks** | Cascading failures | Circuit breakers isolate it |

### Why not...

| Alternative | What it does | Why MCP Gateway is different |
|---|---|---|
| **Direct MCP connections** | Each server connected individually | Every tool definition loaded every request. 100 tools = 15K tokens burned. Gateway: 4 tools, always. |
| **Claude's ToolSearch** | Built-in deferred tool loading | Only works with tools already configured. Gateway adds unlimited backends + REST APIs without MCP servers. |
| **Archestra** | Cloud-hosted MCP registry | Requires cloud account, sends data to third party. Gateway is local-only, zero external dependencies. |
| **Kong / Portkey** | General API gateways | Not MCP-aware. No meta-tool discovery, no tool search, no capability YAML system. |
| **Building fewer MCP servers** | Reduce tool count manually | You lose capabilities. Gateway lets you keep everything and pay the token cost of 4. |

## Key Benefits

### 1. Unlimited Tools, Minimal Tokens

The gateway exposes 4 meta-tools. Your AI searches for what it needs (`gateway_search_tools`), then invokes it (`gateway_invoke`). Tool definitions load on demand, not upfront. Connect 500 tools and pay the token cost of 4.

This isn't just a cost optimization -- it's a **capability unlock**. Without the gateway, you pick which 20-30 tools fit in context. With it, the AI has access to everything and dynamically selects the best tool for each task.

**Token math** (Claude Opus @ $15/M input tokens):
- **Without**: 100 tools × 150 tokens × 1,000 requests = 15M tokens = **$225**
- **With**: 4 meta-tools × 100 tokens × 1,000 requests = 0.4M tokens = **$6**

### 2. Any REST API → MCP Tool -- No Code

Most APIs will never get a dedicated MCP server. The gateway turns any REST API into a tool your AI can use:

**From an OpenAPI spec** (automatic):
```bash
mcp-gateway cap import stripe-openapi.yaml --output capabilities/ --prefix stripe
# Generates one capability YAML per endpoint, ready to use
```

**From a YAML definition** (~30 seconds):
```yaml
name: stock_quote
description: Get real-time stock price

providers:
  primary:
    service: rest
    config:
      base_url: https://finnhub.io
      path: /api/v1/quote
      method: GET
      params:
        symbol: "{symbol}"
        token: "{env.FINNHUB_API_KEY}"
```

Drop the file in a capability directory -- **hot-reloaded in ~500ms**, no restart needed.

The gateway ships with **42 starter capabilities** -- 25 work instantly with zero configuration:

| Category | Zero-Config Tools | Source |
|----------|------------------|--------|
| **Knowledge** | Weather, Wikipedia, country info, public holidays, timezones, number facts | Open-Meteo, Wikipedia, RestCountries, Nager.Date |
| **Developer** | npm packages, PyPI packages, GitHub search, QR codes, UUIDs | npm, PyPI, GitHub API, GoQR |
| **News & Social** | Hacker News, Reddit | HN API, Reddit |
| **Finance** | SEC EDGAR filings (10-K, 10-Q, 8-K, insider trades) | US Gov (free) |
| **Geo** | Geocoding, reverse geocoding | OpenStreetMap Nominatim |
| **Reference** | Book search, air quality | Open Library, OpenAQ |

Plus 17 more with free-tier API keys (Brave Search, stock quotes, movies, IP geolocation, recipes, package tracking).

### 3. Change Your MCP Stack Without Losing Your AI Session

With Claude Code and similar tools, modifying your MCP configuration means restarting the entire AI session -- losing your conversation history, working context, and debugging flow mid-thought.

The gateway is a **stable endpoint**. Your AI connects once to `localhost:39400`. Behind it:

- **REST API capabilities** (YAML files) are **hot-reloaded automatically** -- add, modify, or remove a file and it's live in ~500ms. Zero downtime.
- **MCP server backends** (stdio/HTTP/SSE) require a gateway restart -- but the gateway starts in **~8ms**. Your AI session stays connected.

Experiment with new tools, troubleshoot broken ones, swap configurations -- without ever losing context.

### 4. Production Resilience

One flaky MCP server shouldn't take down your entire toolchain.

| Failsafe | What It Does |
|----------|-------------|
| **Circuit Breaker** | Isolates failing backends after 5 errors, auto-recovers after 30s |
| **Retry with Backoff** | 3 attempts with exponential backoff for transient failures |
| **Rate Limiting** | Per-backend throttling prevents quota exhaustion |
| **Health Checks** | Continuous monitoring with automatic recovery detection |
| **Graceful Shutdown** | Clean connection teardown, no orphaned processes |
| **Concurrency Limits** | Prevent backend overload under burst traffic |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     MCP Gateway (:39400)                         │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Meta-MCP Mode: 4 Tools → Access 100+ Tools Dynamically  │    │
│  │  • gateway_list_servers    • gateway_search_tools        │    │
│  │  • gateway_list_tools      • gateway_invoke              │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                   │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  Failsafes: Circuit Breaker │ Retry │ Rate Limit        │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│         ┌────────────────────┼────────────────────┐             │
│         ▼                    ▼                    ▼             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Tavily    │    │  Context7   │    │   Pieces    │         │
│  │  (stdio)    │    │   (http)    │    │   (sse)     │         │
│  └─────────────┘    └─────────────┘    └─────────────┘         │
└─────────────────────────────────────────────────────────────────┘
```

## How It Works

The gateway exposes 4 meta-tools that replace hundreds of individual tool definitions:

| Meta-Tool | Purpose |
|-----------|---------|
| `gateway_list_servers` | List available backends |
| `gateway_list_tools` | List tools from a specific backend |
| `gateway_search_tools` | Search tools by keyword across all backends |
| `gateway_invoke` | Invoke any tool on any backend |

**Example:** You have 12 MCP servers exposing 180+ tools. Without a gateway, every request carries all 180 definitions (~27,000 tokens). With the gateway, the AI discovers and invokes tools on demand:

**Step 1: Search for relevant tools**

```json
{
  "method": "tools/call",
  "params": {
    "name": "gateway_search_tools",
    "arguments": { "query": "search" }
  }
}
```

Response:

```json
{
  "query": "search",
  "matches": [
    { "server": "tavily",  "tool": "tavily_search",   "description": "Web search via Tavily API" },
    { "server": "brave",   "tool": "brave_web_search", "description": "Search the web with Brave" },
    { "server": "github",  "tool": "search_code",      "description": "Search code across repositories" }
  ],
  "total": 3
}
```

**Step 2: Invoke the tool you need**

```json
{
  "method": "tools/call",
  "params": {
    "name": "gateway_invoke",
    "arguments": {
      "server": "tavily",
      "tool": "tavily_search",
      "arguments": { "query": "MCP protocol specification" }
    }
  }
}
```

The gateway routes the call to the Tavily backend, applies circuit breaker/retry logic, and returns the result. The AI never loaded all 180 tool schemas -- it discovered and used exactly the one it needed.

## Features

### Web Dashboard

The gateway includes an embedded web UI served from the same binary and port. No separate frontend process, no build step.

- **`/ui`** — Single-page dashboard with live status, searchable tool list, server health, and config viewer. Auto-refreshes every 5 seconds via htmx.
- **`/dashboard`** — Operator dashboard with backend health matrix, cache hit rates, and top tools. Server-rendered HTML, auto-refreshes every 5 seconds.
- **`/ui/api/status`** — JSON API for programmatic monitoring.

The dashboard is enabled by default (feature flag `webui`). Disable with `--no-default-features` to strip it from the binary entirely.

### Authentication

Protect your gateway with bearer tokens and/or API keys:

```yaml
auth:
  enabled: true

  # Simple bearer token (good for single-user/dev)
  bearer_token: "auto"  # auto-generates, or use env:VAR_NAME, or literal

  # API keys for multi-client access
  api_keys:
    - key: "env:CLIENT_A_KEY"
      name: "Client A"
      rate_limit: 100        # requests per minute (0 = unlimited)
      backends: ["tavily"]   # restrict to specific backends (empty = all)
    - key: "my-literal-key"
      name: "Client B"
      backends: []           # all backends

  # Paths that bypass auth (always includes /health)
  public_paths: ["/health", "/metrics"]
```

**Token Options:**
- `"auto"` - Auto-generate random token (logged at startup)
- `"env:VAR_NAME"` - Read from environment variable
- `"literal-value"` - Use literal string

**Usage:**
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://localhost:39400/mcp
```

### Per-Client Tool Scopes

Control which tools each API key can access using `allowed_tools` (allowlist) and `denied_tools` (blocklist):

```yaml
auth:
  enabled: true
  api_keys:
    # Frontend app: Only search and read operations
    - key: "env:FRONTEND_KEY"
      name: "Frontend App"
      allowed_tools:
        - "search_*"        # All search tools
        - "read_*"          # All read tools
        - "tavily:*"        # All tools on tavily server
      # When allowed_tools is set, ONLY these tools are accessible

    # Bot: No filesystem or execution tools
    - key: "env:BOT_KEY"
      name: "Bot"
      denied_tools:
        - "filesystem_*"    # Block all filesystem tools
        - "exec_*"          # Block all execution tools
      # When denied_tools is set, these are blocked ON TOP of global policy

    # Data reader: Complex restrictions
    - key: "env:READER_KEY"
      name: "Data Reader"
      allowed_tools:
        - "database_*"
        - "filesystem_*"
      denied_tools:
        - "database_write"  # But no writes
        - "database_delete" # Or deletes
```

**Pattern Matching:**
- `"exact_name"` - Exact match only
- `"prefix_*"` - Glob pattern (matches anything starting with prefix)
- `"server:tool"` - Qualified name (server-specific)
- `"server:*"` - All tools on specific server

**Precedence Rules:**
1. Global tool policy denies (always enforced)
2. Per-client `allowed_tools` (if set, ONLY these tools allowed)
3. Per-client `denied_tools` (if set, these tools blocked)
4. Global policy default action

**Security Best Practices:**
- Use allowlists for untrusted clients (frontend apps, bots)
- Use denylists for additional restrictions on trusted clients
- Always keep global policy enabled (`security.tool_policy.enabled: true`)
- Use qualified names (`server:tool`) for fine-grained control

See [`examples/per-client-tool-scopes.yaml`](examples/per-client-tool-scopes.yaml) for complete examples.

### Capability System

Turn any REST API into an MCP tool by dropping a YAML file into your capabilities directory. Each file follows the Fulcrum 1.0 schema and defines the endpoint, parameters, auth, caching, and metadata. The gateway hot-reloads capabilities automatically -- no restart needed.

Import from an existing OpenAPI spec to generate capability files automatically:

```bash
mcp-gateway cap import stripe-openapi.yaml --prefix stripe --output capabilities/stripe
```

Validate and test capabilities before deploying:

```bash
mcp-gateway cap validate capabilities/my_tool.yaml
mcp-gateway cap test capabilities/my_tool.yaml --args '{"param": "value"}'
```

For the full capability YAML schema and OpenAPI import details, see [docs/OPENAPI_IMPORT.md](docs/OPENAPI_IMPORT.md). Browse and install community capabilities with `mcp-gateway cap search` and `mcp-gateway cap install` -- see [docs/COMMUNITY_REGISTRY.md](docs/COMMUNITY_REGISTRY.md).

### Transform Chains

Transforms modify tool definitions and responses as they pass through the gateway. They compose into ordered chains: namespace, filter, rename, then response.

| Transform | Purpose |
|-----------|---------|
| **Namespace** | Prefix tool names (e.g. all Gmail tools become `gmail_*`) |
| **Filter** | Allow/deny tools by name or glob pattern |
| **Rename** | Rename individual tools |
| **Response** | Project fields, redact PII, reshape output |

Example -- field projection and PII redaction on a response:

```yaml
transform:
  project: [id, name, department, role, status]
  redact: [email, phone, ssn, address]
```

See [`examples/transform-example.yaml`](examples/transform-example.yaml) for a complete example.

### Webhooks

External services (GitHub, Linear, Stripe, etc.) can push events into the gateway via webhook endpoints. The gateway validates HMAC signatures, transforms payloads, and broadcasts them as MCP notifications to connected clients via SSE.

```yaml
webhooks:
  enabled: true
  base_path: /webhooks
  require_signature: true
```

Define webhook endpoints in capability YAML files alongside regular providers. For setup guides, payload transformation, HMAC configuration, and examples, see [docs/WEBHOOKS.md](docs/WEBHOOKS.md).

### Session Sandboxing

Enforce per-session resource limits and access control. Sandbox profiles restrict call counts, session duration, backend access, tool usage, and payload size. Profiles are defined in the gateway config and enforced on every tool invocation before it reaches the backend.

```yaml
sandbox:
  default_profile: strict
  profiles:
    strict:
      max_calls: 50
      max_duration: 1800
      denied_tools: [exec, shell]
      max_payload_bytes: 65536
    permissive:
      max_calls: 0
      max_duration: 0
```

### Config Validation (Linting)

Validate capability definitions against agent-UX best practices with the built-in linter. Supports text, JSON, and SARIF output for CI integration, and can auto-fix common issues.

```bash
# Validate files or directories
mcp-gateway validate capabilities/ --format text

# Output SARIF for CI (GitHub Code Scanning, etc.)
mcp-gateway validate capabilities/ --format sarif

# Auto-fix issues in place
mcp-gateway validate capabilities/ --fix
```

### Hot Reload

The gateway watches both the config file and capability directories for changes. When a file is modified:

- **Capability YAML files**: Reloaded automatically within ~500ms. Add, edit, or remove a file and it is live immediately. No restart, no downtime.
- **Gateway config** (`config.yaml`): A structural diff is computed and only changed sections are patched in-place. Backend additions, removals, and modifications are applied live. Server address/port changes require a manual restart (a warning is logged).
- **Env files** referenced in `env_files:` are also watched and re-expanded on change.

### Tunnel Mode

Expose the gateway securely over the internet without opening firewall ports. Two tunnel backends are supported:

- **Tailscale**: Serve the gateway over a private Tailscale network with `tailscale serve`. Optionally enable `tailscale funnel` for public access. Tailscale identity headers provide zero-trust authentication without a separate bearer token.
- **pipenet**: Create a tunneled HTTPS endpoint via a relay server, making the gateway reachable from environments behind NAT.

```yaml
tunnel:
  tailscale:
    serve_port: 39401
    funnel_enabled: false
    auth_via_identity: true
  pipenet:
    server_url: "https://relay.pipenet.io"
    subdomain: "my-gateway"
```

### Protocol Support

- **MCP Version**: 2025-11-25 (latest)
- **Transports**: stdio, Streamable HTTP, SSE
- **JSON-RPC 2.0**: Full compliance

### Supported Backends

MCP Gateway supports all three MCP transport types. Any MCP-compliant server works -- here are common examples:

| Transport | Backend | Config Example |
|-----------|---------|----------------|
| **stdio** | `@anthropic/mcp-server-tavily` | `command: "npx -y @anthropic/mcp-server-tavily"` |
| **stdio** | `@modelcontextprotocol/server-filesystem` | `command: "npx -y @modelcontextprotocol/server-filesystem /path"` |
| **stdio** | `@modelcontextprotocol/server-github` | `command: "npx -y @modelcontextprotocol/server-github"` |
| **stdio** | `@modelcontextprotocol/server-postgres` | `command: "npx -y @modelcontextprotocol/server-postgres"` |
| **stdio** | `@modelcontextprotocol/server-brave-search` | `command: "npx -y @modelcontextprotocol/server-brave-search"` |
| **HTTP** | Any Streamable HTTP server | `http_url: "http://localhost:8080/mcp"` |
| **SSE** | Pieces, LangChain, etc. | `http_url: "http://localhost:39300/sse"` |

**stdio** backends are spawned as child processes. **HTTP** and **SSE** backends connect to already-running servers. Set `env:` for API keys, `headers:` for auth tokens, and `cwd:` for working directories -- see the [Configuration Reference](#backend) below.

## Quick Start

### Installation

**Homebrew (macOS/Linux):**
```bash
brew tap MikkoParkkola/tap
brew install mcp-gateway
```

**Cargo:**
```bash
cargo install mcp-gateway
```

**Docker:**
```bash
docker run -v /path/to/servers.yaml:/config.yaml \
  ghcr.io/mikkoparkkola/mcp-gateway:latest \
  --config /config.yaml
```

**Binary (from GitHub Releases):**
```bash
# macOS ARM64
curl -L https://github.com/MikkoParkkola/mcp-gateway/releases/latest/download/mcp-gateway-darwin-arm64 -o mcp-gateway
chmod +x mcp-gateway
```

### Usage

```bash
# Start with configuration file
mcp-gateway --config servers.yaml

# Override port
mcp-gateway --config servers.yaml --port 8080

# Debug logging
mcp-gateway --config servers.yaml --log-level debug
```

### Configuration

Create `servers.yaml`:

```yaml
server:
  port: 39400

meta_mcp:
  enabled: true

failsafe:
  circuit_breaker:
    enabled: true
    failure_threshold: 5
  retry:
    enabled: true
    max_attempts: 3

backends:
  tavily:
    command: "npx -y @anthropic/mcp-server-tavily"
    description: "Web search"
    env:
      TAVILY_API_KEY: "${TAVILY_API_KEY}"

  context7:
    http_url: "http://localhost:8080/mcp"
    description: "Documentation lookup"
```

### Client Configuration

Point your MCP client to the gateway:

```json
{
  "mcpServers": {
    "gateway": {
      "type": "http",
      "url": "http://localhost:39400/mcp"
    }
  }
}
```

## API Reference

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check with backend status |
| `/mcp` | POST | Meta-MCP mode (dynamic discovery) |
| `/mcp/{backend}` | POST | Direct backend access |

### Health Check Response

```json
{
  "status": "healthy",
  "version": "2.0.0",
  "backends": {
    "tavily": {
      "name": "tavily",
      "running": true,
      "transport": "stdio",
      "tools_cached": 3,
      "circuit_state": "Closed",
      "request_count": 42
    }
  }
}
```

## Configuration Reference

### Server

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `host` | string | `127.0.0.1` | Bind address |
| `port` | u16 | `39400` | Listen port |
| `request_timeout` | duration | `30s` | Request timeout |
| `shutdown_timeout` | duration | `30s` | Graceful shutdown timeout |

### Meta-MCP

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable Meta-MCP mode |
| `cache_tools` | bool | `true` | Cache tool lists |
| `cache_ttl` | duration | `5m` | Cache TTL |

### Failsafe

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `circuit_breaker.enabled` | bool | `true` | Enable circuit breaker |
| `circuit_breaker.failure_threshold` | u32 | `5` | Failures before open |
| `circuit_breaker.success_threshold` | u32 | `3` | Successes to close |
| `circuit_breaker.reset_timeout` | duration | `30s` | Half-open delay |
| `retry.enabled` | bool | `true` | Enable retries |
| `retry.max_attempts` | u32 | `3` | Max retry attempts |
| `retry.initial_backoff` | duration | `100ms` | Initial backoff |
| `retry.max_backoff` | duration | `10s` | Max backoff |
| `rate_limit.enabled` | bool | `true` | Enable rate limiting |
| `rate_limit.requests_per_second` | u32 | `100` | RPS per backend |

### Backend

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `command` | string | * | Stdio command |
| `http_url` | string | * | HTTP/SSE URL |
| `description` | string | | Human description |
| `enabled` | bool | | Default: true |
| `timeout` | duration | | Request timeout |
| `idle_timeout` | duration | | Hibernation delay |
| `env` | map | | Environment variables |
| `headers` | map | | HTTP headers |
| `cwd` | string | | Working directory |

*One of `command` or `http_url` required

## Environment Variables

| Variable | Description |
|----------|-------------|
| `MCP_GATEWAY_CONFIG` | Config file path |
| `MCP_GATEWAY_PORT` | Override port |
| `MCP_GATEWAY_HOST` | Override host |
| `MCP_GATEWAY_LOG_LEVEL` | Log level |
| `MCP_GATEWAY_LOG_FORMAT` | `text` or `json` |

## Metrics

With `--features metrics`:

```bash
curl http://localhost:39400/metrics
```

Exposes Prometheus metrics for:
- Request count/latency per backend
- Circuit breaker state changes
- Rate limiter rejections
- Active connections

## Performance

MCP Gateway is a local Rust proxy -- it adds minimal overhead between your client and backends.

| Metric | Value | Notes |
|--------|-------|-------|
| **Startup time** | ~8ms | Measured with `hyperfine` ([benchmarks](docs/BENCHMARKS.md)) |
| **Binary size** | 7.1 MB | Release build with LTO, stripped |
| **Gateway overhead** | <2ms per request | Local routing + JSON-RPC parsing (does not include backend latency) |
| **Memory** | Low | Async I/O via tokio; no per-request allocations for routing |

The gateway overhead is the time spent inside the proxy itself (request parsing, backend lookup, failsafe checks, response forwarding). Actual end-to-end latency depends on the backend -- a stdio subprocess adds ~10-50ms for process I/O, while an HTTP backend adds only network round-trip time.

For detailed benchmarks, see [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Troubleshooting

### Backend won't connect

**stdio backend fails to start:**
```bash
# Test the command directly to verify it works
npx -y @anthropic/mcp-server-tavily

# Check the gateway logs for the actual error
mcp-gateway --config servers.yaml --log-level debug
```

Common causes: missing `npx`/`node`, missing API key environment variable, or incorrect `command` path.

**HTTP/SSE backend unreachable:**
- Verify the backend server is running and listening on the configured URL.
- Check that `http_url` includes the full path (e.g., `http://localhost:8080/mcp`, not just `http://localhost:8080`).
- If the backend requires auth, set `headers:` in the backend config.

### Circuit breaker is open

When a backend fails 5 times consecutively, the circuit breaker opens and rejects requests for 30 seconds. Check the health endpoint to see circuit state:

```bash
curl http://localhost:39400/health | jq '.backends'
```

To adjust thresholds:
```yaml
failsafe:
  circuit_breaker:
    failure_threshold: 10   # more tolerance before opening
    reset_timeout: "15s"    # shorter recovery window
```

### Debugging requests

Enable debug logging to see every request routed through the gateway:

```bash
mcp-gateway --config servers.yaml --log-level debug
```

This shows: backend selection, tool invocations, circuit breaker state changes, retry attempts, and rate limiter decisions.

### Tools not appearing in search

- Verify the backend is running: check `gateway_list_servers` output.
- Tool lists are cached (default 5 minutes). Restart the gateway or wait for cache expiry after adding new backends.
- Confirm the backend responds to `tools/list` -- some servers require initialization first.

## Community Registry

Share, discover, and install capability definitions from the community. Browse the built-in registry of 52+ capabilities, search by keyword, or install from any GitHub repository.

```bash
mcp-gateway cap registry-list              # Browse all capabilities
mcp-gateway cap search weather             # Search by keyword
mcp-gateway cap install stock_quote --from-github  # Install from GitHub
```

Submit your own capabilities via pull request. See [docs/COMMUNITY_REGISTRY.md](docs/COMMUNITY_REGISTRY.md) for the full guide.

## Deployment

For production deployment (Docker, systemd, TLS/mTLS, reverse proxy, monitoring, and scaling), see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Building

```bash
git clone https://github.com/MikkoParkkola/mcp-gateway
cd mcp-gateway
cargo build --release
```

## Contributing

Contributions are welcome. The short version:

1. **Fork and branch** -- `git checkout -b feature/your-feature`
2. **Test** -- `cargo test` (all tests must pass)
3. **Lint** -- `cargo fmt && cargo clippy -- -D warnings`
4. **PR** -- open a pull request against `main` with a clear description
5. **Changelog** -- add an entry to [CHANGELOG.md](CHANGELOG.md) for user-facing changes

Look for issues labeled [`good first issue`](https://github.com/MikkoParkkola/mcp-gateway/labels/good%20first%20issue) or [`help wanted`](https://github.com/MikkoParkkola/mcp-gateway/labels/help%20wanted) to get started. For larger changes, open an issue first to discuss the approach.

Full details: [CONTRIBUTING.md](CONTRIBUTING.md)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Credits

Created by [Mikko Parkkola](https://github.com/MikkoParkkola)

Implements [Model Context Protocol](https://modelcontextprotocol.io/) version 2025-11-25.

[Changelog](CHANGELOG.md) | [Releases](https://github.com/MikkoParkkola/mcp-gateway/releases)
