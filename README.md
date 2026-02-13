# MCP Gateway

[![CI](https://github.com/MikkoParkkola/mcp-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/MikkoParkkola/mcp-gateway/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/mcp-gateway.svg)](https://crates.io/crates/mcp-gateway)
[![Rust](https://img.shields.io/badge/rust-1.85+-blue.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Give your AI access to every tool it needs -- without burning your context window or building MCP servers.**

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

### 5. Response Caching

Tool responses are cached with configurable TTLs. Repeated calls return instantly from cache.

```yaml
# In capability YAML
cache_ttl: 300  # 5 minutes

# In config.yaml
cache:
  enabled: true
  default_ttl: 60s
  max_entries: 10000
```

### 6. Usage Stats & Cost Tracking

Track token savings in real-time. The gateway adds a 5th meta-tool `gateway_get_stats`:

```bash
mcp-gateway stats --price 15.0
```

Returns invocations, cache hit rate, tokens saved, estimated cost savings.

### 7. Capability Registry

Install community capabilities with one command:

```bash
mcp-gateway cap install weather
mcp-gateway cap search finance
mcp-gateway cap registry-list
mcp-gateway cap install stripe --from github  # fetch from GitHub
```

### 8. Smart Search Ranking

`gateway_search_tools` results are ranked by your usage patterns. Tools you use frequently appear first. Usage persists across restarts in `~/.mcp-gateway/usage.json`.

### 9. Keychain Integration

Store API keys securely in your system keychain instead of env files:

```yaml
# macOS Keychain
params:
  token: "{keychain.finnhub-api-key}"

# Add secret: security add-generic-password -s 'finnhub-api-key' -a 'mcp-gateway' -w 'YOUR_KEY'
```

Supports macOS Keychain and Linux secret-service. Session-cached for performance.

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

## Configuration Reference

### Response Caching

```yaml
cache:
  enabled: true          # Enable/disable response cache (default: true)
  default_ttl: 60s       # Default cache TTL (default: 60s)
  max_entries: 10000     # Max cached responses (default: 10000)
```

### Usage Statistics

```yaml
stats:
  enabled: true          # Enable stats tracking (default: true)
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
