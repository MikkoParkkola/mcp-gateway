# MCP Gateway

[![CI](https://github.com/MikkoParkkola/mcp-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/MikkoParkkola/mcp-gateway/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/mcp-gateway.svg)](https://crates.io/crates/mcp-gateway)
[![Rust](https://img.shields.io/badge/rust-1.85+-blue.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Universal Model Context Protocol (MCP) Gateway** - Single-port multiplexing with Meta-MCP for ~97% context token savings. At $15/M input tokens (Claude Opus pricing), that reduction saves roughly $0.22 per request -- or **$220 per 1,000 requests** that would otherwise carry 100+ tool definitions.

## The Problem

MCP is powerful, but scaling to many servers creates problems:

| Without Gateway | With Gateway |
|----------------|--------------|
| 100+ tool definitions in context | 4 meta-tools |
| ~15,000 tokens overhead | ~400 tokens |
| Multiple ports to manage | Single port |
| Session loss on reconnect | Persistent proxy |
| Restart AI session to change MCP servers | Restart gateway (~8ms), session stays alive |
| No resilience | Circuit breakers, retries, rate limiting |

### Session Stability: Change MCP Servers Without Losing Context

With tools like Claude Code, changing your MCP server configuration normally means restarting the entire AI session -- losing your conversation history, working context, and flow.

MCP Gateway eliminates this. Your AI client connects to **one stable endpoint** (`localhost:39400`). Behind that endpoint, you can reconfigure freely:

- **REST API capabilities** (YAML files in capability directories) are **hot-reloaded automatically** -- add, modify, or remove a capability file and it's live within ~500ms. No restart of anything.
- **MCP backends** (stdio/HTTP/SSE servers in `config.yaml`) require a gateway restart to pick up changes -- but the gateway restarts in **~8ms**. Your AI session stays connected; just retry the tool call.

The net effect: you can experiment with new MCP servers, troubleshoot broken ones, or swap configurations **without ever losing your AI session context**.

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

## Features

### Meta-MCP Mode (~95% Token Savings)

Instead of loading 100+ tool definitions, Meta-MCP exposes 4 meta-tools:

| Meta-Tool | Purpose |
|-----------|---------|
| `gateway_list_servers` | List available backends |
| `gateway_list_tools` | List tools from a specific backend |
| `gateway_search_tools` | Search tools by keyword across all backends |
| `gateway_invoke` | Invoke any tool on any backend |

**Token Math:**
- Traditional: 100 tools × 150 tokens = 15,000 tokens
- Meta-MCP: 4 tools × 100 tokens = 400 tokens
- **Savings: 97%**

### Real-World Example

Suppose you have 12 MCP servers (Tavily, filesystem, GitHub, Slack, Postgres, Redis, Brave, Jira, Linear, Sentry, Datadog, PagerDuty) exposing 180+ tools. Without a gateway, every LLM request carries all 180 tool definitions -- roughly 27,000 tokens of context overhead before the conversation even starts.

With MCP Gateway, the LLM sees only 4 meta-tools (~400 tokens). It discovers and invokes the right tool on demand:

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

The gateway routes the call to the Tavily backend, applies circuit breaker/retry logic, and returns the result. The LLM never needed to load all 180 tool schemas -- it discovered and used exactly the one it needed.

### Production Failsafes

| Failsafe | Description |
|----------|-------------|
| **Circuit Breaker** | Opens after 5 failures, half-opens after 30s |
| **Retry with Backoff** | 3 attempts with exponential backoff |
| **Rate Limiting** | Per-backend request throttling |
| **Health Checks** | Periodic ping to detect failures |
| **Graceful Shutdown** | Clean connection termination |
| **Concurrency Limits** | Prevent backend overload |

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
