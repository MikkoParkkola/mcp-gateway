# MCP Gateway

[![Crates.io](https://img.shields.io/crates/v/mcp-gateway.svg)](https://crates.io/crates/mcp-gateway)
[![Rust](https://img.shields.io/badge/rust-1.85+-blue.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Universal Model Context Protocol (MCP) Gateway** - Single-port multiplexing with Meta-MCP for ~95% context token savings.

## The Problem

MCP is powerful, but scaling to many servers creates problems:

| Without Gateway | With Gateway |
|----------------|--------------|
| 100+ tool definitions in context | 4 meta-tools |
| ~15,000 tokens overhead | ~400 tokens |
| Multiple ports to manage | Single port |
| Session loss on reconnect | Persistent proxy |
| No resilience | Circuit breakers, retries, rate limiting |

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

## Building

```bash
git clone https://github.com/MikkoParkkola/mcp-gateway
cd mcp-gateway
cargo build --release
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Credits

Created by [Mikko Parkkola](https://github.com/MikkoParkkola)

Implements [Model Context Protocol](https://modelcontextprotocol.io/) version 2025-11-25.
