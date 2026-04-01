# MCP Gateway

[![CI](https://github.com/MikkoParkkola/mcp-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/MikkoParkkola/mcp-gateway/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/mcp-gateway.svg)](https://crates.io/crates/mcp-gateway)
[![Downloads](https://img.shields.io/crates/d/mcp-gateway.svg)](https://crates.io/crates/mcp-gateway)
[![Rust](https://img.shields.io/badge/rust-1.88+-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/crates/l/mcp-gateway.svg)](https://github.com/MikkoParkkola/mcp-gateway/blob/main/LICENSE)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![dependency status](https://deps.rs/repo/github/MikkoParkkola/mcp-gateway/status.svg)](https://deps.rs/repo/github/MikkoParkkola/mcp-gateway)
[![Capabilities](https://img.shields.io/badge/REST%20capabilities-70%2B-purple.svg)](https://github.com/MikkoParkkola/mcp-gateway/tree/main/capabilities)
[![MCP Protocol](https://img.shields.io/badge/MCP-2025--11--25-green.svg)](https://modelcontextprotocol.io)
[![Glama](https://glama.ai/mcp/servers/MikkoParkkola/mcp-gateway/badge)](https://glama.ai/mcp/servers/MikkoParkkola/mcp-gateway)

**Give your AI access to every tool it needs -- without burning your context window or building MCP servers.**

![demo](demo.gif)

MCP Gateway sits between your AI client and your tools. Instead of loading hundreds of tool definitions into every request, the AI gets 4 meta-tools and discovers the right one on demand -- like searching an app store instead of installing every app.

Public benchmark-backed claims in this README are sourced from [docs/BENCHMARKS.md](docs/BENCHMARKS.md) and the machine-readable [benchmarks/public_claims.json](benchmarks/public_claims.json), with CI checks to catch drift.

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

## Quick Start

### Install

**Homebrew (macOS/Linux):**
```bash
brew tap MikkoParkkola/tap && brew install mcp-gateway
```

**Cargo:**
```bash
cargo install mcp-gateway
```

**Binary download:**
```bash
# macOS ARM64 (M1/M2/M3/M4)
curl -L https://github.com/MikkoParkkola/mcp-gateway/releases/latest/download/mcp-gateway-darwin-arm64 -o mcp-gateway

# macOS Intel
curl -L https://github.com/MikkoParkkola/mcp-gateway/releases/latest/download/mcp-gateway-darwin-x86_64 -o mcp-gateway

# Linux x86_64
curl -L https://github.com/MikkoParkkola/mcp-gateway/releases/latest/download/mcp-gateway-linux-x86_64 -o mcp-gateway

chmod +x mcp-gateway
```

**Docker:**
```bash
docker run -v $(pwd)/gateway.yaml:/config.yaml \
  ghcr.io/mikkoparkkola/mcp-gateway:latest \
  --config /config.yaml
```

### Configure

Create `gateway.yaml`:

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

### Run

```bash
mcp-gateway --config gateway.yaml
```

### Connect your AI client

Point your MCP client (Claude Code, Cursor, Windsurf, etc.) at the gateway:

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

That's it. Your AI now has access to all backends through 4 meta-tools. It searches for tools with `gateway_search_tools` and invokes them with `gateway_invoke`.

## Key Benefits

### 1. Unlimited Tools, Minimal Tokens

The gateway exposes 4 meta-tools. Your AI searches for what it needs, then invokes it. Tool definitions load on demand, not upfront. Connect 500 tools and pay the token cost of 4.

**Token math** (Claude Opus @ $15/M input tokens, reproducible via `python benchmarks/token_savings.py --scenario readme`):
- **Without**: 100 tools x 150 tokens x 1,000 requests = 15M tokens = **$225**
- **With**: 4 meta-tools x 100 tokens x 1,000 requests = 0.4M tokens = **$6**

### 2. Any REST API to MCP Tool -- No Code

Turn any REST API into a tool by dropping a YAML file (~30 seconds) or importing an OpenAPI spec:

```bash
mcp-gateway cap import stripe-openapi.yaml --output capabilities/ --prefix stripe
```

The gateway ships with **70+ starter capabilities** -- weather, Wikipedia, GitHub, stock quotes, package tracking, and more. Capability YAMLs hot-reload in ~500ms, no restart needed.

### 3. Change Your MCP Stack Without Losing Your AI Session

Your AI connects once to `localhost:39400`. Behind it, capability YAMLs plus reloadable gateway config sections (including backend add/remove/update and routing/profile changes) can reload live via file watching, `gateway_reload_config`, or `POST /ui/api/reload`. Listener address changes report `restart_required`; `env_files` list changes stay startup-only and take effect after restart. Your AI session stays connected.

### 4. Production Resilience

Circuit breakers, retry with backoff, rate limiting, health checks, graceful shutdown, and concurrency limits. One flaky server won't take down your toolchain.

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                    MCP Gateway (:39400)                        │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  Meta-MCP: 4 Meta-Tools + Surfaced Tools                │  │
│  │  • gateway_list_servers    • gateway_search_tools       │  │
│  │  • gateway_list_tools      • gateway_invoke             │  │
│  └─────────────────────────────────────────────────────────┘  │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  Failsafes: Circuit Breaker │ Retry │ Rate Limit        │  │
│  └─────────────────────────────────────────────────────────┘  │
│                            │                                  │
│         ┌──────────────────┼──────────────────┐               │
│         ▼                  ▼                  ▼               │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐       │
│  │   Tavily    │    │  Context7   │    │   Pieces    │       │
│  │   (stdio)   │    │   (http)    │    │   (sse)     │       │
│  └─────────────┘    └─────────────┘    └─────────────┘       │
└───────────────────────────────────────────────────────────────┘
```

## Features

### Web Dashboard

Embedded web UI at `/ui` -- live status, searchable tools, server health, config viewer. Operator dashboard at `/dashboard`. Cost tracking at `/ui#costs`. All served from the same binary and port, no frontend build step.

### Security & Governance

| Feature | Description | Docs |
|---------|-------------|------|
| **Authentication** | Bearer tokens, API keys, per-client rate limits | [examples/auth.yaml](examples/) |
| **Per-Client Tool Scopes** | Allowlist/denylist tools per API key with glob patterns | [examples/per-client-tool-scopes.yaml](examples/per-client-tool-scopes.yaml) |
| **Security Firewall** | Credential redaction, prompt injection detection, shell/SQL/path traversal scanning | [CHANGELOG](CHANGELOG.md#260---2026-03-13) |
| **Cost Governance** | Per-tool, per-key, daily budgets with alert thresholds (log/notify/block) | [CHANGELOG](CHANGELOG.md#260---2026-03-13) |
| **Session Sandboxing** | Per-session call limits, duration caps, backend restrictions | [CHANGELOG](CHANGELOG.md#250---2026-03-12) |
| **mTLS** | Certificate-based auth for tool execution | [CHANGELOG](CHANGELOG.md#240---2026-02-25) |

### Integration & Discovery

| Feature | Description |
|---------|-------------|
| **Capability System** | REST API to MCP tool via YAML. Hot-reloaded. [70+ built-in](capabilities/). OpenAPI import supported. |
| **Transform Chains** | Namespace, filter, rename, and response transforms. [Example](examples/transform-example.yaml). |
| **Webhooks** | GitHub/Linear/Stripe push events as MCP notifications. [Docs](docs/WEBHOOKS.md). |
| **Auto-Discovery** | Discover MCP servers from existing client configs and running processes. |
| **Surfaced Tools** | Pin high-value tools directly in `tools/list` for one-hop invocation. |
| **Semantic Search** | TF-IDF ranked search across all tool names and descriptions. |
| **Tool Profiles** | Usage analytics per tool: latency, errors, trends. Persisted to disk. |
| **Config Export** | Export sanitized config as YAML/JSON. `mcp-gateway config export` |

### Protocol & Transport

- **MCP Version**: 2025-11-25 (latest spec)
- **Transports**: stdio, Streamable HTTP, SSE, WebSocket
- **Hot Reload**: Capability YAMLs plus reloadable gateway config sections are watched and reloaded live
- **Reload Outcomes**: `gateway_reload_config` and `/ui/api/reload` return `restart_required` for listener changes (for example `server.host` / `server.port`); `env_files` list edits remain startup-only
- **Config Discovery**: Auto-finds `gateway.yaml` in cwd, `~/.config/mcp-gateway/`, `/etc/mcp-gateway/`
- **"Did You Mean?"**: Levenshtein-based typo correction on tool names
- **Tool Annotations**: MCP 2025-11-25 `readOnlyHint`, `destructiveHint`, `openWorldHint`
- **Dynamic Descriptions**: Live tool/server counts in meta-tool descriptions
- **Tunnel Mode**: Expose via Tailscale or pipenet without opening ports
- **Shell Completions**: `mcp-gateway completions bash|zsh|fish`
- **Spec Preview** (opt-in): Filtered `tools/list` (SEP-1821), `tools/resolve` (SEP-1862), dynamic promotion

### Supported Backends

Any MCP-compliant server works. All three transport types supported:

| Transport | Examples |
|-----------|---------|
| **stdio** | `@anthropic/mcp-server-tavily`, `@modelcontextprotocol/server-filesystem`, `@modelcontextprotocol/server-github` |
| **HTTP** | Any Streamable HTTP server |
| **SSE** | Pieces, LangChain, etc. |

## API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check with backend status |
| `/mcp` | POST | Meta-MCP mode (dynamic discovery) |
| `/mcp/{backend}` | POST | Direct backend access |
| `/ui` | GET | Web dashboard |
| `/dashboard` | GET | Operator dashboard |
| `/metrics` | GET | Prometheus metrics (with `--features metrics`) |

## Performance

| Metric | Value | Notes |
|--------|-------|-------|
| **Startup time** | ~8ms | Measured with `hyperfine` ([benchmarks](docs/BENCHMARKS.md)) |
| **Binary size** | ~12-13 MB | Release build with LTO, stripped |
| **Hot-path microbenchmarks** | Included | Criterion suite covers registry, parsing, cache-key, firewall, and semantic search hot paths |
| **End-to-end latency** | Backend-dependent | Measure with your real MCP servers and REST APIs rather than relying on a synthetic single number |

## Documentation

| Document | Contents |
|----------|----------|
| [Quick Start](docs/QUICKSTART.md) | Zero to running in 2 minutes |
| [Configuration Reference](docs/QUICKSTART.md#configuration) | All config options |
| [Deployment Guide](docs/DEPLOYMENT.md) | Docker, systemd, TLS/mTLS, scaling |
| [OpenAPI Import](docs/OPENAPI_IMPORT.md) | Generate capabilities from OpenAPI specs |
| [Webhooks](docs/WEBHOOKS.md) | Event integration setup |
| [Community Registry](docs/COMMUNITY_REGISTRY.md) | Share and install capabilities |
| [Benchmarks](docs/BENCHMARKS.md) | Performance measurements |
| [Changelog](CHANGELOG.md) | Release history |

## Troubleshooting

**Backend won't connect?** Test the command directly (`npx -y @anthropic/mcp-server-tavily`), then check gateway logs with `--log-level debug`.

**Circuit breaker open?** Check `curl localhost:39400/health | jq '.backends'`. Adjust thresholds in `failsafe.circuit_breaker`.

**Tools not appearing?** Verify the backend is running (`gateway_list_servers`). Tool lists are cached for 5 minutes.

## Contributing

1. Fork and branch (`git checkout -b feature/your-feature`)
2. Test (`cargo test`) and lint (`cargo fmt && cargo clippy -- -D warnings`)
3. PR against `main` with a clear description and [CHANGELOG](CHANGELOG.md) entry

See [CONTRIBUTING.md](CONTRIBUTING.md) for full details. Look for [`good first issue`](https://github.com/MikkoParkkola/mcp-gateway/labels/good%20first%20issue) or [`help wanted`](https://github.com/MikkoParkkola/mcp-gateway/labels/help%20wanted) to get started.

## License

MIT License -- see [LICENSE](LICENSE) for details.

## Credits

Created by [Mikko Parkkola](https://github.com/MikkoParkkola). Implements [Model Context Protocol](https://modelcontextprotocol.io/) version 2025-11-25.

[Changelog](CHANGELOG.md) | [Releases](https://github.com/MikkoParkkola/mcp-gateway/releases)
