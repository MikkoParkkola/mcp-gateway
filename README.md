# MCP Gateway

[![CI](https://github.com/MikkoParkkola/mcp-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/MikkoParkkola/mcp-gateway/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/mcp-gateway.svg)](https://crates.io/crates/mcp-gateway)
[![docs](https://img.shields.io/badge/docs-QUICKSTART-blue)](docs/QUICKSTART.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**One proxy, every tool. 95% context token savings.**

MCP Gateway sits between your AI client and your MCP servers. Instead of loading hundreds of tool definitions into every request, the AI gets 4 meta-tools and discovers the right one on demand -- like searching an app store instead of installing every app.

## Quick Start

```bash
cargo install mcp-gateway          # or: brew tap MikkoParkkola/tap && brew install mcp-gateway
mcp-gateway --config servers.yaml  # point at your config and go
```

Then connect your AI client to `http://localhost:39400/mcp`:

```json
{ "mcpServers": { "gateway": { "type": "http", "url": "http://localhost:39400/mcp" } } }
```

> Full walkthrough: [docs/QUICKSTART.md](docs/QUICKSTART.md)

## Why

| | Without Gateway | With Gateway |
|---|----------------|--------------|
| **Tools in context** | Every definition, every request | 4 meta-tools (~400 tokens) |
| **Token overhead** | ~15,000 tokens (100 tools) | ~400 tokens -- **97% savings** |
| **Cost at scale** | ~$0.22/request (Opus input) | ~$0.006/request |
| **Practical tool limit** | 20-50 (context pressure) | **Unlimited** -- on-demand discovery |
| **Add a REST API** | Build an MCP server (days) | Drop a YAML file (minutes) |

## Architecture

```
                     ┌─────────────────────────────────────────────────┐
                     │              MCP Gateway (:39400)               │
                     │                                                 │
  AI Client          │  ┌──────────────┐    ┌───────────────────┐      │
  (Claude, Cursor)   │  │  HTTP Router  │──>│    Meta-MCP        │      │
        |            │  │  (axum)       │   │  - list_servers    │      │
        |            │  │               │   │  - list_tools      │      │
   POST /mcp         │  │  /mcp    ─────┼──>│  - search_tools   │      │
   ─────────────────>│  │  /mcp/{id}───┼─┐ │  - invoke          │      │
        |            │  │  /health ────┼┐│ └────────┬──────────┘      │
   GET /mcp (SSE)    │  └──────────────┘││         │                  │
   ─────────────────>│                   ││ ┌───────v───────────┐      │
        |            │  ┌────────────────┘│ │  Backend Registry │      │
        <────────────│  │  Health         │ │  + Capability Sys │      │
   notifications     │  └────────────────┘│ └───────┬───────────┘      │
                     │                    │         │                  │
                     │  ┌─────────────────┘ ┌───────v───────────┐      │
                     │  │  Direct Access    │    Failsafes      │      │
                     │  │  /mcp/{backend}   │  Circuit Breaker  │      │
                     │  └───────┬──────────>│  Retry + Backoff  │      │
                     │          │           │  Rate Limiter     │      │
                     │          │           └───────┬───────────┘      │
                     │  ┌───────v───────────────────v────────────┐      │
                     │  │           Transport Layer              │      │
                     │  │  ┌────────┐  ┌────────┐  ┌─────────┐  │      │
                     │  │  │ stdio  │  │  HTTP  │  │   SSE   │  │      │
                     │  │  └───┬────┘  └───┬────┘  └────┬────┘  │      │
                     │  └──────┼───────────┼────────────┼───────┘      │
                     │  ┌──────v──┐  ┌─────v────┐  ┌────v───────┐      │
                     │  │Response │  │  OAuth   │  │  Secrets   │      │
                     │  │ Cache   │  │  Client  │  │ (Keychain) │      │
                     │  └─────────┘  └──────────┘  └────────────┘      │
                     └─────────────────────────────────────────────────┘
                                    |          |           |
                     ┌──────────────v──┐ ┌─────v────┐ ┌───v──────┐
                     │  MCP Server A   │ │ MCP Srv B│ │ REST API │
                     │  (stdio)        │ │ (HTTP)   │ │ (YAML)   │
                     └─────────────────┘ └──────────┘ └──────────┘
```

> Full design details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Features

- **Meta-MCP** -- 4 meta-tools replace hundreds of definitions. Search, discover, invoke on demand.
- **Any REST API as a tool** -- Drop a YAML capability file or import an OpenAPI spec. Hot-reloaded in ~500ms.
- **42 starter capabilities** -- 25 work with zero config (weather, Wikipedia, Hacker News, SEC filings, geocoding, and more).
- **Production failsafes** -- Circuit breaker, retry with backoff, rate limiting, health checks, graceful shutdown.
- **Response caching** -- Configurable TTLs per tool. Repeated calls return instantly.
- **OAuth 2.0** -- Per-backend OAuth with dynamic client registration and token refresh.
- **Auth & API keys** -- Bearer tokens, per-client API keys with rate limits and backend restrictions.
- **SSE streaming** -- Full Streamable HTTP transport support (MCP 2025-11-25).
- **Smart search ranking** -- Results ranked by your usage patterns. Persisted across restarts.
- **Capability registry** -- `mcp-gateway cap install weather` / `mcp-gateway cap search finance`.
- **Keychain integration** -- Store secrets in macOS Keychain or Linux secret-service, not env files.
- **Usage stats & cost tracking** -- Token savings, cache hit rates, invocation counts in real time.
- **Validate CLI** -- Lint capability YAMLs with 9 rules, SARIF output, and `--fix` auto-correction.
- **Response transforms** -- Per-capability field projection and PII redaction before responses reach the AI.
- **Playbooks** -- Multi-step tool chains via YAML. Execute with the `gateway_run_playbook` meta-tool.

## Validate CLI

Lint your capability files against 9 built-in rules. Outputs SARIF for CI integration.

```bash
mcp-gateway validate capabilities/         # lint all YAMLs in directory
mcp-gateway validate capabilities/ --fix   # auto-fix common issues
mcp-gateway validate my-cap.yaml -f sarif  # SARIF output for CI
```

## Response Transforms

Strip fields or redact PII before the response reaches the AI client. Configured per-capability:

```yaml
transform:
  project:
    - name
    - summary
    - status
  redact:
    - email
    - phone
```

See [examples/transform-example.yaml](examples/transform-example.yaml) for a full capability with transforms.

## Playbooks

Chain multiple tool invocations into a single reusable workflow:

```yaml
name: morning-briefing
steps:
  - tool: weather
    args: { location: "Helsinki" }
  - tool: hacker_news_top
    args: { count: 5 }
  - tool: summarize
    args: { texts: "$prev" }
```

Run with `gateway_run_playbook(name: "morning-briefing")`. See [examples/playbook-morning-briefing.yaml](examples/playbook-morning-briefing.yaml).

## Installation

| Method | Command |
|--------|---------|
| **Cargo** | `cargo install mcp-gateway` |
| **Homebrew** | `brew tap MikkoParkkola/tap && brew install mcp-gateway` |
| **Docker** | `docker run -v ./servers.yaml:/config.yaml ghcr.io/mikkoparkkola/mcp-gateway:latest --config /config.yaml` |
| **Binary** | [GitHub Releases](https://github.com/MikkoParkkola/mcp-gateway/releases) |

## How It Works

Your AI gets 4 meta-tools instead of hundreds:

| Meta-Tool | Purpose |
|-----------|---------|
| `gateway_list_servers` | List available backends |
| `gateway_list_tools` | List tools from a specific backend |
| `gateway_search_tools` | Search tools by keyword across all backends |
| `gateway_invoke` | Invoke any tool on any backend |

The AI searches for what it needs, invokes it, and moves on. Tool definitions load on demand, not upfront.

## Performance

| Metric | Value |
|--------|-------|
| Startup | ~8ms |
| Gateway overhead | <2ms per request |
| Binary size | 7.1 MB (release, stripped) |

Built in Rust with async I/O (tokio + axum). Benchmarks: [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Token Savings

The "95% savings" claim is backed by a reproducible benchmark (`python3 benchmarks/token_savings.py`).

The direct approach registers every backend tool definition in the LLM's system prompt. The meta-MCP approach registers only 3 gateway tools regardless of backend count. Token estimates use a conservative ~3.5 chars/token heuristic.

**Default scenario (5 backends, 20 tools each = 100 tools):**

| Approach | Tools in Prompt | Est. Tokens |
|----------|-----------------|-------------|
| Direct (all tools) | 100 | 26,412 |
| Meta-MCP (gateway) | 3 | 432 |

**Savings: 98.4% (61x fewer tokens)**

**Scaling across configurations:**

| Backends | Total Tools | Direct (tokens) | Gateway (tokens) | Savings |
|----------|-------------|-----------------|-----------------|---------|
| 1 | 10 | 2,609 | 432 | 83.4% |
| 3 | 45 | 11,949 | 432 | 96.4% |
| 5 | 100 | 26,412 | 432 | 98.4% |
| 10 | 200 | 52,869 | 432 | 99.2% |
| 10 | 300 | 80,052 | 432 | 99.5% |
| 20 | 500 | 132,697 | 432 | 99.7% |

Gateway token count is constant (432 tokens for 3 meta-tools) regardless of how many backends or tools exist. With a typical setup of 5+ backends the savings exceed 98%.

Reproduce locally: `python3 benchmarks/token_savings.py --backends 10 --tools-per-backend 30`

## Documentation

- [**Quickstart**](docs/QUICKSTART.md) -- Zero to working gateway in 5 minutes
- [**Architecture**](docs/ARCHITECTURE.md) -- System diagram, module map, data flow
- [**Benchmarks**](docs/BENCHMARKS.md) -- Startup, overhead, and throughput measurements
- [**Changelog**](CHANGELOG.md) -- Release history
- [**Contributing**](CONTRIBUTING.md) -- How to contribute

## License

[MIT](LICENSE)

## Credits

Created by [Mikko Parkkola](https://github.com/MikkoParkkola). Implements [Model Context Protocol](https://modelcontextprotocol.io/) version 2025-11-25.
