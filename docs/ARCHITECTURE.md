# Architecture

> One-page overview of MCP Gateway internals.

## System Diagram

```
                         ┌─────────────────────────────────────────────────┐
                         │              MCP Gateway (:39400)               │
                         │                                                 │
  AI Client              │  ┌──────────────┐    ┌───────────────────┐      │
  (Claude, Cursor, etc.) │  │  HTTP Router  │───>│    Meta-MCP       │      │
          |              │  │  (axum)       │    │  12-15 meta-tools:│      │
          |              │  │               │    │  - list_servers   │      │
   POST /mcp             │  │  /mcp    ─────┼───>│  - list_tools    │      │
   ──────────────────────>  │  /mcp/{id}───┼──┐ │  - search_tools  │      │
          |              │  │  /health ─────┼─┐│ │  - invoke        │      │
   GET /mcp (SSE)        │  └──────────────┘ ││ └───────┬───────────┘      │
   ──────────────────────>                    ││         │                  │
          |              │  ┌─────────────┐  ││ ┌───────v───────────┐      │
          |              │  │  Streaming   │  ││ │  Backend Registry │      │
          <──────────────│──│  (SSE Mux)   │  ││ │  + Capability Sys │      │
   notifications         │  └─────────────┘  ││ └───────┬───────────┘      │
                         │                   ││         │                  │
                         │  ┌────────────────┘│ ┌───────v───────────┐      │
                         │  │  Health         │ │    Failsafes      │      │
                         │  │  Endpoint       │ │  ┌─────────────┐  │      │
                         │  └────────────────┘│ │  │Circuit Break│  │      │
                         │                    │ │  │Retry+Backoff│  │      │
                         │  ┌─────────────────┘ │  │Rate Limiter │  │      │
                         │  │  Direct Access    │  └─────────────┘  │      │
                         │  │  /mcp/{backend}   └───────┬───────────┘      │
                         │  └────────┬──────────────────┤                  │
                         │           │                  │                  │
                         │  ┌────────v──────────────────v──────────┐      │
                         │  │         Transport Layer              │      │
                         │  │  ┌─────────┐ ┌────────┐ ┌─────────┐ │      │
                         │  │  │  stdio  │ │  HTTP  │ │  SSE    │ │      │
                         │  │  │(spawn)  │ │(POST)  │ │(stream) │ │      │
                         │  │  └────┬────┘ └───┬────┘ └────┬────┘ │      │
                         │  └───────┼──────────┼───────────┼──────┘      │
                         │          │          │           │             │
                         │  ┌───────v──┐ ┌─────v────┐ ┌───v────────┐    │
                         │  │ Response │ │  OAuth   │ │  Secrets   │    │
                         │  │ Cache    │ │  Client  │ │ (Keychain) │    │
                         │  └──────────┘ └──────────┘ └────────────┘    │
                         └─────────────────────────────────────────────────┘
                                        |          |           |
                         ┌──────────────v──┐ ┌─────v────┐ ┌───v──────┐
                         │  MCP Server A   │ │ MCP Srv B│ │ REST API │
                         │  (stdio)        │ │ (HTTP)   │ │ (YAML)   │
                         └─────────────────┘ └──────────┘ └──────────┘
```

## Module Map

Source files live in `src/`. Each module is split to 800 LOC or fewer.

| Module | File(s) | Responsibility |
|--------|---------|----------------|
| **gateway** | `gateway/` | Core server: axum router, request handling, session management |
| **identity_grants** | `identity_grants.rs` | Per-subject and per-agent grant contract for personal capabilities |
| **backend** | `backend/` | Backend lifecycle: spawn, connect, health tracking, tool caching |
| **transport** | `transport/` | Wire protocols: stdio subprocess I/O, HTTP client, SSE streaming |
| **protocol** | `protocol/` | MCP JSON-RPC types, version negotiation (2024-10-07 through 2025-11-25) |
| **config** | `config.rs` | YAML + env config loading via figment, env file support, `${VAR}` expansion |
| **capability** | `capability/` | REST-to-MCP bridge: load YAML definitions, execute HTTP calls, hot-reload |
| **cache** | `cache.rs` | Response cache with TTL eviction and per-capability overrides |
| **failsafe** | `failsafe/` | Circuit breaker (closed/open/half-open), retry with exponential backoff, token-bucket rate limiter |
| **oauth** | `oauth/` | OAuth 2.0 client: authorization code flow, token refresh, dynamic registration |
| **discovery** | `discovery/` | Meta-MCP logic: list, search (ranked), invoke routing |
| **ranking** | `ranking/` | Safety-aware adaptive search ranking, explanations, local feedback persistence |
| **registry** | `registry/` | Capability registry: install, search, list from local and remote sources |
| **secrets** | `secrets/` | Keychain integration (macOS/Linux), env var resolution, session caching |
| **stats** | `stats/` | Invocation counters, cache hit rates, token savings estimation |
| **validator** | `validator/` | Input validation for tool arguments against JSON Schema |
| **cli** | `cli/` | CLI argument parsing: `serve`, `stats`, `cap` subcommands |
| **error** | `error.rs` | Unified error types with `thiserror` |

## Data Flow

### Tool Discovery (Meta-MCP)

```
1. Client sends:  POST /mcp  { "method": "tools/call",
                    "params": { "name": "gateway_search_tools",
                                "arguments": { "query": "weather" } } }
2. Gateway:       discovery::search() -> iterate all backends -> match by name/description
3. Ranking:       ranking::rank() -> suppress unsafe/unavailable tools, then score
                  by relevance, safety, grant fit, trust, health, cost, latency,
                  freshness, and local feedback
                  (persisted in ~/.mcp-gateway/usage.json)
4. Response:      Return ranked matches with server, tool name, description,
                  input schema, score, and explanation metadata
```

### Tool Invocation

```
1. Client sends:  POST /mcp  { "method": "tools/call",
                    "params": { "name": "gateway_invoke",
                                "arguments": { "server": "X", "tool": "Y", ... } } }
2. Gateway:       Resolve backend "X" from registry
3. Cache check:   cache::get(backend, tool, args) -> if hit, return cached response
4. Failsafe:      circuit_breaker::check() -> retry::execute() -> rate_limiter::acquire()
5. Transport:     Route to backend via stdio / HTTP / SSE
6. Cache store:   cache::set(response, ttl)
7. Stats:         stats::record_invocation()
8. Response:      Return tool result to client
```

### Capability Execution (REST APIs)

```
1. Invocation targets a capability backend (e.g., "fulcrum")
2. capability::execute() loads the YAML definition
3. Build HTTP request: base_url + path, substitute {params},
   resolve {env.VAR} / {keychain.name}
4. Send HTTP request via reqwest
5. Extract response via response_path (optional JSON pointer)
6. Return as MCP tool result
```

## Key Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | Rust | Sub-10ms startup, <2ms routing overhead, zero-cost abstractions |
| HTTP framework | axum | Tokio-native, tower middleware, streaming support |
| Config format | YAML + figment | Human-readable, env override, dotenv loading |
| Default port | 39400 | Above ephemeral range, unlikely to conflict |
| Meta-MCP default | ON | Core value prop: compact tool surface with on-demand discovery |
| Capability format | Custom YAML ("fulcrum") | Simpler than OpenAPI for single-endpoint definitions |
| Cache | In-memory HashMap | Local proxy -- no need for Redis; bounded by max_entries |
| Search ranking | Safety-aware deterministic scoring | Keeps relevance primary while suppressing unsafe/unavailable tools and explaining signal-based downgrades; see `docs/adaptive_ranking.md` |

## Security Model

- **Auth** is disabled by default for local-only use. Enable for networked deployments.
- **Bearer tokens** support auto-generation, env vars, and literals.
- **API keys** support per-client rate limits, opt-in per-client circuit breakers, and backend restrictions.
- **Secrets** use OS keychain (macOS Keychain, Linux secret-service) -- never stored in config files.
- **OAuth** supports per-backend configuration with dynamic client registration.
- **`/health`** is always public (configurable via `auth.public_paths`).
