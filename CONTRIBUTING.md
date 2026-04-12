# Contributing to MCP Gateway

## Development Setup

### Prerequisites

- **Rust 1.88+** (edition 2024): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- **Node.js** (only for testing stdio backends that use `npx`)

### Build and Test

```bash
git clone https://github.com/YOUR_USERNAME/mcp-gateway
cd mcp-gateway
cargo build
cargo test --all-features   # full suite, all must pass
cargo run -- init    # Generate a starter config
cargo run -- serve --config gateway.yaml --log-level debug
```

### Full CI Check (Run Before Pushing)

```bash
cargo fmt --all -- --check && \
cargo clippy --all-features -- -D warnings && \
cargo test --all-features && \
python3 benchmarks/token_savings.py --scenario readme --json
```

### Formal Verification (Kani)

`mcp-gateway` also has targeted Kani proofs for small state-machine logic.

```bash
cargo install --locked kani-verifier
cargo kani setup
cargo kani --output-format=terse
```

## Code Organization

Source in `src/`, each module kept to **800 lines or fewer**. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full diagram.

```
src/
  main.rs              Entry point, CLI dispatch
  lib.rs               Library root, module declarations
  error.rs             Unified error types (thiserror)
  cli/                 CLI parsing (clap derive): Cli, Command, CapCommand, ToolCommand
  config/              Configuration (figment: YAML + env vars)
    mod.rs               Config, ServerConfig, BackendConfig, TransportConfig
    features.rs          Auth, cache, security, key server, streaming configs
  gateway/             Core server
    server.rs            Gateway struct, startup, shutdown
    router/              Axum router and request handlers
    auth.rs              Bearer token / API key auth
    proxy.rs             Backend proxy manager
    streaming.rs         SSE notification multiplexer
    meta_mcp/            Meta-MCP tool implementations (search, invoke, list)
    oauth/               OAuth 2.0 (agent auth, OIDC JWT)
    ui/                  Embedded web dashboard (feature: webui)
    webhooks/            Webhook receiver
  backend/             Backend lifecycle (spawn, connect, health, tool cache)
  transport/           Wire protocols
    mod.rs               Transport trait
    stdio.rs             Subprocess I/O (stdin/stdout JSON-RPC)
    http/                HTTP client (Streamable HTTP + SSE)
    websocket.rs         WebSocket transport
  protocol/            MCP JSON-RPC types, version negotiation
  capability/          REST-to-MCP bridge (YAML defs, executor, hot-reload)
  failsafe/            Circuit breaker, retry, rate limiter, health checks
  security/            Tool policy engine, input sanitization
  cache.rs             Response cache with TTL
  secrets.rs           Keychain/env credential resolution
  validator/           Capability YAML linter (agent-UX rules)
  mtls/                Mutual TLS authentication
  key_server/          OIDC identity to scoped API key exchange
```

## Adding a New Capability (YAML)

The easiest way to contribute. No Rust needed.

**1. Create** a YAML file in the appropriate `capabilities/` subdirectory:

```yaml
fulcrum: "1.0"
name: my_api_tool
description: One sentence -- what it does, what API it uses.
schema:
  input:
    type: object
    properties:
      query:
        type: string
        description: Search query
    required: [query]
providers:
  primary:
    service: rest
    cost_per_call: 0
    timeout: 10
    config:
      base_url: https://api.example.com
      path: /v1/search
      method: GET
      params:
        q: "{query}"
cache:
  strategy: exact
  ttl: 300
auth:
  required: false
  type: none
metadata:
  category: knowledge
  tags: [search, free]
  cost_category: free
  read_only: true
  rate_limit: 1000 req/day
  docs: https://api.example.com/docs
```

**2. Validate and test:**

```bash
cargo run -- cap validate capabilities/knowledge/my_api_tool.yaml
cargo run -- cap test capabilities/knowledge/my_api_tool.yaml --args '{"query": "test"}'
cargo run -- validate capabilities/knowledge/my_api_tool.yaml
```

**Guidelines:**
- Zero-config (no API key) capabilities are preferred.
- Use `env:VAR_NAME` or `keychain:name` for credentials. Never hardcode secrets.
- Write a clear, specific `description` -- the AI reads it to decide tool selection.
- Set `read_only: true` for GET-only endpoints.
- Document rate limits in `metadata.rate_limit`.
- Place files in the correct category subdirectory.

## Adding a New Transport

**1. Implement the `Transport` trait** in `src/transport/`:

```rust
#[async_trait]
impl Transport for MyTransport {
    async fn request(&self, method: &str, params: Option<Value>) -> Result<JsonRpcResponse>;
    async fn notify(&self, method: &str, params: Option<Value>) -> Result<()>;
    fn is_connected(&self) -> bool;
    async fn close(&self) -> Result<()>;
}
```

**2. Add config variant** to `TransportConfig` in `src/config/mod.rs`, update `transport_type()`.

**3. Wire into** `src/backend/mod.rs` for config-based selection.

**4. Add tests** -- unit tests in the transport module, integration tests in `tests/`.

## Code Style

- **Formatting:** `cargo fmt` before every commit. CI rejects unformatted code.
- **Linting:** `cargo clippy --all-features -- -D warnings`. Pedantic warnings are promoted to errors in CI.
- **Safety:** `unsafe` code is denied at the crate level. No exceptions.
- **Errors:** `thiserror` for typed errors, `anyhow` for application-level.
- **Logging:** `tracing` macros (`info!`, `debug!`, `warn!`), never `println!`.
- **Concurrency:** `Arc` for shared state, `dashmap`/`parking_lot` for concurrent maps.
- **Config structs:** derive `Serialize`, `Deserialize`, use `#[serde(default)]`.

Allowed clippy exceptions (in `Cargo.toml`): `module_name_repetitions`, `must_use_candidate`, `missing_errors_doc`.

## Pull Request Process

1. **Branch** from `main`: `git checkout -b feature/your-feature`
2. **Verify:** `cargo fmt --all -- --check && cargo clippy --all-features -- -D warnings && cargo test --all-features && python3 benchmarks/token_savings.py --scenario readme --json`
3. **Document:** Update README.md for user-facing features. Add CHANGELOG.md entry.
4. **Open PR** with a clear description of what changed and why.
5. **CI must pass.** Formatting, clippy pedantic, and the full test suite.

Smaller PRs are reviewed faster. For large changes, open an issue first.

## Architecture Decisions

Changes affecting public API, config schema, new dependencies, transport protocols, or security features should be discussed in a GitHub issue before implementation. Design docs live in `docs/design/`.

## Good First Issues

Look for [`good first issue`](https://github.com/MikkoParkkola/mcp-gateway/labels/good%20first%20issue) or [`help wanted`](https://github.com/MikkoParkkola/mcp-gateway/labels/help%20wanted). Good starters: adding a zero-config capability, improving error messages, adding edge-case tests, documentation.

## License

By contributing, you agree your contributions will be licensed under the MIT License.
