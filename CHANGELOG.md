# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.4.0] - 2026-02-25

### Added

- **FastMCP 3.0 Provider Transforms & Playbook Engine** (#32): Dynamic tool transformation
  engine for FastMCP 3.0-compatible backends. `Provider` trait with `McpProvider`,
  `CapabilityProvider`, and `CompositeProvider` implementations. `TransformChain` with
  namespace, filter, rename, and response transforms.
- **LLM Key Server — OIDC to Scoped API Keys** (#43): Convert OIDC identity tokens to
  short-lived, capability-scoped API keys. `InMemoryTokenStore` with dual DashMap indices
  for O(1) validation and revocation. Background reaper for expired tokens. RFC 8693 token
  exchange endpoint with constant-time admin token comparison.
- **mTLS Authenticated Tool Access** (#51): Certificate-based authorization for tool
  execution. Client certificate verification against configured CAs. Per-capability mTLS
  enforcement with policy engine and cert identity extraction.
- **O(1) Tool Registry Lookup** (#78): `IndexedCapabilities` with `HashMap<String, usize>`
  name index. `get()` and `has_capability()` now O(1). Pre-built MCP Tool cache eliminates
  per-request `to_mcp_tool()` computation. Load dedup reduced from O(n²) to O(n).
- **Query Parameter Auth Injection** (`auth.param`): APIs requiring credentials as query
  parameters (e.g., `?apiKey=...`) now supported natively. No YAML workarounds needed.

### Fixed

- **Static Parameters in GET Requests**: `static_params` defined in capability YAML were
  merged into the substitution context but never appended as actual query parameters.
  Weather, recipe search, and other capabilities now send all configured static params.
- **XML Response Parsing**: Added `quick-xml` for XML-to-JSON conversion. Executor
  auto-detects XML `Content-Type` and parses accordingly. ECB exchange rates (29 EUR
  currency pairs) now working.
- **Stats Endpoint Performance**: `gateway_get_stats` replaced sequential `get_tools().await`
  loop (24 backends × 30s timeout worst case) with non-blocking `cached_tools_count()`.
  Response time reduced from >30s to ~0.1s.
- **Registry Test Assertions**: Updated capability count and metadata assertions to match
  post-dedup state (38 bundled capabilities).
- **Merge Conflict Resolution**: Resolved 6 conflict markers across Cargo.toml, config.rs,
  server.rs, and router.rs from stale stash pop.

### Changed

- **Capability YAML Naming Convention** (CAP-010): All capability YAML files renamed to
  match the `name` field declared in their configuration.
- **Capability Validator**: Support for non-REST services, complex placeholders, and
  runtime-injected auth placeholder whitelisting.

## [2.2.0] - 2026-02-13

### Added

- **Validate CLI** (`mcp-gateway validate`): Lint capability YAMLs against 9 built-in rules.
  SARIF output for CI integration. `--fix` flag auto-corrects common issues.
- **Response Transforms**: Per-capability field projection and PII redaction applied before
  the response reaches the AI client. Configured via `transform` block in capability YAML.
- **Playbooks**: Multi-step tool chains defined in YAML. Executed via the
  `gateway_run_playbook` meta-tool. Steps can reference previous outputs with `$prev`.

## [2.1.0] - 2026-02-13

### Added

- **Response Caching**: Tool responses cached with configurable TTLs.
  Per-capability `cache_ttl` override. Configurable `default_ttl` and `max_entries`.
- **Usage Statistics & Cost Tracking**: Real-time token savings tracking via
  `gateway_get_stats` meta-tool and `mcp-gateway stats` CLI command.
- **Capability Registry**: Install community capabilities with
  `mcp-gateway cap install <name>`. Search, list, and fetch from GitHub.
- **Smart Search Ranking**: `gateway_search_tools` results ranked by usage frequency.
  Persisted across restarts in `~/.mcp-gateway/usage.json`.
- **Keychain Integration**: Store API keys in macOS Keychain or Linux secret-service
  via `{keychain.name}` syntax. Session-cached for performance.
- **42 Starter Capabilities**: 25 zero-config (weather, Wikipedia, geocoding, Hacker News,
  npm/PyPI, country info, public holidays, etc.) and 17 free-tier (Brave Search, stock
  quotes, movies, IP geolocation, recipes, package tracking).
- **OpenAPI Import**: `mcp-gateway cap import spec.yaml` generates capability YAMLs
  from OpenAPI/Swagger specs automatically.
- **Metacognition Verification**: Capability for AI self-verification workflows.
- **Integration Tests**: Full test suite covering all 5 major features.
- **87 Unit Tests**: Comprehensive coverage across the codebase.

### Changed

- **Consolidated capabilities**: Registry and capabilities merged into single
  `capabilities/` directory as source of truth.
- **Large files split**: All source files refactored to 800 LOC or fewer.

### Fixed

- Resolved all 243 clippy pedantic warnings; `#![warn(missing_docs)]` enabled.

## [2.0.0] - 2025-01-25

### Changed

- **BREAKING**: Complete rewrite from Python to Rust
- Now requires Rust 1.85+ (Edition 2024)

### Added

- **Rust Implementation**: Full async/await with tokio runtime
- **MCP Protocol**: 2025-11-25 (latest specification)
- **Authentication**: Bearer token and API key auth with per-client rate limits
  and backend restrictions. Supports `auto`, `env:VAR`, or literal tokens.
- **Streaming / SSE**: Real-time backend notifications via Server-Sent Events.
  Notification multiplexer routes backend events to connected clients.
- **OAuth Support**: Per-backend OAuth configuration with dynamic client registration.
- **Failsafes**:
  - Circuit breaker with configurable thresholds
  - Exponential backoff retry (backoff crate)
  - Rate limiting (governor crate)
  - Concurrency limits per backend
- **Transport Support**:
  - stdio: Subprocess with JSON-RPC over stdin/stdout
  - HTTP: Streamable HTTP POST with session management
  - SSE: Server-Sent Events parsing
- **Architecture**:
  - Axum HTTP server with graceful shutdown
  - DashMap for lock-free concurrent access
  - Health checks and idle backend hibernation
  - Signal handling (SIGINT/SIGTERM)
- **Environment**: `env_files` config field loads `.env` files with `~` expansion
  before variable resolution.
- **Docker Support**: Official container image at `ghcr.io/mikkoparkkola/mcp-gateway`.
- **Homebrew**: `brew install MikkoParkkola/tap/mcp-gateway`.
- **JSON Logging**: `--log-format json` for structured log output.
- **Prometheus Metrics**: Optional `--features metrics` for request count, latency,
  circuit breaker state changes, and rate limiter rejections.

### Removed

- Python implementation (see v1.0.0 for Python version)
- Pydantic configuration (replaced with figment + serde)

## [1.0.0] - 2025-01-24

### Added

- Initial release of MCP Gateway (Python implementation)
- Meta-MCP Mode: 4 meta-tools for dynamic tool discovery
- Transport support: stdio, HTTP, SSE
- Configuration via YAML with Pydantic validation
- systemd/launchd service templates

[Unreleased]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.2.0...HEAD
[2.2.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/MikkoParkkola/mcp-gateway/releases/tag/v1.0.0
