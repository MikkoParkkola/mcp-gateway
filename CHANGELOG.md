# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Windows x86_64 release artifact**: release workflow now builds and publishes `mcp-gateway-windows-x86_64.exe` for `x86_64-pc-windows-msvc`.

### CI / Build

- **Windows compile coverage in CI**: `ci.yml` now runs `cargo check --all-features` on `windows-latest` in addition to the existing Linux checks.

### Docs

- **README Windows install path**: install table and direct-download section now include the Windows MSVC release binary.

### Tests

- **Windows path regressions**: added coverage proving Windows-style path separators do not bypass tool-poisoning detection and do not destabilize capability hash pinning.

## [2.11.0] - 2026-04-25

### Changed

- **Dual licensing introduced** (Path C, MIK-3034 / MIK-3036): designated Enterprise Edition modules are now licensed under PolyForm Noncommercial 1.0.0; everything else remains MIT. See [LICENSE-EE.md](LICENSE-EE.md) and the License section of the README for the full file list.
- Every EE-designated source file now carries an `// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0` header.
- Releases prior to v2.11.0 remain entirely MIT and stay MIT forever; the new license terms apply only to commits in v2.11.0 and later that touch EE-designated paths.

### Added

- **Output schema enforcement** in `MetaMcp::invoke`: tool results are validated against the capability's declared output schema for both meta-MCP and backend-routed dispatch paths. Non-conforming results return an LLM-readable "Tool result validation failed" error so agents can self-repair.

## [2.10.0] - 2026-04-16

### Security

- **Destructive confirmation gate** (OWASP ASI09): Meta-tools annotated as destructive now require explicit user confirmation before execution, preventing unintended data loss from autonomous agents.
- **HMAC-SHA256 message signing** (OWASP ASI07, ADR-001): Inter-agent messages carry HMAC-SHA256 signatures with nonce-based replay protection, ensuring message integrity and authenticity across the gateway mesh.
- **Anomaly blocking gate** (OWASP ASI10): Anomaly detector promoted from warn-only to active blocking — anomalous tool invocation patterns are now rejected, not just logged.
- **Response content inspection**: Outbound responses scanned for credential exfiltration patterns (API keys, tokens, secrets) before reaching the AI client.
- **Tool poisoning validator**: Hash-pinned capability definitions detect tampering in OpenAPI-imported tool schemas.

### Added

- **A2A transport adapter — Phase 1**: Google Agent2Agent (A2A) protocol support with types, client, translator, and provider. Proxy A2A agents as native MCP backends. Feature-gated behind `a2a` (included in defaults).
- **Upgrade command** (`mcp-gateway upgrade`): Version-stamp tracking, what's-new registry with arrow-style output, config backup before migrations, and post-upgrade migration framework.
- **`gateway_reload_capabilities` meta-tool**: Agent-callable hot-reload of capability definitions without gateway restart.
- **FSM state-gated tool visibility** (#113): Finite state machine controls which tools are surfaced based on session state, enabling multi-step workflows where tools appear/disappear as the conversation progresses.
- **Structured self-healing error responses** (#115): Tool invocation errors now include structured recovery hints (retry, fallback tool, parameter correction) for autonomous agent self-repair.
- **Response transforms wired into `gateway_invoke`** (#118): Per-capability field projection and PII redaction now applied inline during tool invocation, not just in playbooks.
- **Universal protocol adapters**: GraphQL and JSON-RPC 2.0 adapters join HTTP REST — backends speaking any of the 3 protocols are proxied transparently.
- **SKILL.md / agentskills.io compatibility** (#114): Parser, registry, and CLI for the emerging agent skills specification.
- **Multi-platform MCP guides**: Prompts and annotations tailored for Claude, GPT, Gemini, and other LLM clients.
- **Trawl web extraction capability**: Structured web content extraction as a built-in capability.
- **8 knowledge capabilities**: Gzip/deflate/brotli compression added to reqwest; 8 new knowledge-domain capabilities bundled.
- **OAuth refresh improvements**: `client_id`/`client_secret` sent on token refresh; Google capabilities migrated to new auth flow.
- **Kani formal verification proofs**: State machine and kill-switch budget decision correctness proved with Kani.

### Changed

- **Unified error handling**: Router, SSE, WebUI, webhook, and middleware error responses consolidated into shared HTTP error builders with consistent JSON-RPC error codes.
- **Config runtime contract**: Reload outcomes now distinguish restart-required vs. hot-reloadable changes; restart-required outcomes exposed to callers.
- **Backend metadata cache**: Coalesced cache refreshes with shared snapshots reduce redundant backend queries.
- **Meta-MCP prompt cache**: Isolated into dedicated module for testability.
- **Prometheus metrics hardened**: Install and export logic made more robust.

### Fixed

- Missing `KeyInit` import for HMAC message signing.
- Clippy `doc_markdown` warnings in invoke.rs.
- Skills parser doc comment incorrectly compiled as doctest.
- Stale "4 meta-tools" claims removed from all public surfaces.
- JSON-RPC response serialization and contract hardening.
- Stdio request parsing alignment and pending-write clearing on failure.
- Backend notification routing via `notify`.
- Provider tool content preservation.
- Transform chain error context propagation.
- HTTP close header contract alignment.
- Public capability count claims updated (93 to 101).

### Docs

- **OWASP Agentic AI compliance matrix**: 8/10 Top 10 items covered, with per-item status and mitigation references.
- **ADR-001**: Inter-agent message signing design (OWASP ASI07).
- **ADR-002**: A2A transport adapter design.
- **AP2/Galileo evaluation**: Independent agent protocol evaluation results.
- **README**: Agent-first install flow, OWASP 8/10 badge, independent review links (Ruach Tov), VS Code / Cursor one-click install badges, tool count corrections.
- **CODEOWNERS** added.

### CI / Build

- TruffleHog secrets scanning job.
- Workflow action SHAs pinned.
- Release workflow lint fix and pre-publish gate.
- Published crate contents curated (`include` list).
- Dependabot automation added.
- Smithery manifest added.

### Tests

- Firewall action resolution proof.
- Kill-switch budget decision proof.
- Kani state machine proofs.
- Meta-MCP tool-count assertions updated for `gateway_reload_capabilities`.
- README startup claim guards.

## [2.9.1] - 2026-03-24

### Changed

- **refactor: extract `build_meta_mcp` helper** — ~110 lines of duplicated Meta-MCP construction logic consolidated into a single reusable function.

### Fixed

- **Notion capability `database_id` parent type** — `notion_create_page.yaml` now correctly supports `database_id` as a parent type in addition to `page_id`.

### Dependencies

- **tokio-tungstenite** bumped to 0.29.0.

### Tests

- **6 new stdio edge-case tests** — covers malformed JSON, empty lines, oversized payloads, concurrent requests, graceful shutdown, and partial reads (2576 total).

## [2.9.0] - 2026-03-24

### Added

- **Native stdio transport** (`mcp-gateway serve --stdio`): gateway now reads newline-delimited JSON-RPC from stdin and writes responses to stdout, enabling direct use as a Claude Code / MCP stdio subprocess without a bridge script. Supports all MCP methods (`initialize`, `tools/list`, `tools/call`, `prompts/*`, `resources/*`, `logging/setLevel`, `ping`) and batch requests. Reuses the same `MetaMcp` dispatch logic as the HTTP server.
- **5 new capability YAML files**:
  - `capabilities/productivity/notion_create_page.yaml` — create a Notion page under any parent page or database
  - `capabilities/finance/stripe_create_payment_intent.yaml` — create a Stripe PaymentIntent (modern payments API)
  - `capabilities/developer/github_create_issue.yaml` — create a GitHub issue with labels, assignees, and milestone
- **`capabilities/developer/` directory** — new top-level category for developer-tool capabilities

## [2.7.3] - 2026-03-16

### Added

- **WebUI: Cost tracking dashboard** — new "Costs" tab at `/ui#costs` showing aggregate spend, per-key and per-session breakdowns with stat cards and tables. Backed by `GET /ui/api/costs` endpoint (admin-only, feature-gated behind `cost-governance`).

## [2.7.2] - 2026-03-15

### Fixed

- **Dependency minimum versions raised** — `Cargo.toml` version constraints now exclude all known vulnerable ranges: `bytes` ≥1.11.1 (RUSTSEC-2026-0007), `chrono` ≥0.4.20 (RUSTSEC-2020-0159), `rustls` ≥0.23.18 (RUSTSEC-2024-0399), `time` ≥0.3.47 (RUSTSEC-2026-0009), `tracing-subscriber` ≥0.3.20 (RUSTSEC-2025-0055).

### Added

- **Glama registry metadata** — `glama.json` for MCP server registry scoring and author verification.
- **Automated crates.io publishing** — release workflow now auto-publishes to crates.io on tag push.

## [2.7.1] - 2026-03-14

### Fixed

- **WebUI: JS syntax error breaking all views** — orphaned code block with top-level `return` statements caused `Uncaught SyntaxError: Illegal return statement`, preventing the entire UI from loading in any browser.
- **WebUI: missing Cache-Control header** — `/ui` response now sends `no-cache, no-store, must-revalidate` to prevent browsers from serving stale HTML after gateway rebuilds.
- **WebUI: confusing auth indicator** — when authentication is disabled, the auth bar now auto-detects this and shows a green "Auth disabled" status instead of the misleading red "Not authenticated" with a non-functional "Set API Key" link.

## [2.7.0] - 2026-03-14

### Added

- **Intelligent Tool Surfacing** (RFC-0081): Static tool pinning via `surfaced_tools` config — operators can expose high-value backend tools directly in `tools/list` for one-hop invocation while preserving ~95% context token savings for the rest.
- **Tool Annotations** (MCP 2025-11-25): All meta-tools now carry `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint` annotations. `gateway_search_tools` includes `outputSchema`.
- **"Did You Mean?" suggestions**: Levenshtein-based typo correction on both meta-tool dispatch (`handle_tools_call`) and backend tool invocation (`gateway_invoke`).
- **Dynamic meta-tool descriptions**: Tool and server counts are live (`format!()`) instead of static "150+".
- **Enhanced initialize instructions**: Discovery-first pattern with "use `gateway_search_tools` FIRST" emphasis and dynamic counts.
- **SEP-1821: Filtered `tools/list`** (behind `spec-preview` flag): Optional `query` parameter triggers semantic search returning filtered tools with full schemas.
- **SEP-1862: `tools/resolve`** (behind `spec-preview` flag): Deferred schema loading — resolve a tool's full `inputSchema` by name on demand.
- **Dynamic promotion** (behind `spec-preview` flag): Session-scoped auto-surfacing of tools after successful `gateway_invoke`, with FIFO eviction at configurable max (default: 10).
- **`notifications/tools/list_changed`**: Gateway now sends the notification it already advertised — fired on backend connect/disconnect and config reload. Fixes MCP spec compliance gap.
- **Config path discovery**: Auto-detect `gateway.yaml` / `config.yaml` in cwd, `~/.config/mcp-gateway/`, and `/etc/mcp-gateway/` when `--config` is omitted.
- **Config validation**: `Config::validate()` checks port, backend name validity, and HTTP URL parseability at load time.
- 8 new synonym groups in search ranking (12 → 20 total).
- 78 new tests across both RFCs.

### Changed

- **Config split** (RFC-0080): `config/features.rs` (650 lines) split into 10 focused modules under `config/features/`.
- **Error handling overhaul**: 48 of 58 `Error::Internal(String)` replaced with 6 typed variants (`ConfigValidation`, `CircuitOpen`, `ToolNotFound`, `OAuth`, `Tls`, `ConfigWatcher`).
- **3 dependencies removed**: `dialoguer` (replaced with stdin prompt), `md5` (replaced with `sha2`), `open` (replaced with `std::process::Command`).
- `derive(Default)` applied where manual impl was equivalent (`UsageStats`).
- Surfaced tools respect routing profiles — blocked backends never leak through surfacing.
- Collision detection prevents surfaced tool names from shadowing meta-tools.

### Fixed

- 112 `collapsible_if` clippy warnings for Rust 1.93 stable compatibility.
- MSRV bumped to 1.88 (matching Docker image and CI).
- `criterion` 0.7→0.8, `metrics-exporter-prometheus` 0.16→0.18.

## [2.6.0] - 2026-03-13

### Added

- **Cost Governance** (RFC-0075): Per-tool, per-key, and global daily budgets with configurable alert thresholds (log, notify, block). Live spend dashboard at `/ui/api/costs`.
- **Security Firewall** (RFC-0071): Bidirectional request/response scanning with credential redaction (AWS keys, GitHub tokens, JWTs), prompt injection detection, shell/SQL/path traversal detection, per-tool glob rules, and NDJSON audit logging.
- **Config Export** (RFC-0070): Export sanitized gateway config as YAML/JSON. Supports Claude Code, Cursor, Windsurf, and Zed client formats via `mcp-gateway config export`.
- **Auto-Discovery** (RFC-0074): Discover MCP servers from npm, pip, and Docker sources with quality scoring and deduplication via `mcp-gateway discover`.
- **Semantic Search** (RFC-0072): TF-IDF ranked tool search across all tool names and descriptions with relevance feedback learning.
- **Tool Profiles** (RFC-0073): Usage analytics per tool with latency histograms, error categorization, usage trends, and persistent storage.
- 19 cross-feature integration tests covering all RFC combinations.
- Performance benchmarks for all v2.6.0 features (Criterion): firewall <1us, cost enforcer <100ns, semantic search <50us.
- Complete example config (`examples/gateway-full.yaml`) with all options documented.

### Changed

- **13 dependency upgrades**: reqwest 0.12->0.13, rand 0.9->0.10, rcgen 0.13->0.14, jsonwebtoken 9.3->10.3, quick-xml 0.37->0.39, x509-parser 0.16->0.18, axum-server 0.7->0.8, md5 0.7->0.8, dialoguer 0.11->0.12, clap_complete 4.5->4.6, tokio-tungstenite 0.28, rustls 0.23, time 0.3.
- rcgen 0.14 `Issuer` API migration -- removed ~60 lines of manual DER parsing in JWKS endpoint.
- rand 0.10 `RngExt` API migration across 4 modules.
- All 7 features compile-time gated with `#[cfg(feature)]` -- disable any with `--no-default-features`.

### Fixed

- `--no-default-features` build failure: `add`/`remove` commands gated behind `webui` feature.
- GitHub push protection false positive for Slack token test patterns in firewall redactor tests.

## [2.5.0] - 2026-03-12

### Added

- **Embedded Web UI** (`/ui`): htmx SPA with 5 views (Dashboard, Tools, Servers, Capabilities, Config), hash routing, search, YAML editor with line numbers. Feature-gated behind `webui`.
- **Operator Dashboard** (`/dashboard`): Server-rendered HTML with backend health matrix, cache hit rates, top tools. Auto-refreshes every 5 seconds.
- **Web UI Management API**: Server management, capability management, OpenAPI import via `/ui/api/*` endpoints.
- **WebSocket transport** for MCP backends.
- **Plugin CLI**: `plugin install`, `plugin list`, `plugin search`, `plugin uninstall` with marketplace support.
- **Setup wizard** (`mcp-gateway setup`) with 48-server registry.
- **CLI server management**: `add`/`remove`/`list`/`get` commands (Claude/Codex compatible syntax).
- **Doctor command** (`mcp-gateway doctor`) for configuration diagnostics.
- **MCP protocol version negotiation** for stdio transports.
- Load test suite and deployment documentation.

### Changed

- Agent-scoped tool permissions via OAuth 2.0 JWT identity.
- Cache key propagation for backend tool invocations.
- Engram-inspired O(1) tool registry with prefetching.
- Secret injection proxy with OS keychain integration.
- Durable capability chains with step-level checkpoint/retry.

### Fixed

- FD exhaustion from streaming session leak + unpooled connections.
- Split 12 oversized files under 800 LOC limit.
- All clippy pedantic warnings resolved.

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

[Unreleased]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.10.0...HEAD
[2.10.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.9.1...v2.10.0
[2.9.1]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.9.0...v2.9.1
[2.9.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.8.1...v2.9.0
[2.7.3]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.7.2...v2.7.3
[2.7.2]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.7.1...v2.7.2
[2.7.1]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.7.0...v2.7.1
[2.7.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.6.0...v2.7.0
[2.6.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.5.0...v2.6.0
[2.5.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.2.0...v2.4.0
[2.2.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/MikkoParkkola/mcp-gateway/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/MikkoParkkola/mcp-gateway/releases/tag/v1.0.0
