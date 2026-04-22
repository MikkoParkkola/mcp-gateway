# MCP Gateway

[![CI](https://github.com/MikkoParkkola/mcp-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/MikkoParkkola/mcp-gateway/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/mcp-gateway.svg)](https://crates.io/crates/mcp-gateway)
[![Downloads](https://img.shields.io/crates/d/mcp-gateway.svg)](https://crates.io/crates/mcp-gateway)
[![Rust](https://img.shields.io/badge/rust-1.88+-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/crates/l/mcp-gateway.svg)](https://github.com/MikkoParkkola/mcp-gateway/blob/main/LICENSE)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![dependency status](https://deps.rs/repo/github/MikkoParkkola/mcp-gateway/status.svg)](https://deps.rs/repo/github/MikkoParkkola/mcp-gateway)
[![Capabilities](https://img.shields.io/badge/REST%20capabilities-100%2B-purple.svg)](https://github.com/MikkoParkkola/mcp-gateway/tree/main/capabilities)
[![MCP Protocol](https://img.shields.io/badge/MCP-2025--11--25-green.svg)](https://modelcontextprotocol.io)
[![OWASP Agentic AI](https://img.shields.io/badge/OWASP_Agentic_AI-10%2F10_covered-brightgreen.svg)](docs/OWASP_AGENTIC_AI_COMPLIANCE.md)
[![Glama](https://glama.ai/mcp/servers/MikkoParkkola/mcp-gateway/badge)](https://glama.ai/mcp/servers/MikkoParkkola/mcp-gateway)
[![Quality Score](https://glama.ai/mcp/servers/MikkoParkkola/mcp-gateway/badges/score.svg)](https://glama.ai/mcp/servers/MikkoParkkola/mcp-gateway)
[![Install in VS Code](https://img.shields.io/badge/VS_Code-Install_MCP-0078d4?logo=visualstudiocode)](https://insiders.vscode.dev/redirect/mcp/install?name=mcp-gateway&config=%7B%22command%22%3A%22mcp-gateway%22%2C%22args%22%3A%5B%22serve%22%2C%22--stdio%22%5D%7D)
[![Install in Cursor](https://img.shields.io/badge/Cursor-Install_MCP-black?logo=cursor)](cursor://anysphere.cursor-deeplink/mcp/install?name=mcp-gateway&config=%7B%22command%22%3A%22mcp-gateway%22%2C%22args%22%3A%5B%22serve%22%2C%22--stdio%22%5D%7D)

**Give your AI access to every tool it needs -- without burning your context window or building MCP servers.**

![demo](demo.gif)

### Independent Reviews

- [Five MCP hot-reload tools compared](https://ruachtov.ai/blog/five-tools-mcp-restart.html) -- Ruach Tov Collective's BPD-based comparison of mcp-gateway against four restart-focused alternatives. Includes a feature matrix and architectural analysis.
- [mcp-gateway deep dive](https://ruachtov.ai/blog/mcp-gateway-deep-dive.html) -- Detailed walkthrough of the capability system, SHA-256 integrity pinning, and the v2.5-to-v2.9 development arc.

MCP Gateway sits between your AI client and your tools. Instead of loading hundreds of tool definitions into every request, the AI gets a compact Meta-MCP surface -- 14 tools minimum, 16 in the README benchmark scenario, 17 when webhook status is surfaced -- and discovers the right backend tool on demand.

Public quantitative claims in this README are sourced from [docs/BENCHMARKS.md](docs/BENCHMARKS.md) and the machine-readable [benchmarks/public_claims.json](benchmarks/public_claims.json), with CI checks to catch drift.

## What MCP Gateway is / is not

MCP Gateway is a **tool and capability gateway**. It routes MCP tool/resource/prompt traffic to backend MCP servers and capability-backed REST APIs, and it can proxy MCP server-to-client requests like `sampling/createMessage`, `elicitation/create`, and `roots/list` back to the connected client over the existing gateway session.

MCP Gateway is **not** a general OpenAI/Anthropic chat completions or embeddings gateway. When a backend asks for `sampling/createMessage`, the connected client still performs the model call. The OpenAI-compatible prompt-cache helpers in the gateway exist only so `gateway_invoke` can preserve `prompt_cache_key` behavior for backends or capabilities that happen to call LLM APIs internally.

## Why

**The context window is the bottleneck.** Every MCP tool you connect costs ~150 tokens of context overhead. Connect 20 servers with 100+ tools and you've burned 15,000 tokens before the conversation starts -- on tool definitions the AI probably won't use this turn.

Worse: context limits force you to **choose** which tools to connect. You leave tools out because they don't fit -- and your AI makes worse decisions because it can't reach the right data.

MCP Gateway removes that tradeoff entirely.

| | Without Gateway | With Gateway |
|---|----------------|--------------|
| **Tools in context** | Every definition, every request | 16 Meta-MCP tools in the README benchmark (~1600 tokens) |
| **Token overhead** | ~15,000 tokens (100 tools) | ~1600 tokens -- **89% savings** |
| **Cost at scale** | ~$0.22/request (Opus input) | ~$0.024/request -- **$201 saved per 1K** |
| **Practical tool limit** | 20-50 tools (context pressure) | **Unlimited** -- discovered on demand |
| **Connect a new REST API** | Build an MCP server (days) | Drop a YAML file or import an OpenAPI spec (minutes) |
| **Changing MCP config** | Restart AI session, lose context | Restart gateway (~8ms), session stays alive |
| **When one tool breaks** | Cascading failures | Circuit breakers isolate it |

The base discovery quartet (`gateway_list_servers`, `gateway_list_tools`, `gateway_search_tools`, `gateway_invoke`) stays constant. The README benchmark scenario also surfaces stats, cost report, playbooks, profile controls, disabled-capability visibility, and reload for a 15-tool surface. Surfacing webhook status adds the 16th tool.

### Why not...

| Alternative | What it does | Why MCP Gateway is different |
|---|---|---|
| **Direct MCP connections** | Each server connected individually | Every tool definition loaded every request. 100 tools = 15K tokens burned. Gateway: a small fixed 13-16 tool surface instead of every backend tool. |
| **Claude's ToolSearch** | Built-in deferred tool loading | Only works with tools already configured. Gateway adds unlimited backends + REST APIs without MCP servers. |
| **Archestra** | Cloud-hosted MCP registry | Requires cloud account, sends data to third party. Gateway is local-only, zero external dependencies. |
| **Kong / Portkey** | General API gateways | Not MCP-aware. No meta-tool discovery, no tool search, no capability YAML system. |
| **Building fewer MCP servers** | Reduce tool count manually | You lose capabilities. Gateway lets you keep everything and pay the token cost of the compact Meta-MCP surface. |

## Security

Connecting N MCP servers to an agent means accepting N attack surfaces. Tool poisoning, rug pulls, and exfiltration via hidden instructions in tool descriptions are demonstrated attacks, not hypotheticals. Invariant Labs' writeup ([MCP Security Notification: Tool Poisoning Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)) and Simon Willison's summary ([MCP has prompt injection security problems](https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/)) lay out the threat model.

mcp-gateway puts every backend tool description behind one audit surface and defends it structurally:

- **Tool-poisoning validator (AX-010).** Every backend tool description is scanned before it reaches the agent's context window. HIGH patterns fail-closed: `<IMPORTANT>` blocks, `~/.ssh`/`~/.aws`/`id_rsa`/`.env`/`/etc/passwd`, `sidenote` exfiltration language, `curl .* https?://`, `base64` in exfil context. MEDIUM patterns warn: 40+ consecutive spaces, zero-width / bidi-override Unicode, oversized descriptions. Implementation: [`src/validator/rules/tool_poisoning.rs`](src/validator/rules/tool_poisoning.rs) (19 tests).
- **SHA-256 capability hash-pinning.** `mcp-gateway cap pin <file>` writes a `sha256:` line over the file's canonical hash (`grep -v '^sha256:' capability.yaml | sha256sum` is reproducible from any shell). The loader refuses any mismatched file on load and on every watcher event.
- **Rug-pull detection.** When a pinned capability's on-disk content changes after approval, the watcher unloads it and logs `RUG-PULL DETECTED`. The capability stays quarantined until an operator re-pins. Implementation: [`src/capability/hash.rs`](src/capability/hash.rs) and `detect_rug_pulls` in [`src/capability/backend.rs`](src/capability/backend.rs).
- **Centralized audit surface.** Capability YAMLs are plain text, diffable, grep-able, PR-reviewable. The agent only ever sees the compact Meta-MCP surface (13-16 tools). No N-server tool-list pollution means no N-server attack surface.

Full walkthrough, PoC snippets, and roadmap: [docs/blog/security-aware-mcp-gateway.md](docs/blog/security-aware-mcp-gateway.md).

- **OWASP Agentic AI Top 10.** Full coverage across all 10 risks. See [docs/OWASP_AGENTIC_AI_COMPLIANCE.md](docs/OWASP_AGENTIC_AI_COMPLIANCE.md).

### Recent additions

- **OpenAPI importer.** `mcp-gateway cap import <spec-url-or-file>` turns an OpenAPI 3 spec into one validated capability YAML per operation. The full Swagger Petstore spec becomes 19 validated capability YAMLs end-to-end:
  ```bash
  mcp-gateway cap import https://petstore3.swagger.io/api/v3/openapi.json --output capabilities/ --prefix petstore
  ```
  22 tests across [`src/capability/openapi.rs`](src/capability/openapi.rs) and [`tests/openapi_import_tests.rs`](tests/openapi_import_tests.rs).

## Quick Start

**Tell your AI assistant** (recommended):

> Read https://github.com/MikkoParkkola/mcp-gateway and install mcp-gateway to consolidate all my MCP servers behind one gateway

Your agent will install the binary, run the setup wizard, import your existing MCP servers, and wire itself up. Works in Claude Code, Cursor, Windsurf, Codex, and any AI with terminal access.

**Or four commands:**

```bash
brew install MikkoParkkola/tap/mcp-gateway   # 1. install
mcp-gateway setup wizard --configure-client  # 2. import existing servers + wire up clients
mcp-gateway serve                            # 3. run
mcp-gateway doctor                           # 4. verify everything is healthy
```

That's it. Your AI clients now talk to the gateway and the gateway routes to every backend you already had configured — at a flat `~15 tools` instead of `~150`. Start with `gateway_search_tools` from your AI client to find any backend tool, then invoke it with `gateway_invoke`.

> **Nothing to import yet?** `mcp-gateway init --with-examples` writes a working `gateway.yaml` with public capabilities so you can confirm the gateway is alive before adding your own servers.

### Install

| Method | Command |
|--------|---------|
| **Homebrew (macOS/Linux, recommended)** | `brew install MikkoParkkola/tap/mcp-gateway` |
| **Cargo** | `cargo install mcp-gateway` |
| **cargo-binstall** | `cargo binstall mcp-gateway` |
| **Docker** | `docker run -v $(pwd)/gateway.yaml:/config.yaml ghcr.io/mikkoparkkola/mcp-gateway:latest --config /config.yaml` |

<details>
<summary>Direct binary download</summary>

```bash
# macOS Apple Silicon
curl -L https://github.com/MikkoParkkola/mcp-gateway/releases/latest/download/mcp-gateway-darwin-arm64 -o mcp-gateway && chmod +x mcp-gateway

# macOS Intel
curl -L https://github.com/MikkoParkkola/mcp-gateway/releases/latest/download/mcp-gateway-darwin-x86_64 -o mcp-gateway && chmod +x mcp-gateway

# Linux x86_64
curl -L https://github.com/MikkoParkkola/mcp-gateway/releases/latest/download/mcp-gateway-linux-x86_64 -o mcp-gateway && chmod +x mcp-gateway
```

</details>

### Set up — three ways

#### Option A — Auto-import everything (recommended)

```bash
mcp-gateway setup wizard --configure-client
```

Scans Claude Desktop, Claude Code, Cursor, Zed, Continue.dev, Codex, and running MCP processes; lets you pick which servers to import into `gateway.yaml`; and writes the gateway entry back into each detected client config so they route through the gateway instead. Add `--yes` to skip the prompts and import everything.

#### Option B — Add servers from the built-in registry

48 popular MCP servers are pre-registered with the right command, args, and env-var template. `mcp-gateway add` is `claude mcp add` / `codex mcp add` compatible:

```bash
mcp-gateway add tavily                                       # known server, fills env vars
mcp-gateway add my-server -- npx -y @some/mcp-server --flag  # arbitrary stdio command
mcp-gateway add --url https://mcp.sentry.dev/mcp sentry      # HTTP server
mcp-gateway add -e API_KEY=xxx my-server -- npx my-mcp-server
```

`mcp-gateway list` shows what's configured. `mcp-gateway remove <name>` removes one.

#### Option C — Hand-write `gateway.yaml`

For the full schema reference, see [docs/QUICKSTART.md#configuration](docs/QUICKSTART.md#configuration). Minimal example:

```yaml
server:
  port: 39400

meta_mcp:
  enabled: true

backends:
  tavily:
    command: "npx -y @anthropic/mcp-server-tavily"
    description: "Web search"
    env:
      TAVILY_API_KEY: "${TAVILY_API_KEY}"

  sentry:
    http_url: "https://mcp.sentry.dev/mcp"
    description: "Sentry issues"
```

### Run and verify

```bash
mcp-gateway serve                  # start the gateway
mcp-gateway doctor                 # diagnose config, port, env vars, backend health
mcp-gateway doctor --fix           # auto-fix issues where possible
```

The web dashboard is at <http://localhost:39400/ui> once `serve` is running.

### Connect AI clients (if you skipped Option A)

`setup export` writes the gateway entry into client config files for you. It auto-detects the right path per client:

```bash
mcp-gateway setup export --target all                 # all detected clients
mcp-gateway setup export --target claude-code         # one client
mcp-gateway setup export --target all --dry-run       # preview without writing
mcp-gateway setup export --target all --watch         # regenerate on gateway.yaml changes
```

| Client | Config path |
|--------|-------------|
| `claude-code` | `~/.claude.json` |
| `claude-desktop` | platform-specific |
| `cursor` | `.cursor/mcp.json` (workspace) |
| `vs-code-copilot` | `.vscode/mcp.json` (workspace) |
| `windsurf` | `~/.codeium/windsurf/mcp_config.json` |
| `cline` | `.cline/mcp_servers.json` (workspace) |
| `zed` | `~/.config/zed/settings.json` |

Modes: `--mode proxy` (HTTP), `--mode stdio` (subprocess), `--mode auto` (probe health endpoint, fall back).

<details>
<summary>Manual JSON snippet (if you prefer to edit by hand)</summary>

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

</details>

## Key Benefits

### 1. Unlimited Tools, Minimal Tokens

The gateway exposes 14 Meta-MCP tools minimum, 16 in the README benchmark scenario, and 17 when webhook status is surfaced. The base discovery quartet stays fixed; the rest are operator helpers for stats, cost, playbooks, profile control, disabled-capability visibility, reload, and webhook status.

**Token math** (Claude Opus @ $15/M input tokens, reproducible via `python benchmarks/token_savings.py --scenario readme`):
- **Without**: 100 tools x 150 tokens x 1,000 requests = 15M tokens = **$225**
- **With (README benchmark)**: 16 Meta-MCP tools x 100 tokens x 1,000 requests = 1.6M tokens = **$24.00**

### 2. Any REST API to MCP Tool -- No Code

Turn any REST API into a tool by dropping a YAML file (~30 seconds) or importing an OpenAPI spec:

```bash
mcp-gateway cap import stripe-openapi.yaml --output capabilities/ --prefix stripe
```

The gateway ships with **100+ built-in capabilities** -- weather, Wikipedia, GitHub, stock quotes, package tracking, and more. Capability YAMLs hot-reload automatically after file changes, no restart needed.

### 3. Change Your MCP Stack Without Losing Your AI Session

Your AI connects once to `localhost:39400`. Behind it, capability YAMLs plus reloadable gateway config sections (including backend add/remove/update and routing/profile changes) can reload live via file watching, `gateway_reload_config`, or `POST /ui/api/reload`. Listener address changes report `restart_required`; `env_files` list changes stay startup-only and take effect after restart. Your AI session stays connected.

### 4. Production Resilience

Circuit breakers, retry with backoff, rate limiting, health checks, graceful shutdown, and concurrency limits. One flaky server won't take down your toolchain.

## Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                    MCP Gateway (:39400)                        │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  Meta-MCP: 13-16 Tools + Surfaced Tools                 │  │
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
| **Capability System** | REST API to MCP tool via YAML. Hot-reloaded. [100+ built-in](capabilities/). OpenAPI import supported. |
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
| **SSE** | Pieces, LangChain, [GitMCP](https://gitmcp.io) (free remote docs+code search for any GitHub repo) |

Remote MCP servers plug in by URL — no extra code. See
[examples/gateway-full.yaml](examples/gateway-full.yaml) for a commented GitMCP
backend entry and [docs/REMOTE_BACKENDS.md](docs/REMOTE_BACKENDS.md) for a
step-by-step walkthrough.

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

## SKILL.md / agentskills.io compatibility

MCP Gateway can ingest [Agent Skills](https://agentskills.io) / Claude Code
`SKILL.md` files and expose them as discoverable skills alongside capability
YAML. This lets the gateway consume any SKILL.md — whether authored locally,
shipped from `agentskills.io`, or pulled from a GitHub release — and surface
it through the same meta-tool surface used for capabilities.

```bash
# Import a local skill directory (auto-discovers SKILL.md + resources/)
mcp-gateway skills import ~/.claude/skills/gws-gmail-send

# Import a single SKILL.md file
mcp-gateway skills import ./path/to/SKILL.md

# Import from an agentskills.io URL
mcp-gateway skills import https://agentskills.io/skills/my-skill/SKILL.md

# List imported skills
mcp-gateway skills list

# Search by name, description, trigger, or keyword
mcp-gateway skills search "gmail"

# Show the full body (including any embedded code blocks)
mcp-gateway skills show gws-gmail-send

# Remove a skill
mcp-gateway skills remove gws-gmail-send
```

**What gets parsed**

- YAML frontmatter (`name`, `description`, `version`, `effort`,
  `allowed-tools`, `triggers`, `keywords`)
- Markdown body, with fenced `bash`/`python`/`json` code blocks extracted as
  structured `SkillCodeBlock` entries
- Progressive-disclosure resources: `SKILL.advanced.md`, `reference.md`,
  `README.md`, and any `resources/*.md` files in the skill directory

**Security model (read-only)**

Imported skills are stored as data, not executed. Embedded `bash` or
`python` blocks are parsed and surfaced to users/agents via `skills show`,
but MCP Gateway will never run them automatically. A future release may
add opt-in execution gated on per-skill user consent. If you need to run
a skill's commands today, copy them from `skills show` and run them in
your own shell.

Registry location: `~/.mcp-gateway/skills.json` (override with
`MCP_GATEWAY_SKILLS_REGISTRY` or `--registry`).

Reference: [Anthropic SKILL.md spec](https://docs.claude.com/en/docs/claude-code/skills) ·
[agentskills.io](https://agentskills.io)

## Documentation

| Document | Contents |
|----------|----------|
| [Quick Start](docs/QUICKSTART.md) | Zero to running in 2 minutes |
| [Configuration Reference](docs/QUICKSTART.md#configuration) | All config options |
| [OAuth Configuration](docs/OAUTH_CONFIG.md) | OAuth 2.0 setup with Slack and Figma examples |
| [Deployment Guide](docs/DEPLOYMENT.md) | Docker, systemd, TLS/mTLS, scaling |
| [OpenAPI Import](docs/OPENAPI_IMPORT.md) | Generate capabilities from OpenAPI specs |
| [Webhooks](docs/WEBHOOKS.md) | Event integration setup |
| [Community Registry](docs/COMMUNITY_REGISTRY.md) | Share and install capabilities |
| [Benchmarks](docs/BENCHMARKS.md) | Performance measurements |
| [Changelog](CHANGELOG.md) | Release history |
| [OWASP Agentic AI Compliance](docs/OWASP_AGENTIC_AI_COMPLIANCE.md) | Risk coverage matrix |

## Troubleshooting

**Backend won't connect?** Test the command directly (`npx -y @anthropic/mcp-server-tavily`), then check gateway logs with `--log-level debug`.

**Circuit breaker open?** Check `curl localhost:39400/health | jq '.backends'`. Adjust thresholds in `failsafe.circuit_breaker`.

**Tools not appearing?** Verify the backend is running (`gateway_list_servers`). Tool lists are cached for 5 minutes.

## Contributing

1. Fork and branch (`git checkout -b feature/your-feature`)
2. Test (`cargo test`) and lint (`cargo fmt && cargo clippy -- -D warnings`)
3. PR against `main` with a clear description and [CHANGELOG](CHANGELOG.md) entry

See [CONTRIBUTING.md](CONTRIBUTING.md) for full details. Look for [`good first issue`](https://github.com/MikkoParkkola/mcp-gateway/labels/good%20first%20issue) or [`help wanted`](https://github.com/MikkoParkkola/mcp-gateway/labels/help%20wanted) to get started.

## Ecosystem

mcp-gateway is part of a suite of MCP tools:

| Tool | Description |
|------|-------------|
| **[mcp-gateway](https://github.com/MikkoParkkola/mcp-gateway)** | **Universal MCP gateway — compact 13-16 tool surface replaces 100+ registrations** |
| [trvl](https://github.com/MikkoParkkola/trvl) | AI travel agent — 36 MCP tools for flights, hotels, ground transport |
| [nab](https://github.com/MikkoParkkola/nab) | Web content extraction — fetch any URL with cookies + anti-bot bypass |
| [axterminator](https://github.com/MikkoParkkola/axterminator) | macOS GUI automation — 34 MCP tools via Accessibility API |

## License

MIT License -- see [LICENSE](LICENSE) for details.

## Credits

Created by [Mikko Parkkola](https://github.com/MikkoParkkola). Implements [Model Context Protocol](https://modelcontextprotocol.io/) version 2025-11-25.

[Changelog](CHANGELOG.md) | [Releases](https://github.com/MikkoParkkola/mcp-gateway/releases)
