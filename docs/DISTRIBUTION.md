# MCP Server Directory Distribution

Tracks submission status of mcp-gateway to public MCP server directories.
Ref: [GitHub issue #119](https://github.com/MikkoParkkola/mcp-gateway/issues/119).

## Directories

### 1. Smithery (smithery.ai)

**Status:** Manifest added to repo (`smithery.yaml` at repository root).

The `smithery.yaml` manifest declares:
- `startCommand.type: stdio` — the gateway speaks MCP JSON-RPC over stdin/stdout.
- `configSchema` — optional `configFile` string pointing at a `gateway.yaml`.
- `commandFunction` — launches `mcp-gateway serve --stdio`.

**Installation via Smithery:**
```bash
npx -y @smithery/cli run mcp-gateway
```

**Badge:** Added to README.md.

### 2. Glama (glama.ai)

**Status:** Listed and verified.

Glama auto-indexes GitHub repositories that contain MCP server metadata.
The listing is available at:
<https://glama.ai/mcp/servers/MikkoParkkola/mcp-gateway>

Two badges are embedded in README.md:
- Standard Glama badge (server listing link)
- Quality Score badge (automated quality assessment)

**Verified items:**
- Badge URLs point to the correct repository path.
- Repository is public and contains MCP protocol support.
- README includes MCP protocol version badge (2025-11-25).

### 3. mcp.so

**Status:** Pending manual submission.

mcp.so requires manual submission through their web form. Review takes 1–7 days.
The draft submission text below is ready to copy into the submission form.

**Submission URL:** <https://mcp.so>

---

## mcp.so Submission Draft

> **Server Name:** MCP Gateway
>
> **Repository:** <https://github.com/MikkoParkkola/mcp-gateway>
>
> **Description:**
> MCP Gateway is a universal Meta-MCP gateway that sits between your AI client
> and your tools. Instead of loading hundreds of tool definitions into every
> request, the AI gets a compact 14–17 tool Meta-MCP surface and discovers the
> right backend tool on demand — saving ~89% of context token overhead.
>
> **Key Features:**
> - Aggregates multiple MCP backends + 110+ REST capability definitions behind a single stdio/HTTP endpoint
> - Dynamic tool discovery via `gateway_search_tools` and `gateway_invoke`
> - SHA-256 integrity pinning per capability definition
> - Circuit breaker isolation — one broken backend does not cascade
> - OWASP Agentic AI controls (10+ tracked controls)
> - Unified cost accounting and trace correlation across backends
> - Hot-reload: add/remove backends without restarting the AI session
>
> **Install:**
> ```bash
> cargo install mcp-gateway
> mcp-gateway serve --stdio
> ```
>
> **Or use as a stdio MCP server:**
> ```json
> {
>   "mcpServers": {
>     "mcp-gateway": {
>       "command": "mcp-gateway",
>       "args": ["serve", "--stdio"]
>     }
>   }
> }
> ```
>
> **Tags:** gateway, proxy, meta-mcp, tool-aggregation, context-optimization, circuit-breaker, security
>
> **License:** PolyForm-Noncommercial-1.0.0
>
> **Language:** Rust

---

## Maintenance

When updating directory listings:
1. **Smithery:** Update `smithery.yaml` at repo root if the CLI interface changes.
2. **Glama:** Ensure the repository stays public and the README retains the Glama badges.
3. **mcp.so:** Re-submit if major features are added that change the description materially.
