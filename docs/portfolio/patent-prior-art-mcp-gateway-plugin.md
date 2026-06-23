# Patent Prior-Art Sweep — mcp-gateway-plugin

**Ticket:** MIK-4625
**Prior-art reference:** MIK-4619
**Date:** 2026-06-23
**Verdict:** ✅ GREEN / CLEAR

## Summary

A patent prior-art sweep was conducted for the `mcp-gateway-plugin`
concept: distributing an MCP gateway as a Claude Code plugin with
curated, pin-versioned server bundles, turning the local router into
a de-facto MCP package-manager and curation layer.

## Scope of Claims Examined

1. **Single-endpoint meta-tool routing** — A single `/mcp` endpoint that
   multiplexes N backend MCP servers through one tool definition, achieving
   ~95% context-token savings vs. loading N servers directly.
2. **Plugin-distributed config bundles** — Shipping pin-versioned backend
   rosters as YAML config bundles alongside a plugin manifest.
3. **Federated plugin dependency graph** — Downstream plugins declaring
   the gateway as a dependency, with the plugin manager resolving the
   dependency chain.
4. **PreToolUse attribution hooks** — Injecting provenance metadata into
   tool invocations at the plugin dispatch boundary.

## Prior-Art Search (MIK-4619)

### Databases Searched

- USPTO Full-Text and Image Database
- Google Patents
- EPO Espacenet
- WIPO PATENTSCOPE
- arXiv (cs.AI, cs.SE, cs.DC)
- GitHub public repositories (MCP-related)

### Key Findings

| Claim Area                        | Prior Art Found | Blocking? | Notes                                      |
|-----------------------------------|-----------------|-----------|--------------------------------------------|
| MCP server multiplexing           | No              | No        | Novel combination of MCP + plugin manifest |
| Context-token savings via meta-tool | No           | No        | Specific to MCP protocol routing           |
| Pin-versioned config bundles      | No              | No        | Standard package management pattern        |
| Plugin dependency resolution      | Yes (generic)   | No        | Generic plugin deps are well-known art     |
| PreToolUse hooks                  | Yes (generic)   | No        | Hook patterns exist in Claude Code docs    |

### Analysis

The specific combination of:
- MCP protocol routing through a single meta-tool endpoint
- Distributed as a Claude Code plugin with `mcpServers` map
- Pin-versioned backend rosters as config bundles
- Federated dependency graph for downstream portfolio plugins

...does not appear in any prior patent or published application as of
the search date. Individual components (plugin manifests, config bundles,
hook systems) are well-known art, but their specific application to MCP
server management via a gateway plugin is novel.

Generic plugin dependency resolution and PreToolUse hook patterns are
well-established prior art and are NOT claimed as novel — they are
standard mechanisms used in a novel architectural context.

## Verdict

**GREEN / CLEAR** — No blocking prior art identified for the novel
aspects of the mcp-gateway-plugin architecture. The combination of MCP
meta-tool routing with plugin distribution is not anticipated by any
single prior-art reference.

## References

- MIK-4619: Portfolio-wide patent prior-art sweep (parent issue)
- ARCHITECTURE.md: Gateway architecture and context-token savings analysis
- `.claude-plugin/plugin.json`: Plugin manifest implementation
- `examples/plugin-backend-roster.yaml`: Backend roster implementation
