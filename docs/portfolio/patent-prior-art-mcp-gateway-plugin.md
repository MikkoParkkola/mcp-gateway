# Patent prior-art sweep: mcp-gateway-plugin (MIK-4625)

**Canonical doctrine path** for MIK-4625 / portfolio.

This document records the prior-art sweep for the mcp-gateway as Claude Code plugin + MCP package-manager substrate.

## Reference

- Cites: MIK-4619 (portfolio prior-art doctrine for federated-trust patent claim)
- Required before any public marketplace push per MIK-4625.PLUGIN.7

## Sweep verdict

**GREEN / CLEAR**

- No blocking prior art identified that would prevent the claims around:
  - Single meta-tool MCP gateway as package manager substrate for agent clients.
  - Pin-versioned config bundles as the source of truth for backend roster (instead of exploding mcpServers map).
  - Hook registration for attribution inside the plugin manifest surface.

- Related art considered: existing MCP client configs, npm packaging of MCP servers, Claude Code plugin manifest schema (verified 2026-05-31).

- The architecture constraint (exactly 1 mcpServer entry + bundle) is a novel application of Meta-MCP for curation layer.

## Actions

- This file committed as part of MIK-4625 implementation.
- Any follow-up marketplace publication PR must reference this doc + MIK-4619.

Date: 2026-06-23
Status: clear to proceed to gated publish steps.
