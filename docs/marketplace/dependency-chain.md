# Dependency Chain — mcp-gateway plugin

## Overview

The `mcp-gateway` plugin serves as the foundational infrastructure layer
for the MIK-4615 constellation of portfolio plugins. Every downstream
portfolio plugin declares `mcp-gateway` as a dependency, making it the
critical-path package in the W1 delivery sequence.

## Dependency Graph

```
mcp-gateway (v2.19.0)
├── nab-plugin        → depends on mcp-gateway ~2.19.0
├── hebb-plugin       → depends on mcp-gateway ~2.19.0
├── pithy-plugin      → depends on mcp-gateway ~2.19.0
├── symphony-plugin   → depends on mcp-gateway ~2.19.0
└── trvl-plugin       → depends on mcp-gateway ~2.19.0
```

## Why mcp-gateway is the Root Dependency

The gateway implements a **single `/mcp` meta-tool endpoint** that routes
to 29 pin-versioned backend MCP servers. This architecture achieves ~95%
context-token savings compared to loading N servers directly into the
client context window.

Downstream plugins (nab, hebb, pithy, symphony, trvl) do NOT each declare
29 MCP server entries in their own `mcpServers` maps. Instead, they depend
on `mcp-gateway` and customize behavior through:

1. **Config bundles** — YAML files selecting subsets of the 29-backend roster
2. **Tool profiles** — per-plugin tool curation via the gateway's RFC-0073 system
3. **Capability overrides** — REST API tool definitions layered on top

## Dependency Resolution

When a downstream plugin (e.g., `nab-plugin`) is installed:

1. The plugin manager resolves `nab-plugin`'s `dependencies` array
2. It finds `{"name": "mcp-gateway", "version": "~2.19.0"}`
3. `mcp-gateway` is installed (if not already present) from the marketplace
4. The gateway process starts as the single MCP server for `nab-plugin`
5. `nab-plugin`'s config bundle is loaded by the gateway at startup

## Version Compatibility

| Downstream Plugin | mcp-gateway Requirement | Status     |
|-------------------|------------------------|------------|
| nab-plugin        | ~2.19.0                | MIK-4615   |
| hebb-plugin       | ~2.19.0                | MIK-4615   |
| pithy-plugin      | ~2.19.0                | MIK-4615   |
| symphony-plugin   | ~2.19.0                | MIK-4615   |
| trvl-plugin       | ~2.19.0                | MIK-4615   |

## Verification

Dependency resolution is verified by parsing the plugin manifest's
`dependencies` field (see `tests/plugin_manifest.rs::dependencies_well_formed`).
Live cross-plugin install testing is deferred to MIK-4615 when downstream
plugins are available.
