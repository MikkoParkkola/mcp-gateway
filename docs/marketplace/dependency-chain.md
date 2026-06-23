# mcp-gateway Dependency Chain (MIK-4625.PLUGIN.5)

`mcp-gateway` is the W1 critical path substrate for the MIK-4615 constellation.

Every downstream portfolio plugin declares `mcp-gateway` as a dependency:

- nab
- hebb
- pithy
- symphony
- trvl

## Manifest example (downstream)

In the downstream plugin's `.claude-plugin/plugin.json`:

```json
{
  "name": "hebb",
  ...
  "dependencies": [
    "mcp-gateway",
    { "name": "@mikkoparkkola/mcp-gateway", "version": "^2.12.1" }
  ]
}
```

## Verification

Dependencies field in gateway's own manifest is well-formed (array of strings or objects with name+version).

The single `mcpServers` entry (the gateway) + shipped bundle (see examples/* with `capabilities:` / `backends:`) replaces the anti-pattern of expanding 29+ servers in the client mcpServers map.

This is per ARCHITECTURE.md single-/mcp design for 95% token reduction.

Addresses AC#PLUGIN.5.
