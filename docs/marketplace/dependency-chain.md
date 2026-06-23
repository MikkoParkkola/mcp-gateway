# mcp-gateway dependency chain (MIK-4625)

This documents the expected downstream plugin dependency graph per MIK-4625.PLUGIN.5.

## Core

- `mcp-gateway` (this plugin) is the package-manager substrate.
- Published as npm `@mikkoparkkola/mcp-gateway` v2.12.1+ and corresponding release artifacts.
- Every downstream portfolio plugin declares `mcp-gateway` as a dependency.

## Declared downstream requirements (MIK-4615 constellation)

- nab
- hebb
- pithy
- symphony
- trvl

These declare in their own `.claude-plugin/plugin.json`:

```json
"dependencies": [
  "mcp-gateway",
  { "name": "mcp-gateway", "version": "~2.12.1" }
]
```

Verification of `dependencies` field and documentation is done by parsing the manifest (see `cargo test --test plugin_manifest dependencies_well_formed`).

No live cross-plugin install is required for this AC (downstream plugins may be developed in parallel tracks).

See also: MIK-4625, MIK-4615.
