---
name: smithery-manifest
description: Correct smithery.yaml manifest format for Smithery MCP server registry — commandFunction must be a JS arrow function string, not a YAML array
source: auto-skill
extracted_at: '2026-06-24T16:45:33.877Z'
---

# Smithery Manifest Format (`smithery.yaml`)

When adding or fixing a `smithery.yaml` for Smithery MCP server registry listing, the manifest has one top-level key `startCommand` with specific formatting requirements that are easy to get wrong.

## Common Mistake

The `commandFunction` field must be a **JavaScript arrow function string** (using YAML `|-` block scalar), NOT a YAML array. An array like `[mcp-gateway, serve, --stdio]` will not work.

## Correct Format

```yaml
# Smithery configuration file: https://smithery.ai/docs/config#smitheryyaml

startCommand:
  type: stdio
  configSchema:
    # JSON Schema defining user-provided configuration options.
    type: object
    properties:
      configFile:
        type: string
        description: Path to config file. Leave empty for defaults.
        title: Config File
  commandFunction:
    # JS arrow function receiving `config` and returning { command, args, env }.
    |-
    (config) => ({ command: 'mcp-gateway', args: ['serve', '--stdio'].concat(config.configFile ? ['--config', config.configFile] : []), env: {} })
```

## Required Fields

| Field | Type | Notes |
|-------|------|-------|
| `startCommand.type` | string | Transport type, typically `"stdio"` |
| `startCommand.configSchema` | JSON Schema object | Must have `type: object`. Properties define user-configurable options. Max 20 fields, 1KB total. |
| `startCommand.commandFunction` | string (JS arrow function) | Receives `config` object, must return `{ command, args, env }` |

## commandFunction Return Shape

The JS arrow function must return an object with exactly:
- `command` (string): The executable name (e.g., `'node'`, `'mcp-gateway'`, `'python'`)
- `args` (array of strings): CLI arguments
- `env` (object): Environment variables (can be `{}`)

## For Rust Binaries

When the MCP server is a Rust binary installed via `cargo install`:
- Use the binary name directly as `command` (e.g., `'mcp-gateway'`)
- Include `--stdio` in args for MCP stdio transport mode
- Expose optional config file path via `configSchema.properties`

## Validation Test Pattern

When adding a `smithery.yaml`, include a test that:
1. Parses the YAML with `serde_yaml`
2. Asserts `startCommand.type == "stdio"`
3. Asserts `commandFunction` contains `"=>"` (JS arrow, not array)
4. Asserts `commandFunction` contains `command`, `args`, and `env` keys
5. Asserts `configSchema.type == "object"`
