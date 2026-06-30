# Shadow Scan — MCP Security Inventory

> **MIK-6554**: Read-only `shadow scan` capability for local MCP security inventory.

## Overview

`shadow scan` produces a risk-scored inventory of all MCP assets on a workstation.
It discovers MCP client configs, running MCP-like processes, local listening ports,
and gateway-configured instances/backends — all without spawning configured stdio
server commands.

Operators can use this inventory to identify unmanaged MCP servers **before** they
become production dependencies.

## Quick Start

```bash
# JSON report to stdout
mcp-gateway cap discover --shadow --format json

# Human-readable table
mcp-gateway cap discover --shadow --format table
```

## ShadowAsset JSON Schema

Every asset in the scan report follows this contract. The `schema_version`
field guarantees forward-compatible ingestion by SIEM and control-plane consumers.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://mcpgateway.io/schemas/shadow-asset/v1",
  "title": "ShadowAsset",
  "description": "A single MCP asset discovered during a shadow scan.",
  "type": "object",
  "required": [
    "schema_version",
    "asset_id",
    "name",
    "kind",
    "source",
    "transport_summary",
    "evidence",
    "management_status",
    "risks",
    "remediation_hints"
  ],
  "properties": {
    "schema_version": {
      "type": "integer",
      "description": "Schema version of this asset record (currently 1).",
      "const": 1
    },
    "asset_id": {
      "type": "string",
      "description": "Stable, unique identifier for this asset across scans.",
      "examples": ["shadow-brave-search", "gateway-managed-filesystem"]
    },
    "name": {
      "type": "string",
      "description": "Human-readable name of the MCP asset."
    },
    "kind": {
      "type": "string",
      "enum": [
        "mcp_server",
        "mcp_config",
        "mcp_process",
        "gateway_backend",
        "listening_port"
      ],
      "description": "Classification of the discovered asset."
    },
    "source": {
      "type": "string",
      "description": "Where the asset was discovered (config file path, process scanner, gateway config, etc.)."
    },
    "transport_summary": {
      "type": "string",
      "description": "Compact transport description (e.g. 'stdio: npx server', 'http: localhost:39300')."
    },
    "evidence": {
      "type": "array",
      "items": { "type": "string" },
      "description": "List of evidence strings supporting the discovery."
    },
    "management_status": {
      "type": "string",
      "enum": ["managed", "unmanaged", "unknown"],
      "description": "Whether the asset is registered as a gateway backend."
    },
    "risks": {
      "type": "array",
      "items": {
        "type": "string",
        "enum": [
          "unmanaged",
          "duplicate_port",
          "unauthenticated",
          "stale_binary",
          "unknown_provenance",
          "personal_credential_reference",
          "missing_trust_metadata"
        ]
      },
      "description": "Risk classifications for this asset."
    },
    "remediation_hints": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Actionable hints for resolving identified risks."
    },
    "first_observed": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp of first observation (null if unknown)."
    },
    "last_observed": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp of last observation (null if unknown)."
    },
    "redacted_metadata": {
      "description": "Additional metadata with secrets redacted.",
      "oneOf": [
        { "type": "object" },
        { "type": "null" }
      ]
    }
  }
}
```

## ShadowReport (Top-Level)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://mcpgateway.io/schemas/shadow-report/v1",
  "title": "ShadowReport",
  "description": "Full shadow scan report containing all discovered assets.",
  "type": "object",
  "required": [
    "schema_version",
    "scan_id",
    "scan_timestamp",
    "total_assets",
    "assets",
    "scan_duration_ms",
    "scan_mode"
  ],
  "properties": {
    "schema_version": {
      "type": "integer",
      "const": 1
    },
    "scan_id": {
      "type": "string",
      "description": "Unique scan identifier (UUID v4)."
    },
    "scan_timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "ISO 8601 timestamp when the scan ran."
    },
    "total_assets": {
      "type": "integer",
      "description": "Total number of assets discovered."
    },
    "assets": {
      "type": "array",
      "items": { "$ref": "#/ShadowAsset" },
      "description": "All discovered assets."
    },
    "scan_duration_ms": {
      "type": "integer",
      "description": "Scan duration in milliseconds."
    },
    "scan_mode": {
      "type": "string",
      "enum": ["free", "enterprise"],
      "description": "License tier under which the scan was run."
    }
  }
}
```

## Risk Taxonomy

| Risk | Severity | Description |
|------|----------|-------------|
| `unmanaged` | medium (2) | Asset not registered as a gateway backend |
| `duplicate_port` | low (1) | Two or more assets share the same listening port |
| `unauthenticated` | high (3) | HTTP transport without authentication |
| `stale_binary` | medium (2) | Binary on disk is older than 180 days |
| `unknown_provenance` | medium (2) | Cannot determine origin of the asset |
| `personal_credential_reference` | high (3) | Credential references personal account paths |
| `missing_trust_metadata` | critical (4) | No SHA-256 pin, signature, or attestation |

## Example Fixture

```json
{
  "schema_version": 1,
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "scan_timestamp": "2025-01-15T12:00:00Z",
  "total_assets": 2,
  "assets": [
    {
      "schema_version": 1,
      "asset_id": "shadow-brave-search",
      "name": "brave-search",
      "kind": "mcp_server",
      "source": "ClaudeDesktop",
      "transport_summary": "stdio: npx -y @anthropic/mcp-server-brave-search",
      "evidence": [
        "Found in ~/Library/Application Support/Claude/claude_desktop_config.json"
      ],
      "management_status": "unmanaged",
      "risks": ["unmanaged", "unauthenticated"],
      "remediation_hints": [
        "Register as gateway backend: mcp-gateway add brave-search -- npx -y @anthropic/mcp-server-brave-search"
      ],
      "first_observed": null,
      "last_observed": null,
      "redacted_metadata": null
    },
    {
      "schema_version": 1,
      "asset_id": "gateway-managed-filesystem",
      "name": "managed-filesystem",
      "kind": "gateway_backend",
      "source": "gateway.yaml",
      "transport_summary": "stdio: npx -y @anthropic/mcp-server-filesystem /safe/path",
      "evidence": ["Registered in gateway.yaml backends section"],
      "management_status": "managed",
      "risks": [],
      "remediation_hints": [],
      "first_observed": null,
      "last_observed": null,
      "redacted_metadata": null
    }
  ],
  "scan_duration_ms": 150,
  "scan_mode": "free"
}
```

## Passive Probe Behavior

The shadow scanner performs passive HTTP MCP probing only:

- Sends a single `initialize`-style JSON-RPC handshake to discovered HTTP endpoints
- Strict 5-second timeout (configurable via `passive_probe_timeout_ms`)
- **Never** sends `tools/call`, `tools/list`, or any tool-execution methods
- **Never** invokes unknown MCP tools
- Redacts secret-like values (API keys, tokens, passwords) from all output
- Does not spawn configured stdio commands

## Enterprise vs Free Mode

| Feature | Free (Core) | Enterprise |
|---------|-------------|------------|
| Local config scan | ✅ | ✅ |
| Process scanning | ✅ | ✅ |
| Port scanning | ✅ | ✅ |
| Gateway registry comparison | ✅ | ✅ |
| Passive HTTP probing | ✅ | ✅ |
| JSON/table reports | ✅ | ✅ |
| CIDR/network scanning | ❌ | ✅ |
| Scheduled scans | ❌ | ✅ |
| SIEM export | ❌ | ✅ |
| Owner assignment | ❌ | ✅ |
| Policy remediation workflow | ❌ | ✅ |
| Centralized risk scoring | ❌ | ✅ |

Free mode rejects CIDR inputs with a clear message:
> "CIDR/network scanning requires an enterprise license."

## `schema_version`

Current schema version: **1**

Changes to the `ShadowAsset` or `ShadowReport` schema will increment this
integer. Consumers should reject records with an unrecognized `schema_version`
and alert the operator to upgrade their tooling.
