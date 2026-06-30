# ShadowRadar Passive Discovery

ShadowRadar is the local, passive inventory path for unmanaged MCP servers. It
helps operators find MCP endpoints that exist in client configs, environment
hints, local process metadata, or gateway-adjacent discovery output before
those servers become production dependencies.

The local scan is free/core functionality. It reads local evidence and compares
discovered names against a gateway config. It does not start configured stdio
servers, call tools, mutate gateway config by default, or perform fleet/network
range scans.

Enterprise scope is intentionally separate: network range discovery, scheduled
fleet inventory, drift evidence, SIEM export, owner assignment, and policy
remediation are represented through the enterprise boundary contract and require
enterprise licensing.

## Command

Run the passive local report:

```bash
mcp-gateway cap discover --shadow --format json
```

Adopt reviewed local findings explicitly:

```bash
mcp-gateway cap discover --shadow --write-config
```

The write path only adopts findings classified as local and adoptable. Findings
that require owner review, quarantine, or enterprise workflow are skipped.

## ShadowAsset JSON schema

Reports use `schema_version: "shadow_radar.v1"`. Each unmanaged asset includes:

| Field | Meaning |
| --- | --- |
| `id` | Stable report-local identifier for diffs. |
| `asset_id` | Stable ingestion identifier, equal to `id`. |
| `kind` | Asset kind. Current value: `mcp_server`. |
| `name` | Discovered server name. |
| `source` | Discovery source, such as client config, environment, or process scan. |
| `management_status` | Current gateway management status. Local shadow assets use `unmanaged`. |
| `transport` | Transport kind plus sanitized endpoint and locality. |
| `trust_status` | Gateway trust status. Local shadow assets use `unmanaged`. |
| `evidence` | Human-safe pointers such as config path, pid, port, executable basename, sanitized endpoint, and gateway config path. |
| `risk_reasons` | Stable string risk codes for lightweight clients. |
| `risks` | Structured risk objects with `code`, `severity`, and `detail`. |
| `remediation` | Recommended action, confidence, confirmation requirement, verification, rollback, and optional dry-run/apply commands. |
| `remediation_hints` | Human-safe remediation strings copied from verification, rollback, dry-run, and apply paths. |

Example:

```json
{
  "schema_version": "shadow_radar.v1",
  "license_tier": "free_core",
  "mode": "local_passive",
  "passive": true,
  "tools_invoked": false,
  "assets": [
    {
      "id": "shadow:claudecode:local-filesystem:mcp-files",
      "asset_id": "shadow:claudecode:local-filesystem:mcp-files",
      "kind": "mcp_server",
      "name": "local-filesystem",
      "management_status": "unmanaged",
      "trust_status": "unmanaged",
      "risk_reasons": [
        "unmanaged_server",
        "not_registered_in_gateway_config",
        "missing_trust_metadata",
        "local_stdio_process",
        "source_client_config",
        "command_arguments_redacted"
      ],
      "risks": [
        {
          "code": "unmanaged_server",
          "severity": "medium",
          "detail": "unmanaged_server"
        }
      ],
      "remediation_hints": [
        "mcp-gateway cap discover --shadow --format json",
        "Remove the inserted backend entry or restore the previous gateway.yaml from VCS/backup."
      ]
    }
  ]
}
```

## Risk codes

Current stable codes include:

| Code | Meaning |
| --- | --- |
| `unmanaged_server` | Discovered asset is outside the compared gateway config. |
| `not_registered_in_gateway_config` | Server name is absent from the compared config. |
| `missing_trust_metadata` | Gateway-owned trust metadata is absent. |
| `unauthenticated_http_endpoint` | HTTP transport lacks passive access metadata. |
| `local_http_without_auth_metadata` | Loopback HTTP transport lacks passive access metadata. |
| `network_http_without_auth_metadata` | Non-loopback HTTP transport lacks passive access metadata. |
| `local_stdio_process` | Local stdio server was found in passive evidence. |
| `sensitive_data_domain` | Name, description, or command indicates sensitive data access. |
| `high_privilege_domain` | Name, description, or command indicates high-privilege local access. |
| `source_client_config` | Evidence came from local client config. |
| `source_local_process` | Evidence came from a local process. |
| `source_environment` | Evidence came from environment configuration. |
| `unknown_owner` | Passive evidence does not identify an owner. |
| `unknown_provenance` | Passive evidence does not identify provenance. |
| `command_arguments_redacted` | Command existed, but arguments were omitted from evidence. |
| `personal_access_reference` | Passive evidence referenced personal access material. |
| `stale_binary` | Passive evidence suggests legacy, deprecated, or stale binary use. |
| `duplicate_port` | Multiple unmanaged assets reported the same local port. |

## Enterprise boundary

The derived `shadow_radar.enterprise_boundary.v1` contract separates local
free/core discovery from enterprise fleet workflows.

Free/core local scan:

- `license_tier`: `free_core`
- `mode`: `local_passive`
- `activity`: `passive`
- denied capabilities: network range scan, scheduled scan, fleet scope, tool
  invocation, config mutation

Enterprise scan extension:

- `license_tier`: `enterprise`
- `mode`: `enterprise_fleet`
- allowed capabilities: network range scan, scheduled scan, fleet scope
- denied capabilities: tool invocation, config mutation
- export contracts require enterprise licensing and mark protected values as
  excluded

This split lets public docs and local users benefit from passive discovery
without turning the free/core path into a fleet scanner or policy automation
surface.
