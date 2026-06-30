# Willow / Webrix — Enterprise Agent Governance Competitive Landscape

**Status**: competitive scan, 2026-06-30 | **Verdict**: direct enterprise governance competitor | **Ticket**: MIK-5843

## TL;DR

Willow (product) / Webrix (company, <https://withwillow.ai>, <https://app.webrix.ai>) is a
direct enterprise governance competitor for mcp-gateway. Willow offers agent identity
management, permissioned least-privilege tool access, audit trail / audit log,
MCP gateway functionality, API-to-MCP bridging, 1000+ connectors, IdP integration
(Okta, Entra, JumpCloud), runtime guards, and shadow-AI / unmanaged-MCP discovery.

mcp-gateway's positioning is **not** a Willow clone. The wedge is:

- **Sovereign / self-hosted deployment** — the gateway runs on the operator's
  infrastructure; no cloud tenancy dependency.
- **Signed `.state` and per-action attestation receipts** — cryptographically verifiable
  execution evidence at the `gateway_invoke` boundary, not ordinary audit log lines.
- **Local-first deployment** — single-binary, zero-orchestration startup.
- **Transparent capability routing** — the meta-MCP surface is inspectable, the tool
  catalog is declarative YAML, and the dispatch path is open source.

Willow leads on cloud enterprise governance (managed IdP, approval workflows, connector
breadth, hosted audit dashboards). mcp-gateway leads on sovereign deployment and
cryptographic attestation.

---

## Competitor Profile

| Attribute | Willow / Webrix |
|---|---|
| Product URL | <https://withwillow.ai> |
| Platform URL | <https://app.webrix.ai> |
| Category | Enterprise agent governance platform |
| Deployment | Cloud-hosted SaaS |
| Target buyer | Enterprise IT / security teams |
| Core thesis | Centralised governance for AI agents and MCP tool usage |

---

## Feature-Bar Comparison

The table below compares mcp-gateway versus Willow across the governance surfaces
that matter for enterprise buyers. Verdicts are from the **mcp-gateway** perspective.

| Capability | mcp-gateway | Willow / Webrix | Verdict (mcp-gateway) |
|---|---|---|---|
| **Connectors** | 572+ tools via capability YAML, stdio + HTTP backends | 1000+ connectors (API-to-MCP bridging, managed catalog) | **LAG** — Willow has broader out-of-box connector count; mcp-gateway covers the long tail via custom backend definitions |
| **IdP integration** | Bearer token + API key auth, OAuth 2.0 PKCE for backends; no client-facing SSO | Okta, Entra, JumpCloud — full enterprise IdP federation | **LAG** — Willow ships managed IdP connectors; mcp-gateway is local-first auth (see RFC-0132 Component 2) |
| **Shadow-AI / unmanaged-MCP detection** | Config scanning (`src/discovery/config_scanner.rs`), process scanning (`src/discovery/process_scanner.rs`), exported network/SIEM rules via `mcp-gateway discover --shadow` | Shadow-AI discovery, unmanaged MCP detection, enterprise-wide visibility dashboard | **MATCH** on detection scope; **LEAD** on local-first self-hosted detection without cloud dependency |
| **Runtime guards** | Pre/post tool-use hooks, per-action attestation enforcement at `gateway_invoke`, circuit breaker failsafe, scope-before-treatment policy | Runtime guards, approval workflows, policy engines, managed enforcement | **MATCH** — both enforce at the tool-use boundary; mcp-gateway adds cryptographic attestation |
| **Audit trail** | Structured event log (tracing), per-action attestation receipt at `gateway_invoke` boundary, `.state` persistence for session replay | Audit log dashboards, compliance reporting, enterprise audit trail, managed log aggregation | **MATCH** on audit capability; **LEAD** on cryptographic verifiability — signed attestation receipts vs ordinary audit log entries |
| **Cryptographic attestation** | Per-action attestation tokens validated at `gateway_invoke` (`src/gateway/meta_mcp/invoke.rs:245`), signed `.state` session files, B1 identity-bound dispatch | No public cryptographic attestation primitive; audit relies on conventional log integrity | **LEAD** — mcp-gateway ships per-action attestation receipts and signed `.state` as first-class primitives |

### Verdict Summary

| Verdict | Capabilities |
|---|---|
| **LEAD** | Cryptographic attestation (signed `.state`, per-action attestation receipts), sovereign/self-hosted deployment, shadow-AI detection (local-first) |
| **MATCH** | Runtime guards, audit trail |
| **LAG** | Connectors count (572 vs 1000+), IdP integration (no managed Okta/Entra/JumpCloud federation) |

---

## Shadow-AI Detection as Net-New Capability Candidate

Shadow-AI detection — the ability to find AI agents and MCP servers that operate
outside the governed gateway — is a competitive differentiator for both platforms.
For mcp-gateway, this is bounded to three layers unless the gateway becomes a
network proxy (which it is not, and should not become):

### Layer 1: Config Scanning

`src/discovery/config_scanner.rs` scans known MCP configuration locations:
Claude Desktop, Claude Code, VS Code, Cursor, Windsurf, Zed, and additional
config paths. Any MCP server entry found in these configs that is **not** registered
in the current gateway backend registry is an unmanaged MCP candidate.

**Implementation pointer**: `ConfigScanner::scan_all()` — extend with a
`--shadow` flag that diffs discovered servers against registered backends.

### Layer 2: Process Scanning

`src/discovery/process_scanner.rs` scans running processes for stdio MCP server
patterns (pieces-os, surrealdb, generic `mcp-server`, `mcp` process names).
Any running MCP process not originating from the gateway is a shadow candidate.

**Implementation pointer**: `ProcessScanner::scan()` — cross-reference discovered
processes against the gateway's managed backend PID list.

### Layer 3: Exported Network / SIEM Rules

For HTTP-layer MCP traffic that bypasses the gateway, mcp-gateway cannot intercept
traffic (it is not a network proxy). Instead, it can **export** detection rules
for the operator's existing network tooling:

- Regex selectors matching MCP handshake patterns (`"method": "initialize"`,
  `"method": "tools/call"`, `"protocolVersion": "202[4-9]"`)
- Export formats: `grep`-compatible shell patterns, Nginx/HAProxy log filters,
  YAML for SIEM ingestion

**Implementation pointer**: `mcp-gateway discover --shadow` subcommand generates
these rules. See RFC-0132 Component 2 for the full selector set and DLP regex
patterns derived from Cloudflare's enterprise MCP reference architecture.

### Scope Boundary

Shadow-AI detection in mcp-gateway is explicitly bounded to config scanning,
process scanning, and exported network/SIEM rules. Full network-layer interception
would require the gateway to become a network proxy, which is architecturally
out of scope for a local-first, single-binary deployment model.

---

## Positioning Strategy

mcp-gateway should not attempt to match Willow feature-for-feature on cloud
enterprise governance (managed IdP, 1000+ connectors, hosted audit dashboards).
Instead, the positioning leads on:

1. **Sovereign / self-hosted deployment** — runs on the operator's infrastructure,
   no cloud tenancy, no data leaving the network.
2. **Cryptographically verifiable execution evidence** — per-action attestation
   receipts and signed `.state` session files provide tamper-evident proof of
   tool invocations, stronger than conventional audit log entries.
3. **Transparent capability routing** — open-source dispatch path, inspectable
   meta-MCP surface, declarative capability YAML.
4. **Local-first shadow-AI detection** — config and process scanning without
   requiring cloud connectivity or managed agent deployment.

Willow / Webrix validates the B4 gateway platform thesis (enterprise buyers need
governed MCP tool access) and the B1 identity thesis (per-action attribution matters).
The competitive response is not to build a Willow clone but to sharpen the
sovereign + attestation wedge.

---

## References

- Willow product site: <https://withwillow.ai>
- Webrix platform: <https://app.webrix.ai>
- mcp-gateway attestation enforcement: `src/gateway/meta_mcp/invoke.rs:245`, `src/gateway/meta_mcp/invoke.rs:394`
- mcp-gateway config scanner: `src/discovery/config_scanner.rs:24`
- mcp-gateway process scanner: `src/discovery/process_scanner.rs:69`
- mcp-gateway descriptor spec (attestation substrate): `docs/runtime/descriptor_spec.md:25`, `docs/runtime/descriptor_spec.md:62`
- RFC-0132 shadow MCP detection design: `docs/design/RFC-0132-cloudflare-enterprise-mcp-gap-analysis.md:114`
