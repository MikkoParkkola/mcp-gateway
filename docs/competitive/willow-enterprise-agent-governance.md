# Willow / Webrix — enterprise agent governance comparison

**Ticket**: MIK-5843
**Public sources** (read 2026-08-31, not independently re-measured):
[withwillow.ai](https://withwillow.ai),
[withwillow.ai/pricing](https://withwillow.ai/pricing),
[app.webrix.ai](https://app.webrix.ai)
**Purpose**: keep the mcp-gateway feature bar honest against a public enterprise
identity + MCP gateway + audit product.

Willow (Webrix) is an enterprise agent-governance surface: agent identity,
permissioned least-privilege tool access, an audit trail, an MCP gateway,
API-to-MCP conversion, a large connector catalog, IdP integration, runtime
guards, and shadow-AI / unmanaged-MCP discovery. Those claims are taken from
the public product pages above.

mcp-gateway is not a Willow clone. Properties this repository can defend from
code:

- operator-owned source and local YAML configuration (sovereign control of the
  binary you run)
- optional HMAC-signed `_meta.provenance` receipts on `gateway_invoke` (see
  `src/gateway/meta_mcp/invoke.rs`). This is not a signed `.state` file.
- local-first capability routing (`gateway_search` / `gateway_execute`)

Willow's pricing page also lists SaaS, self-hosted, and on-prem/air-gapped
deployments. Self-hosting is therefore not a unique mcp-gateway property.
The remaining distinction is source visibility and operator-controlled config,
not the mere existence of a self-hosted SKU.

An ordinary audit log is useful. It is not the same object as an attestation receipt.
mcp-gateway's receipt path is opt-in and does not cover every cache hit.

## Feature bar

Header (single line for mechanical checks): `| Connectors | IdP | Shadow | Runtime guards | Audit | Attestation |`

| Capability | mcp-gateway (this repo) | Willow / Webrix (public pages) | mcp-gateway verdict |
| --- | --- | --- | --- |
| Connectors | YAML capabilities + OpenAPI import; no 1000-item catalog | **1000+** connectors claimed | **LAG** |
| IdP | OAuth / OIDC backends (`docs/OAUTH_CONFIG.md`); no first-class Okta / Entra / JumpCloud product | IdP integration claimed (Okta, Entra, JumpCloud-class enterprise SSO) | **LAG** |
| Shadow-AI / unmanaged MCP | Local passive scan: `src/discovery/config_scanner.rs`, `src/discovery/process_scanner.rs`, `mcp-gateway cap discover --shadow`. Not a network proxy. Not org-wide automatic discovery. Follow-up work is required before treating this as an enterprise product surface. | Organization-wide automatic discovery claimed | **LAG** (local scan exists; enterprise discovery does not) |
| Runtime guards | Policy, firewall, circuit-breaker, rate-limit, schema validation | Runtime guards claimed | **MATCH** |
| Audit | Structured tracing/telemetry; cache-hit paths can skip the invocation event; transparency log is optional | Every action logged and exportable (public claim) | **LAG** |
| Attestation | Optional outbound HMAC `_meta.provenance` receipts. This is not a signed `.state` artifact. Inbound attestation token validation is a separate opt-in. | Ordinary audit log, not cryptographic action receipts | **LEAD** only when the opt-in receipt path is enabled |

Verdict vocabulary is **LEAD** / **MATCH** / **LAG** relative to the public
Willow/Webrix bar.

## Shadow-AI detection — capability candidate (no runtime change in this ticket)

Shadow-AI / unmanaged MCP detection remains a **net-new capability candidate**
beyond the local scan that already ships:

1. **Config scanning** — `src/discovery/config_scanner.rs` reads client MCP
   configs. A server in those files that is not registered here is an unmanaged
   MCP candidate.
2. **Process scanning** — `src/discovery/process_scanner.rs` lists running
   stdio MCP patterns. Processes the gateway did not spawn are unmanaged
   candidates.
3. **Exported network / SIEM rules** — operators can feed selector patterns to
   their own firewall, proxy, or SIEM. mcp-gateway is **not** a network proxy
   and does not inspect bypass traffic.

Operator command already documented in `docs/SHADOW_SCAN.md`:

```bash
mcp-gateway cap discover --shadow --format json
```

This ticket does not change that command or the scanners.

## Implementation anchors

| Concern | Where |
| --- | --- |
| Per-action provenance receipts | `src/gateway/meta_mcp/invoke.rs` |
| Config-file unmanaged MCP candidates | `src/discovery/config_scanner.rs` |
| Process unmanaged MCP candidates | `src/discovery/process_scanner.rs` |
| Shadow MCP design + SIEM export bound | `docs/design/RFC-0132-cloudflare-enterprise-mcp-gap-analysis.md` (Component 2) |
| Local `discover --shadow` CLI | `docs/SHADOW_SCAN.md` |

## What this page is not

- Not a Willow clone specification.
- Not a network-proxy design.
- Not a promise of Okta / Entra / JumpCloud SKUs.
- Not a claim that mcp-gateway uniquely offers self-hosted deployment.
- Not a claim that a signed `.state` file format exists in this repository.
- Not an instruction to change runtime gateway behavior in this commit.

## See also

- [RFC-0132 Component 2 — Shadow MCP Detection](../design/RFC-0132-cloudflare-enterprise-mcp-gap-analysis.md)
- [ShadowRadar passive discovery](../SHADOW_SCAN.md)
- [OAuth / identity](../OAUTH_CONFIG.md)
