# Willow / Webrix — enterprise agent governance comparison

**Ticket**: MIK-5843
**Public sources**: [withwillow.ai](https://withwillow.ai), [app.webrix.ai](https://app.webrix.ai)
**Purpose**: keep the mcp-gateway feature bar honest against a public enterprise
identity + MCP gateway + audit product, and state where mcp-gateway is
self-hosted and cryptographically attested rather than a copy of a cloud
governance console.

Willow (Webrix) is an enterprise agent-governance surface: agent identity,
permissioned least-privilege tool access, an audit trail, an MCP gateway,
API-to-MCP conversion, a large connector catalog, IdP integration, runtime
guards, and shadow-AI / unmanaged-MCP discovery. Those claims are taken from
the public product pages above and are **not** independently re-measured here.

mcp-gateway is not a Willow clone. The positioning that this repository can
defend from code is:

- **sovereign / self-hosted** deployment (the operator runs the binary)
- **signed `.state`** / **per-action attestation receipts** at
  `gateway_invoke`, rather than an ordinary audit log of “who called what”
- local-first capability routing (`gateway_search` / `gateway_execute`)
- transparent YAML capability definitions instead of an opaque connector
  marketplace

Ordinary audit logs remain useful. They are not a substitute for a signed
attestation receipt bound to the action.

## Feature bar

Header (single line for mechanical checks): `| Connectors | IdP | Shadow | Runtime guards | Audit | Attestation |`

| Capability | mcp-gateway (this repo) | Willow / Webrix (public pages) | mcp-gateway verdict |
| --- | --- | --- | --- |
| Connectors | YAML capabilities + OpenAPI import; no 1000-item catalog | **1000+** connectors claimed | **LAG** |
| IdP | OAuth / OIDC backends (`docs/OAUTH_CONFIG.md`); no first-class Okta / Entra / JumpCloud product | IdP integration claimed (Okta, Entra, JumpCloud-class enterprise SSO) | **LAG** |
| Shadow-AI / unmanaged MCP | Config + process scanners; `mcp-gateway cap discover --shadow`; not a network proxy | Shadow-AI / unmanaged-MCP discovery claimed | **MATCH** as a bounded candidate (see below) |
| Runtime guards | Policy, firewall, circuit-breaker, rate-limit, schema validation | Runtime guards claimed | **MATCH** |
| Audit | Structured logs / telemetry | Audit trail claimed | **MATCH** on logs |
| Attestation | Per-action attestation at `src/gateway/meta_mcp/invoke.rs`; signed `.state` receipts | Ordinary audit log, not cryptographic action receipts | **LEAD** |

Verdict vocabulary is **LEAD** / **MATCH** / **LAG** relative to the public
Willow/Webrix bar, not a claim that either product is finished.

## Shadow-AI detection — capability candidate (no runtime change in this ticket)

Shadow-AI / unmanaged MCP detection is a **net-new capability candidate** for
mcp-gateway. Scope is deliberately bounded:

1. **Config scanning** — `src/discovery/config_scanner.rs` already reads client
   MCP configs. A server in those files that is not registered in this gateway
   is an unmanaged MCP candidate.
2. **Process scanning** — `src/discovery/process_scanner.rs` already lists
   running stdio MCP patterns. Processes the gateway did not spawn are
   unmanaged candidates.
3. **Exported network / SIEM rules** — operators can feed selector patterns to
   their own firewall, proxy, or SIEM. mcp-gateway is **not** a network proxy
   and does not inspect bypass traffic. If that architectural limit is
   unacceptable, do not expand this candidate into a packet path; file a
   follow-up instead.

Operator command already documented in `docs/SHADOW_SCAN.md`:

```bash
mcp-gateway cap discover --shadow --format json
```

This ticket does not change that command or the scanners. Follow-up Linear
work is required before treating shadow-AI as a shipped product surface.

## Implementation anchors

| Concern | Where |
| --- | --- |
| Per-action attestation | `src/gateway/meta_mcp/invoke.rs` |
| Config-file unmanaged MCP candidates | `src/discovery/config_scanner.rs` |
| Process unmanaged MCP candidates | `src/discovery/process_scanner.rs` |
| Shadow MCP design + SIEM export bound | `docs/design/RFC-0132-cloudflare-enterprise-mcp-gap-analysis.md` (Component 2) |
| Local `discover --shadow` CLI | `docs/SHADOW_SCAN.md` |

## What this page is not

- Not a Willow clone specification.
- Not a network-proxy design.
- Not a promise of Okta / Entra / JumpCloud SKUs.
- Not an instruction to change runtime gateway behavior in this commit.

## See also

- [RFC-0132 Component 2 — Shadow MCP Detection](../design/RFC-0132-cloudflare-enterprise-mcp-gap-analysis.md)
- [ShadowRadar passive discovery](../SHADOW_SCAN.md)
- [OAuth / identity](../OAUTH_CONFIG.md)
