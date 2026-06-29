# Identity Grants

Identity grants are the free/core authorization contract for personal MCP
capabilities. They define who may use a capability, which agent may act for that
subject, which action scope is allowed, when the permission expires, and why the
decision was made.

The local evaluator is wired into gateway dispatch for capability tools that
opt in with `metadata.exposure: personal`. Existing capability files default to
`shared`, so current single-user deployments remain compatible while personal
tools fail closed unless caller identity, owner evidence, and a live grant match.

## Local Grant File

Free/core deployments can load local grant rows at startup:

```yaml
security:
  identity_grants:
    enabled: true
    path: ~/.mcp-gateway/identity-grants.yaml
    fail_on_error: true
    trust_caller_identity_headers: false
```

`fail_on_error` defaults to `true`. If the operator explicitly enables local
grants but the file is missing, unreadable, malformed, or uses an unsupported
schema version, gateway startup fails instead of silently running with an empty
grant store.

`trust_caller_identity_headers` defaults to `false`. Enable it only when the
gateway is reachable solely through a trusted edge or bridge that authenticates
the caller and strips or overwrites inbound identity headers. When enabled, the
gateway accepts:

- `X-Gateway-Identity-Subject` or `X-Gateway-Identity`
- Optional `X-Gateway-Identity-Authority`
- Optional `X-Gateway-Identity-Label`
- Cloudflare Access fallback: `Cf-Access-Authenticated-User-Id` or
  `Cf-Access-Authenticated-User-Email`

Validated OIDC temporary-token identities take precedence over trusted headers.
Trusted headers take precedence over mTLS and agent-JWT identities. If none are
present, dispatch falls back to the authenticated API key name as the local
grant subject.

Grant files are JSON or YAML:

```yaml
schema_version: identity_grants.v1
grants:
  - grant_id: alice-calendar-read
    subject:
      authority: api_key
      subject: alice
      label: Alice
    agent:
      exact: agent-a
    capability: personal_calendar
    tool: read_day
    scope: read
    owner:
      authority: api_key
      subject: alice
      label: Alice
    expires_at: "2026-06-28T23:00:00Z"
    provenance: local-operator
    reason: Alice approved read-only calendar access for agent-a.
```

## Model

An `IdentityGrant` records:

- Stable grant id.
- Subject authority and subject id.
- Agent binding: any agent or one exact agent id.
- Capability id and optional tool name.
- Action scope: read, write, execute, or any.
- Optional owner subject for personal capabilities.
- Expiry and revocation timestamps.
- Provenance and human-readable reason.

Grant evaluation emits an `IdentityGrantAuditEvent` for every allow or deny
decision. Audit events contain the subject, agent id, capability, tool, scope,
reason code, matching grant id when present, and timestamp.

## Behavior

- Public capabilities remain allowed without a personal grant.
- Shared capabilities remain allowed without a personal grant.
- Capability metadata defaults to `shared` exposure for backward compatibility.
- Personal capabilities fail closed when the caller identity is missing.
- Personal capabilities fail closed when owner evidence is missing.
- Personal capabilities fail closed when owner and caller differ.
- Expired or revoked grants do not allow access.
- A live matching grant allows the request and records its grant id.

The gateway also carries the verified caller subject into the capability
execution context. Direct capability execution uses the same personal owner
check before schema validation or upstream auth resolution. The legacy
no-context path remains compatible for public and shared capabilities, but
personal capabilities require an explicit matching caller identity.

Personal capability YAML uses the existing metadata block:

```yaml
metadata:
  exposure: personal
  identity_owner:
    authority: api_key
    subject: alice
    label: Alice
```

## Recommendations

`LocalIdentityGrantStore::recommend` is a recommendation-only layer for
automation-first UX. It does not create, mutate, or activate grants by itself;
live dispatch uses only the stored grant rows evaluated above. Given a caller,
agent, capability, scope, data class, tool risk, owner, and request reason, it
returns one of:

- Allow public or shared capability.
- Reuse an existing live grant.
- Recommend a short least-privilege lease.
- Require human confirmation.
- Request delegated administrator review.
- Deny because caller or owner evidence is missing.

Lease recommendations default to one hour and are clamped to at most 24 hours.
The recommendation output includes a stable reason code, human-readable
explanation, confirmation flag, optional lease proposal, revoke path, and audit
event. Cross-user personal access never receives an automatic lease proposal.
Sensitive, destructive, or broad-scope workflows require confirmation before a
lease can be used.

## License Split

Free/core:

- Local grant schema.
- Local JSON/YAML grant-file loader and in-memory evaluator.
- Fail-closed personal capability dispatch for local capability tools.
- Audit-event shape.
- Recommendation-only least-privilege lease suggestions for local workflows.

Enterprise:

- Durable org-wide grant storage and synchronization.
- SSO and group inheritance.
- Delegated approvals.
- Evidence export.
- Fleet policy reconciliation.
- Delegated approval queues and policy-aware grant recommendation.

## Integration Notes

Dispatch enforcement runs before capability executor calls, so a denied personal
tool cannot reach the upstream HTTP/GraphQL/JSON-RPC provider. Stdio and other
callers without an authenticated API key fail closed for personal tools.

Control-plane mutation workflows should use the same grant row and audit-event
shapes rather than creating a parallel authorization model. Durable storage,
OIDC/SCIM, delegated approvals, and fleet policy reconciliation remain
enterprise follow-up work.
