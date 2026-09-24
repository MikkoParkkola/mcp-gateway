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
    agent: any
    capability: calendar_read_day
    scope: read
    owner:
      authority: api_key
      subject: alice
    provenance: local-operator
    reason: Alice approved read-only access to her calendar.
```

A grant matches a caller on `authority` and `subject` only. `label` is display
text and never takes part in matching, so the `Alice` above still matches the
caller the gateway labels `alice`. The subject a caller carries depends on how
it authenticated:

| Caller | `authority` | `subject` |
|---|---|---|
| API key (`auth.api_keys`) | `api_key` | the key's `name` |
| OIDC temporary token | the token's issuer | the token's `sub` |
| Trusted identity headers | `X-Gateway-Identity-Authority`, else `trusted_header` | the header subject |
| mTLS client certificate | `mtls` | first SAN URI, else CN |
| Agent JWT | `agent_oauth` | the agent's `client_id` |

Every `auth.api_keys` entry must have a non-empty `name`, unique across the
list, because that name is the key's grant identity. Config load refuses a
missing or duplicated name.

`agent: {exact: AGENT_ID}` matches only a caller with a proven agent id, which
only mTLS and agent-JWT callers have. An API-key caller has none, so an
API-key grant uses `agent: any`.

`capability` is the capability's `name`. `tool` is optional; for a capability
tool it is the same name, so leave it out.

`scope` is one of:

- `read`: allows capabilities that declare `metadata.read_only: true`.
- `execute`: allows any call to the capability, read-only or not.
- `any`: the same as `execute`.

`write` is refused at load. Dispatch cannot tell a write from any other
non-read-only call, so a `write` grant would never allow anything.

`expires_at` (RFC 3339) is optional; a grant without it stays live until revoked.

## Model

An `IdentityGrant` records:

- Stable grant id.
- Subject authority and subject id.
- Agent binding: any agent or one exact agent id.
- Capability id and optional tool name.
- Action scope: read, execute, or any.
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
- Expired grants stop allowing access as soon as they expire; no reload is needed.
- Revoked grants stop allowing access once a running gateway reloads the grant
  file (see [Applying changes to a running gateway](#applying-changes-to-a-running-gateway)),
  or at the next start.
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
  read_only: true
  identity_owner:
    authority: api_key
    subject: alice
```

## Local CLI Administration

Operators can manage the free/core local grant file without hand-writing YAML.
The CLI writes the same `identity_grants.v1` schema that gateway startup loads:

```bash
mcp-gateway identity grants grant \
  --file ~/.mcp-gateway/identity-grants.yaml \
  --grant-id alice-calendar-read \
  --subject api_key:alice \
  --subject-label Alice \
  --any-agent \
  --capability calendar_read_day \
  --scope read \
  --ttl-seconds 3600 \
  --reason "Alice approved read-only access to her calendar"
```

`--subject` takes `AUTHORITY:SUBJECT` from the table above. Pass
`--agent AGENT_ID` instead of `--any-agent` only for mTLS or agent-JWT callers,
the ones that carry a proven agent id. The command rejects duplicate grant ids unless `--replace` is
passed. If `--owner` is omitted, the owner defaults to the subject so the common
"user grants access to their own personal capability" flow does not require
extra fields.

List and revoke grants with:

```bash
mcp-gateway identity grants list --file ~/.mcp-gateway/identity-grants.yaml
mcp-gateway identity grants revoke \
  --file ~/.mcp-gateway/identity-grants.yaml \
  --grant-id alice-calendar-read
```

All three commands support `--format table|json|plain`. JSON is intended for
automation; table output is for local operators.

### Applying changes to a running gateway

The CLI only writes the file. It replaces it atomically, so a gateway never
reads a half-written grant file. A running gateway applies a `grant` or
`revoke` on its next config reload:

- the `gateway_reload_config` meta-tool (admin only);
- the admin UI reload;
- an automatic reload after `config.yaml` or an env file changes. Editing the
  grant file alone does not trigger one.

The reload report carries a grants line, for example
`identity grants reloaded (2 rows, 0 added, 0 removed, revoked +1, 0 pool slots evicted)`.
It appears even when the config half of the reload is refused. The
control-plane grant view shows the grants the gateway is enforcing at that
moment.

If the file cannot be read or parsed, the reload is refused and the grants
already in force stay in force, so a revocation has not landed. The refusal
names the file. A `busy` refusal means another grant reload was running; retry
it unchanged. A valid file with an empty `grants` list is applied, and it is
the way to revoke everything.

The file is authoritative on reload. Restoring an older copy, from a backup or
config management, re-grants everything revoked since that copy was taken. The
reload log and report show this as a negative `revoked` count. Grant reloads
are recorded in the tracing log only, not in the governance audit log. A
gateway running with auth disabled has no actor to attribute them to.

## Recommendations

`LocalIdentityGrantStore::recommend` is a recommendation-only layer for
automation-first UX. It does not create, mutate, or activate grants by itself;
live dispatch uses only the stored grant rows evaluated above. The CLI can write
those stored rows only after an explicit local operator command. Given a caller,
agent, capability, scope, data class, tool risk, owner, and request reason,
recommendation returns one of:

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
- Local CLI list/grant/revoke commands for single-node operator workflows.
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

MIK-6207, MIK-6208, and MIK-6209 are consolidated into this identity-grant path:
per-user personal capability access should use `IdentityGrant`, `GrantSubject`,
and the local grant-file/enterprise control-plane split described here. Do not
add a second ownership or grant model for those older tickets.
