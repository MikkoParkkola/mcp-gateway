# Identity Grants

Identity grants are the free/core authorization contract for personal MCP
capabilities. They define who may use a capability, which agent may act for that
subject, which action scope is allowed, when the permission expires, and why the
decision was made.

The first implementation slice is a local contract and evaluator. It does not
change live dispatch behavior yet. That keeps existing single-user deployments
compatible while the gateway gains a stable decision surface for later routing,
admin UI, and durable storage integration.

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
- Personal capabilities fail closed when the caller identity is missing.
- Personal capabilities fail closed when owner evidence is missing.
- Personal capabilities fail closed when owner and caller differ.
- Expired or revoked grants do not allow access.
- A live matching grant allows the request and records its grant id.

## Recommendations

`LocalIdentityGrantStore::recommend` is a recommendation-only layer for
automation-first UX. It does not change dispatch behavior. Given a caller,
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
- Local in-memory evaluator.
- Fail-closed personal capability decision contract.
- Audit-event shape.
- Recommendation-only least-privilege lease suggestions for local workflows.

Enterprise:

- Durable org-wide grant storage.
- SSO and group inheritance.
- Delegated approvals.
- Evidence export.
- Fleet policy reconciliation.
- Delegated approval queues and policy-aware grant recommendation.

## Integration Notes

The contract is intentionally standalone. Live dispatch enforcement should wire
the evaluator before personal capability execution and before any personal
resource lookup. Control-plane mutation workflows should use the same grant row
and audit-event shapes rather than creating a parallel authorization model.
