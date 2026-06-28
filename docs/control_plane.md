# Control Plane

The control plane is the enterprise governance surface for mcp-gateway. The first implementation slice is a backend domain model, not a full UI: it defines the objects, RBAC checks, read-only inventory projection, mutation guard, audit event, rollback requirement, and license boundary that future API and web UI work must use.

## Domain Model

The model covers:

- Servers and tools.
- TrustCard references.
- TrustLab evaluation references.
- Grants and policies.
- Users and groups.
- Runtime health.
- Audit events and rollback plans.

The read-only projection intentionally excludes grant and policy mutation helpers. This lets inventory and evidence views ship before editing workflows are enabled.

## Roles

- `admin`: can read, review, approve, and mutate grants or policies.
- `security_reviewer`: can read inventory/evidence and record reviews, but cannot mutate grants or policies.
- `developer`: can read inventory/evidence.
- `auditor`: read-only inventory/evidence role.

All mutations require an audit event whose actor, action, and target match the requested mutation, plus a rollback plan.

## License Split

Free/core:

- Local read-only status.
- Local inventory and evidence summaries.

Enterprise:

- Fleet inventory.
- Grant and policy mutation workflows.
- Approval queues.
- Evidence export.
- Multi-user governance.

## Current Limits

- No web UI pages are served by this slice.
- No API routes are wired yet.
- No database persistence is added.
- No OIDC/SCIM integration is added.
- No SIEM or OTel export sink is added.

Those pieces should consume the domain and RBAC contract here instead of creating parallel authorization rules.
