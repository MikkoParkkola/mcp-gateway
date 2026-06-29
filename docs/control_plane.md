# Control Plane

The control plane is the governance surface for mcp-gateway. It defines the
objects, RBAC checks, read-only inventory projection, mutation guard, audit
event, rollback requirement, and license boundary that API and web UI work must
use.

## Domain Model

The model covers:

- Servers and tools.
- TrustCard references.
- TrustLab evaluation references.
- Grants and policies.
- Users and groups.
- Runtime health.
- Audit events and rollback plans.

The read-only projection intentionally excludes grant and policy mutation
helpers. This lets inventory and evidence views ship before editing workflows are
enabled.

The decision queue is the UI/API-ready projection for the next control-plane
surface. It turns pending approvals, requested grants, non-enforced policies,
low-trust evaluations, and unhealthy runtimes into role-aware human decision
items with a reason code, suggested next step, required role, license tier, and
per-actor `can_act` flag. It does not mutate state; grant and policy changes
still require the audited mutation contract below.

## Local API

`GET /ui/api/control-plane` returns the current read-only control-plane
projection for the local gateway process. It is served by the authenticated web
UI API router and does not mutate state.

The response includes:

- `schema_version`: currently `control_plane.api.v1`.
- `source`: currently `local_runtime_snapshot`.
- `route`: confirms the route is read-only and is not a mutation endpoint.
- `actor`: the authenticated client projected into a control-plane role.
- `features`: free/core versus enterprise feature boundaries.
- `authorizations`: RBAC decisions for read, review, and mutation actions.
- `coverage` and `inventory_counts`: which domains are represented in the local snapshot.
- `view`: read-only server, tool, trust evidence, runtime health, and audit evidence projection.
- `decision_queue`: human-gated items derived from policy, trust, server, grant, and runtime state.
- `current_limits`: machine-readable limitations of this slice.

The local API derives server and runtime health from the in-process backend
registry. It does not fetch tools over the network; it only reports tools already
present in the backend cache.

When cached tool metadata is present, the local API also derives local
TrustCard references for Control Plane consumers. The projection includes the
server id, TrustCard schema version, and canonical TrustCard SHA-256 digest.
The same digest source is projected into live `tools/list` descriptors as a
small `trustCard` reference so Control Plane rows, protocol clients, and policy
consumers can correlate a tool descriptor with its local TrustCard evidence
without embedding the full TrustCard in every descriptor.

## Local Web UI

The embedded `/ui` dashboard includes a `Control Plane` tab that consumes
`GET /ui/api/control-plane`. It shows the local actor, inventory coverage,
server inventory, TrustCard digest references, runtime health, role-aware
decision queue, RBAC projection, and free/core versus enterprise feature
boundaries.

The tab is intentionally read-only. It does not add grant or policy mutation
controls, approval actions, persistence, evidence export, OIDC/SCIM integration,
or SIEM/OTel sinks.

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
- `GET /ui/api/control-plane` local runtime snapshot.
- `/ui#control-plane` local read-only control-plane tab.

Enterprise:

- Fleet inventory.
- Grant and policy mutation workflows.
- Approval queues.
- Evidence export.
- Multi-user governance.

## Current Limits

- The visual web UI is local and read-only.
- No database persistence is added.
- No mutation API route is added.
- No OIDC/SCIM integration is added.
- No SIEM or OTel export sink is added.

Those pieces should consume the domain and RBAC contract here instead of creating parallel authorization rules.
