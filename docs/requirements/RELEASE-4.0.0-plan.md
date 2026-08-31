# v4.0.0 release plan — closing the 26 blocking criteria

Companion to `docs/requirements/RELEASE-4.0.0-criteria-status.md`, which is the status SSOT.
This file is the ORDER OF WORK, not a second status table. When the two disagree, the status
doc wins.

Standing: 43 MET, plus 4 qualified MET (2 `MET (I)`, 1 residual, 1 caveat). 26 criteria are
blocking — 17 UNWIRED (code exists, nothing calls it), 12 ABSENT (nothing implements it), 0
UNTESTED as of 2026-08-31.

## The shape of the problem

Two thirds of the blocking set is not missing code. It is code that exists and is not
reachable. That changes the plan: for UNWIRED criteria the expensive part is deciding *where*
the wiring belongs and what it changes for existing deployments, and the cheap part is the
edit. Every one of those decisions is a §P1 design event and none of them is an edit.

## Clusters, in dependency order

### A. MRTR continuation state — MIK-7212, 10 criteria — CRITICAL PATH

MRTR.1 through MRTR.10a: sealed continuation envelopes minted by the gateway, principal and
request binding, single-use with expiry holding across replicas, replica affinity on retry,
the modern-to-legacy `InputRequiredResult` bridge, bounded in-flight state, and never sending
an `inputRequest` type the client has not declared.

Largest cluster, deepest security surface, and it gates two other clusters. Already in flight
in another session (`src/protocol/continuation.rs`, `tests/mik_7212_acs.rs`).
Blocks: cluster H, and MRTR.10a feeds cluster B's SUB.4 key contents.

### B. MCP 2026 protocol semantics — MIK-7272, 10 of 17 criteria

Not one job. It splits by size:

- **Small, self-contained**: ERROR.2 (resource-not-found returns `-32602`, not `-32002`),
  RESULT.2 (a missing `resultType` defaults to complete when the gateway reads a backend
  reply). Each is a narrow change with a test that is red today.
- **Design-first**: SUB.4 (idempotency wiring — design at revision 4, see
  `docs/design/2026-08-31-sub-4-idempotency-wiring.md`. Larger than it looked: seven verified
  implementation defects are prerequisites, and no advertised way exists for a client to send a
  retry key at all. One question still blocks all code, and it is a tool-surface decision the
  operator has been asked and has not yet answered),
  ORDER.2 (tool set must not vary per connection), SUB.2 (request-scoped notifications on the
  request's own response stream), EXT.1 (declare extensions through server capabilities),
  OTEL.1 (`traceparent`/`tracestate`/`baggage` through `_meta`).
- **Whole feature**: TASK.1, the `io.modelcontextprotocol/tasks` extension for long-running
  backend calls. Largest single item outside cluster A. It is also SUB.4's alternative
  branch, so a decision to build it changes SUB.4's scope.

### C. Backend era detection — MIK-7217, 7 criteria

DISCOVER.4 (detect a backend's protocol era by probing, never by trusting a version string)
and DISCOVER.5 (cache the detected era per backend, re-probe when a cached assumption fails)
are the two named. One coherent design covers the cluster.
Blocks: cluster D's HEADER.9, which is conditioned on what the peer negotiated.

### D. Header forwarding — MIK-7214, 4 criteria

HEADER.5 (`x-mcp-header` mirroring an argument into `Mcp-Param-{name}` outbound, SEP-2243)
plus HEADER.7-9. HEADER.9 sends the modern `_meta` envelope only where the peer negotiated it,
so it cannot be finished before cluster C.

### E. Principal-keyed security — MIK-7116 + MIK-7215, 4 criteria

TENANT.1 (cross-tenant data-minimisation keyed on authenticated principal, not session),
CONTROL.2 (principal-keyed budget), CONTROL.3 (transparency-log correlation on the OTel trace
id, not session id), CONTROL.4 (session-lifecycle TTL reaping owning cleanup that disconnect
used to do). One theme: session identity is the wrong key everywhere it is still used.
In flight in another session (`src/security/firewall/principal_window.rs`, `tenant_guard.rs`).

### F. Response-cache keying — MIK-7213, 2 criteria

CACHE.3 (public scope only, with proof and a decision table) and CACHE.4 (shared cache keyed
on all eight response-varying inputs plus a policy epoch). Both are correctness-of-caching
questions, independent of everything above, and safe to run in parallel.

### G. Schema validity — MIK-6865.SCHEMA.1

Tool schemas must remain valid under JSON Schema 2020-12. There is no validator in the
dependency tree, so this is a dependency decision before it is a test: which crate, what it
costs at startup, and whether validation runs at load time or in CI only. Supply-chain gate
(DoD D30) applies. Design first; the criterion cannot be closed by a hand-rolled check.

### H. Confirmation gate reachability — MIK-7246.CONFIRM.2

The destructive-action confirmation gate must be reachable through the MRTR path so a modern
client can actually confirm. CONFIRM.1 closed 2026-08-31; this is the other half and it cannot
be built before cluster A lands.

## Order of work

**Wave 1 — designs only, no code, all parallel.** C, F, G, and the design-first half of B.
Each is a §P1 note reviewed by two vendors before an edit. This is the wave that decides
things, and it is the one most likely to be skipped under release pressure.

**Wave 2 — the small self-contained items.** B's ERROR.2 and RESULT.2, and D's HEADER.5.
Failing test first, then the change. These need no wave-1 output and can start immediately.

**Wave 3 — implementation of wave 1.** Plus D's HEADER.7-9 once C lands.

**Wave 4 — the two long poles.** Cluster A (in flight) and B's TASK.1. H follows A.

Clusters A and E are owned by other sessions. Coordinate before touching
`src/protocol/continuation.rs`, `src/security/firewall/`, or their test files.

## What would make this plan wrong

- If TASK.1 is dropped from v4.0.0, SUB.4 loses its alternative branch and its design
  narrows to the idempotency route alone. That is a scope decision for the operator, not an
  engineering one, and it is worth asking before wave 1 finishes.
- If cluster A slips, H slips with it and MRTR.10a's key contents stay open, which leaves
  SUB.4 implementable but not fully specified.
