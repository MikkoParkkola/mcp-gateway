<!-- SPDX-FileCopyrightText: 2026 Mikko Parkkola -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Partial requirements audit — recovered from a killed run

The `audit-requirements` sweep died on an output-token ceiling mid-emit. These
rows are everything it had produced, recovered from its final message. The run
was NOT complete: the last row is truncated mid-word and an unknown number of
groups were never reached. Treat this as a floor on the blocking count, never a
total. Each row is the agent's claim; none is independently verified here.

| criterion | finding | evidence | verdict |
|---|---|---|---|
| MIK-7212.MRTR.2 | continuation minting exists, zero non-test callers | `src/protocol/continuation.rs:206-354` | BLOCKS |
| NFR.SEC.6 | MIK-7262 open: `registers_external_callback` override silently skipped for read-only/non-mutating/no-schema methods | `src/capability/definition/mod.rs:1113-1152` | BLOCKS |
| MIK-7215.TENANT.1 | no cross-tenant data-minimisation guard anywhere in `src/` | absent | BLOCKS |
| MIK-7215.CONFIRM.2 | destructive-op confirmation requires an SSE session; no stateless/modern path | `proxy.rs:213-260` | BLOCKS |
| MIK-7215.CONTROL.4 | `session_lifecycle` expiry module declared, zero other references | `src/gateway/mod.rs:19` | BLOCKS |
| MIK-7215.CONTROL.3 | transparency-log correlation key is the literal string `unknown` on every stateless request; live `trace_id` never passed in | `src/gateway/meta_mcp/invoke.rs:1299-1314,429` | BLOCKS |
| MIK-7217.DISCOVER.4 | no `server/discover` probe; era cache is unreferenced | `src/protocol/era.rs:61-171` | BLOCKS |
| MIK-7213.CACHE.4 | no policy-epoch cache invalidation on grant/profile change; TTL-only | `src/gateway/meta_mcp/invoke.rs:835-839` | BLOCKS |
| MIK-7272.ERROR.2 | resource-not-found returns -32002, spec requires -32602 | `src/gateway/meta_mcp/resources.rs:276-280` | BLOCKS |
| TASK.1 | `tasks/get` and `tasks/update` resolve to method-not-found | `src/protocol/meta.rs:240-246` | BLOCKS |
| EXT.1 | gateway never declares its own extensions; `ExtensionSet::gateway_declares()` has zero callers | `src/protocol/extensions.rs:59-64` | BLOCKS |
| SCHEMA.1 | truncated mid-emit — finding lost, concerned `gateway_execute`'s `chain` parameter | not recoverable | UNRESOLVED |

## What this changes

The gap plan's nine increments were sized against MRTR's ten criteria. At least
eight of the rows above sit outside MRTR entirely — tenancy, confirmation on the
stateless path, session expiry, transparency-log correlation, cache invalidation,
error codes, tasks and extensions. The plan's own section 2 already carries a
note that it is undersized; this is the first measured evidence of by how much,
and it is still a floor.

Two rows corroborate findings already reached independently: MRTR.2's unwired
minting (closed by increment 1) and the unreferenced era cache (increment 6).

One row is a security defect with a ticket already open against it: NFR.SEC.6
cites MIK-7262. A release that ships with it open is shipping a known bypass of
an external-callback declaration, and that is a decision for the owner rather
than a wiring increment.
