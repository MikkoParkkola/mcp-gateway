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
| NFR.SEC.6 | ~~MIK-7262 open~~ SUPERSEDED 2026-09-06: the declared value returns at `:1127-1129`, above the inference short-circuits, and is mutation-probed | `src/capability/definition/mod.rs:1127-1129` | DOES NOT BLOCK |
| MIK-7215.TENANT.1 | no cross-tenant data-minimisation guard anywhere in `src/` | absent | BLOCKS |
| MIK-7215.CONFIRM.2 | destructive-op confirmation requires an SSE session; no stateless/modern path | `proxy.rs:213-260` | BLOCKS |
| MIK-7215.CONTROL.4 | `session_lifecycle` expiry module declared, zero other references | `src/gateway/mod.rs:19` | BLOCKS |
| MIK-7215.CONTROL.3 | transparency-log correlation key is the literal string `unknown` on every stateless request; live `trace_id` never passed in | `src/gateway/meta_mcp/invoke.rs:1299-1314,429` | BLOCKS |
| MIK-7217.DISCOVER.4 | no `server/discover` probe; era cache is unreferenced | `src/protocol/era.rs:61-171` | BLOCKS |
| MIK-7213.CACHE.4 | no policy-epoch cache invalidation on grant/profile change; TTL-only | `src/gateway/meta_mcp/invoke.rs:835-839` | BLOCKS |
| MIK-7272.ERROR.2 | resource-not-found returns -32002, spec requires -32602 | `src/gateway/meta_mcp/resources.rs:276-280` | BLOCKS |
| TASK.1 | ~~`tasks/get` and `tasks/update` resolve to method-not-found~~ **WITHDRAWN (2026-09-09, verified at source)** — both are served on the modern path at `src/gateway/router/handlers.rs:1564,1573`, reached through the routing arm at `handlers.rs:169`; `src/protocol/meta.rs:281-283` lists them as ADDED in 2026-07-28, not removed, and the cited `:240-246` is `MODERN_VERSIONS`, which says nothing about these methods. `tests/mik_7272_subscriptions_acs.rs:582` asserts the served behaviour | `src/gateway/router/handlers.rs:169,1564,1573`; `src/protocol/meta.rs:281-283` | WITHDRAWN |
| EXT.1 | ~~gateway never declares its own extensions; `ExtensionSet::gateway_declares()` has zero callers~~ **WITHDRAWN (2026-09-08, verified at source)** — refuted on both clauses. `gateway_declares()` is called at `src/gateway/meta_mcp_helpers.rs:182` inside `discovery_extensions()` (defined `:181`), which is in turn called at `src/gateway/meta_mcp/mod.rs:1207` on the live discovery path, so the gateway does declare its own extensions in production. `RELEASE-4.0.0-criteria-status.md:241` already corrected this same fact; this row was never updated to match | `src/protocol/extensions.rs:74`; callers at `src/gateway/meta_mcp_helpers.rs:182`, `src/gateway/meta_mcp/mod.rs:1207` | WITHDRAWN |
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

One row read as a security defect with a ticket open against it: NFR.SEC.6 cites
MIK-7262. That reading was wrong, and was corrected on 2026-09-06 -- the fix is
present, above the short-circuits rather than below them, and mutation-probed.
There is no owner decision here and no known bypass to ship. **CORRECTED 2026-09-06 -- MIK-7262 is CLOSED.** The line numbers this row was written against drifted: the declared-value return is at `src/capability/definition/mod.rs:1127-1129`, not `:1150` (`:1150` is now a `.get("properties")` call), and it sits ABOVE the inference short-circuits, not below them. Only the `read_only` return at `~:1113` precedes it, deliberately. Mutation-probed: deleting `:1127-1129` and running `cargo test --lib caller_addressed_state_tests` gives `6 passed; 4 failed` on four named declaration assertions (`:1326`, `:1344`, `:1360`, `:1369`); restoring and re-running gives `10 passed; 0 failed`. Enforcement is wired, not schema-only: `src/gateway/meta_mcp/invoke.rs:927-938` refuses a non-admin caller. See `RELEASE-4.0.0-criteria-status.md` NFR.SEC.6.
