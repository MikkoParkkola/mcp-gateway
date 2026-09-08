# MIK-7272.SUB.4 — wiring the idempotency cache

Status: **HELD — subordinate to `docs/design/2026-08-31-sub-4-idempotency-wiring.md`
(revision 5, 430 lines)**, which designs the same change and was reviewed twice
(GPT-5.x and Grok, both SHIP-WITH-FIXES on revision 2). This document was written
without knowledge of that one and is a narrower re-derivation of its Axis-1
conclusion: it omits nine of its decisions, the direct `POST /mcp/{name}` route,
every prerequisite it names (including MRTR.10a), and its own gate — revision 5
is unreviewed and says it "rides the next dual-vendor design review, before SUB.4
writes code."

Two things must be settled before this document is either folded in or dropped
(H2 UPDATE > CREATE), and both are asked of the team lead, not checkable here:

1. **Config gate.** `docs/requirements/RELEASE-4.0.0-criteria-status.md` line 227
   records a ruling of 2026-09-07: *"idempotency defaults ON. A protocol guarantee
   that holds only when someone opts in is not a guarantee; the config gate exists
   so an operator can DISABLE it, never as the default posture. The TTL takes
   CONTROL.4's shape — a config field with a defensible default."* The Decision
   section below says the opposite (unconditional, module constants, no config
   surface). The 2026-09-08 acceptance recorded above was for the two-change
   split; whether it also superseded the config gate is not established.

   **Checked since (2026-09-08):** the reviewed design agrees with this one, not
   with the ruling. `2026-08-31-sub-4-idempotency-wiring.md:375` asks "May an
   operator disable protection a criterion states as MUST?" and answers *"DECIDED
   on the requirement rather than asked: no. A switch makes the criterion
   unverifiable wherever the running configuration differs from the shipped
   default. Recorded so it can be overruled, not so it can be confirmed."* So the
   question is no longer which of two documents is right — both say unconditional
   — but whether the 2026-09-07 ruling IS the overrule that row invited. It reads
   like one. Nobody but the team lead can say so, and the code as committed
   follows the design, not the ruling.
2. **Which document survives**, and whether revision 5's outstanding dual review
   gates the code.

The implementation of change one is committed (`7851736d`) so it is not lost, and
its commit message records the same two open questions. **No criteria row has
been moved and none will be until both are answered.**

Change one of two.

## Problem

`MetaMcp::enable_idempotency` (`src/gateway/meta_mcp/mod.rs:683`) exists, carries
`#[allow(dead_code)]`, and has exactly one caller anywhere in the tree — a test
(`src/gateway/meta_mcp/tests.rs:3565`). `MetaMcp::idempotency_cache` is
initialised `None` at `mod.rs:464` and nothing in the boot path ever populates it.

`Gateway::build_meta_mcp` is the ONLY production construction site: every other
`MetaMcp::new` in the tree sits inside `mod tests` (`server/mod.rs:2216`), and
both entry points route through it — `run` (`:836`, HTTP) and `run_stdio`
(`:1553`). So populating it there covers both transports, and "inert in every
deployment" is falsified for both. stdio stays unprotected for a *different*
reason, below: its client's key never reaches the funnel.

With the field `None`, `idempotency_key_for` short-circuits on `idem_cache?`
(`support.rs:35`), so both the key and the fingerprint are `None`, the
`if let (Some, Some, Some)` guard at `invoke.rs:1244` never runs, and every
re-issued call re-dispatches. There is no refusal and no warning: a client that
retries a side-effecting tool under the same key gets the side effect twice,
silently. `IdempotencyCache::mark_completed` is inert in every deployment for the
same reason.

## Decision — unconditional, no config field

The cache is populated for every gateway, with constants, and
`#[allow(dead_code)]` is removed.

Idempotency is a correctness mechanism, not a preference. The only thing an
operator-facing toggle buys is the ability to switch duplicated side effects back
on, which nobody wants; a knob nobody has asked for is the thing to skip. Cache
bounds already exist as module constants (`COMPLETED_TTL`, `IN_FLIGHT_TIMEOUT`,
`MAX_ENTRIES` in `src/idempotency.rs`); this change adds one more,
`CLEANUP_INTERVAL`, for the eviction sweep. If an operator ever asks for tunable
bounds, a config section is added then and not before.

Recorded here because "unconditional, no config" is a design event by anyone's
reading: it changes an observable property of every deployment.

## Scope — two changes, and the row is MET only when both land

The criterion says UNWIRED on every route, and that is true for two *different*
reasons:

| transport | why the key does not take effect |
|---|---|
| HTTP | `RetryFields` is parsed (`handlers.rs:1220`) and threaded through (`:1401`). Only the `None` cache blocks it. |
| stdio | `server/mod.rs:2633` and `:3671` hardcode an absent retry. The client's key is discarded before it reaches the funnel. |

Populating the cache therefore protects HTTP-with-a-cooperating-client and leaves
stdio structurally unprotectable. That is a partial state, not a released
criterion — so SUB.4 goes MET only when both land.

They are two changes rather than one because the stdio seam has its own design
doc (`docs/design/2026-09-02-cluster-g-stdio-dispatch-parity.md` section P3) and
its own test rows; folding them together makes the HTTP half wait on a cross-lane
coordination it does not need.

- **Change one (this one):** populate the cache at `build_meta_mcp`.
- **Change two:** the stdio seam. Before starting it, read the cluster-G doc
  section P3 and establish whether that lane is active — if someone is already
  building `RetryFields` at the convergence point we consume their work. The
  ignored watchdog `stdio_should_present_a_retry_when_the_context_declares_one`
  (`server/mod.rs:3582`) is the row that un-ignores when change two lands.

## Out of scope

- The stdio seam (change two).
- Any config surface for idempotency.
- Gateway-derived keys. The key is client-supplied by design; `support.rs:21-35`
  records why deriving one would make a deliberate identical second call silently
  return the first result. The JSON-RPC request id plays no part — the
  fingerprint is over server, tool and arguments plus the retry discriminator
  (`invoke.rs:1233-1237`), so a fresh request id is already transparent.
- The three unrelated clippy failures already present on this branch.

## Coupled ledger row

`docs/requirements/RELEASE-4.0.0-criteria-status.md` line 144 (MRTR.10b) rests
its verdict on `idempotency_cache` never being populated, citing SUB.4. This
change falsifies that sentence, so the row is rewritten in the same commit. The
SUB.4 row's line references have also drifted (`mod.rs:656` and `:437` are now
`:683` and `:464`) and are corrected in passing; the rest of the file is left
alone.

## Unknowns

- *Does the invoke path settle a successful dispatch as completed, so a re-issued
  key is served the stored result rather than re-dispatching?* — answered by the
  behavioural test below, which fails if it does not.

## Test plan

| criterion | case | level | type |
|---|---|---|---|
| SUB.4 — the cache is populated on the production boot path | `sub4_boot_populates_the_idempotency_cache`: default config, `build_meta_mcp`, then the field is `Some` | integration (boot path) | wiring |
| SUB.4 — what the wiring buys: a re-issued key is not re-dispatched | `a_reissued_idempotency_key_is_served_from_the_stored_result`: counting backend, **no response cache**, two invokes under one key, backend asked once, both replies carry the backend's body | unit (invoke path) | behavioural |

The first case fails before the change (the field is `None` on every boot) and is
the RED test. **Verified, not asserted (2026-09-08):** the test was written first
(`359293e2`) but its red was never observed, so it was recovered with the §P2
falsifier probe — `git show 7851736d^:src/gateway/server/mod.rs` restored under a
trap, one run, then the repair copied back and re-run. Pre-fix: FAILED at
`server/mod.rs:3104`, *"the boot path must populate the idempotency cache; an
unpopulated one makes every client-supplied idempotency key inert"* — the
intended assertion, not a compile error. Restored: ok, 1 passed. The second is honestly a characterization test for an existing
mechanism, not a free failure: the guard is already written, and before this
change it was reachable only from tests. It earns its place by pinning the
behaviour the wiring turns on — and it can fail, because the response cache is
deliberately left out, so a second identical call reaches the backend unless the
idempotency guard stops it.
