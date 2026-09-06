# Test plan — NFR.PERF.3 reclamation

Status: draft for dual-vendor review as a PLAN. No test code written.
Design: `docs/design/2026-09-01-nfr-perf3-reclamation.md`, including its 2026-09-06 receipt update
and the same-day correction that hands the lifetime mechanism to MRTR.8b.
Depends on: `docs/design/2026-09-06-mrtr-8b-10a-lifetime-and-idempotency-wiring.md` Design A
(`InFlight::guard(now)`). Row 2 cannot pass before it lands, which is the point of it.

`NFR.PERF.4` is not covered here and never was this slice's: the ceiling, its assertion and its
open breaking-change question all live in `docs/design/2026-09-02-perf4-meta-tool-ceiling.md`,
which owns the production change that turns the assertion green. A second plan writing the same
case would have been the duplicate the review caught.

## Scope of this plan

One row per clause of `NFR.PERF.3` as the clause is worded in
`docs/requirements/RELEASE-4.0.0-requirements.md:283`. No row asserts anything about the capacity
constant itself, about `NFR.PERF.1`, or about the meta-tool surface.

| # | criterion clause | the case that proves it | level | type | can it fail today, and on what |
|---|---|---|---|---|---|
| 1 | memory MUST NOT grow unboundedly with abandoned continuations — the bound holds | fill to `IN_FLIGHT_CAPACITY` (4 096) with live, unexpired holds, then `hold` once more; the refusal is `None` and occupancy stays at 4 096 | unit, `src/protocol/continuation.rs` tests | boundary | **No — and it is stated as already met.** `hold`'s capacity branch is built (`:696-717`). The row exists so the clause has a case, not because it is expected to go red; its value is regression, and the falsifier probe below is what earns it |
| 2 | …and a soak with abandonment MUST show reclamation | abandon 8 192 exchanges (2x capacity, so the table wraps its own ceiling once) against a **driven clock**; advance `now` past the deadline; occupancy is 0 with no capacity pressure applied | unit, same module | lifetime / state | **Yes.** Today reclamation runs only inside the capacity branch, so below capacity an expired hold is retained indefinitely. Fails on the occupancy assertion until `guard(now)` lands |

## Why no wall-clock soak

The requirement names no duration, no abandonment rate and no reclamation threshold — recorded as
an unknown and resolved in the design's receipt update. A wall-clock soak would therefore be
inventing its own bound, would not run in the suite, and would be a weaker observation than the
driven clock: it can only show that reclamation happened *somewhere* in the interval, where row 2
shows it happened *at the deadline*. The clock is a parameter on the entry points (`now: u64`,
already the module's shape at `:696` and in Design A), so no sleeping and no timing tolerance.

## Assertion strength — the second question a plan review must answer

Every row states above what makes it fail. The risks specific to this plan:

- **Row 1 asserts a property that is already true.** That is an honest weakness, not a hidden
  one: written after the mechanism, it inherits none of the free failure. It gets the
  retrofitting falsifier probe from the process — restore the pre-`ec11dcec` body of the
  capacity branch and show the case fails on the occupancy assertion, then restore and show it
  passes. Without the probe it is not evidence.
- **Row 2 must not stage away the condition it observes.** The fixture may not call
  `complete` on the abandoned exchanges, and may not reach capacity before asserting; either would
  reclaim through a path that already works and make the assertion true without the mechanism
  under test. 8 192 is chosen so the *fill* crosses capacity while the *observation* happens after
  the drain, and the assertion is on holds that were never completed.
- **The admission-recovery row was deleted, not repaired.** An earlier draft carried a third row —
  after row 2's drain, a fresh `hold` at the advanced clock returns `Some` — presented as failing
  evidence of the wedge. It is not: `hold`'s capacity branch already calls `reclaim_abandoned(now)`
  and re-checks (`continuation.rs:696-717`), so against 4 096 expired holds that case returns
  `Some` **today**, through the path that already works. It would have been a green row wearing a
  red label. Its stated justification — that a reclaimer could empty the map while leaving capacity
  accounting stale — describes a state this module cannot reach, because `held.len()` *is* the
  accounting. One map, one number, no second bookkeeping to drift.

## What is deliberately not covered

- Memory or RSS. Bounded at 4 096 entries either way, so any RSS assertion passes against the
  unfixed code — recorded in the design as the wrong assertion rather than omitted silently.
- The at-capacity O(4 096) walk under the lock. It is a real finding, raised against MRTR.8b's
  design where the code lives; a performance assertion here would test a mechanism this slice does
  not own.
- Anything about the meta-tool surface. `docs/design/2026-09-02-perf4-meta-tool-ceiling.md` owns
  `NFR.PERF.4`, including the deletion of the seventeenth tool, the matching
  `benchmarks/public_claims.json` edit, and the operator question gating both.

