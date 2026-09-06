# Test plan — NFR.PERF.3 reclamation, NFR.PERF.4 ceiling

Status: draft for dual-vendor review as a PLAN. No test code written.
Design: `docs/design/2026-09-01-nfr-perf3-reclamation.md`, including its 2026-09-06 receipt update
and the same-day correction that hands the lifetime mechanism to MRTR.8b.
Depends on: `docs/design/2026-09-06-mrtr-8b-10a-lifetime-and-idempotency-wiring.md` Design A
(`InFlight::guard(now)`). Rows 2 and 3 cannot pass before it lands, which is the point of them.

## Scope of this plan

One row per clause of the two criteria, as the clauses are worded in
`docs/requirements/RELEASE-4.0.0-performance.md:77-88`. No row asserts anything about the
capacities themselves, about NFR.PERF.1, or about deleting the seventeenth meta-tool.

| # | criterion clause | the case that proves it | level | type | can it fail today, and on what |
|---|---|---|---|---|---|
| 1 | PERF.3 — in-flight state MUST NOT grow unboundedly | fill to `IN_FLIGHT_CAPACITY` (4 096) with live, unexpired holds, then `hold` once more; the refusal is `None` and occupancy stays at 4 096 | unit, `src/protocol/continuation.rs` tests | boundary | **No — and it is stated as already met.** `hold`'s capacity branch is built (`:696-717`). The row exists so the clause has a case, not because it is expected to go red; its value is regression, and the falsifier probe below is what earns it |
| 2 | PERF.3 — abandoned exchange state MUST be reclaimed | abandon 8 192 exchanges (2x capacity, so the table wraps its own ceiling once) against a **driven clock**; advance `now` past the deadline; occupancy is 0 with no capacity pressure applied | unit, same module | lifetime / state | **Yes.** Today reclamation runs only inside the capacity branch, so below capacity an expired hold is retained indefinitely. Fails on the occupancy assertion until `guard(now)` lands |
| 3 | PERF.3 — a soak MUST show reclamation | after row 2's drain, a fresh `hold` at the advanced clock returns `Some` | unit, same module | the wedge | **Yes.** This is the clause's user-visible meaning: not "memory is bounded" but "the gateway still accepts elicitations after a client walked away". Distinct from row 2 because occupancy reaching 0 and admission actually recovering are two assertions, and a reclaimer that empties the map while leaving the capacity accounting stale would pass row 2 and fail this |
| 4 | PERF.4 — the model-facing meta-tool surface MUST NOT exceed the stated ceiling | `build_meta_tools_filtered` with every feature flag on and the default exposure; the returned length is `<= 16` | unit, `src/gateway/meta_mcp_tool_defs.rs` tests | ceiling | **Yes — it fails at 17 today**, with `build_meta_tools_all_enabled_has_17_tools` (`meta_mcp_tool_defs_tests.rs:60-66`) as the standing proof of the count. Landed `#[ignore]`d with the open question named in the comment, so a shared branch does not go red on a decision nobody has made |

## Why no wall-clock soak

The requirement names no duration, no abandonment rate and no reclamation threshold — recorded as
an unknown and resolved in the design's receipt update. A wall-clock soak would therefore be
inventing its own bound, would not run in the suite, and would be a weaker observation than the
driven clock: it can only show that reclamation happened *somewhere* in the interval, where rows 2
and 3 show it happened *at the deadline*. The clock is a parameter on the entry points (`now: u64`,
already the module's shape at `:696` and in Design A), so no sleeping and no timing tolerance.

## Assertion strength — the second question a plan review must answer

Every row states above what makes it fail. The three risks specific to this plan:

- **Row 1 asserts a property that is already true.** That is an honest weakness, not a hidden one:
  written after the mechanism, it inherits none of the free failure. It gets the retrofitting
  falsifier probe from the process — restore the pre-`ec11dcec` body of the capacity branch, show
  the case fails on the occupancy assertion, restore and show it passes — or it is not evidence.
- **Rows 2 and 3 must not stage away the condition they observe.** The fixture may not call
  `complete` on the abandoned exchanges, and may not reach capacity before asserting; either would
  reclaim through a path that already works and make the assertion true without the mechanism
  under test. 8 192 is chosen so the *fill* crosses capacity while the *observation* happens after
  the drain, and the assertion is on holds that were never completed.
- **Row 4 must count the filtered set, not the built set.** `build_meta_tools` is the pre-exposure
  list; asserting on it would measure a number no model ever sees. The criterion is about the
  surface presented to a client, so the case goes through `build_meta_tools_filtered` with the
  default exposure.

## What is deliberately not covered

- Memory or RSS. Bounded at 4 096 entries either way, so any RSS assertion passes against the
  unfixed code — recorded in the design as the wrong assertion rather than omitted silently.
- The at-capacity O(4 096) walk under the lock. It is a real finding, raised against MRTR.8b's
  design where the code lives; a performance assertion here would test a mechanism this slice does
  not own.
- Deleting the seventeenth meta-tool and the matching `with_webhook_status: 17` entry in
  `benchmarks/public_claims.json`. Gated on an unanswered operator question; when it is answered
  the deletion and the claims edit land in one commit, because
  `tests/public_claims_validation.rs:247-256` asserts the two agree.
