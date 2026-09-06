// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! NFR.PERF.3 — a table full of abandoned continuations drains at the deadline.
//!
//! Plan: `docs/design/2026-09-06-perf3-reclamation-test-plan.md`, row 2.
//! Design: `docs/design/2026-09-01-nfr-perf3-reclamation.md`.
//!
//! Written against `InFlight::len(now)`, which arrives with MRTR.8b Design A
//! (`docs/design/2026-09-06-mrtr-8b-10a-lifetime-and-idempotency-wiring.md`).
//! `len` takes no clock today (`src/protocol/continuation.rs:756`), so this
//! file does not compile until that lands — which is the declared landing
//! order, not an accident. A compile error is **not** evidence about
//! reclamation: the assertion-level red this row owes is the falsifier probe
//! named in the plan's Residual section, run after `guard(now)` exists.
//!
//! It lives in its own target rather than beside the MIK-7212 acceptance
//! criteria because a non-compiling case takes its whole test binary with it,
//! and `ac_mrtr_8_the_table_is_bounded` — row 1's entire evidence — is in that
//! binary.

use mcp_gateway::protocol::continuation::InFlight;

/// Capacity driven by this fixture, injected through `InFlight::new` rather
/// than read from the production `IN_FLIGHT_CAPACITY`. The property under test
/// is *fill exactly to capacity, never one more*, and it is identical at 4 and
/// at 4 096; binding it once is what stops the fill and the occupancy
/// assertions drifting apart. The production constant's own value is pinned by
/// MRTR.8b row .08, in the module that can see it.
const CAPACITY: usize = 4;

/// Every exchange in the fill shares one deadline, so a single clock move
/// expires all of them at once.
const DEADLINE: u64 = 1_000;

#[tokio::test]
async fn nfr_perf3_a_table_of_abandoned_exchanges_drains_at_the_deadline() {
    let table = InFlight::new("gw-1", CAPACITY);

    // Fill to exactly capacity, and never attempt one more. `hold` reclaims
    // inside its capacity branch (`src/protocol/continuation.rs:696-717`), so a
    // single overshooting attempt would drain the table through the path that
    // already works and turn this case green with `guard` never involved.
    // Asserting every hold makes that constraint self-enforcing rather than
    // commented: a capacity-semantics change fails here instead of quietly
    // passing the case for the wrong reason.
    for i in 0..CAPACITY {
        assert!(
            table.hold("weather", DEADLINE, 0).await.is_some(),
            "hold {i} of the fill must be admitted; a refusal means the fixture \
             reached the capacity branch it is built to stay out of"
        );
    }
    assert_eq!(
        table.len(0).await,
        CAPACITY,
        "the fill must have driven occupancy to exactly capacity before the \
         clock moves; a fill that fell short would let the drain below report 0 \
         without anything ever having been abandoned"
    );

    // The deadline edge, not just the far side of it. `reclaim_abandoned`
    // retains on `now <= deadline` (`src/protocol/continuation.rs:675-677`), so
    // an over-eager reclaimer that dropped not-yet-expired entries would reach
    // the same final 0 and pass without this assertion.
    assert_eq!(
        table.len(DEADLINE).await,
        CAPACITY,
        "an exchange is live at its own deadline; reclaiming at `now == \
         deadline` would drop a record the gateway still accepts"
    );

    // Nothing completed these exchanges and no reaper exists, so the drain is
    // `guard`'s, on the first read past the deadline. This is the clause:
    // memory does not grow with abandoned continuations.
    assert_eq!(
        table.len(DEADLINE + 1).await,
        0,
        "every abandoned exchange must be reclaimed once its deadline has \
         passed, without a completion and without a reaper"
    );
}
