// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Regression tests for the three idempotency-guard defects P1, P3 and P6.
//!
//! P1: `enforce` admitted two concurrent retries of the same key.
//! P3: the entry map was unbounded; at the bound it must fail closed, never evict.
//! P6: a reservation abandoned by an early return stayed in-flight until it timed out.

use std::sync::{Arc, Barrier};

use mcp_gateway::idempotency::{
    CheckOutcome, GuardOutcome, IdempotencyCache, MAX_ENTRIES, enforce,
};
use serde_json::json;

/// P1 — only one of N concurrent racers for the same fresh key may proceed.
#[test]
fn concurrent_enforce_on_one_key_admits_exactly_one_caller() {
    const RACERS: usize = 8;
    const ROUNDS: usize = 200;

    for round in 0..ROUNDS {
        let cache = Arc::new(IdempotencyCache::new());
        let barrier = Arc::new(Barrier::new(RACERS));
        let key = format!("race-{round}");
        // All racers retry the *same* request, so they share one fingerprint —
        // that is what makes them retries rather than distinct calls.
        let fingerprint = format!("fp-{round}");

        let handles: Vec<_> = (0..RACERS)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let barrier = Arc::clone(&barrier);
                let key = key.clone();
                let fingerprint = fingerprint.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    // The outcome is returned, not dropped, so a winning caller does
                    // not release its reservation before the others have voted.
                    enforce(&cache, &key, &fingerprint).map_err(|e| e.to_string())
                })
            })
            .collect();

        let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let admitted = outcomes.iter().filter(|o| o.is_ok()).count();

        assert_eq!(
            admitted, 1,
            "round {round}: {admitted} of {RACERS} concurrent callers were admitted for one key; \
             exactly 1 may proceed"
        );
    }
}

/// P3 — at the entry bound a new key is refused, and nothing already tracked is evicted.
#[test]
fn enforce_fails_closed_at_the_entry_bound_without_evicting() {
    let cache = Arc::new(IdempotencyCache::new());
    for i in 0..MAX_ENTRIES {
        cache.mark_in_flight(&format!("filler-{i}"));
    }
    assert_eq!(
        cache.len(),
        MAX_ENTRIES,
        "precondition: cache is at the bound"
    );

    let refused = enforce(&cache, "a-brand-new-key", "fp-new");
    assert!(
        refused.is_err(),
        "a new protected side effect must be refused at the bound"
    );
    let message = refused.err().map(|e| e.to_string()).unwrap_or_default();
    assert!(
        message.to_lowercase().contains("capacity"),
        "refusal must name capacity, got: {message}"
    );

    // Fail closed means refuse, never evict: evicting readmits a duplicate.
    assert_eq!(
        cache.len(),
        MAX_ENTRIES,
        "no entry may be evicted to make room"
    );
    assert!(
        matches!(cache.check("filler-0"), CheckOutcome::InFlight),
        "the oldest tracked entry must survive the refusal"
    );
}

/// P3 — a key already tracked as completed is still served while the cache is at the bound.
#[test]
fn completed_entries_are_still_served_at_the_entry_bound() {
    let cache = Arc::new(IdempotencyCache::new());
    for i in 0..MAX_ENTRIES {
        cache.mark_in_flight(&format!("filler-{i}"));
    }
    assert!(cache.mark_completed(
        "filler-7",
        json!({"resultType": "complete", "status": "ok"})
    ));
    assert_eq!(cache.len(), MAX_ENTRIES);

    let outcome = enforce(&cache, "filler-7", "fp-filler-7")
        .expect("a completed entry must still be servable");
    assert!(
        matches!(outcome, GuardOutcome::CachedResult(v) if v == json!({"resultType": "complete", "status": "ok"})),
        "at the bound a completed key must return its cached result, not a refusal"
    );
}

/// P6 — a reservation abandoned without completing leaves no in-flight entry behind.
#[test]
fn abandoned_reservation_does_not_strand_an_in_flight_entry() {
    let cache = Arc::new(IdempotencyCache::new());

    // Models an early return after dispatch: the guard goes out of scope
    // without the caller ever reaching `mark_completed`.
    let abandon = |key: &str| -> Result<(), String> {
        let outcome = enforce(&cache, key, &format!("fp-{key}")).map_err(|e| e.to_string())?;
        if matches!(outcome, GuardOutcome::CachedResult(_)) {
            return Ok(());
        }
        Err("blocked by contract gate".to_string())
    };

    assert!(
        abandon("k").is_err(),
        "fixture must take the early-return path"
    );

    assert_eq!(
        cache.len(),
        0,
        "an abandoned reservation must not stay in-flight until IN_FLIGHT_TIMEOUT"
    );
    assert!(
        matches!(cache.check("k"), CheckOutcome::Proceed),
        "the key must be immediately retryable after the reservation was abandoned"
    );
}

/// P6 — once the protected side effect has committed, abandoning the reservation
/// must settle the key as completed rather than release it: releasing would
/// readmit the retry that P3 refuses to evict its way into.
#[test]
fn abandoned_reservation_after_commit_does_not_readmit_a_duplicate() {
    let cache = Arc::new(IdempotencyCache::new());
    let dispatched = json!({"resultType": "complete", "status": "ok"});

    // Models the response-contract gate (`meta_mcp/invoke.rs:1093`): the backend
    // has already acted, then a post-dispatch early return drops the guard.
    let blocked = |key: &str| -> Result<(), String> {
        let outcome = enforce(&cache, key, &format!("fp-{key}")).map_err(|e| e.to_string())?;
        if let GuardOutcome::Proceed(mut reservation) = outcome {
            reservation.commit(&dispatched);
        }
        Err("blocked by contract gate".to_string())
    };

    assert!(
        blocked("k").is_err(),
        "fixture must take the early-return path"
    );

    match cache.check("k") {
        CheckOutcome::Completed(cached) => assert_eq!(
            cached, dispatched,
            "the committed result must be what a retry is served"
        ),
        other => panic!("a committed side effect must not be re-executable, got {other:?}"),
    }
}
