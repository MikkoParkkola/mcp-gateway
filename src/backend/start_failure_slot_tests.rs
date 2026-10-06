// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2261: a request captures its slot's entry before it claims the slot. If
//! the idle reaper evicts that entry in between, the claim creates a fresh
//! one and the start runs on it. A failed start must be recorded on the entry
//! that was started, or the live slot's breaker never sees the failure.
//!
//! The race is forced without a new seam: the backend's request semaphore
//! sits between the capture and the claim. Holding every permit parks the
//! request there, and the test waits until the request's captured clone of
//! the entry shows in its strong count before it evicts (MIK-7664).

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::slot_eviction_tests::{per_user_backend, slot};

/// GIVEN a request parked between capturing its idle slot's entry and
/// claiming the slot, and that entry then evicted by the idle reaper
/// WHEN the request resumes and its start fails on the fresh entry
/// THEN the failure is on the fresh entry's breaker, not the evicted one's.
#[tokio::test(flavor = "current_thread")]
async fn a_start_failure_after_the_eviction_race_lands_on_the_live_slot() {
    const BINDING: &str = "idp:alpha@ledger";
    let backend = per_user_backend("race");
    let key = slot(BINDING);
    let stale = backend.pooled_entry(&key).unwrap();
    stale.last_used.store(0, Ordering::Relaxed);

    let all = u32::try_from(backend.semaphore.available_permits()).expect("permit count");
    let permits = backend.semaphore.acquire_many(all).await.expect("permits");
    let unclaimed = Arc::strong_count(&stale);
    let request = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move {
            backend
                .request_with_headers("tools/list", None, &[], Some(BINDING))
                .await
        })
    };
    // The race needs the request to hold the stale entry before the eviction:
    // its captured clone raises the count by one. Bounded by yields, not time,
    // so a slow host cannot fail it and a request that never captures does.
    let mut yields = 0;
    while Arc::strong_count(&stale) == unclaimed {
        assert!(
            yields < 1_000,
            "the request never captured the stale entry, so the race was not set up"
        );
        tokio::task::yield_now().await;
        yields += 1;
    }
    assert_eq!(Arc::strong_count(&stale), unclaimed + 1);

    assert_eq!(
        backend.evict_idle_per_user_entries(Duration::from_secs(1)),
        1,
        "the parked request must not hold the slot it has not claimed yet"
    );
    drop(permits);
    assert!(
        request.await.expect("request task").is_err(),
        "the fixture backend has no URL, so its start must fail"
    );

    let live = backend
        .pool
        .get(&key)
        .map(|slot| Arc::clone(slot.value()))
        .expect("the resumed request re-created the slot");
    assert!(!Arc::ptr_eq(&live, &stale), "the race did not happen");
    assert_eq!(
        live.failsafe.circuit_breaker.stats().current_failures,
        1,
        "the live slot's breaker missed the start failure"
    );
    assert_eq!(
        stale.failsafe.circuit_breaker.stats().current_failures,
        0,
        "the start failure was recorded on the evicted entry"
    );
}
