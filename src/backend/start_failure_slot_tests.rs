// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2261: a request captures its slot's entry before it claims the slot. If
//! the idle reaper evicts that entry in between, the claim creates a fresh
//! one and the start runs on it. A failed start must be recorded on the entry
//! that was started, or the live slot's breaker never sees the failure.
//!
//! The race is forced without a new seam: the backend's request semaphore
//! sits between the capture and the claim. Holding every permit parks the
//! request there; nothing before it awaits, so on a current-thread runtime
//! one yield is enough to reach it.

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
    let request = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move {
            backend
                .request_with_headers("tools/list", None, &[], Some(BINDING))
                .await
        })
    };
    tokio::task::yield_now().await;

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
