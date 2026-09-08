// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT
//! MRTR.8b Change A — observer reclamation, prerequisite to scheduled expiry.
//!
//! Plan: `docs/design/2026-09-06-mrtr-8b-lifetime-test-plan.md`. Row numbers
//! below are that plan's. Every `now` is supplied by the test and anchored to
//! one synthetic epoch, never `SystemTime::now()`: a `guard` that read the
//! clock itself would answer identically to a correct one under a real-clock
//! fixture, and row .07 could then not fail for its stated reason.

use super::{IN_FLIGHT_CAPACITY, InFlight, Routing};

/// The synthetic epoch. Every deadline and every supplied `now` is relative
/// to this, so a `guard` reading the wall clock is ~1.7 billion seconds past
/// every deadline in this module and reclaims everything.
const T: u64 = 1_000;

/// One replica holding one exchange whose deadline is exactly `T`.
async fn held_until_t(capacity: usize) -> (InFlight, String) {
    let table = InFlight::new("gw-1", capacity);
    let key = table
        .hold("backend", T, T)
        .await
        .expect("an empty table admits");
    (table, key)
}

// --- C1: no reader observes a record whose deadline is behind its `now`. ---

#[tokio::test]
async fn row_01_len_does_not_count_an_expired_entry() {
    let (table, _key) = held_until_t(4).await;
    assert_eq!(table.len(T + 1).await, 0);
}

#[tokio::test]
async fn row_02_route_does_not_answer_here_for_an_expired_entry() {
    let (table, key) = held_until_t(4).await;
    assert_eq!(table.route(&key, T + 1).await, Routing::Gone);
}

#[tokio::test]
async fn row_03_complete_does_not_report_completing_an_expired_entry() {
    let (table, key) = held_until_t(4).await;
    assert!(!table.complete(&key, T + 1).await);
}

#[tokio::test]
async fn row_04_a_live_entry_survives_every_reader() {
    // Negative control: the reclaim must not eat live records. A count of 1
    // could be the wrong record, so all three readers name the same key.
    let (table, key) = held_until_t(4).await;
    assert_eq!(table.len(T - 1).await, 1);
    assert_eq!(table.route(&key, T - 1).await, Routing::Here);
    assert!(table.complete(&key, T - 1).await);
}

#[tokio::test]
async fn row_04a_an_entry_is_live_at_its_own_deadline() {
    // The boundary, and the only `now` at which `<` and `<=` differ: .01 and
    // .04 pass under either. `Keyring::open` accepts at equality, so a table
    // reclaiming here would drop a record the envelope still opens.
    let (table, key) = held_until_t(4).await;
    assert_eq!(table.len(T).await, 1);
    assert_eq!(table.route(&key, T).await, Routing::Here);
    assert!(table.complete(&key, T).await);
}

#[tokio::test]
async fn row_07_a_now_that_never_moves_never_expires_an_entry() {
    // The contract's limit, stated: reclamation is driven by the supplied
    // `now`, so repeated reads at the same `now` are idempotent.
    let (table, key) = held_until_t(4).await;
    assert_eq!(table.route(&key, T - 1).await, Routing::Here);
    assert_eq!(table.route(&key, T - 1).await, Routing::Here);
}

// --- C2: the first observer removes abandoned holds from storage. ---

#[tokio::test]
async fn row_05_len_reclaims_from_storage() {
    let (table, _key) = held_until_t(4).await;
    assert_eq!(table.len(T + 1).await, 0, "len");
    assert!(table.held.lock().await.is_empty());
}

#[tokio::test]
async fn row_05_route_reclaims_from_storage() {
    let (table, key) = held_until_t(4).await;
    assert_eq!(table.route(&key, T + 1).await, Routing::Gone, "route");
    assert!(table.held.lock().await.is_empty());
}

#[tokio::test]
async fn row_05_complete_reclaims_from_storage() {
    let (table, key) = held_until_t(4).await;
    assert!(!table.complete(&key, T + 1).await, "complete");
    assert!(table.held.lock().await.is_empty());
}

#[tokio::test]
async fn row_05_is_empty_reclaims_from_storage() {
    let (table, _key) = held_until_t(4).await;
    assert!(table.is_empty(T + 1).await, "is_empty");
    assert!(table.held.lock().await.is_empty());
}

#[tokio::test]
async fn row_06_an_expired_entry_stays_resident_until_the_first_reader() {
    // R2a's bargain, stated as a test: reclamation is lazy, so the record is
    // still in the map after its deadline passes and before anyone asks.
    // Inspected directly rather than through a public reader, because every
    // public reader is the event whose absence is the assertion.
    let (table, _key) = held_until_t(4).await;
    assert_eq!(
        table.held.lock().await.len(),
        1,
        "resident before any reader"
    );
    assert_eq!(table.len(T + 1).await, 0, "gone at the first reader");
    assert!(table.held.lock().await.is_empty());
}

#[tokio::test]
async fn row_08_hold_at_capacity_admits_when_the_occupants_are_expired() {
    // Transferred from NFR.PERF.3. Today the reclaim lives inside the
    // capacity branch; after the change `hold` keeps only its refusal, so
    // the reclaim must have happened in `guard` before the check reads `len`.
    let table = InFlight::new("gw-1", 4);
    for _ in 0..4 {
        assert!(table.hold("backend", T, T).await.is_some());
    }
    assert!(table.hold("backend", T + 2, T + 1).await.is_some());
}

#[tokio::test]
async fn row_08_capacity_is_the_documented_bound() {
    // The design's cost number, pinned. A test cannot see a walk length.
    assert_eq!(IN_FLIGHT_CAPACITY, 4_096);
}

#[tokio::test]
async fn row_09_hold_at_capacity_still_refuses_when_the_occupants_are_live() {
    // The pair to .08: without it, .08 passes trivially if the capacity
    // refusal is deleted rather than re-ordered.
    let table = InFlight::new("gw-1", 4);
    for _ in 0..4 {
        assert!(table.hold("backend", T, T).await.is_some());
    }
    assert!(table.hold("backend", T, T).await.is_none());
}

async fn assert_hold_reclaims_below_capacity() {
    let (table, old_key) = held_until_t(4).await;
    let new_key = table
        .hold("backend", T + 2, T + 1)
        .await
        .expect("below capacity admits a live exchange");
    // No public observer: len/route could clean up a broken hold for it.
    let held = table.held.lock().await;
    assert!(
        !held.contains_key(&old_key),
        "hold retained an expired record"
    );
    assert_eq!(held.len(), 1);
    assert_eq!(held.get(&new_key), Some(&("gw-1".to_string(), T + 2)));
}

#[tokio::test]
async fn row_05_hold_below_capacity_reclaims_without_another_observer() {
    assert_hold_reclaims_below_capacity().await;
}

#[tokio::test]
async fn row_12_is_empty_observes_expiry_with_fresh_fixtures() {
    for (now, expected) in [(T - 1, false), (T, false), (T + 1, true)] {
        let (table, _key) = held_until_t(4).await;
        assert_eq!(table.is_empty(now).await, expected, "now={now}");
        assert_eq!(table.held.lock().await.is_empty(), expected);
    }
}

#[tokio::test]
async fn row_12_initially_empty_is_empty() {
    assert!(InFlight::new("gw-1", 4).is_empty(T).await);
}

#[derive(Clone, Copy)]
enum Observer {
    Len,
    IsEmpty,
    Route,
    Complete,
    Hold,
}

async fn assert_mixed_state(observer: Observer) {
    // Keep every setup hold at T: advancing time during setup could reclaim
    // an expired key before the observer under test gets to see it.
    let (table, expired_key) = held_until_t(8).await;
    let second_expired_key = table.hold("other", T + 1, T).await.expect("room");
    let live_key = table.hold("live", T + 10, T).await.expect("room");
    let new_key = match observer {
        Observer::Len => {
            assert_eq!(table.len(T + 2).await, 1);
            None
        }
        Observer::IsEmpty => {
            assert!(!table.is_empty(T + 2).await);
            None
        }
        Observer::Route => {
            assert_eq!(table.route(&live_key, T + 2).await, Routing::Here);
            None
        }
        Observer::Complete => {
            assert!(!table.complete("missing-unrelated-key", T + 2).await);
            None
        }
        Observer::Hold => Some(table.hold("new", T + 20, T + 2).await.expect("room")),
    };
    let held = table.held.lock().await;
    assert!(!held.contains_key(&expired_key));
    assert!(!held.contains_key(&second_expired_key));
    assert_eq!(held.get(&live_key), Some(&("gw-1".to_string(), T + 10)));
    assert_eq!(held.len(), if new_key.is_some() { 2 } else { 1 });
    if let Some(new_key) = new_key {
        assert_eq!(held.get(&new_key), Some(&("gw-1".to_string(), T + 20)));
    }
}

// Independently registered: an early assertion failure in one observer
// cannot hide the red evidence for another observer.
#[tokio::test]
async fn row_13_mixed_len() {
    assert_mixed_state(Observer::Len).await;
}

#[tokio::test]
async fn row_13_mixed_is_empty() {
    assert_mixed_state(Observer::IsEmpty).await;
}

#[tokio::test]
async fn row_13_mixed_route() {
    assert_mixed_state(Observer::Route).await;
}

#[tokio::test]
async fn row_13_mixed_complete() {
    assert_mixed_state(Observer::Complete).await;
}

#[tokio::test]
async fn row_13_mixed_hold() {
    assert_mixed_state(Observer::Hold).await;
}

#[tokio::test]
async fn row_14_expired_insertion_is_refused_without_consuming_capacity() {
    let table = InFlight::new("gw-1", 4);
    assert!(table.hold("backend", T - 1, T).await.is_none());
    assert!(table.held.lock().await.is_empty());
    // Equality is live: refusing all insertions is not an acceptable fix.
    let key = table.hold("backend", T, T).await.expect("equality is live");
    let held = table.held.lock().await;
    assert_eq!(held.len(), 1);
    assert_eq!(held.get(&key), Some(&("gw-1".to_string(), T)));
}
