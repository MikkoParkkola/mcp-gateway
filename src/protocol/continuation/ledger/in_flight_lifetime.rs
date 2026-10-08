// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MRTR.8b Change A — the `InFlight` table's bounded lifetime.
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

// --- C2: an abandoned hold leaves without anyone scheduling a reclaimer. ---

#[tokio::test]
async fn row_05_the_first_call_through_any_reader_reclaims() {
    // Nothing completes the exchange and no reaper exists. Each reader gets
    // its own fresh fixture, so C2 is not as strong as whichever single
    // method an implementer happened to wire.

    // `len`
    let (table, _key) = held_until_t(4).await;
    assert_eq!(table.len(T + 1).await, 0, "len");

    // `route`
    let (table, key) = held_until_t(4).await;
    assert_eq!(table.route(&key, T + 1).await, Routing::Gone, "route");

    // `complete`
    let (table, key) = held_until_t(4).await;
    assert!(!table.complete(&key, T + 1).await, "complete");

    // `hold` — observed through its own admission at a capacity of one: the
    // slot can only be free if that same call reclaimed the expired entry.
    let (table, _key) = held_until_t(1).await;
    assert!(table.hold("backend", T + 2, T + 1).await.is_some(), "hold");
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
}

#[tokio::test]
async fn row_08_hold_at_capacity_admits_when_the_occupants_are_expired() {
    // Transferred from NFR.PERF.3. `hold` keeps only its refusal, so the
    // reclaim must have happened in `guard` before the check reads `len`.
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

// --- MIK-8060: a reader walks the table only when something can be expired. ---

/// A full table whose every deadline is still ahead of `T`.
async fn full_of_live_holds() -> InFlight {
    let table = InFlight::new("gw-1", IN_FLIGHT_CAPACITY);
    for i in 0..IN_FLIGHT_CAPACITY {
        let deadline = T + 1_000 + u64::try_from(i).expect("small");
        table.hold("backend", deadline, T).await.expect("capacity");
    }
    table
}

#[tokio::test]
async fn row_09_readers_of_a_table_with_nothing_expired_never_walk_it() {
    let table = full_of_live_holds().await;
    let before = table.walks.load(std::sync::atomic::Ordering::SeqCst);
    let key = "absent".to_string();
    for _ in 0..100 {
        assert!(matches!(table.route(&key, T).await, Routing::Gone));
    }
    assert_eq!(table.len(T).await, IN_FLIGHT_CAPACITY);
    let walked = table.walks.load(std::sync::atomic::Ordering::SeqCst) - before;
    assert_eq!(
        walked, 0,
        "nothing had expired, yet readers walked {walked} times"
    );
}

#[tokio::test]
async fn row_10_completing_the_earliest_hold_never_hides_a_later_expiry() {
    // The tracked earliest deadline may go stale when its hold completes; it
    // must stay a lower bound, so an expiry behind it is still reclaimed.
    let table = InFlight::new("gw-1", 4);
    let first = table.hold("backend", T, T).await.expect("capacity");
    let _second = table.hold("backend", T + 10, T).await.expect("capacity");
    assert!(table.complete(&first, T).await);
    assert_eq!(table.len(T + 5).await, 1, "the later hold is still live");
    assert_eq!(
        table.len(T + 11).await,
        0,
        "and is reclaimed once it expires"
    );
}

#[tokio::test]
async fn row_11_holds_inserted_out_of_deadline_order_expire_in_order() {
    let table = InFlight::new("gw-1", 4);
    for deadline in [T + 30, T + 10, T + 20] {
        table.hold("backend", deadline, T).await.expect("capacity");
    }
    assert_eq!(table.len(T + 15).await, 2);
    assert_eq!(table.len(T + 25).await, 1);
    assert_eq!(table.len(T + 31).await, 0);
}

#[tokio::test]
async fn row_12_a_reader_at_the_earliest_deadline_neither_walks_nor_evicts() {
    let table = InFlight::new("gw-1", 4);
    table.hold("backend", T + 10, T).await.expect("capacity");
    let before = table.walks.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(table.len(T + 10).await, 1, "live at its own deadline");
    let walked = table.walks.load(std::sync::atomic::Ordering::SeqCst) - before;
    assert_eq!(walked, 0, "nothing can be expired at the earliest deadline");
}

#[tokio::test]
async fn row_13_a_walk_resets_the_bound_to_the_earliest_survivor() {
    let table = InFlight::new("gw-1", 4);
    table.hold("backend", T + 5, T).await.expect("capacity");
    table.hold("backend", T + 50, T).await.expect("capacity");
    assert_eq!(table.len(T + 6).await, 1, "the first hold is reclaimed");
    let before = table.walks.load(std::sync::atomic::Ordering::SeqCst);
    for _ in 0..10 {
        assert_eq!(table.len(T + 40).await, 1);
    }
    let walked = table.walks.load(std::sync::atomic::Ordering::SeqCst) - before;
    assert_eq!(walked, 0, "a stale bound would walk on every read");
}

/// `MIK-8168`: a paused chain's step digest goes with its hold when the chain
/// is abandoned. Expiry is the abandonment path (a client that stops calling
/// makes no call; a reload keeps the shared table). Asserted on the map itself,
/// after a reader that is not `step_digest`, so only the reclaim can clear it.
#[tokio::test]
async fn an_expired_hold_drops_its_step_digest() {
    let (table, key) = held_until_t(4).await;
    table
        .steps
        .lock()
        .insert(key.clone(), "step-digest".to_string());
    assert_eq!(table.len(T).await, 1);
    assert_eq!(table.steps.lock().len(), 1, "a live hold keeps its digest");
    assert_eq!(table.len(T + 1).await, 0);
    assert!(
        table.steps.lock().is_empty(),
        "an abandoned chain's digest stayed"
    );
}

/// `MIK-8060` x `MIK-8168`: with the reclaim walk skipped when nothing can be
/// expired, a step recorded for an exchange no longer held (a bind that raced
/// its hold's reclaim) must still not be returned.
#[tokio::test]
async fn a_step_digest_is_returned_only_while_its_hold_exists() {
    let (table, key) = held_until_t(4).await;
    let orphan = "backend:no-longer-held".to_string();
    table
        .steps
        .lock()
        .insert(orphan.clone(), "orphan-digest".to_string());
    table
        .steps
        .lock()
        .insert(key.clone(), "live-digest".to_string());
    assert_eq!(
        table.step_digest(&key, T).await.as_deref(),
        Some("live-digest")
    );
    assert_eq!(
        table.step_digest(&orphan, T).await,
        None,
        "an orphan step leaked"
    );
}
