// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.1 cold-lease rows (s1-t0 C2-C7, R1, R2; s1-t1 L1b): a
//! stored read whose caller's slot was really evicted claims one lease, and
//! the lease decides who resolves and what every other read answers. Driven
//! through the public `/mcp` handler as alpha; resolutions are counted at the
//! fixture's mint, upstream lists at the fixture's transport.

use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::{Value, json};

use super::super::slot_verdict_http_tests::{CLOSED, Gateway, gateway};
use super::{OUTPUT, backend, finished, task_get};
use crate::gateway::meta_mcp::slot_verdict_fixture::{
    BINDING, CallerSlot, Surfaced, rearm_alpha_slot_with, valid,
};

/// The lease a cold claim takes (task_replay.rs COLD_RETRY_BACKOFF).
const LEASE: Duration = Duration::from_secs(60);

/// Drop alpha's slot by a real idle eviction, then re-attach its upstream
/// answering `read` with `schema` (or refusing every list).
fn evict_alpha(gw: &Gateway, schema: &Value, fail_list: bool) {
    let backend = backend(gw);
    backend.age_per_user_slot_for_test(BINDING, 400);
    backend.evict_idle_per_user_entries(Duration::from_secs(300));
    assert!(
        !backend.holds_per_user_slot_for_test(BINDING),
        "premise: the real eviction dropped alpha's slot"
    );
    let _ = rearm_alpha_slot_with(&backend, schema, fail_list);
}

fn mints(gw: &Gateway) -> usize {
    gw.mints.load(Ordering::SeqCst)
}

/// The retryable answer: -32603 with `data.retryable`, never output.
fn assert_retryable(read: &Value, row: &str) -> Option<u64> {
    assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32603)),
        "{row}: {read}"
    );
    assert_eq!(
        read.pointer("/error/data/retryable"),
        Some(&json!(true)),
        "{row}: the answer says retryable: {read}"
    );
    assert!(!read.to_string().contains(OUTPUT), "{row}: output: {read}");
    read.pointer("/error/data/retry_after_ms")
        .and_then(Value::as_u64)
}

/// C2 + R2: a cold attempt whose fill fails answers retryable; reads inside
/// the lease resolve nothing; once the lease has run out on the tokio clock
/// (R2: a std clock never expires under `advance`), one read resolves again
/// and serves, and warm polls after it resolve nothing. Mutants: M6b
/// (expiry check removed), M23 (std::time::Instant).
#[tokio::test]
async fn c2_a_failed_cold_attempt_retries_after_its_lease() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-c2").await;
    evict_alpha(&gw, &valid(), true);
    tokio::time::pause();
    let before = mints(&gw);
    assert_retryable(&task_get(&gw, &id).await, "C2 first");
    assert_eq!(mints(&gw) - before, 1, "C2: the winner resolved once");
    for _ in 0..3 {
        assert_retryable(&task_get(&gw, &id).await, "C2 inside the lease");
    }
    assert_eq!(
        mints(&gw) - before,
        1,
        "C2: reads inside the lease resolve nothing"
    );
    let _ = rearm_alpha_slot_with(&backend(&gw), &valid(), false);
    tokio::time::advance(LEASE).await;
    let served = task_get(&gw, &id).await;
    assert!(
        served.to_string().contains(OUTPUT),
        "C2: after the lease, served: {served}"
    );
    assert_eq!(mints(&gw) - before, 2, "C2: one more resolution");
    for _ in 0..3 {
        let _ = task_get(&gw, &id).await;
    }
    assert_eq!(mints(&gw) - before, 2, "C2: warm polls resolve nothing");
}

/// R1: the retryable answer carries what is left of the lease, as data the
/// shared error converter would strip (M44).
#[tokio::test]
async fn r1_the_retryable_answer_carries_the_remaining_lease() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-r1").await;
    evict_alpha(&gw, &valid(), true);
    tokio::time::pause();
    let _ = task_get(&gw, &id).await;
    tokio::time::advance(Duration::from_secs(20)).await;
    let read = task_get(&gw, &id).await;
    let after = assert_retryable(&read, "R1").expect("R1: retry_after_ms on the wire");
    assert!(
        after <= 40_000 && after > 30_000,
        "R1: about 40 s of the lease are left: {after} ms"
    );
}

/// C7: the lease ends exactly at `until`: a read at that instant claims
/// (M39, an inclusive comparison, keeps it leased).
#[tokio::test]
async fn c7_a_read_at_the_lease_end_claims() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-c7").await;
    evict_alpha(&gw, &valid(), true);
    tokio::time::pause();
    let before = mints(&gw);
    let first = task_get(&gw, &id).await;
    let left = assert_retryable(&first, "C7 first").expect("a running lease");
    let _ = rearm_alpha_slot_with(&backend(&gw), &valid(), false);
    tokio::time::advance(Duration::from_millis(left)).await;
    let served = task_get(&gw, &id).await;
    assert!(
        served.to_string().contains(OUTPUT),
        "C7: claimed at the end: {served}"
    );
    assert_eq!(mints(&gw) - before, 2, "C7");
}

/// C4: the winner's read is dropped mid-resolution. Its lease stays: reads
/// inside it resolve nothing; after it, one read resolves and serves (M37:
/// a dropped attempt clears its lease).
#[tokio::test]
async fn c4_a_dropped_winner_keeps_its_lease() {
    let gw = std::sync::Arc::new(gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await);
    let id = finished(&gw, "s1-c4").await;
    evict_alpha(&gw, &valid(), false);
    tokio::time::pause();
    let before = mints(&gw);
    let (reached, _release) = backend(&gw).cold_winner.arm();
    let winner = tokio::spawn({
        let (gw, id) = (std::sync::Arc::clone(&gw), id.clone());
        async move { task_get(&gw, &id).await }
    });
    reached.notified().await;
    winner.abort();
    let _ = winner.await;
    assert_retryable(&task_get(&gw, &id).await, "C4 inside the lease");
    assert_eq!(
        mints(&gw) - before,
        0,
        "C4: nothing resolved inside the lease"
    );
    tokio::time::advance(LEASE).await;
    let served = task_get(&gw, &id).await;
    assert!(
        served.to_string().contains(OUTPUT),
        "C4: served after: {served}"
    );
    assert_eq!(mints(&gw) - before, 1, "C4");
}

/// C5: during a failed attempt's lease, alpha's own live call refills its
/// slot; the next read serves with nothing resolved beyond that call's own
/// (M38: a fill of the owner's slot does not replace the lease).
#[tokio::test]
async fn c5_the_owners_live_call_ends_the_lease_early() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-c5").await;
    evict_alpha(&gw, &valid(), true);
    tokio::time::pause();
    assert_retryable(&task_get(&gw, &id).await, "C5 setup: the lease is taken");
    let _ = rearm_alpha_slot_with(&backend(&gw), &valid(), false);
    // Past the failed fill's 10 s cooldown, well inside the 60 s lease.
    tokio::time::advance(Duration::from_secs(11)).await;
    let live = super::send(
        &gw,
        3,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": crate::gateway::meta_mcp::slot_verdict_fixture::BACKEND,
                "tool": crate::gateway::meta_mcp::slot_verdict_fixture::TOOL,
                "arguments": {"q": "x"}},
            "_meta": super::modern_meta()}),
    )
    .await;
    assert_eq!(
        live.pointer("/result/isError"),
        Some(&json!(false)),
        "C5 setup: the live call served: {live}"
    );
    let after_live = mints(&gw);
    let read = task_get(&gw, &id).await;
    assert!(read.to_string().contains(OUTPUT), "C5: served: {read}");
    assert_eq!(mints(&gw), after_live, "C5: nothing further resolved");
}

/// L1b: winner A's lease runs out while A is parked; reader B claims anew.
/// When A comes back it neither publishes over nor forgets B's lease: a read
/// still answers retryable until B finishes, then B's result serves, with 2
/// resolutions in all (M24: no generation check; M17: unconditional publish).
#[tokio::test]
async fn l1b_a_stale_winner_cannot_publish_over_a_newer_lease() {
    let gw = std::sync::Arc::new(gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await);
    let id = finished(&gw, "s1-l1b").await;
    evict_alpha(&gw, &valid(), false);
    tokio::time::pause();
    let before = mints(&gw);
    let read = |gw: &std::sync::Arc<Gateway>| {
        let (gw, id) = (std::sync::Arc::clone(gw), id.clone());
        tokio::spawn(async move { task_get(&gw, &id).await })
    };
    let (a_reached, a_release) = backend(&gw).cold_winner.arm();
    let a = read(&gw);
    a_reached.notified().await;
    tokio::time::advance(LEASE).await;
    let (b_reached, b_release) = backend(&gw).cold_winner.arm();
    let b = read(&gw);
    b_reached.notified().await;
    a_release.notify_one();
    let _ = a.await.expect("A's read");
    assert_retryable(&task_get(&gw, &id).await, "L1b: B's lease still runs");
    b_release.notify_one();
    let b_read = b.await.expect("B's read");
    assert!(
        b_read.to_string().contains(OUTPUT),
        "L1b: B serves: {b_read}"
    );
    assert_eq!(mints(&gw) - before, 2, "L1b: two resolutions in all");
}

/// C3: N readers on a cold view while the winner is held: exactly one
/// resolution, every loser answers retryable with nothing resolved, and the
/// winner then serves (M6: a non-atomic claim lets two win).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c3_concurrent_cold_readers_resolve_once() {
    let gw = std::sync::Arc::new(gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await);
    let id = finished(&gw, "s1-c3").await;
    evict_alpha(&gw, &valid(), false);
    let before = mints(&gw);
    let (reached, release) = backend(&gw).cold_winner.arm();
    let winner = tokio::spawn({
        let (gw, id) = (std::sync::Arc::clone(&gw), id.clone());
        async move { task_get(&gw, &id).await }
    });
    reached.notified().await;
    let losers: Vec<_> = (0..6)
        .map(|_| {
            let (gw, id) = (std::sync::Arc::clone(&gw), id.clone());
            tokio::spawn(async move { task_get(&gw, &id).await })
        })
        .collect();
    for loser in losers {
        assert_retryable(&loser.await.expect("a loser's read"), "C3 loser");
    }
    assert_eq!(mints(&gw) - before, 0, "C3: losers resolve nothing");
    release.notify_one();
    let served = winner.await.expect("the winner's read");
    assert!(
        served.to_string().contains(OUTPUT),
        "C3: the winner serves: {served}"
    );
    assert_eq!(mints(&gw) - before, 1, "C3: one resolution in all");
}

/// C8: an eviction during a lease forgets slots, never the lease: a read
/// after it still answers retryable with nothing resolved (M40).
#[tokio::test]
async fn c8_an_eviction_keeps_a_running_lease() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-c8").await;
    evict_alpha(&gw, &valid(), true);
    tokio::time::pause();
    let before = mints(&gw);
    assert_retryable(&task_get(&gw, &id).await, "C8 setup");
    let backend = backend(&gw);
    backend.age_per_user_slot_for_test(BINDING, 400);
    backend.evict_idle_per_user_entries(Duration::from_secs(300));
    assert_retryable(&task_get(&gw, &id).await, "C8: the lease survives");
    assert_eq!(
        mints(&gw) - before,
        1,
        "C8: only the first attempt resolved"
    );
}

/// L3: an indexed Held entry whose slot was retired is claimable: one
/// resolution, then served (M41: never claimable, retryable forever).
#[tokio::test]
async fn l3_a_retired_held_entry_is_claimable() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-l3").await;
    backend(&gw).retire_per_user_slot_for_test(BINDING);
    let _ = rearm_alpha_slot_with(&backend(&gw), &valid(), false);
    let before = mints(&gw);
    let first = task_get(&gw, &id).await;
    assert!(first.to_string().contains(OUTPUT), "L3: served: {first}");
    assert_eq!(mints(&gw) - before, 1, "L3: one resolution");
}
