// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests of the idempotency cache.

use super::*;
use serde_json::json;
use std::thread;

/// Move the cache's clock forward by `by`. An entry stored before the move
/// is that much older; one stored after is fresh (MIK-8070: no past `Instant`
/// is ever built, so no test depends on how long ago the host booted).
fn advance(cache: &IdempotencyCache, by: Duration) {
    cache
        .ahead
        .fetch_add(by.as_secs(), std::sync::atomic::Ordering::Relaxed);
}

/// The marker is the gateway's own word, so nothing a backend sends may
/// mint it. The other writer of a cached error body serializes a
/// `JsonRpcError`, and this pins that that serialization has no field
/// which could land on the marker's name — including when the backend
/// fills `data` with the marker itself, because the replay reads the top
/// level only.
#[test]
fn a_serialized_backend_error_cannot_carry_the_refusal_marker() {
    let hostile = crate::protocol::JsonRpcError {
        code: -32600,
        message: format!("{FIREWALL_REFUSAL_MARKER} is mine now"),
        data: Some(json!({FIREWALL_REFUSAL_MARKER: true})),
    };
    let body = serde_json::to_value(&hostile).expect("a JsonRpcError serializes");

    assert!(
        body.get(FIREWALL_REFUSAL_MARKER).is_none(),
        "a backend-authored error must never present as a gateway refusal: {body}"
    );
}

// ── derive_key ────────────────────────────────────────────────────────────

#[test]
fn derive_key_is_deterministic_for_same_inputs() {
    // GIVEN: identical tool name and arguments
    // WHEN: deriving the key twice
    // THEN: both keys are identical
    let k1 = derive_key("gmail_send_email", &json!({"to": "a@b.com", "body": "hi"}));
    let k2 = derive_key("gmail_send_email", &json!({"to": "a@b.com", "body": "hi"}));
    assert_eq!(k1, k2);
}

#[test]
fn derive_key_is_64_hex_chars() {
    // GIVEN: any tool + arguments
    // WHEN: deriving the key
    // THEN: result is a 64-character hex string (SHA-256)
    let key = derive_key("my_tool", &json!({}));
    assert_eq!(key.len(), 64);
    assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn derive_key_differs_for_different_tool_names() {
    // GIVEN: same arguments but different tool names
    // WHEN: deriving keys
    // THEN: keys are different
    let k1 = derive_key("tool_a", &json!({"x": 1}));
    let k2 = derive_key("tool_b", &json!({"x": 1}));
    assert_ne!(k1, k2);
}

#[test]
fn derive_key_differs_for_different_arguments() {
    // GIVEN: same tool name but different arguments
    // WHEN: deriving keys
    // THEN: keys are different
    let k1 = derive_key("send", &json!({"to": "a@b.com"}));
    let k2 = derive_key("send", &json!({"to": "c@d.com"}));
    assert_ne!(k1, k2);
}

#[test]
fn derive_key_prevents_prefix_collision() {
    // GIVEN: a tool whose name is a prefix of another (tool, tool_extended)
    // WHEN: deriving keys with the same suffix args
    // THEN: keys are different (NUL separator prevents collision)
    let k1 = derive_key("tool", &json!({"a": "extended"}));
    let k2 = derive_key("tool_extended", &json!({"a": ""}));
    assert_ne!(k1, k2);
}

// ── IdempotencyState ──────────────────────────────────────────────────────

#[test]
fn state_in_flight_is_not_expired_immediately() {
    // GIVEN: a freshly created InFlight state
    // WHEN: checking expiry
    // THEN: not expired
    let state = IdempotencyState::InFlight(Instant::now());
    assert!(!state.is_expired());
}

#[test]
fn state_completed_is_not_expired_immediately() {
    // GIVEN: a freshly created Completed state
    // WHEN: checking expiry
    // THEN: not expired
    let state = IdempotencyState::Completed(json!({"ok": true}), Instant::now());
    assert!(!state.is_expired());
}

#[test]
fn state_in_flight_is_live_immediately() {
    // GIVEN: a freshly created InFlight state
    // WHEN: checking is_in_flight
    // THEN: true
    let state = IdempotencyState::InFlight(Instant::now());
    assert!(state.is_in_flight());
}

#[test]
fn state_completed_is_not_in_flight() {
    // GIVEN: a Completed state
    // WHEN: checking is_in_flight
    // THEN: false
    let state = IdempotencyState::Completed(json!(null), Instant::now());
    assert!(!state.is_in_flight());
}

// ── IdempotencyCache::check ───────────────────────────────────────────────

#[test]
fn check_returns_proceed_for_unknown_key() {
    // GIVEN: an empty cache
    // WHEN: checking an unknown key
    // THEN: Proceed
    let cache = IdempotencyCache::new();
    assert!(matches!(cache.check("unknown"), CheckOutcome::Proceed));
}

#[test]
fn check_returns_in_flight_for_live_in_flight_key() {
    // GIVEN: cache with a live in-flight key
    // WHEN: checking the same key
    // THEN: InFlight
    let cache = IdempotencyCache::new();
    cache.mark_in_flight("key-1");
    assert!(matches!(cache.check("key-1"), CheckOutcome::InFlight));
}

#[test]
fn check_returns_completed_result_for_completed_key() {
    // GIVEN: cache with a completed key
    // WHEN: checking the same key
    // THEN: Completed with the stored value
    let cache = IdempotencyCache::new();
    let result = json!({"issue_id": "LIN-42"});
    cache.mark_in_flight("key-2");
    cache.mark_completed("key-2", result.clone());
    match cache.check("key-2") {
        CheckOutcome::Completed(v) => assert_eq!(v, result),
        other => panic!("expected Completed, got {other:?}"),
    }
}

/// An aged in-flight entry whose owner is gone is refused at admission and
/// reclaimed by the sweep — the two halves of ADR-012 consequence 3.
#[test]
fn check_refuses_an_ownerless_aged_entry_and_the_sweep_reclaims_it() {
    // GIVEN: an in-flight entry older than IN_FLIGHT_TIMEOUT whose owner
    // never existed, so its handle is dead
    let cache = IdempotencyCache::new();
    cache.mark_in_flight("stale");
    assert!(cache.age_in_flight("stale", IN_FLIGHT_TIMEOUT + Duration::from_secs(1)));

    // WHEN: a second caller checks the key
    // THEN: it is told in flight rather than readmitted, and the entry is
    // still there — admission never frees a key, the sweep does
    assert!(matches!(cache.check("stale"), CheckOutcome::InFlight));
    assert_eq!(cache.len(), 1, "admission must not reclaim the entry");

    cache.evict_expired();
    assert_eq!(cache.len(), 0, "the sweep reclaims an ownerless entry");
}

// ── ADR-012 amendment A2: liveness, not the clock ─────────────────────────

/// Spin `work` on a new thread until `stop` is set.
///
/// Both A2 race harnesses need a concurrent spinner and they must observe
/// the same `stop`, so the loop lives once here.
fn spawn_until(
    stop: &Arc<std::sync::atomic::AtomicBool>,
    mut work: impl FnMut() + Send + 'static,
) -> std::thread::JoinHandle<()> {
    let stop = Arc::clone(stop);
    std::thread::spawn(move || {
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            work();
        }
    })
}

/// Row 4a — a live owner past the timeout is told in-flight, not admitted.
#[test]
fn an_aged_entry_with_a_live_owner_refuses_a_second_caller() {
    // GIVEN: a reservation whose call has been running past the timeout
    let cache = Arc::new(IdempotencyCache::new());
    let GuardOutcome::Proceed(_reservation) = enforce(&cache, "k", "fp").unwrap() else {
        panic!("first caller must be admitted");
    };
    assert!(cache.age_in_flight("k", IN_FLIGHT_TIMEOUT + Duration::from_secs(1)));

    // WHEN: a second caller arrives on the same key
    // THEN: it is refused, because staleness is a liveness question
    assert!(matches!(cache.check("k"), CheckOutcome::InFlight));
    assert!(enforce(&cache, "k", "fp").is_err());
}

/// Row 4b — that same entry survives an explicit `evict_expired` sweep.
///
/// Separate from row 4a because the sweep does not consult
/// `decide_check_plan`; it is the second place the predicate has to hold.
#[test]
fn an_aged_entry_with_a_live_owner_survives_a_sweep() {
    // GIVEN: the same aged-but-owned entry
    let cache = Arc::new(IdempotencyCache::new());
    let GuardOutcome::Proceed(_reservation) = enforce(&cache, "k", "fp").unwrap() else {
        panic!("first caller must be admitted");
    };
    assert!(cache.age_in_flight("k", IN_FLIGHT_TIMEOUT + Duration::from_secs(1)));

    // WHEN: the background cleanup runs
    cache.evict_expired();

    // THEN: the entry is still there
    assert_eq!(cache.len(), 1, "a running call must keep its entry");
}

/// Row 4c — a sweep landing while a reservation's settlement is in
/// progress does not evict its entry.
///
/// The race A2 exists for. A liveness rule built on
/// `Weak<IdempotencyReservation>` passes rows 4a and 4b and still loses the
/// entry here: `Arc` zeroes the strong count before running `Drop`, so the
/// sweep sees an ownerless aged entry while `Drop` is still storing the
/// terminal state, and the next caller is admitted fresh against a key whose
/// mutation may have committed. The token is a *field* of the reservation,
/// dropped only after the `Drop` body returns, so that window does not exist.
///
/// A race has no honest single-shot failing test, so this follows the repro
/// harness above: a one-sided invariant that holds under any interleaving —
/// from the moment a key is admitted until its reservation has settled, no
/// concurrent caller is ever told the key is free.
#[test]
fn a_sweep_during_settlement_never_readmits_a_settling_key() {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    // GIVEN: aged reservations settling while the background sweep runs
    let cache = Arc::new(IdempotencyCache::new());
    let stop = Arc::new(AtomicBool::new(false));
    let outstanding: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let readmitted = Arc::new(AtomicUsize::new(0));

    let sweeper = spawn_until(&stop, {
        let cache = Arc::clone(&cache);
        move || cache.evict_expired()
    });
    let checker = spawn_until(&stop, {
        let cache = Arc::clone(&cache);
        let outstanding = Arc::clone(&outstanding);
        let readmitted = Arc::clone(&readmitted);
        move || {
            let key = outstanding.lock().unwrap().clone();
            // A stale read can only name a key that has since settled, and a
            // settled key answers `Completed`, so this cannot false-positive.
            if let Some(key) = key
                && matches!(cache.check(&key), CheckOutcome::Proceed)
            {
                readmitted.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    // WHEN: each one ages past the timeout and then settles
    for i in 0..500 {
        let key = format!("k{i}");
        let GuardOutcome::Proceed(mut reservation) = enforce(&cache, &key, "fp").unwrap() else {
            panic!("first caller must be admitted");
        };
        *outstanding.lock().unwrap() = Some(key.clone());
        assert!(cache.age_in_flight(&key, IN_FLIGHT_TIMEOUT + Duration::from_secs(1)));
        reservation.commit(&json!({"ok": true}));
        drop(reservation);
        *outstanding.lock().unwrap() = None;
    }
    stop.store(true, Ordering::Relaxed);
    sweeper.join().unwrap();
    checker.join().unwrap();

    // THEN: no caller was ever handed a key that was still settling
    assert_eq!(
        readmitted.load(Ordering::Relaxed),
        0,
        "a sweep during settlement freed a key whose side effect had committed"
    );
}

// ── evict_expired ─────────────────────────────────────────────────────────

/// Repro harness for the eviction race gpt-review raised on 2026-09-08.
///
/// A race has no honest single-shot failing test, so the repair protocol
/// asks for a deterministic repro harness instead. The invariant is
/// one-sided and holds under any interleaving: a freshly admitted entry is
/// not expired, so `evict_expired` must never remove it. Under the previous
/// collect-then-remove pass it could — the evictor selected the key while
/// the old entry was stale and deleted whatever held the key afterwards.
#[test]
fn eviction_never_removes_a_fresh_entry_that_replaced_an_expired_one() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    // GIVEN: one key that keeps alternating between an expired entry the
    // evictor wants and a fresh entry it must leave alone
    let cache = Arc::new(IdempotencyCache::new());
    let stop = Arc::new(AtomicBool::new(false));
    let lost = Arc::new(AtomicUsize::new(0));
    let expired_at = cache.now();
    advance(&cache, COMPLETED_TTL + Duration::from_secs(1));

    // WHEN: the background evictor runs against that churn
    let evictor = {
        let cache = Arc::clone(&cache);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                cache.evict_expired();
            }
        })
    };

    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline {
        cache.entries.insert(
            "k".to_string(),
            Entry::new(IdempotencyState::Completed(json!(null), expired_at), ""),
        );
        cache.entries.insert(
            "k".to_string(),
            Entry::new(IdempotencyState::InFlight(cache.now()), ""),
        );
        if !cache.entries.contains_key("k") {
            lost.fetch_add(1, Ordering::Relaxed);
        }
    }
    stop.store(true, Ordering::Relaxed);
    evictor.join().unwrap();

    // THEN: the fresh entry survived every pass
    assert_eq!(
        lost.load(Ordering::Relaxed),
        0,
        "eviction deleted an entry that was not expired"
    );
}

#[test]
fn evict_expired_removes_only_stale_entries() {
    // GIVEN: one fresh and one stale completed entry
    // WHEN: calling evict_expired
    // THEN: only the stale entry is removed
    let cache = IdempotencyCache::new();
    cache.mark_in_flight("stale");
    assert!(cache.mark_completed("stale", json!(2)));
    advance(&cache, COMPLETED_TTL + Duration::from_secs(1));
    cache.mark_in_flight("fresh");
    cache.mark_completed("fresh", json!(1));

    cache.evict_expired();

    assert_eq!(cache.len(), 1);
    assert!(matches!(cache.check("fresh"), CheckOutcome::Completed(_)));
}

/// MIK-7991 review (Codex P2): the direct route settles into this cache with
/// no sync admission in front of it, so a completed entry is owed its replay
/// for the whole documented day; a retry one second before it ends must not
/// run the side effect again.
#[test]
fn a_completed_entry_still_replays_one_second_before_the_day_ends() {
    let cache = IdempotencyCache::new();
    cache.mark_in_flight("k");
    cache.mark_completed("k", json!(1));
    advance(&cache, Duration::from_secs(24 * 60 * 60 - 1));
    assert!(
        matches!(cache.check("k"), CheckOutcome::Completed(_)),
        "a retry inside the day re-executed instead of replaying"
    );
}

// ── enforce ───────────────────────────────────────────────────────────────

#[test]
fn enforce_marks_in_flight_and_returns_proceed_for_new_key() {
    // GIVEN: an empty cache
    // WHEN: enforcing on a new key
    // THEN: Proceed, and the key is now in-flight
    let cache = Arc::new(IdempotencyCache::new());
    let outcome = enforce(&cache, "k1", "fp1").expect("should not fail");
    assert!(matches!(outcome, GuardOutcome::Proceed(_)));
    assert!(matches!(cache.check("k1"), CheckOutcome::InFlight));
}

#[test]
fn enforce_returns_cached_result_for_completed_key() {
    // GIVEN: a completed key in cache
    // WHEN: enforcing on that key
    // THEN: CachedResult with the stored value
    let cache = Arc::new(IdempotencyCache::new());
    let expected = json!({"done": true});
    cache.mark_in_flight("k2");
    cache.mark_completed("k2", expected.clone());
    match enforce(&cache, "k2", "fp2").expect("should not fail") {
        GuardOutcome::CachedResult(v) => assert_eq!(v, expected),
        other => panic!("expected CachedResult, got {other:?}"),
    }
}

#[test]
fn enforce_returns_error_for_in_flight_key() {
    // GIVEN: a live in-flight key
    // WHEN: enforcing on the same key from a concurrent caller
    // THEN: Err with code 409
    let cache = Arc::new(IdempotencyCache::new());
    cache.mark_in_flight("k3");
    let err = enforce(&cache, "k3", "fp3").expect_err("should return 409");
    match err {
        crate::Error::JsonRpc { code, .. } => assert_eq!(code, 409),
        _ => panic!("expected JsonRpc error"),
    }
}

// ── remove ────────────────────────────────────────────────────────────────

#[test]
fn remove_clears_key_making_it_retryable() {
    // GIVEN: an in-flight key
    // WHEN: calling remove (e.g. on tool failure)
    // THEN: key is gone and check returns Proceed
    let cache = IdempotencyCache::new();
    cache.mark_in_flight("fail-key");
    cache.remove("fail-key");
    assert!(matches!(cache.check("fail-key"), CheckOutcome::Proceed));
    assert_eq!(cache.len(), 0);
}

// ── concurrent access ─────────────────────────────────────────────────────

#[test]
fn concurrent_mark_completed_is_safe() {
    // GIVEN: cache shared across threads
    // WHEN: 10 threads each mark different keys completed
    // THEN: all entries are present without data races
    let cache = Arc::new(IdempotencyCache::new());
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let c = Arc::clone(&cache);
            thread::spawn(move || {
                let key = format!("key-{i}");
                c.mark_in_flight(&key);
                c.mark_completed(&key, json!(i));
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }

    assert_eq!(cache.len(), 10);
}

// ── is_empty / len ────────────────────────────────────────────────────────

#[test]
fn new_cache_is_empty() {
    let cache = IdempotencyCache::new();
    assert!(cache.is_empty());
    assert_eq!(cache.len(), 0);
}

#[test]
fn len_increases_on_insert() {
    let cache = IdempotencyCache::new();
    cache.mark_in_flight("a");
    cache.mark_in_flight("b");
    assert_eq!(cache.len(), 2);
    assert!(!cache.is_empty());
}

// ── cleanup task (tokio) ──────────────────────────────────────────────────

#[tokio::test(start_paused = true)]
async fn spawn_cleanup_task_evicts_expired_entries() {
    // A stale entry is evicted. On the paused clock the task's ticks run
    // before the virtual wait returns, however loaded the host (#1821).
    let cache = Arc::new(IdempotencyCache::new());
    cache.mark_in_flight("stale");
    assert!(cache.mark_completed("stale", json!(null)));
    assert_eq!(cache.len(), 1, "the fixture stored the entry to evict");
    advance(&cache, COMPLETED_TTL + Duration::from_secs(1));

    spawn_cleanup_task(Arc::clone(&cache), Duration::from_millis(10));

    // Let the cleanup run during 50 ms of virtual time.
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(cache.len(), 0, "stale entry should have been evicted");
}

#[test]
fn released_then_completed_entry_stays_bound_to_its_own_request() {
    // GIVEN: a key admitted for request A, whose dispatch failed — the
    // invoke path releases the reservation and then still stores the
    // structured error result (`src/gateway/meta_mcp/invoke.rs:1480`,
    // `:1836`), which `complete` documents as deliberate.
    let cache = Arc::new(IdempotencyCache::new());
    let GuardOutcome::Proceed(mut reservation) = enforce(&cache, "k", "fp-A").unwrap() else {
        panic!("a fresh key is admitted");
    };
    reservation.release();
    assert!(reservation.complete(&json!({"isError": true})));

    // WHEN: a *different* request reuses the same client-supplied key
    let outcome = enforce(&cache, "k", "fp-B");

    // THEN: it is refused, not answered with request A's error. A stored
    // result carries the fingerprint it was admitted for; an entry that
    // binds nothing answers every later request for the whole TTL.
    let Err(err) = outcome else {
        panic!("key bound to fp-A must not serve fp-B");
    };
    // Named, not merely `is_err`: the in-flight and at-capacity refusals
    // are errors too, and neither would prove the binding held.
    let message = err.to_string();
    assert!(
        message.contains("already in use for a different request"),
        "expected the fingerprint-mismatch refusal, got: {message}"
    );
}

/// MIK-7116.MIN.2 row 14: a replay restores the reading kept in the same
/// entry as its result; an entry completed without one replays as unread.
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_replay_restores_its_entrys_reading() {
    use crate::security::firewall::tenant_guard::TenantGuardConfig;
    use crate::security::firewall::{Firewall, FirewallConfig};
    use crate::security::tenant_reads::{ReadAttribution, with_read_scope};

    let fw = Arc::new(Firewall::from_config(
        FirewallConfig {
            tenant_guard: TenantGuardConfig {
                arg_keys: vec!["customer_id".to_string()],
                ..TenantGuardConfig::default()
            },
            ..FirewallConfig::default()
        },
        None,
    ));
    let cache = Arc::new(IdempotencyCache::new());
    let reading = ReadAttribution::of([String::from("cust-b")].into(), false);
    let GuardOutcome::Proceed(mut reservation) = enforce(&cache, "k", "fp").unwrap() else {
        panic!("a fresh key proceeds");
    };
    assert!(reservation.complete_read(
        &json!({"ok": true}),
        (
            Some(reading.clone()),
            crate::gateway::gateway_writes::WriteRecord::default()
        )
    ));
    let (replay, restored) =
        with_read_scope(Arc::clone(&fw), async { enforce(&cache, "k", "fp") }).await;
    assert!(matches!(replay, Ok(GuardOutcome::CachedResult(_))));
    assert_eq!(
        restored, reading,
        "the replay restores its own entry's reading"
    );

    let GuardOutcome::Proceed(mut bare) = enforce(&cache, "bare", "fp").unwrap() else {
        panic!("a fresh key proceeds");
    };
    assert!(bare.complete(&json!({"ok": true})));
    let (_, restored) = with_read_scope(fw, async { enforce(&cache, "bare", "fp") }).await;
    assert!(
        restored.uninspected,
        "an entry completed without a reading is unread"
    );
}
