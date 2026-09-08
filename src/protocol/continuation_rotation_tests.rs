// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: MIT
//! NFR.SEC.3 assertion-first rotation cases. See the approved rotation test plan.

use super::*;
use std::collections::BTreeSet;
#[path = "continuation_rotation_tests/support.rs"]
mod support;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::time::Duration;
use support::*;

const T: u64 = 1_000;
const KEY: [u8; 32] = [0xa7; 32];

#[test]
fn rotate_01_age_boundary_rotates_once_and_keeps_live_envelopes() {
    let ring = ring();
    let first = payload(T);
    let initial = ring.mint(&first).unwrap();
    assert_eq!(kid(&initial), 1);
    let before = payload(T + CONTINUATION_ROTATION_SECS - 1);
    let before_token = ring.mint(&before).unwrap();
    assert_eq!(kid(&before_token), 1);
    let due = payload(T + CONTINUATION_ROTATION_SECS);
    let due_token = ring.mint(&due).unwrap();
    assert_eq!(kid(&due_token), 2, "ROTATE.1: no age-triggered successor");
    for (token, original) in [
        (&initial, &first),
        (&before_token, &before),
        (&due_token, &due),
    ] {
        assert_opens(&ring, token, original, due.issued_at);
    }
}

#[test]
fn rotate_02_retirement_equality_retains_key_then_later_mint_prunes() {
    let ring = ring();
    ring.mint(&payload(T)).unwrap();
    let retired_at = T + CONTINUATION_ROTATION_SECS;
    let last_old = payload(retired_at);
    let old_token = seal_under_current(&ring, &last_old);
    let successor = ring.mint(&payload(retired_at)).unwrap();
    assert_eq!(kid(&successor), 2);
    assert!(
        snapshot(&ring)
            .entries
            .contains(&(1, Some(T), Some(retired_at)))
    );
    let equality = retired_at + CONTINUATION_LIFETIME_SECS;
    let live = payload(equality);
    let live_token = ring.mint(&live).unwrap();
    assert!(snapshot(&ring).entries.iter().any(|entry| entry.0 == 1));
    assert_opens(&ring, &old_token, &last_old, equality);
    assert_eq!(
        ring.open(&old_token, equality + 1),
        Err(ContinuationError::Expired)
    );
    ring.mint(&payload(equality + CONTINUATION_ROTATION_SECS))
        .unwrap();
    assert!(!snapshot(&ring).entries.iter().any(|entry| entry.0 == 1));
    assert_eq!(
        ring.open(&old_token, equality + CONTINUATION_ROTATION_SECS),
        Err(ContinuationError::UnknownKey(1))
    );
    assert_opens(
        &ring,
        &live_token,
        &live,
        equality + CONTINUATION_ROTATION_SECS,
    );
}

#[test]
fn rotate_03_open_never_rotates_or_prunes_and_reports_expiry() {
    let ring = ring();
    let first = payload(T);
    let token = ring.mint(&first).unwrap();
    let before = snapshot(&ring);
    assert_opens(&ring, &token, &first, T + CONTINUATION_ROTATION_SECS);
    assert_eq!(
        ring.open(&token, first.expires_at + 1),
        Err(ContinuationError::Expired)
    );
    assert_eq!(
        snapshot(&ring),
        before,
        "ROTATE.3: verification changed ring state"
    );
    let next = ring
        .mint(&payload(T + 2 * CONTINUATION_LIFETIME_SECS))
        .unwrap();
    assert_eq!(
        kid(&next),
        2,
        "idle time causes one mint-side rotation, not catch-up rotations"
    );
}

#[test]
fn rotate_04_wraps_successor_and_bounds_retained_cohorts() {
    const { assert!((256_u64 - 1) * CONTINUATION_ROTATION_SECS > CONTINUATION_LIFETIME_SECS) };
    let ring = ring();
    let bound =
        usize::try_from(CONTINUATION_LIFETIME_SECS / CONTINUATION_ROTATION_SECS + 2).unwrap();
    assert_eq!(bound, 7);
    let mut envelopes: Vec<(String, Payload)> = Vec::new();
    let mut reached_bound = false;
    for step in 0..=257_u64 {
        let now = T + step * CONTINUATION_ROTATION_SECS;
        let value = payload(now);
        let token = ring.mint(&value).unwrap();
        assert_eq!(
            kid(&token),
            1_u8.wrapping_add(u8::try_from(step % 256).unwrap()),
            "ROTATE.4 at step {step}"
        );
        let current = snapshot(&ring);
        let ids: BTreeSet<_> = current.entries.iter().map(|entry| entry.0).collect();
        assert_eq!(ids.len(), current.entries.len());
        assert_eq!(ids.len(), (usize::try_from(step).unwrap() + 1).min(bound));
        reached_bound |= ids.len() == bound;
        for (old_token, old) in &envelopes {
            if now <= old.expires_at {
                assert_opens(&ring, old_token, old, now);
            }
        }
        envelopes.push((token, value));
    }
    assert!(reached_bound, "equality must retain the seventh cohort");
}

#[test]
fn rotate_05_exhaustion_refuses_until_age_then_resets_per_key_budget() {
    let ring = ring().with_mint_budget(2);
    ring.mint(&payload(T)).unwrap();
    ring.mint(&payload(T + CONTINUATION_ROTATION_SECS - 1))
        .unwrap();
    let before = snapshot(&ring);
    for _ in 0..16 {
        assert_eq!(
            ring.mint(&payload(T + CONTINUATION_ROTATION_SECS - 1)),
            Err(ContinuationError::MintBudgetExhausted)
        );
        assert_eq!(snapshot(&ring), before);
    }
    let token = ring.mint(&payload(T + CONTINUATION_ROTATION_SECS)).unwrap();
    assert_eq!(kid(&token), 2);
    assert_eq!(ring.mint_budget_remaining(), 1);
}

#[test]
fn rotate_06_concurrent_due_mints_publish_one_successor_and_share_quota() {
    const N: usize = 16;
    let ring = Arc::new(ring().with_mint_budget(N as u64));
    ring.mint(&payload(T)).unwrap();
    let all_due = Arc::new(Barrier::new(N));
    let due_calls = Arc::new(AtomicUsize::new(0));
    let arrivals = Arc::clone(&due_calls);
    set_hooks(
        &ring,
        KeyringTestHooks {
            due_checked: Some(Arc::new(move || {
                arrivals.fetch_add(1, Ordering::SeqCst);
                all_due.wait();
            })),
            ..KeyringTestHooks::default()
        },
    );
    let now = T + CONTINUATION_ROTATION_SECS;
    let results = concurrent_mints(&ring, now, N);
    set_hooks(&ring, KeyringTestHooks::default());
    assert_eq!(
        due_calls.load(Ordering::SeqCst),
        N,
        "all contenders reached the due-read/write transition"
    );
    assert!(
        results.iter().all(|(_, result)| result.is_ok()),
        "all {N} due mints must use fresh quota: {results:?}"
    );
    for (original, result) in results {
        let token = result.unwrap();
        assert_eq!(kid(&token), 2);
        assert_opens(&ring, &token, &original, now);
    }
    assert_eq!(snapshot(&ring).entries.len(), 2);
    assert_eq!(ring.mint_budget_remaining(), 0);
    assert_eq!(
        ring.mint(&payload(now)),
        Err(ContinuationError::MintBudgetExhausted)
    );
}

#[test]
fn rotate_07_concurrent_reservations_never_exceed_remaining_budget() {
    let ring = Arc::new(ring().with_mint_budget(4));
    ring.mint(&payload(T)).unwrap();
    let quota_gate = Arc::new(Barrier::new(24));
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observations = Arc::clone(&observed);
    set_hooks(
        &ring,
        KeyringTestHooks {
            quota_observed: Some(Arc::new(move |used| {
                observations.lock().unwrap().push(used);
                quota_gate.wait();
            })),
            ..KeyringTestHooks::default()
        },
    );
    let results = concurrent_mints(&ring, T, 24);
    set_hooks(&ring, KeyringTestHooks::default());
    assert_eq!(
        *observed.lock().unwrap(),
        vec![1; 24],
        "contenders must observe the same quota decision before reservation"
    );
    assert_eq!(
        results.iter().filter(|(_, result)| result.is_ok()).count(),
        3
    );
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| *result == Err(ContinuationError::MintBudgetExhausted))
            .count(),
        21
    );
    let before = snapshot(&ring);
    for _ in 0..32 {
        assert_eq!(
            ring.mint(&payload(T)),
            Err(ContinuationError::MintBudgetExhausted)
        );
    }
    assert_eq!(snapshot(&ring), before);
}

#[test]
fn rotate_07_saturated_counter_refusals_never_wrap_or_rewrite_it() {
    let ring = ring().with_mint_budget(2);
    ring.mint(&payload(T)).unwrap();
    force_counter(&ring, u64::MAX);
    let before = snapshot(&ring);
    for _ in 0..4 {
        assert_eq!(
            ring.mint(&payload(T)),
            Err(ContinuationError::MintBudgetExhausted)
        );
        assert_eq!(
            snapshot(&ring),
            before,
            "ROTATE.7: a refusal mutated the saturated counter"
        );
    }
}

#[test]
fn rotate_08_first_trusted_epoch_stamps_once_and_backward_time_does_not_rotate() {
    let ring = ring();
    assert_eq!(snapshot(&ring).entries, vec![(1, None, None)]);
    ring.mint(&payload(T)).unwrap();
    assert_eq!(snapshot(&ring).entries, vec![(1, Some(T), None)]);
    let backwards = ring.mint(&payload(T - 100)).unwrap();
    assert_eq!(kid(&backwards), 1);
    assert_eq!(snapshot(&ring).entries, vec![(1, Some(T), None)]);
    let due = ring.mint(&payload(T + CONTINUATION_ROTATION_SECS)).unwrap();
    assert_eq!(kid(&due), 2);
}

#[test]
fn rotate_08_near_maximum_epoch_never_wraps_age_or_retention() {
    let ring = ring();
    let first = payload(u64::MAX - CONTINUATION_ROTATION_SECS);
    let old = ring.mint(&first).unwrap();
    let next = ring.mint(&payload(u64::MAX)).unwrap();
    assert_eq!(kid(&next), 2);
    assert_opens(&ring, &old, &first, u64::MAX);
    assert_eq!(kid(&ring.mint(&payload(u64::MAX - 1)).unwrap()), 2);
    assert_eq!(kid(&ring.mint(&payload(u64::MAX)).unwrap()), 2);
    assert!(
        snapshot(&ring)
            .entries
            .contains(&(1, Some(first.issued_at), Some(u64::MAX)))
    );
}

#[tokio::test]
async fn rotate_09_real_state_keeps_pending_and_spent_exchanges_and_replica_isolation() {
    let state = ContinuationState::new();
    let foreign = ContinuationState::new();
    let replica = state.replica().to_owned();
    let spent = state
        .begin_exchange(
            "backend".into(),
            Some("spent state".into()),
            "caller".into(),
            "request".into(),
            T,
        )
        .await
        .unwrap();
    let spent_token = state.keyring().mint(&spent).unwrap();
    assert!(
        state
            .ledger()
            .consume(&spent.jti, spent.expires_at, T)
            .await
    );
    let pending = state
        .begin_exchange(
            "backend".into(),
            Some("pending state".into()),
            "caller".into(),
            "request".into(),
            T,
        )
        .await
        .unwrap();
    let pending_token = state.keyring().mint(&pending).unwrap();
    let held_before = state.in_flight().snapshot().await;
    let due = payload(T + CONTINUATION_ROTATION_SECS);
    let next = state.keyring().mint(&due).unwrap();
    assert_ne!(
        kid(&next),
        kid(&pending_token),
        "ROTATE.9 must cross an actual rotation"
    );
    assert_eq!(state.replica(), replica);
    assert_eq!(state.in_flight().snapshot().await, held_before);
    assert_opens(state.keyring(), &pending_token, &pending, due.issued_at);
    assert_opens(state.keyring(), &spent_token, &spent, due.issued_at);
    assert_eq!(
        state
            .in_flight()
            .route(&pending.hold_key, due.issued_at)
            .await,
        Routing::Here
    );
    assert!(
        !state
            .ledger()
            .consume(&spent.jti, spent.expires_at, due.issued_at)
            .await
    );
    assert_eq!(
        foreign.keyring().open(&pending_token, due.issued_at),
        Err(ContinuationError::NotAuthentic)
    );
    assert!(
        foreign
            .ledger()
            .consume(&pending.jti, pending.expires_at, due.issued_at)
            .await,
        "component control: a fresh independent ledger accepts its first spend"
    );
}

#[test]
fn rotate_10_preloaded_verifiers_stamp_on_first_mint_and_retain_full_window() {
    let old = Keyring::new(&[(7, [0x19; 32])]).unwrap();
    let original = payload(T);
    let token = old.mint(&original).unwrap();
    let ring = Keyring::new(&[(1, KEY), (7, [0x19; 32])]).unwrap();
    assert_opens(&ring, &token, &original, T);
    assert_eq!(
        snapshot(&ring).entries,
        vec![(1, None, None), (7, None, None)]
    );
    ring.mint(&payload(T)).unwrap();
    assert!(snapshot(&ring).entries.contains(&(7, None, Some(T))));
    assert_eq!(
        kid(&ring.mint(&payload(T + CONTINUATION_ROTATION_SECS)).unwrap()),
        2
    );
    ring.mint(&payload(T + CONTINUATION_LIFETIME_SECS)).unwrap();
    assert_opens(&ring, &token, &original, original.expires_at);
    ring.mint(&payload(
        T + CONTINUATION_LIFETIME_SECS + CONTINUATION_ROTATION_SECS,
    ))
    .unwrap();
    assert!(!snapshot(&ring).entries.iter().any(|entry| entry.0 == 7));
    assert_eq!(
        ring.open(
            &token,
            T + CONTINUATION_LIFETIME_SECS + CONTINUATION_ROTATION_SECS
        ),
        Err(ContinuationError::UnknownKey(7))
    );
}

#[test]
fn rotate_10_retained_successor_collision_preserves_material_and_allows_mint() {
    const SUCCESSOR: [u8; 32] = [0x6e; 32];
    let imported = Keyring::new(&[(2, [0x19; 32])]).unwrap();
    let original = payload(T);
    let imported_token = imported.mint(&original).unwrap();
    let ring = Keyring::new(&[(1, KEY), (2, [0x19; 32])]).unwrap();
    ring.mint(&payload(T)).unwrap();
    let (due, collision_events) =
        capture_events(|| ring.mint(&payload(T + CONTINUATION_ROTATION_SECS)).unwrap());
    assert_eq!(kid(&due), 1, "retained successor must not be overwritten");
    assert_eq!(collision_events.len(), 1);
    assert_eq!(
        serde_json::to_value(&collision_events[0]).unwrap(),
        serde_json::json!({
            "message":"Continuation key rotation blocked: successor is retained",
            "minting_kid":1,"successor_kid":2,"retained_keys":2
        }),
        "collision diagnostic contains only bounded public metadata"
    );
    assert_opens(
        &ring,
        &imported_token,
        &original,
        T + CONTINUATION_ROTATION_SECS,
    );
    assert_eq!(snapshot(&ring).entries.len(), 2);
    assert_eq!(kid(&ring.mint(&payload(original.expires_at)).unwrap()), 1);
    assert_opens(&ring, &imported_token, &original, original.expires_at);
    set_hooks(
        &ring,
        KeyringTestHooks {
            successor: Some(Arc::new(|| Ok(SUCCESSOR))),
            ..KeyringTestHooks::default()
        },
    );
    let replacement_payload = payload(original.expires_at + 1);
    let replacement = ring.mint(&replacement_payload).unwrap();
    assert_eq!(
        kid(&replacement),
        2,
        "rotation resumes once successor retention ends"
    );
    assert_opens(
        &Keyring::new(&[(2, SUCCESSOR)]).unwrap(),
        &replacement,
        &replacement_payload,
        replacement_payload.issued_at,
    );
    assert_eq!(
        ring.open(&imported_token, original.expires_at + 1),
        Err(ContinuationError::NotAuthentic),
        "reused kid has fresh material; Expired alone would allow promotion of the imported key"
    );
}

#[test]
fn rotate_11_version_bindings_and_aad_tampering_remain_enforced() {
    let ring = Keyring::new(&[(1, KEY), (2, [0x19; 32])]).unwrap();
    let original = payload(T);
    let token = ring.mint(&original).unwrap();
    assert_opens(&ring, &token, &original, T);
    assert_eq!(
        original.redeemable_by("verified-rotation-caller", "original-request-digest"),
        Ok(())
    );
    assert_eq!(
        original.redeemable_by("different-caller", "original-request-digest"),
        Err(ContinuationError::NotAuthentic)
    );
    assert_eq!(
        original.redeemable_by("verified-rotation-caller", "different-request"),
        Err(ContinuationError::NotAuthentic)
    );
    let wire = B64.decode(&token).unwrap();
    assert_eq!(wire[0], VERSION);
    let mut changed = wire.clone();
    changed[0] = VERSION + 1;
    assert_eq!(
        ring.open(&B64.encode(changed), T),
        Err(ContinuationError::UnknownVersion(VERSION + 1))
    );
    let mut changed = wire.clone();
    changed[1] = 2;
    assert_eq!(
        ring.open(&B64.encode(changed), T),
        Err(ContinuationError::NotAuthentic)
    );
    let mut changed = wire;
    changed[2 + NONCE_LEN] ^= 1;
    assert_eq!(
        ring.open(&B64.encode(changed), T),
        Err(ContinuationError::NotAuthentic)
    );
}

#[test]
fn rotate_11_debug_and_actual_rotation_event_do_not_disclose_material() {
    const SUCCESSOR: [u8; 32] = [0x3c; 32];
    let ring = ring();
    ring.mint(&payload(T)).unwrap();
    set_hooks(
        &ring,
        KeyringTestHooks {
            successor: Some(Arc::new(|| Ok(SUCCESSOR))),
            ..KeyringTestHooks::default()
        },
    );
    let value = payload(T + CONTINUATION_ROTATION_SECS);
    let (token, events) = capture_events(|| ring.mint(&value).unwrap());
    // A known verifier proves the successor override actually supplied material.
    assert_opens(
        &Keyring::new(&[(2, SUCCESSOR)]).unwrap(),
        &token,
        &value,
        value.issued_at,
    );
    assert_eq!(
        events.len(),
        1,
        "exactly one real rotation event is required"
    );
    assert_eq!(
        serde_json::to_value(&events[0]).unwrap(),
        serde_json::json!({
            "message":"Continuation key rotated","old_kid":1,"new_kid":2,"retained_keys":2
        })
    );
    // Exact field equality also rejects secret data in unexpected fields or
    // alternate encodings. The known old/new material gets explicit checks too.
    let debug = format!("{ring:?}");
    let logs = serde_json::to_string(&events).unwrap();
    for material in [KEY, SUCCESSOR] {
        for representation in [
            format!("{material:?}"),
            B64.encode(material),
            hex::encode(material),
        ] {
            assert!(!debug.contains(&representation));
            assert!(!logs.contains(&representation));
        }
    }
    for sensitive in [
        value.backend_request_state.as_deref().unwrap(),
        value.principal_fingerprint.as_str(),
        value.original_request_digest.as_str(),
        value.hold_key.as_str(),
    ] {
        assert!(!logs.contains(sensitive));
    }
    assert_eq!(B64.decode(&token).unwrap()[0], VERSION);
    let mut changed = B64.decode(token).unwrap();
    changed[1] = 1;
    assert_eq!(
        ring.open(&B64.encode(changed), value.issued_at),
        Err(ContinuationError::NotAuthentic)
    );
}

#[test]
fn rotate_14_successor_rng_failure_leaves_ring_and_quota_unchanged() {
    for retained in [false, true] {
        let ring = ring();
        let original = payload(T);
        let token = ring.mint(&original).unwrap();
        let mut active_payload = original.clone();
        let mut active_token = token.clone();
        let due = if retained {
            active_payload = payload(T + CONTINUATION_ROTATION_SECS);
            active_token = ring.mint(&active_payload).unwrap();
            assert_eq!(
                kid(&active_token),
                2,
                "fault fixture must include a real retired key"
            );
            T + CONTINUATION_ROTATION_SECS + CONTINUATION_LIFETIME_SECS + 1
        } else {
            T + CONTINUATION_ROTATION_SECS
        };
        let before = snapshot(&ring);
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        set_hooks(
            &ring,
            KeyringTestHooks {
                successor: Some(Arc::new(move || {
                    counted.fetch_add(1, Ordering::Relaxed);
                    Err(ContinuationError::Malformed)
                })),
                ..KeyringTestHooks::default()
            },
        );
        let result = ring.mint(&payload(due));
        assert_eq!(
            result,
            Err(ContinuationError::Malformed),
            "ROTATE.14: successor failure must be surfaced"
        );
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(snapshot(&ring), before);
        assert_opens(&ring, &token, &original, T);
        assert_opens(
            &ring,
            &active_token,
            &active_payload,
            active_payload.issued_at,
        );
        if retained {
            assert_eq!(
                ring.open(&token, due),
                Err(ContinuationError::Expired),
                "failed transaction must not prune the retained verification key"
            );
        }
        set_hooks(&ring, KeyringTestHooks::default());
        assert_eq!(
            kid(&ring.mint(&payload(due)).unwrap()),
            if retained { 3 } else { 2 }
        );
    }
}

#[test]
fn rotate_14_prepublication_panic_leaves_live_transaction_untouched() {
    for retained in [false, true] {
        let ring = ring();
        let original = payload(T);
        let token = ring.mint(&original).unwrap();
        let mut active_payload = original.clone();
        let mut active_token = token.clone();
        let due = if retained {
            active_payload = payload(T + CONTINUATION_ROTATION_SECS);
            active_token = ring.mint(&active_payload).unwrap();
            assert_eq!(
                kid(&active_token),
                2,
                "fault fixture must include a real retired key"
            );
            T + CONTINUATION_ROTATION_SECS + CONTINUATION_LIFETIME_SECS + 1
        } else {
            T + CONTINUATION_ROTATION_SECS
        };
        let before = snapshot(&ring);
        let prepared = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&prepared);
        set_hooks(
            &ring,
            KeyringTestHooks {
                successor: Some(Arc::new(move || {
                    marker.store(true, Ordering::SeqCst);
                    Ok([0x48; 32])
                })),
                before_publish: Some(Arc::new(|| panic!("ROTATE.14 injected before publication"))),
                ..KeyringTestHooks::default()
            },
        );
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ring.mint(&payload(due))));
        assert!(
            result.is_err(),
            "ROTATE.14: real pre-publication boundary was not reached"
        );
        assert!(prepared.load(Ordering::SeqCst));
        assert_eq!(snapshot(&ring), before);
        assert_opens(&ring, &token, &original, T);
        assert_opens(
            &ring,
            &active_token,
            &active_payload,
            active_payload.issued_at,
        );
        if retained {
            assert_eq!(
                ring.open(&token, due),
                Err(ContinuationError::Expired),
                "failed transaction must not prune the retained verification key"
            );
        }
        set_hooks(&ring, KeyringTestHooks::default());
        assert_eq!(
            kid(&ring.mint(&payload(due)).unwrap()),
            if retained { 3 } else { 2 }
        );
    }
}

#[test]
fn rotate_15_due_writer_progresses_while_readers_keep_opening() {
    const READERS: usize = 6;
    let ring = Arc::new(ring());
    let original = payload(T);
    let token = ring.mint(&original).unwrap();
    let start = Arc::new(Barrier::new(READERS + 1));
    let stop = Arc::new(AtomicBool::new(false));
    let opens = Arc::new(AtomicUsize::new(0));
    let requested = Arc::new(AtomicBool::new(false));
    let pressure = Arc::new(AtomicUsize::new(0));
    let pressure_gate = Arc::new(Barrier::new(READERS + 1));
    let writer_requested = Arc::clone(&requested);
    let writer_gate = Arc::clone(&pressure_gate);
    set_hooks(
        &ring,
        KeyringTestHooks {
            write_requested: Some(Arc::new(move || {
                writer_requested.store(true, Ordering::SeqCst);
                writer_gate.wait();
            })),
            ..KeyringTestHooks::default()
        },
    );
    let (reader_done, reader_finished) = mpsc::channel();
    let mut readers = Vec::new();
    assert_opens(&ring, &token, &original, T + CONTINUATION_ROTATION_SECS);
    for _ in 0..READERS {
        let ring = Arc::clone(&ring);
        let original = original.clone();
        let token = token.clone();
        let start = Arc::clone(&start);
        let stop = Arc::clone(&stop);
        let opens = Arc::clone(&opens);
        let reader_done = reader_done.clone();
        let requested = Arc::clone(&requested);
        let pressure = Arc::clone(&pressure);
        let pressure_gate = Arc::clone(&pressure_gate);
        readers.push(std::thread::spawn(move || {
            assert_opens(&ring, &token, &original, T + CONTINUATION_ROTATION_SECS);
            opens.fetch_add(1, Ordering::SeqCst);
            start.wait();
            let mut signalled = false;
            while !stop.load(Ordering::SeqCst) {
                assert_opens(&ring, &token, &original, T + CONTINUATION_ROTATION_SECS);
                opens.fetch_add(1, Ordering::SeqCst);
                if !signalled && requested.load(Ordering::SeqCst) {
                    // A real open completes after the writer requested its
                    // transition. Keep every reader running after releasing it.
                    assert_opens(&ring, &token, &original, T + CONTINUATION_ROTATION_SECS);
                    pressure.fetch_add(1, Ordering::SeqCst);
                    signalled = true;
                    pressure_gate.wait();
                }
            }
            let _ = reader_done.send(());
        }));
    }
    drop(reader_done);
    start.wait();
    assert!(opens.load(Ordering::SeqCst) >= READERS);
    let (tx, rx) = mpsc::channel();
    let writer_ring = Arc::clone(&ring);
    let writer = std::thread::spawn(move || {
        let _ = tx.send(writer_ring.mint(&payload(T + CONTINUATION_ROTATION_SECS)));
    });
    // Deadlock watchdog only. The trusted protocol clock never sleeps or advances.
    let completed = rx.recv_timeout(Duration::from_secs(5));
    stop.store(true, Ordering::SeqCst);
    // Assert writer completion before joining any possibly lock-blocked reader.
    let next = completed
        .expect("ROTATE.15: writer failed to progress before readers stopped")
        .unwrap();
    assert_eq!(
        pressure.load(Ordering::SeqCst),
        READERS,
        "every reader completed another real open during the write-request window"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    for _ in 0..READERS {
        reader_finished
            .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            .expect("ROTATE.15: reader did not stop after writer completed");
    }
    for reader in readers {
        reader.join().unwrap();
    }
    writer.join().unwrap();
    assert_eq!(kid(&next), 2);
    assert_opens(&ring, &token, &original, T + CONTINUATION_ROTATION_SECS);
}
