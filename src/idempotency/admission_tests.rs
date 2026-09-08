// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Core falsifiers for SUB4.SLOTS.1 / BYTES.1 / MODE.1 / REPR.1 / SPOOF.1.
//! These tests do not claim transport activation or durable Task ownership.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

use serde_json::{Value, json};

use super::*;

const REQUIRED_RETENTION_SECS: u64 = 86_400;

fn fixture() -> (Arc<ExecutionAdmission>, Arc<AtomicU64>) {
    let now = Arc::new(AtomicU64::new(1_000));
    let clock = Arc::clone(&now);
    let service = ExecutionAdmission::new(Arc::new(move || clock.load(Ordering::SeqCst)));
    (service, now)
}

fn admit(
    service: &Arc<ExecutionAdmission>,
    principal: &str,
    key: &str,
) -> Result<Admission, Refusal> {
    admit_mode(service, principal, key, Mode::Sync)
}

fn admit_mode(
    service: &Arc<ExecutionAdmission>,
    principal: &str,
    key: &str,
    mode: Mode,
) -> Result<Admission, Refusal> {
    service.admit(Request {
        principal,
        key,
        operation: &json!({"backend": "orders", "tool": "create", "arguments": {"quantity": 1}}),
        representation: &json!({"full": false}),
        mode,
    })
}

fn owned(outcome: Result<Admission, Refusal>) -> Lease {
    match outcome {
        Ok(Admission::Owned(lease)) => lease,
        other => panic!("expected one execution owner, got {other:?}"),
    }
}

fn replay(outcome: Result<Admission, Refusal>) -> Arc<[u8]> {
    match outcome {
        Ok(Admission::Replay(bytes)) => bytes,
        other => panic!("expected retained secured bytes, got {other:?}"),
    }
}

#[test]
fn sub4_core_one_owner_then_canonical_secured_replay() {
    let (service, _) = fixture();
    let mut owner = owned(admit(&service, "owner", "key"));
    assert!(matches!(
        admit(&service, "owner", "key"),
        Ok(Admission::InFlight)
    ));
    let other_key = owned(admit(&service, "owner", "other-key"));
    let other_owner = owned(admit(&service, "another-owner", "key"));
    owner.mark_dispatched();
    assert_eq!(
        owner.complete_secured(&json!({"z": 2, "a": [true, null]})),
        Settlement::Retained
    );
    assert_eq!(
        replay(admit(&service, "owner", "key")).as_ref(),
        br#"{"a":[true,null],"z":2}"#
    );
    assert_eq!(service.snapshot().entries, 3);
    drop((other_key, other_owner));
}

#[test]
fn sub4_core_operation_representation_and_mode_mismatch_refuse_before_replay() {
    let (service, _) = fixture();
    let operation = json!({"backend": "orders", "arguments": {"x": 1}});
    let representation = json!({"full": false});
    for (initial_mode, completed) in [(Mode::Sync, false), (Mode::Sync, true), (Mode::Task, false)]
    {
        let key = format!("key-{initial_mode:?}-{completed}");
        let other_mode = if initial_mode == Mode::Sync {
            Mode::Task
        } else {
            Mode::Sync
        };
        let mut owner = Some(owned(service.admit(Request {
            principal: "owner",
            key: &key,
            operation: &operation,
            representation: &representation,
            mode: initial_mode,
        })));
        if completed {
            owner
                .take()
                .unwrap()
                .complete_secured(&json!({"private": "owner result"}));
        }
        for (op, repr, mode) in [
            (
                json!({"backend": "orders", "arguments": {"x": 2}}),
                representation.clone(),
                initial_mode,
            ),
            (operation.clone(), json!({"full": true}), initial_mode),
            (operation.clone(), representation.clone(), other_mode),
        ] {
            assert!(matches!(
                service.admit(Request {
                    principal: "owner",
                    key: &key,
                    operation: &op,
                    representation: &repr,
                    mode,
                }),
                Err(Refusal::Mismatch)
            ));
        }
        drop(owner);
    }
}

#[test]
fn sub4_core_same_key_actual_thread_race_has_one_owner() {
    let (service, _) = fixture();
    let gate = Arc::new(Barrier::new(32));
    let handles: Vec<_> = (0..32)
        .map(|_| {
            let service = Arc::clone(&service);
            let gate = Arc::clone(&gate);
            thread::spawn(move || {
                gate.wait();
                // Returning ownership keeps the winning lease alive through every admission.
                admit(&service, "owner", "shared-key")
            })
        })
        .collect();
    let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|x| matches!(x, Ok(Admission::Owned(_))))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|x| matches!(x, Ok(Admission::InFlight)))
            .count(),
        31
    );
    assert_eq!(service.snapshot().entries, 1);
}

#[test]
fn sub4_core_last_default_slot_race_is_strict_and_existing_key_still_serves() {
    let (service, _) = fixture();
    let held: Vec<_> = (0..SLOT_LIMIT - 1)
        .map(|i| owned(admit(&service, "owner", &format!("held-{i}"))))
        .collect();
    let gate = Arc::new(Barrier::new(16));
    let handles: Vec<_> = (0..16)
        .map(|i| {
            let service = Arc::clone(&service);
            let gate = Arc::clone(&gate);
            thread::spawn(move || {
                gate.wait();
                admit_mode(
                    &service,
                    "owner",
                    &format!("racing-{i}"),
                    if i % 2 == 0 { Mode::Sync } else { Mode::Task },
                )
            })
        })
        .collect();
    let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|x| matches!(x, Ok(Admission::Owned(_))))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|x| matches!(x, Err(Refusal::Capacity)))
            .count(),
        15
    );
    assert_eq!(service.snapshot().entries, 10_000);
    assert!(matches!(
        admit(&service, "owner", "held-0"),
        Ok(Admission::InFlight)
    ));
    assert!(service.snapshot().metadata_bytes <= SLOT_LIMIT * METADATA_LIMIT);
    drop((held, outcomes));
    assert_eq!(service.snapshot(), Snapshot::default());
}

#[test]
fn sub4_core_live_owner_never_expires_and_predispatch_drop_releases() {
    let (service, now) = fixture();
    let owner = owned(admit(&service, "owner", "key"));
    for elapsed in [
        301,
        REQUIRED_RETENTION_SECS + 1,
        REQUIRED_RETENTION_SECS * 10,
    ] {
        now.store(1_000 + elapsed, Ordering::SeqCst);
        assert_eq!(service.reclaim_completed(), 0);
        assert!(matches!(
            admit(&service, "owner", "key"),
            Ok(Admission::InFlight)
        ));
    }
    drop(owner);
    assert_eq!(service.snapshot(), Snapshot::default());
    let _new_owner = owned(admit(&service, "owner", "key"));
}

#[test]
fn sub4_core_dispatched_owner_stays_live_then_drop_retains_uncertainty() {
    let (service, now) = fixture();
    let mut owner = owned(admit(&service, "owner", "key"));
    owner.mark_dispatched();
    for elapsed in [
        301,
        REQUIRED_RETENTION_SECS + 1,
        REQUIRED_RETENTION_SECS * 10,
    ] {
        now.store(1_000 + elapsed, Ordering::SeqCst);
        assert_eq!(service.reclaim_completed(), 0);
        assert!(matches!(
            admit(&service, "owner", "key"),
            Ok(Admission::InFlight)
        ));
    }
    drop(owner);
    assert!(matches!(
        admit(&service, "owner", "key"),
        Ok(Admission::Unavailable)
    ));
    assert_eq!(service.reclaim_completed(), 0);
    assert_eq!(service.snapshot().entries, 1);
}

#[test]
fn sub4_core_postdispatch_drop_keeps_unavailable_until_exact_expiry() {
    assert_eq!(RETENTION_SECS, REQUIRED_RETENTION_SECS);
    let (service, now) = fixture();
    let mut owner = owned(admit(&service, "owner", "key"));
    owner.mark_dispatched();
    drop(owner);
    assert!(matches!(
        admit(&service, "owner", "key"),
        Ok(Admission::Unavailable)
    ));
    now.store(1_000 + REQUIRED_RETENTION_SECS - 1, Ordering::SeqCst);
    assert_eq!(service.reclaim_completed(), 0);
    now.fetch_add(1, Ordering::SeqCst);
    assert_eq!(service.reclaim_completed(), 1);
    assert_eq!(service.snapshot(), Snapshot::default());
    let _new_owner = owned(admit(&service, "owner", "key"));
}

#[test]
fn sub4_core_task_mode_reserves_same_identity_and_abort_releases() {
    let (service, _) = fixture();
    let task = owned(service.admit(Request {
        principal: "owner",
        key: "key",
        operation: &json!({}),
        representation: &json!({}),
        mode: Mode::Task,
    }));
    assert_eq!(service.snapshot().entries, 1);
    assert!(service.snapshot().metadata_bytes > 0);
    assert!(service.snapshot().metadata_bytes <= 4_096);
    assert!(matches!(
        service.admit(Request {
            principal: "owner",
            key: "key",
            operation: &json!({}),
            representation: &json!({}),
            mode: Mode::Task,
        }),
        Ok(Admission::InFlight)
    ));
    assert!(matches!(
        service.admit(Request {
            principal: "owner",
            key: "key",
            operation: &json!({}),
            representation: &json!({}),
            mode: Mode::Sync,
        }),
        Err(Refusal::Mismatch)
    ));
    drop(task);
    assert_eq!(service.snapshot(), Snapshot::default());
    let _sync = owned(admit(&service, "owner", "key"));
}

#[test]
fn sub4_core_ambiguous_concatenation_pairs_are_independent() {
    let (service, _) = fixture();
    // Real legacy construction: key + empty projection suffix + "|idp:" + binding
    // (support::idempotency_key_for / invoke's identity_suffix). Key comes FIRST.
    let (first_principal, first_key) = ("b|idp:c", "a");
    let (second_principal, second_key) = ("c", "a|idp:b");
    assert_eq!(
        format!("{first_key}|idp:{first_principal}"),
        format!("{second_key}|idp:{second_principal}")
    );
    let first = owned(admit(&service, first_principal, first_key));
    let second = owned(admit(&service, second_principal, second_key));
    first.complete_secured(&json!("first"));
    second.complete_secured(&json!("second"));
    assert_eq!(
        replay(admit(&service, first_principal, first_key)).as_ref(),
        br#""first""#
    );
    assert_eq!(
        replay(admit(&service, second_principal, second_key)).as_ref(),
        br#""second""#
    );
}

#[test]
fn sub4_core_exact_keys_preserve_whitespace_and_unicode_scalar_sequences() {
    let (service, _) = fixture();
    let keys = ["key", " key", "key ", "é", "e\u{301}"];
    for (index, key) in keys.iter().enumerate() {
        assert_eq!(
            owned(admit(&service, "owner", key)).complete_secured(&json!(index)),
            Settlement::Retained
        );
    }
    for (index, key) in keys.iter().enumerate() {
        assert_eq!(
            serde_json::from_slice::<Value>(&replay(admit(&service, "owner", key))).unwrap(),
            json!(index)
        );
    }
    assert_eq!(service.snapshot().entries, keys.len());
}

#[test]
fn sub4_core_exact_escaped_metadata_bound_and_one_over() {
    let (service, _) = fixture();
    // Independent accounting oracle: max-width expiry and most expensive permitted
    // 36-byte task ID (NUL requires six JSON bytes), including every JSON delimiter.
    let prefix = "quote\"backslash\\unicode-ä-🦀";
    let encode = |key: &str| {
        serde_json::to_vec(&json!([
            1,
            "owner",
            key,
            "0".repeat(64),
            "0".repeat(64),
            "sync",
            u64::MAX,
            "completed_unavailable",
            "\0".repeat(36)
        ]))
        .unwrap()
        .len()
    };
    let exact = format!("{prefix}{}", "x".repeat(4_096 - encode(prefix)));
    assert_eq!(encode(&exact), 4_096);
    assert_eq!(encode(&format!("{exact}x")), 4_097);
    let owner = owned(admit(&service, "owner", &exact));
    assert_eq!(service.snapshot().metadata_bytes, 4_096);
    assert!(matches!(
        admit(&service, "owner", &format!("{exact}x")),
        Err(Refusal::MetadataTooLarge)
    ));
    assert_eq!(service.snapshot().entries, 1);
    drop(owner);
    assert_eq!(service.snapshot(), Snapshot::default());
}

#[test]
fn sub4_core_exact_result_limit_and_one_over_preserve_guard() {
    let (service, _) = fixture();
    let exact = Value::String("x".repeat(512 * 1_024 - 2));
    assert_eq!(serde_json::to_vec(&exact).unwrap().len(), 512 * 1_024);
    assert_eq!(
        owned(admit(&service, "owner", "exact")).complete_secured(&exact),
        Settlement::Retained
    );
    let over = Value::String("x".repeat(512 * 1_024 - 1));
    assert_eq!(
        owned(admit(&service, "owner", "over")).complete_secured(&over),
        Settlement::Unavailable
    );
    assert!(matches!(
        admit(&service, "owner", "over"),
        Ok(Admission::Unavailable)
    ));
    assert_eq!(replay(admit(&service, "owner", "exact")).len(), 512 * 1_024);
    assert_eq!(service.snapshot().result_bytes, 512 * 1_024);
    assert_eq!(service.snapshot().entries, 2);
}

#[test]
fn sub4_core_default_aggregate_budget_race_and_expiry_release_exact_bytes() {
    let (service, now) = fixture();
    let result = Arc::new(Value::String("x".repeat(512 * 1_024 - 2)));
    for i in 0..255 {
        assert_eq!(
            owned(admit(&service, "owner", &format!("held-{i}"))).complete_secured(&result),
            Settlement::Retained
        );
    }
    let owners: Vec<_> = (0..8)
        .map(|i| owned(admit(&service, "owner", &format!("race-{i}"))))
        .collect();
    let gate = Arc::new(Barrier::new(8));
    let handles: Vec<_> = owners
        .into_iter()
        .map(|owner| {
            let gate = Arc::clone(&gate);
            let result = Arc::clone(&result);
            thread::spawn(move || {
                gate.wait();
                owner.complete_secured(&result)
            })
        })
        .collect();
    let outcomes: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|x| **x == Settlement::Retained)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|x| **x == Settlement::Unavailable)
            .count(),
        7
    );
    assert_eq!(service.snapshot().result_bytes, 128 * 1_024 * 1_024);
    assert_eq!(
        replay(admit(&service, "owner", "held-0")).len(),
        512 * 1_024
    );
    assert_eq!(
        owned(admit(&service, "owner", "over-budget")).complete_secured(&json!(0)),
        Settlement::Unavailable
    );
    now.store(1_000 + REQUIRED_RETENTION_SECS, Ordering::SeqCst);
    assert_eq!(service.reclaim_completed(), 264);
    assert_eq!(service.snapshot(), Snapshot::default());
    assert_eq!(
        owned(admit(&service, "owner", "held-0")).complete_secured(&json!(0)),
        Settlement::Retained
    );
}

#[test]
fn sub4_core_invalid_identity_and_checked_expiry_fail_without_reservation() {
    let (service, now) = fixture();
    assert!(matches!(
        admit(&service, "", "key"),
        Err(Refusal::InvalidIdentity)
    ));
    assert!(matches!(
        admit(&service, "owner", ""),
        Err(Refusal::InvalidIdentity)
    ));
    assert_eq!(service.snapshot(), Snapshot::default());
    now.store(u64::MAX - REQUIRED_RETENTION_SECS + 1, Ordering::SeqCst);
    assert!(matches!(
        admit(&service, "owner", "key"),
        Err(Refusal::ExpiryOverflow)
    ));
    assert_eq!(service.snapshot(), Snapshot::default());
    now.store(u64::MAX - REQUIRED_RETENTION_SECS, Ordering::SeqCst);
    let _owner = owned(admit(&service, "owner", "key"));
}

#[test]
fn sub4_core_clock_overflow_after_dispatch_never_readmits_uncertain_effect() {
    let (service, now) = fixture();
    let mut owner = owned(admit(&service, "owner", "key"));
    owner.mark_dispatched();
    now.store(u64::MAX, Ordering::SeqCst);
    drop(owner);
    assert_eq!(service.reclaim_completed(), 0);
    assert!(matches!(
        admit(&service, "owner", "key"),
        Ok(Admission::Unavailable)
    ));
    assert_eq!(service.snapshot().entries, 1);
}
