// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Failing tests for S1 — admission-owned task binding, restart import, expiry.
//!
//! Written BEFORE the runtime they name, from the reviewed test plan
//! (`task-admission-s1-test-plan.md`, GPT SHIP `1520295a`, Grok SHIP `3506a046`).
//! Rows 1-14 and 19-21 live here because they need only admission. The
//! integration rows (15-18c) need the store's private surface and therefore live
//! beside the store's own suite; splitting them is a visibility fact, not a
//! preference.
//!
//! These COMPILE against an additive scaffold whose entry points return approved
//! refusing outcomes, and they fail there: most at the scaffold's refusal before
//! their own claim runs. That distinction is the point — a compile receipt is not
//! a behavioural one, and the rows earn their green only against the runtime.

use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

use super::*;

fn fixture() -> Arc<ExecutionAdmission> {
    let now = Arc::new(AtomicU64::new(1_000));
    ExecutionAdmission::new(Arc::new(move || now.load(Ordering::SeqCst)))
}

/// Owned fixture values. A `Request` borrows its operation and representation,
/// so building them inline would borrow a temporary that dies at the end of the
/// statement (E0515). These live for the whole test binary instead.
static OPERATION: LazyLock<Value> =
    LazyLock::new(|| json!({"backend": "orders", "tool": "create", "arguments": {"quantity": 1}}));
static OTHER_OPERATION: LazyLock<Value> =
    LazyLock::new(|| json!({"backend": "orders", "tool": "create", "arguments": {"quantity": 2}}));
static REPRESENTATION: LazyLock<Value> = LazyLock::new(|| json!({"full": false}));
static OTHER_REPRESENTATION: LazyLock<Value> = LazyLock::new(|| json!({"full": true}));

fn task_request<'a>(principal: &'a str, key: &'a str) -> Request<'a> {
    Request {
        principal,
        key,
        operation: &OPERATION,
        representation: &REPRESENTATION,
        mode: Mode::Task,
    }
}

fn owned(outcome: Result<Admission, Refusal>) -> Lease {
    match outcome {
        Ok(Admission::Owned(lease)) => lease,
        other => panic!("expected one execution owner, got {other:?}"),
    }
}

fn owned_task(outcome: Result<TaskAdmission, Refusal>) -> TaskLease {
    match outcome {
        Ok(TaskAdmission::Owned(lease)) => lease,
        other => panic!("expected one task owner, got {other:?}"),
    }
}

fn existing_task(outcome: Result<TaskAdmission, Refusal>) -> (String, TaskBinding) {
    match outcome {
        Ok(TaskAdmission::Existing { task_id, binding }) => (task_id, binding),
        other => panic!("expected the existing task handle, got {other:?}"),
    }
}

/// Publish one task and hand back the binding admission retained for it.
fn published(
    service: &Arc<ExecutionAdmission>,
    principal: &str,
    key: &str,
    id: &str,
) -> TaskBinding {
    let lease = owned_task(service.admit_task(task_request(principal, key)));
    let binding = lease.binding().clone();
    lease.into_publication().publish(id);
    binding
}

// Row 1 — a fresh key yields an owner whose binding carries the REAL digests.
#[test]
fn task_01_a_fresh_admission_owns_the_task_and_carries_its_binding() {
    let service = fixture();
    let lease = owned_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    let binding = lease.binding();

    // Every digest is recomputed here the way `Request::prepare` computes it, so
    // a stub binding cannot agree with itself. Grok P2: the earlier version left
    // `identity` unasserted, shape-checked the principal and compared
    // `metadata_bytes` against the same service's own snapshot — three oracles
    // that a self-consistent stub satisfies.
    assert_eq!(
        binding.identity(),
        canonical_json_sha256(&json!([
            "mcp-gateway.execution-admission.v1",
            "oidc:acme:alice",
            "k-1"
        ]))
    );
    assert_eq!(
        binding.principal_digest(),
        canonical_json_sha256(&json!([
            "mcp-gateway.execution-admission.principal.v1",
            "oidc:acme:alice"
        ])),
        "the principal is persisted as a digest, never verbatim"
    );
    assert_eq!(binding.operation(), canonical_json_sha256(&OPERATION));
    assert_eq!(
        binding.representation(),
        canonical_json_sha256(&REPRESENTATION)
    );

    // The byte count is compared against an INDEPENDENT reconstruction of the
    // reservation `prepare` makes, not against a snapshot of the same object.
    let fingerprint_width = "0".repeat(64);
    let expected_bytes = crate::hashing::canonical_json(&json!([
        1,
        "oidc:acme:alice",
        "k-1",
        fingerprint_width,
        fingerprint_width,
        "task",
        u64::MAX,
        "completed_unavailable",
        "\0".repeat(36)
    ]))
    .len();
    assert_eq!(binding.metadata_bytes(), expected_bytes);
}

// Row 2 — MIK-7272.TASK.1.8: an identical retry recovers the SAME task.
#[test]
fn task_02_an_identical_retry_recovers_the_same_task_and_binding() {
    let service = fixture();
    let published_binding = published(&service, "oidc:acme:alice", "k-1", "task-abc");

    let (task_id, binding) =
        existing_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(task_id, "task-abc");
    assert_eq!(binding, published_binding);
}

// Row 3 — a retry whose OPERATION changed is refused, against a published entry.
#[test]
fn task_03_a_changed_operation_is_refused_and_changes_nothing() {
    let service = fixture();
    let kept = published(&service, "oidc:acme:alice", "k-1", "task-abc");
    let before = service.snapshot();

    let refusal = service.admit_task(Request {
        operation: &OTHER_OPERATION,
        ..task_request("oidc:acme:alice", "k-1")
    });

    assert_eq!(refusal.unwrap_err(), Refusal::Mismatch);
    assert_eq!(service.snapshot(), before);
    // A counter can be restored by an implementation that overwrote the entry
    // and put the numbers back. Re-admitting the ORIGINAL proves the fingerprints
    // and the task it owns are the ones that were there before the conflict.
    let (task_id, recovered) =
        existing_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(task_id, "task-abc");
    assert_eq!(recovered, kept);
}

// Row 4 — a retry whose REPRESENTATION changed is refused. Separate from row 3:
// an implementation comparing only the operation passes that one and fails this.
#[test]
fn task_04_a_changed_representation_is_refused_and_changes_nothing() {
    let service = fixture();
    let kept = published(&service, "oidc:acme:alice", "k-1", "task-abc");
    let before = service.snapshot();

    let refusal = service.admit_task(Request {
        representation: &OTHER_REPRESENTATION,
        ..task_request("oidc:acme:alice", "k-1")
    });

    assert_eq!(refusal.unwrap_err(), Refusal::Mismatch);
    assert_eq!(service.snapshot(), before);
    let (task_id, recovered) =
        existing_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(task_id, "task-abc");
    assert_eq!(recovered, kept);
}

// Row 5 — distinct retry keys are distinct tasks, even for one principal.
#[test]
fn task_05_a_second_key_is_a_second_task_not_a_recovery() {
    let service = fixture();
    let first = owned_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    let second = owned_task(service.admit_task(task_request("oidc:acme:alice", "k-2")));

    assert_ne!(first.binding().identity(), second.binding().identity());
    assert_eq!(service.snapshot().entries, 2);
}

// Row 6 — MIK-7272.TASK.1.11: another principal's retry is not a recovery.
#[test]
fn task_06_another_principal_never_recovers_this_task() {
    let service = fixture();
    published(&service, "oidc:acme:alice", "k-1", "task-abc");

    let outcome = service.admit_task(task_request("oidc:acme:mallory", "k-1"));

    let lease = owned_task(outcome);
    assert_ne!(lease.binding().principal_digest(), {
        let (_, mine) = existing_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
        mine.principal_digest().to_owned()
    });
}

// Row 7 — a retry BEFORE publication is in flight, not an existing handle.
#[test]
fn task_07_a_retry_before_publication_is_in_flight() {
    let service = fixture();
    let _lease = owned_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    let before = service.snapshot();

    assert!(matches!(
        service.admit_task(task_request("oidc:acme:alice", "k-1")),
        Ok(TaskAdmission::InFlight)
    ));
    assert_eq!(service.snapshot(), before);
}

// Row 8 — Sync-mode input never mints a task lease.
#[test]
fn task_08_sync_mode_input_is_refused_by_the_task_entry_point() {
    let service = fixture();
    let before = service.snapshot();

    let refusal = service.admit_task(Request {
        mode: Mode::Sync,
        ..task_request("oidc:acme:alice", "k-1")
    });

    assert_eq!(refusal.unwrap_err(), Refusal::Mismatch);
    // The WHOLE snapshot, not the entry count: a refusal that reserved metadata
    // bytes and then failed would leave the count at zero and the capacity gone.
    assert_eq!(service.snapshot(), before);
}

// Row 9 — a mode switch on an EXISTING entry refuses, in both directions.
#[test]
fn task_09_a_mode_switch_on_an_existing_entry_refuses_both_ways() {
    let service = fixture();
    published(&service, "oidc:acme:alice", "k-1", "task-abc");
    assert_eq!(
        service
            .admit_task(Request {
                mode: Mode::Sync,
                ..task_request("oidc:acme:alice", "k-1")
            })
            .unwrap_err(),
        Refusal::Mismatch
    );

    let sync = fixture();
    // Owned, asserted: a setup that silently refused would let an unconditional
    // Mismatch below satisfy this row without any Sync entry existing.
    let _live = owned(sync.admit(Request {
        mode: Mode::Sync,
        ..task_request("oidc:acme:bob", "k-9")
    }));
    assert_eq!(
        sync.admit_task(task_request("oidc:acme:bob", "k-9"))
            .unwrap_err(),
        Refusal::Mismatch
    );
}

// Row 10 — the Sync entry point can never be handed a task.
#[test]
fn task_10_the_sync_entry_point_refuses_a_published_task_entry() {
    let service = fixture();
    published(&service, "oidc:acme:alice", "k-1", "task-abc");

    let outcome = service.admit(Request {
        mode: Mode::Sync,
        ..task_request("oidc:acme:alice", "k-1")
    });

    assert_eq!(outcome.unwrap_err(), Refusal::Mismatch);
}

// Row 11 — restart import restores one task before serving.
#[test]
fn task_11_an_imported_binding_is_recovered_by_the_original_key() {
    let live = fixture();
    let binding = published(&live, "oidc:acme:alice", "k-1", "task-abc");

    let restarted = fixture();
    restarted
        .import_task(&restored_from(&binding), "task-abc")
        .expect("a well-formed persisted binding imports");

    let (task_id, recovered) =
        existing_task(restarted.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(task_id, "task-abc");
    assert_eq!(recovered, binding);
}

// Row 12 — import ADDS bytes, and release gives them back one entry at a time.
#[test]
fn task_12_import_adds_metadata_bytes_and_release_returns_them() {
    let live = fixture();
    let first = published(&live, "oidc:acme:alice", "short", "task-1");
    let second = published(
        &live,
        "oidc:acme:alice",
        "a-much-longer-retry-key-value",
        "task-2",
    );
    assert_ne!(first.metadata_bytes(), second.metadata_bytes());

    let restarted = fixture();
    restarted
        .import_task(&restored_from(&first), "task-1")
        .unwrap();
    restarted
        .import_task(&restored_from(&second), "task-2")
        .unwrap();
    assert_eq!(
        restarted.snapshot().metadata_bytes,
        first.metadata_bytes() + second.metadata_bytes(),
        "a store that ASSIGNS instead of adding passes a one-record fixture and fails here"
    );

    restarted.expiry_guard(first.identity()).release();
    assert_eq!(restarted.snapshot().metadata_bytes, second.metadata_bytes());
    restarted.expiry_guard(second.identity()).release();
    assert_eq!(restarted.snapshot().metadata_bytes, 0);
}

// Row 13 — every persisted digest is validated, not just the first.
#[test]
fn task_13_every_persisted_digest_field_is_validated_independently() {
    let live = fixture();
    let binding = published(&live, "oidc:acme:alice", "k-1", "task-abc");
    let good = restored_from(&binding);
    // A SEED import gives the refusals something to leak into. Against an empty
    // service every snapshot is zero whatever the refusal did with its bytes,
    // which is why the earlier version of this row could not see a leak.
    let seed = restored_from(&published(&live, "oidc:acme:alice", "seed", "task-seed"));

    let shapes = [
        ("too short", "a".repeat(63)),
        ("too long", "a".repeat(65)),
        ("non hex", "z".repeat(64)),
        ("uppercase", "A".repeat(64)),
    ];
    for (label, bad) in &shapes {
        for field in ["identity", "principal", "operation", "representation"] {
            let service = fixture();
            service.import_task(&seed, "task-seed").unwrap();
            let held = service.snapshot();
            assert!(held.metadata_bytes > 0);
            let mut restored = good.clone();
            match field {
                "identity" => restored.identity = bad.clone(),
                "principal" => restored.principal_digest = bad.clone(),
                "operation" => restored.operation = bad.clone(),
                "representation" => restored.representation = bad.clone(),
                // Exhaustive on purpose: a mistyped name in the list above must
                // fail here rather than corrupt the wrong digest and still
                // expect the same refusal.
                other => panic!("unrecognised persisted field {other}"),
            }
            assert_eq!(
                service.import_task(&restored, "task-abc").unwrap_err(),
                Refusal::InvalidIdentity,
                "{field} {label} must be refused"
            );
            assert_eq!(
                service.snapshot(),
                held,
                "{field} {label} moved entries or leaked metadata bytes"
            );
        }
    }
}

// Row 14 — persisted metadata_bytes is validated at both ends of its range.
#[test]
fn task_14_persisted_metadata_bytes_is_bounded_at_both_ends() {
    let live = fixture();
    let binding = published(&live, "oidc:acme:alice", "k-1", "task-abc");
    let good = restored_from(&binding);

    let seed = restored_from(&published(&live, "oidc:acme:alice", "seed", "task-seed"));
    for bad in [0, METADATA_LIMIT + 1] {
        let service = fixture();
        service.import_task(&seed, "task-seed").unwrap();
        let held = service.snapshot();
        let mut restored = good.clone();
        restored.metadata_bytes = bad;
        assert_eq!(
            service.import_task(&restored, "task-abc").unwrap_err(),
            Refusal::MetadataTooLarge
        );
        // Against the SEEDED state, so a refusal that reserved bytes before
        // failing shows up instead of hiding behind an empty service.
        assert_eq!(service.snapshot(), held);
    }

    // Exactly at the limit is legal, which is what stops the fix from being
    // "refuse at the limit".
    let service = fixture();
    let mut restored = good;
    restored.metadata_bytes = METADATA_LIMIT;
    service
        .import_task(&restored, "task-abc")
        .expect("exactly the metadata limit is within an inclusive maximum");
    assert_eq!(service.snapshot().metadata_bytes, METADATA_LIMIT);
    assert_eq!(service.snapshot().entries, 1);
}

// Row 19 — the expiry guard covers ONLY a published task entry.
#[test]
fn task_19_the_expiry_guard_never_matches_a_sync_entry() {
    let service = fixture();
    let active = owned(service.admit(Request {
        mode: Mode::Sync,
        ..task_request("oidc:acme:bob", "sync-active")
    }));
    let identity = active.identity.clone();
    let before = service.snapshot();

    let guard = service.expiry_guard(&identity);
    assert!(guard.published_task().is_none());
    guard.release();

    assert_eq!(
        service.snapshot(),
        before,
        "a Sync slot must survive an expiry guard"
    );
}

// Row 20 — generic reclaim never touches a published task entry.
#[test]
fn task_20_generic_reclaim_leaves_a_published_task_alone() {
    let service = fixture();
    let binding = published(&service, "oidc:acme:alice", "k-1", "task-abc");

    assert_eq!(service.reclaim_completed(), 0);
    let (task_id, _) = existing_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(task_id, "task-abc");
    assert_eq!(service.snapshot().metadata_bytes, binding.metadata_bytes());
}

// Row 21 — the Sync path's observable behaviour is unchanged by this slice.
#[test]
fn task_21_the_sync_path_is_behaviourally_untouched() {
    let service = fixture();
    let lease = owned(service.admit(Request {
        mode: Mode::Sync,
        ..task_request("oidc:acme:bob", "sync-1")
    }));
    let snapshot = service.snapshot();

    drop(lease);
    assert_eq!(service.snapshot().entries, 0);
    assert_eq!(snapshot.entries, 1);
    assert!(matches!(
        service.admit(Request {
            mode: Mode::Sync,
            ..task_request("oidc:acme:bob", "sync-1")
        }),
        Ok(Admission::Owned(_))
    ));
}

/// The persisted shape a durable record would hand back at startup, built here
/// from a live binding so the test states what the record must carry.
fn restored_from(binding: &TaskBinding) -> RestoredBinding {
    RestoredBinding {
        identity: binding.identity().to_owned(),
        principal_digest: binding.principal_digest().to_owned(),
        operation: binding.operation().to_owned(),
        representation: binding.representation().to_owned(),
        metadata_bytes: binding.metadata_bytes(),
    }
}
