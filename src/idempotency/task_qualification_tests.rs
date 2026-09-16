// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Qualification rows for already-approved S1 admission semantics.
//!
//! Sibling helpers in `task_admission_tests.rs` are private, so this module
//! keeps small local fixtures consistent with that suite.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use serde_json::{Value, json};

use super::*;

static OPERATION: LazyLock<Value> =
    LazyLock::new(|| json!({"backend": "orders", "tool": "create", "arguments": {"quantity": 1}}));
static REPRESENTATION: LazyLock<Value> = LazyLock::new(|| json!({"full": false}));

fn fixture_clock() -> (Arc<ExecutionAdmission>, Arc<AtomicU64>) {
    let now = Arc::new(AtomicU64::new(1_000));
    let clock = Arc::clone(&now);
    (
        ExecutionAdmission::new(Arc::new(move || clock.load(Ordering::SeqCst))),
        now,
    )
}

fn fixture() -> Arc<ExecutionAdmission> {
    fixture_clock().0
}

fn task_request<'a>(principal: &'a str, key: &'a str) -> Request<'a> {
    Request {
        principal,
        key,
        operation: &OPERATION,
        representation: &REPRESENTATION,
        mode: Mode::Task,
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

fn restored_from(binding: &TaskBinding) -> RestoredBinding {
    RestoredBinding {
        identity: binding.identity().to_owned(),
        principal_digest: binding.principal_digest().to_owned(),
        operation: binding.operation().to_owned(),
        representation: binding.representation().to_owned(),
        metadata_bytes: binding.metadata_bytes(),
    }
}

#[test]
fn task_q_supported_bounds_refuse_without_reserving() {
    let empty = Snapshot::default();
    let oversize = "x".repeat(METADATA_LIMIT);

    let service = fixture();
    assert_eq!(
        service.admit_task(task_request("", "k-1")).unwrap_err(),
        Refusal::InvalidIdentity
    );
    assert_eq!(service.snapshot(), empty);

    let service = fixture();
    assert_eq!(
        service
            .admit_task(task_request("oidc:acme:alice", ""))
            .unwrap_err(),
        Refusal::InvalidIdentity
    );
    assert_eq!(service.snapshot(), empty);

    let service = fixture();
    assert_eq!(
        service
            .admit_task(task_request(&oversize, "k"))
            .unwrap_err(),
        Refusal::MetadataTooLarge
    );
    assert_eq!(service.snapshot(), empty);

    let service = ExecutionAdmission::new(Arc::new(|| u64::MAX));
    assert_eq!(
        service
            .admit_task(task_request("oidc:acme:alice", "k-1"))
            .unwrap_err(),
        Refusal::ExpiryOverflow
    );
    assert_eq!(service.snapshot(), empty);
}

#[test]
fn task_q_slot_limit_refuses_new_work_and_releases_on_drop() {
    let service = fixture();
    let keys: Vec<String> = (0..SLOT_LIMIT).map(|i| format!("k-{i}")).collect();
    let mut held: Vec<TaskLease> = keys
        .iter()
        .map(|key| owned_task(service.admit_task(task_request("oidc:acme:alice", key))))
        .collect();
    assert_eq!(service.snapshot().entries, SLOT_LIMIT);
    let before = service.snapshot();

    assert_eq!(
        service
            .admit_task(task_request("oidc:acme:alice", "overflow"))
            .unwrap_err(),
        Refusal::Capacity
    );
    assert_eq!(service.snapshot(), before);

    held.pop();
    let _lease = owned_task(service.admit_task(task_request("oidc:acme:alice", "overflow")));
    assert_eq!(service.snapshot().entries, SLOT_LIMIT);
}

#[test]
fn task_q_dropping_an_unpublished_lease_releases_the_slot() {
    let service = fixture();
    drop(owned_task(
        service.admit_task(task_request("oidc:acme:alice", "k-1")),
    ));
    assert_eq!(service.snapshot(), Snapshot::default());

    let _live = owned_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(service.snapshot().entries, 1);
}

#[test]
fn task_q_empty_and_duplicate_imports_refuse_without_leaking() {
    let live = fixture();
    let seed = published(&live, "oidc:acme:alice", "seed", "task-seed");
    let extra = published(&live, "oidc:acme:alice", "k-1", "task-abc");

    let service = fixture();
    service
        .import_task(&restored_from(&seed), "task-seed")
        .unwrap();
    let held = service.snapshot();
    assert!(held.metadata_bytes > 0);

    assert_eq!(
        service.import_task(&restored_from(&extra), "").unwrap_err(),
        Refusal::InvalidIdentity
    );
    assert_eq!(service.snapshot(), held);

    assert_eq!(
        service
            .import_task(&restored_from(&seed), "task-other")
            .unwrap_err(),
        Refusal::Mismatch
    );
    assert_eq!(service.snapshot(), held);
}

#[test]
fn task_q_an_expired_sync_result_does_not_block_a_later_task() {
    let (service, now) = fixture_clock();
    let lease = match service.admit(Request {
        mode: Mode::Sync,
        ..task_request("oidc:acme:alice", "k-1")
    }) {
        Ok(Admission::Owned(lease)) => lease,
        other => panic!("expected a sync owner, got {other:?}"),
    };
    assert_eq!(
        lease.complete_secured(&json!({"ok": true})),
        Settlement::Retained
    );
    assert_eq!(service.snapshot().entries, 1);

    now.store(1_000 + RETENTION_SECS, Ordering::SeqCst);
    let _task = owned_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(service.snapshot().entries, 1);
}

#[test]
fn task_q_a_published_task_survives_retention_and_generic_reclaim() {
    let (service, now) = fixture_clock();
    let binding = published(&service, "oidc:acme:alice", "k-1", "task-abc");
    now.store(1_000 + RETENTION_SECS, Ordering::SeqCst);

    assert_eq!(service.reclaim_completed(), 0);
    let before = service.snapshot();
    let (task_id, recovered) =
        existing_task(service.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(task_id, "task-abc");
    assert_eq!(recovered, binding);
    assert_eq!(service.snapshot(), before);
}
