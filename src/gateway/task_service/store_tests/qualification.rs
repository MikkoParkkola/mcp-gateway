// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Qualification rows for already-approved S1 store/admission coupling.
//!
//! Sibling helpers in `admission.rs` are private, so this module keeps small
//! local fixtures consistent with that suite. Record construction uses
//! `PreparedTask::admitted` only.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use serde_json::{Value, json};

use super::super::record::PreparedTask;
use super::super::store::{CommitStage, StoreError, TaskStore};
use super::support::*;
use crate::idempotency::admission::{
    ExecutionAdmission, Mode, RETENTION_SECS, Request, RestoredBinding, TaskAdmission, TaskBinding,
};
use crate::protocol::tasks::{Task, TaskOptions, TaskStatus, TaskTransition};

static OPERATION: LazyLock<Value> =
    LazyLock::new(|| json!({"backend": "orders", "tool": "create"}));
static REPRESENTATION: LazyLock<Value> = LazyLock::new(|| json!({"full": false}));

fn services() -> Arc<ExecutionAdmission> {
    ExecutionAdmission::new(Arc::new(|| 1_000))
}

fn services_clock() -> (Arc<ExecutionAdmission>, Arc<AtomicU64>) {
    let now = Arc::new(AtomicU64::new(1_000));
    let clock = Arc::clone(&now);
    (
        ExecutionAdmission::new(Arc::new(move || clock.load(Ordering::SeqCst))),
        now,
    )
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

fn owned_task(
    outcome: Result<TaskAdmission, crate::idempotency::admission::Refusal>,
) -> crate::idempotency::admission::TaskLease {
    match outcome {
        Ok(TaskAdmission::Owned(lease)) => lease,
        other => panic!("expected an owner, got {other:?}"),
    }
}

fn existing_task(
    outcome: Result<TaskAdmission, crate::idempotency::admission::Refusal>,
) -> (String, TaskBinding) {
    match outcome {
        Ok(TaskAdmission::Existing { task_id, binding }) => (task_id, binding),
        other => panic!("expected the existing task handle, got {other:?}"),
    }
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

async fn commit_admitted(
    store: &TaskStore,
    admission: &Arc<ExecutionAdmission>,
    principal: &str,
    key: &str,
    task: Task,
) -> (String, TaskBinding) {
    let lease = owned_task(admission.admit_task(task_request(principal, key)));
    let binding = lease.binding().clone();
    let id = task.id().to_owned();
    store
        .create(PreparedTask::admitted(
            &task,
            &binding,
            lease.into_publication(),
            "fixture",
        ))
        .await
        .unwrap();
    (id, binding)
}

async fn settled_task(
    store: &TaskStore,
    admission: &Arc<ExecutionAdmission>,
    key: &str,
) -> (String, TaskBinding) {
    let (id, binding) = commit_admitted(store, admission, "oidc:acme:alice", key, task()).await;
    store
        .transition(
            binding.principal_digest(),
            &id,
            1,
            TaskTransition::Complete(json!({"content":[{"type":"text","text":"settled"}]})),
            at(1),
        )
        .await
        .expect("a settlement makes the record terminal, which is what expiry requires");
    (id, binding)
}

#[tokio::test]
async fn task_q_reopened_records_enumerate_import_and_preserve_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let admission = services();
    let store = open(&path).await;

    let alice_one = Task::create_at(
        "private-tool",
        at(0),
        TaskOptions {
            ttl_ms: Some(3_600_000),
            poll_interval_ms: Some(5_000),
        },
    );
    let alice_one_expected = serde_json::to_value(alice_one.snapshot()).unwrap();
    let (alice_one_id, alice_one_binding) =
        commit_admitted(&store, &admission, "oidc:acme:alice", "k-1", alice_one).await;

    let alice_two = task();
    let alice_two_expected = serde_json::to_value(alice_two.snapshot()).unwrap();
    let (alice_two_id, alice_two_binding) =
        commit_admitted(&store, &admission, "oidc:acme:alice", "k-2", alice_two).await;

    let mallory = task();
    let mallory_expected = serde_json::to_value(mallory.snapshot()).unwrap();
    let (mallory_id, mallory_binding) =
        commit_admitted(&store, &admission, "oidc:acme:mallory", "k-1", mallory).await;

    store.close().await.unwrap();
    let reopened = open(&path).await;
    let listed: BTreeMap<_, _> = reopened
        .restored_bindings()
        .into_iter()
        .map(|(binding, id)| (id, binding))
        .collect();
    assert_eq!(listed.len(), 3);
    assert_eq!(listed[&alice_one_id], restored_from(&alice_one_binding));
    assert_eq!(listed[&alice_two_id], restored_from(&alice_two_binding));
    assert_eq!(listed[&mallory_id], restored_from(&mallory_binding));

    let restarted = services();
    for (restored, id) in reopened.restored_bindings() {
        restarted.import_task(&restored, &id).unwrap();
    }
    assert_eq!(restarted.snapshot().entries, 3);

    let (recovered_one, recovered_one_binding) =
        existing_task(restarted.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(recovered_one, alice_one_id);
    assert_eq!(recovered_one_binding, alice_one_binding);

    let (recovered_mallory, recovered_mallory_binding) =
        existing_task(restarted.admit_task(task_request("oidc:acme:mallory", "k-1")));
    assert_eq!(recovered_mallory, mallory_id);
    assert_eq!(recovered_mallory_binding, mallory_binding);
    assert_ne!(
        recovered_mallory_binding.identity(),
        alice_one_binding.identity()
    );

    let alice_one_view = reopened
        .get(alice_one_binding.principal_digest(), &alice_one_id)
        .unwrap();
    assert_eq!(
        serde_json::to_value(alice_one_view.task.snapshot()).unwrap(),
        alice_one_expected
    );
    assert_eq!(
        serde_json::to_value(
            reopened
                .get(alice_two_binding.principal_digest(), &alice_two_id)
                .unwrap()
                .task
                .snapshot()
        )
        .unwrap(),
        alice_two_expected
    );
    assert_eq!(
        serde_json::to_value(
            reopened
                .get(mallory_binding.principal_digest(), &mallory_id)
                .unwrap()
                .task
                .snapshot()
        )
        .unwrap(),
        mallory_expected
    );
    assert_eq!(
        reopened
            .get(mallory_binding.principal_digest(), &alice_one_id)
            .unwrap_err(),
        StoreError::NotFound
    );
    assert_eq!(
        reopened
            .get(alice_one_binding.principal_digest(), &mallory_id)
            .unwrap_err(),
        StoreError::NotFound
    );
    reopened.close().await.unwrap();
}

#[tokio::test]
async fn task_q_expiry_refusals_leave_durable_and_admission_capacity() {
    for kind in [
        "not-terminal",
        "revision",
        "unknown",
        "foreign-admission",
        "closed",
        "poisoned",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let admission = services();
        let store = open(&path).await;

        match kind {
            "not-terminal" => {
                let (id, binding) =
                    commit_admitted(&store, &admission, "oidc:acme:alice", "k-1", task()).await;
                let held = admission.snapshot();
                let before = files(&path);
                assert_eq!(
                    store.expire(&id, 1, &admission).await.unwrap_err(),
                    StoreError::InvalidTransition
                );
                assert_eq!(admission.snapshot(), held);
                assert_eq!(files(&path), before);
                assert_eq!(
                    store
                        .get(binding.principal_digest(), &id)
                        .unwrap()
                        .task
                        .status(),
                    TaskStatus::Working
                );
                store.close().await.unwrap();
            }
            "revision" => {
                let (id, binding) = settled_task(&store, &admission, "k-1").await;
                let held = admission.snapshot();
                let before = files(&path);
                assert_eq!(
                    store.expire(&id, 1, &admission).await.unwrap_err(),
                    StoreError::RevisionConflict
                );
                assert_eq!(admission.snapshot(), held);
                assert_eq!(files(&path), before);
                assert_eq!(
                    store.get(binding.principal_digest(), &id).unwrap().revision,
                    2
                );
                store.close().await.unwrap();
            }
            "unknown" => {
                let (id, binding) = settled_task(&store, &admission, "k-1").await;
                let held = admission.snapshot();
                let before = files(&path);
                assert_eq!(
                    store
                        .expire(super::FOREIGN_NAME, 2, &admission)
                        .await
                        .unwrap_err(),
                    StoreError::NotFound
                );
                assert_eq!(admission.snapshot(), held);
                assert_eq!(files(&path), before);
                assert_eq!(
                    store.get(binding.principal_digest(), &id).unwrap().revision,
                    2
                );
                store.close().await.unwrap();
            }
            "foreign-admission" => {
                let (id, binding) = settled_task(&store, &admission, "k-1").await;
                let held = admission.snapshot();
                let before = files(&path);
                let foreign = services();
                assert_eq!(
                    store.expire(&id, 2, &foreign).await.unwrap_err(),
                    StoreError::NotFound
                );
                assert_eq!(admission.snapshot(), held);
                assert_eq!(foreign.snapshot().entries, 0);
                assert_eq!(files(&path), before);
                assert_eq!(
                    store.get(binding.principal_digest(), &id).unwrap().revision,
                    2
                );
                store.close().await.unwrap();
            }
            "closed" => {
                let (id, _) = settled_task(&store, &admission, "k-1").await;
                let held = admission.snapshot();
                let closed = store.clone();
                store.close().await.unwrap();
                let before = files(&path);
                assert_eq!(
                    closed.expire(&id, 2, &admission).await.unwrap_err(),
                    StoreError::Unavailable
                );
                assert_eq!(admission.snapshot(), held);
                assert_eq!(files(&path), before);
            }
            "poisoned" => {
                let (id, _) = settled_task(&store, &admission, "k-1").await;
                store
                    .set_hook(Some(Arc::new(|stage| {
                        if stage == CommitStage::DirectorySync {
                            return Err(std::io::Error::other("injected poison"));
                        }
                        Ok(())
                    })))
                    .await;
                let lease =
                    owned_task(admission.admit_task(task_request("oidc:acme:alice", "k-2")));
                let binding = lease.binding().clone();
                let second = task();
                assert_eq!(
                    store
                        .create(PreparedTask::admitted(
                            &second,
                            &binding,
                            lease.into_publication(),
                            "fixture",
                        ))
                        .await
                        .unwrap_err(),
                    StoreError::Storage
                );
                assert!(!store.ready());
                let held = admission.snapshot();
                let before = files(&path);
                assert_eq!(
                    store.expire(&id, 2, &admission).await.unwrap_err(),
                    StoreError::Unavailable
                );
                assert_eq!(admission.snapshot(), held);
                assert_eq!(files(&path), before);
                store.close().await.unwrap();
            }
            other => panic!("unrecognised expiry refusal {other}"),
        }
    }
}

#[tokio::test]
async fn task_q_retry_keeps_handle_until_store_expiry_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (admission, now) = services_clock();
    let store = open(&path).await;
    let (id, binding) = settled_task(&store, &admission, "k-1").await;

    let (task_id, recovered) =
        existing_task(admission.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(task_id, id);
    assert_eq!(recovered, binding);

    now.store(1_000 + RETENTION_SECS, Ordering::SeqCst);
    assert_eq!(admission.reclaim_completed(), 0);
    let held = admission.snapshot();
    let (still, still_binding) =
        existing_task(admission.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(still, id);
    assert_eq!(still_binding, binding);
    assert_eq!(admission.snapshot(), held);

    store.expire(&id, 2, &admission).await.unwrap();
    assert_eq!(
        store.get(binding.principal_digest(), &id).unwrap_err(),
        StoreError::NotFound
    );
    let _fresh = owned_task(admission.admit_task(task_request("oidc:acme:alice", "k-1")));
    assert_eq!(admission.snapshot().entries, 1);
    store.close().await.unwrap();
}
