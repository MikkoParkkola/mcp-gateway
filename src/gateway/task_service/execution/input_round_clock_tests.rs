// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `readable_now`'s two stops on a clock before 1970 (MIK-8202): the task's
//! row is gone, and the cancel sender is dropped. Paused time; no wall clock.

use super::{ClockWait, readable_now};
use crate::gateway::task_service::StoreLimits;
use crate::gateway::task_service::TaskStore;
use tokio::sync::watch;

/// A store whose clock reads before 1970, holding no task.
async fn store_before_epoch() -> (TaskStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = TaskStore::open(&dir.path().join("tasks"), StoreLimits::default())
        .await
        .expect("an empty store opens");
    store.set_clock_for_test(chrono::DateTime::from_timestamp(-1, 0));
    (store, dir)
}

/// A wait for a task whose row has left the store stops at its next retry:
/// nothing is left to wait for. Mutant: the gone row read as no bound.
#[tokio::test(start_paused = true)]
async fn a_wait_for_a_row_that_is_gone_stops() {
    let (store, _dir) = store_before_epoch().await;
    let (_tx, mut rx) = watch::channel(false);
    let outcome = readable_now(&store, "task-gone", &mut rx).await;
    assert!(matches!(outcome, ClockWait::Stopped));
    assert!(
        store.refused_reads_for_test() >= 2,
        "it retried once before stopping"
    );
}

/// A wait whose cancel sender is gone stops at once: nothing can cancel it
/// any more. Mutant: a dropped sender read as a retry.
#[tokio::test(start_paused = true)]
async fn a_wait_whose_cancel_sender_is_dropped_stops() {
    let (store, _dir) = store_before_epoch().await;
    let (tx, mut rx) = watch::channel(false);
    drop(tx);
    let outcome = readable_now(&store, "task-gone", &mut rx).await;
    assert!(matches!(outcome, ClockWait::Stopped));
    assert_eq!(
        store.refused_reads_for_test(),
        1,
        "it stopped on its first wait"
    );
}

/// R2b-P2 (MIK-8202.AC.16, AC.2; deferred to the fix by the lead). A resume's
/// clock wait that expires on a 1 ms TTL fails the task `clock_expired`,
/// dated at the record's own `last_updated_at`, through the one non-waiting
/// settle: the task is failed, not stranded `working`, and never dated 1969.
/// Mutant M2i (this Expired site reverted to `settle_cas`, which reads the
/// dark clock and waits a second time) is killed by `attempts == 1`: the
/// fallback commits once, dated; the mutant commits undated first.
#[tokio::test(flavor = "current_thread")]
async fn r2b_p2_an_expired_input_round_wait_fails_the_task_at_last_updated_at() {
    use std::sync::Arc;

    use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};
    use crate::gateway::task_service::execution::TaskExecutor;
    use crate::gateway::task_service::{CreateOutcome, Task, TaskOptions, TaskService, TaskStatus};
    use crate::idempotency::admission::{ExecutionAdmission, Mode, Request};

    const OWNER: &str = "verified-owner";
    let created = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("a valid instant");
    let dir = tempfile::tempdir().expect("tempdir");
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    let service = Arc::new(
        TaskService::open(&dir.path().join("tasks"), StoreLimits::default(), admission)
            .await
            .expect("the store opens"),
    );
    let registry = SubscriptionRegistry::new(
        DEFAULT_MAX_LISTENERS,
        crate::gateway::test_helpers::auth_state(&crate::config::AuthConfig::default()),
    );
    let executor = TaskExecutor::new(Arc::clone(&service), Arc::new(registry), 1);
    let options = TaskOptions {
        ttl_ms: Some(1),
        poll_interval_ms: Some(1_000),
    };
    let task = Task::create_at("echo", created, options);
    let (operation, representation) = (serde_json::json!({"tool": "echo"}), serde_json::json!({}));
    let workers = Arc::new(tokio::sync::Semaphore::new(1));
    let request = Request {
        principal: OWNER,
        key: "r2b-p2",
        operation: &operation,
        representation: &representation,
        mode: Mode::Task,
    };
    let created_row = service
        .create(request, &task, "peer", move || {
            workers.try_acquire_owned().ok()
        })
        .await
        .expect("the store accepts a create");
    let CreateOutcome::Created { task: row, slot } = created_row else {
        panic!("a fresh key creates its task");
    };
    drop(slot);
    let (id, revision) = (row.task.id().to_owned(), row.revision);
    let hook = executor.commit_hook_for_test();
    service
        .store
        .set_clock_for_test(chrono::DateTime::from_timestamp(-1, 0));
    let (_tx, mut rx) = watch::channel(false);

    let read = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        super::readable_or_fail(&executor, (OWNER, &id, revision), &mut rx),
    )
    .await
    .expect("an expired wait settles without waiting again");

    assert!(read.is_none(), "an expired wait reads no time");
    let stored = service.get(OWNER, &id).expect("the owner reads it");
    assert_eq!(stored.task.status(), TaskStatus::Failed, "not stranded");
    let wire = serde_json::to_value(stored.task.wire()).expect("the wire form serializes");
    assert_eq!(wire["error"]["message"], super::clock_expired().message);
    assert_eq!(
        stored.task.last_updated_at(),
        created,
        "its own last_updated_at"
    );
    assert_eq!(hook.attempts(&id), 1, "one dated commit, no second wait");
}
