// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The early exits of a resumed input round (MIK-7324.COV.3): a host that is
//! gone settles the task interrupted, and a late deadline closes the round
//! instead of resuming it. Real store, real executor, one real working task;
//! each exit is paired with the control that does not take it.

use std::sync::Arc;

use serde_json::json;

use super::settle_interrupted;
use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};
use crate::gateway::task_service::execution::TaskExecutor;
use crate::gateway::task_service::{
    CreateOutcome, StoreLimits, Task, TaskOptions, TaskService, TaskStatus,
};
use crate::idempotency::admission::{ExecutionAdmission, Mode, Request};

const OWNER: &str = "verified-owner";
const BACKEND: &str = "peer";

struct Fixture {
    service: Arc<TaskService>,
    executor: Arc<TaskExecutor>,
    id: String,
    revision: u64,
    _dir: tempfile::TempDir,
}

/// A freshly created working row, owned by [`OWNER`].
async fn fixture(key: &str) -> Fixture {
    let dir = tempfile::tempdir().expect("a fixture store root");
    let admission = ExecutionAdmission::new(Arc::new(|| 1_000));
    let service = Arc::new(
        TaskService::open(&dir.path().join("tasks"), StoreLimits::default(), admission)
            .await
            .expect("the fixture store opens"),
    );
    let executor = TaskExecutor::new(
        Arc::clone(&service),
        Arc::new(SubscriptionRegistry::new(
            DEFAULT_MAX_LISTENERS,
            crate::gateway::test_helpers::auth_state(&crate::config::AuthConfig::default()),
        )),
        1,
    );
    let (operation, representation) = (json!({"backend": BACKEND, "tool": "echo"}), json!({}));
    let workers = Arc::new(tokio::sync::Semaphore::new(1));
    let task = Task::create_at(
        "echo",
        chrono::Utc::now(),
        TaskOptions {
            ttl_ms: Some(86_400_000),
            poll_interval_ms: Some(1_000),
        },
    );
    let created = service
        .create(
            Request {
                principal: OWNER,
                key,
                operation: &operation,
                representation: &representation,
                mode: Mode::Task,
            },
            &task,
            BACKEND,
            move || workers.try_acquire_owned().ok(),
        )
        .await
        .expect("the fixture store accepts a create");
    let CreateOutcome::Created { task, slot } = created else {
        panic!("the fixture row must originate in a real committed task");
    };
    drop(slot);
    Fixture {
        service,
        executor,
        id: task.task.id().to_owned(),
        revision: task.revision,
        _dir: dir,
    }
}

fn status(fx: &Fixture) -> TaskStatus {
    fx.service
        .get(OWNER, &fx.id)
        .expect("the owner reads its task")
        .task
        .status()
}

/// A resumed round whose host is gone cannot dispatch: the task settles
/// interrupted rather than staying `working` for a call that will never run.
/// Mutant: the exit forgets to settle, or settles a row it does not own.
#[tokio::test]
async fn a_resume_without_its_host_settles_the_task_interrupted() {
    let fx = fixture("exit-host").await;
    std::assert_eq!(status(&fx), TaskStatus::Working, "control: it is working");

    let flow = settle_interrupted(&fx.executor, (OWNER, &fx.id, fx.revision)).await;

    assert!(flow.is_none(), "nothing is left to run after the settle");
    std::assert_ne!(status(&fx), TaskStatus::Working, "the task was settled");
    let stored = fx.service.get(OWNER, &fx.id).expect("the owner reads it");
    let result = stored
        .task
        .result()
        .expect("the interrupted result is stored")
        .to_string();
    assert!(
        result.contains("gateway_interrupted_before_dispatch"),
        "settled as interrupted before dispatch, not as some other outcome: {result}"
    );
}

/// A deadline that has not been reached lets the resume carry on; one that has
/// closes the round (cancelled) and stops it. Mutant: the late flag is
/// ignored in either direction, or a round without a deadline is closed.
#[tokio::test]
async fn a_resume_past_its_deadline_closes_the_round_and_one_before_it_carries_on() {
    let fx = fixture("exit-late").await;
    let ids = (OWNER, fx.id.as_str(), fx.revision);
    let (_cancel, mut cancel_rx) = tokio::sync::watch::channel(false);

    let on_time = fx
        .executor
        .proceed_unless_late(ids, Some(10), false, &mut cancel_rx)
        .await;
    assert!(on_time.is_some(), "before the deadline the resume proceeds");
    let no_deadline = fx
        .executor
        .proceed_unless_late(ids, None, true, &mut cancel_rx)
        .await;
    assert!(
        no_deadline.is_some(),
        "a round with no deadline is never closed as late"
    );
    std::assert_eq!(status(&fx), TaskStatus::Working, "control: still open");

    let late = fx
        .executor
        .proceed_unless_late(ids, Some(10), true, &mut cancel_rx)
        .await;
    assert!(late.is_none(), "past the deadline the resume stops");
    std::assert_eq!(status(&fx), TaskStatus::Cancelled, "the round was closed");
}
