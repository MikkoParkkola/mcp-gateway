// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The two writers that outlive a test body keep the store's folder through
//! their own handle: a task worker still running, and an expiry pass that has
//! upgraded the executor (as the stdio expiry sweep does). Each row drops the
//! test's own share first, lets the writer write, and expects the folder to
//! go only with the writer's last handle.

use std::sync::Arc;

use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};
use crate::gateway::task_service::record::PreparedTask;
use crate::gateway::task_service::{StoreLimits, Task, TaskOptions, open_runtime};

const OWNER: &str = "keep-dir-owner";

fn subscriptions() -> Arc<SubscriptionRegistry> {
    Arc::new(SubscriptionRegistry::new(
        DEFAULT_MAX_LISTENERS,
        crate::gateway::test_helpers::auth_state(
            &crate::config::AuthConfig::default(),
            crate::gateway::record_principal::TEST_RECORD_KEY,
        ),
    ))
}

/// A task created in 2026-09 with a one-day retention: long expired by now.
fn expired_task() -> Task {
    Task::create_at(
        "private-tool",
        chrono::DateTime::parse_from_rfc3339("2026-09-07T00:00:00Z")
            .expect("a fixed time")
            .with_timezone(&chrono::Utc),
        TaskOptions {
            ttl_ms: Some(86_400_000),
            poll_interval_ms: Some(1_000),
        },
    )
}

#[tokio::test]
async fn a_worker_writing_after_the_test_body_keeps_the_folder() {
    let root = Arc::new(tempfile::tempdir().expect("store root"));
    let root_path = root.path().to_owned();
    let (service, executor) = open_runtime(
        &root_path.join("tasks"),
        1,
        StoreLimits::default(),
        subscriptions(),
    )
    .await
    .expect("the store opens");
    service.keep_test_dir(Arc::clone(&root));
    let (go, written) = (
        Arc::new(tokio::sync::Notify::new()),
        Arc::new(tokio::sync::Notify::new()),
    );
    let task = expired_task();
    let record = root_path.join("tasks").join(format!("{}.json", task.id()));
    let worker_service = Arc::clone(&service);
    let (wait, done) = (Arc::clone(&go), Arc::clone(&written));
    executor
        .spawn_worker(async move {
            wait.notified().await;
            worker_service
                .store
                .create(PreparedTask::for_test(&task, OWNER, 1))
                .await
                .expect("the worker's write lands in the still-owned folder");
            done.notify_one();
        })
        .await
        .expect("the worker starts");
    tokio::task::yield_now().await;
    // The test body ends: its own share and its service handle go first.
    drop(root);
    drop(service);
    go.notify_one();
    crate::test_pause::within("the worker's write", written.notified()).await;
    assert!(record.is_file(), "the worker's record is in place");

    drop(executor);
    let gone_by = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while root_path.exists() && tokio::time::Instant::now() < gone_by {
        tokio::task::yield_now().await;
    }
    assert!(
        !root_path.exists(),
        "the folder outlived the worker's last handle"
    );
}

#[tokio::test]
async fn an_expiry_pass_holding_the_executor_keeps_the_folder() {
    let root = Arc::new(tempfile::tempdir().expect("store root"));
    let root_path = root.path().to_owned();
    let (service, executor) = open_runtime(
        &root_path.join("tasks"),
        1,
        StoreLimits::default(),
        subscriptions(),
    )
    .await
    .expect("the store opens");
    service.keep_test_dir(Arc::clone(&root));
    let task = expired_task();
    service
        .store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .expect("an expired row to sweep");
    let record = root_path.join("tasks").join(format!("{}.json", task.id()));
    assert!(record.is_file(), "premise: the row is stored");
    // The sweep upgrades its weak executor for each pass; this handle is that
    // upgrade. The test body ends: its own share and its service go first.
    let pass = Arc::clone(&executor);
    drop(root);
    drop(service);
    drop(executor);
    pass.expiry_pass_for_test()
        .await
        .expect("the pass deletes the expired row in the still-owned folder");
    assert!(!record.exists(), "the pass deleted the expired row");

    drop(pass);
    assert!(
        !root_path.exists(),
        "the folder outlived the pass's last handle"
    );
}
