// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A task worker still running when its test body ends keeps the store's
//! folder through its own handle: the row drops the test's own share first,
//! lets the worker write, and expects the folder to go only with the worker's
//! last handle. The expiry pass's row lives with the expiry tests, whose seed
//! commits a row the pass may delete (`runtime_tests/expiry/keep_dir.rs`).

use std::sync::Arc;

use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};
use crate::gateway::task_service::record::PreparedTask;
use crate::gateway::task_service::{StoreLimits, Task, TaskOptions, TaskTransition, open_runtime};

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

/// A task completed in 2026-09 with a one-day retention: finished, and long
/// expired by now, so an expiry pass deletes it.
fn expired_task() -> Task {
    let created = chrono::DateTime::parse_from_rfc3339("2026-09-07T00:00:00Z")
        .expect("a fixed time")
        .with_timezone(&chrono::Utc);
    let mut task = Task::create_at(
        "private-tool",
        created,
        TaskOptions {
            ttl_ms: Some(86_400_000),
            poll_interval_ms: Some(1_000),
        },
    );
    task.transition(
        TaskTransition::Complete(serde_json::json!({})),
        created + crate::duration_bound::delta!(seconds, 1),
    )
    .expect("a working task completes");
    task
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
    crate::test_wait::wait_until(crate::test_wait::HANG_BOUND, || async {
        if root_path.exists() {
            std::ops::ControlFlow::Continue("the folder is still there".to_owned())
        } else {
            std::ops::ControlFlow::Break(())
        }
    })
    .await
    .expect("the folder goes with the worker's last handle");
}
