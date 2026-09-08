// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Internal publication ordering; routed owner filtering has separate stream tests.

use std::future::Future;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Waker};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::oneshot;
use tokio::time::timeout;

use super::test_subscriptions;
use crate::gateway::subscription_registry::Listener;
use crate::gateway::task_service::execution::{OwnedAdmissionRequest, TaskWrite, WriteOutcome};
use crate::gateway::task_service::store::{CommitHook, CommitStage};
use crate::gateway::task_service::{
    CreateOutcome, ServiceError, StoreLimits, Task, TaskOptions, TaskService, open_runtime,
};

const BOUND: Duration = Duration::from_secs(5);
const OWNER: &str = "notification-commit-owner";

fn request() -> OwnedAdmissionRequest {
    OwnedAdmissionRequest::new(
        OWNER.to_owned(),
        "notification-commit-key".to_owned(),
        json!({"server": "fixture", "tool": "write", "arguments": {}}),
        json!({"wire": "modern"}),
    )
}

fn task() -> Task {
    Task::create_at(
        "write",
        chrono::Utc::now(),
        TaskOptions {
            ttl_ms: Some(60_000),
            poll_interval_ms: Some(1_000),
        },
    )
}

fn before_directory_sync() -> (oneshot::Receiver<()>, mpsc::Sender<()>, CommitHook) {
    let (entered_tx, entered_rx) = oneshot::channel();
    let entered = Mutex::new(Some(entered_tx));
    let (release_tx, release_rx) = mpsc::channel();
    let release = Mutex::new(release_rx);
    let hook: CommitHook = Arc::new(move |stage| {
        if stage == CommitStage::DirectorySync
            && let Some(entered) = entered.lock().unwrap().take()
        {
            let _ = entered.send(());
            release
                .lock()
                .unwrap()
                .recv_timeout(BOUND)
                .map_err(std::io::Error::other)?;
        }
        Ok(())
    });
    // Dropping release_tx also unblocks the store on any assertion unwind.
    (entered_rx, release_tx, hook)
}

fn assert_no_queued_event(listener: &mut Listener) {
    let mut receive = Box::pin(listener.recv());
    assert!(
        receive
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
}

fn assert_visible(
    service: &TaskService,
    dir: &Path,
    id: &str,
    revision: u64,
    status: &str,
    notification: &Value,
) -> Value {
    assert_eq!(
        notification,
        &json!({"jsonrpc": "2.0", "method": "notifications/tasks",
            "params": {"taskId": id, "status": status}})
    );
    let committed = service
        .get(OWNER, id)
        .expect("state is readable when the event arrives");
    assert_eq!(committed.revision, revision);
    assert!(matches!(
        service.get("another-owner", id),
        Err(ServiceError::NotFound)
    ));
    let disk: Value =
        serde_json::from_slice(&std::fs::read(dir.join(format!("{id}.json"))).unwrap()).unwrap();
    assert_eq!(disk["revision"], revision);
    assert_eq!(
        disk["model"]["task"],
        serde_json::to_value(committed.task.wire()).unwrap()
    );
    assert_eq!(disk["model"]["task"]["status"], status);
    disk
}

#[tokio::test]
async fn create_notifies_after_durable_commit_and_replay_is_silent() {
    timeout(BOUND, async {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("tasks");
        let subscriptions = test_subscriptions();
        let (service, executor) =
            open_runtime(&dir, 1, StoreLimits::default(), Arc::clone(&subscriptions))
                .await
                .unwrap();
        let mut listener = subscriptions.subscribe().unwrap();
        let (entered, release, hook) = before_directory_sync();
        service.store.set_hook(Some(hook)).await;
        let created = task();
        let id = created.id().to_owned();
        let producer = Arc::clone(&executor);
        let commit = tokio::spawn(async move {
            producer
                .commit(TaskWrite::Create {
                    request: &request(),
                    task: &created,
                    backend: "fixture",
                })
                .await
        });
        entered
            .await
            .expect("create reached the actual durability boundary");
        assert_no_queued_event(&mut listener);
        assert!(matches!(
            service.get(OWNER, &id),
            Err(ServiceError::NotFound)
        ));
        release.send(()).unwrap();
        let event = listener.recv().await.unwrap();
        assert_visible(&service, &dir, &id, 1, "working", &event);
        let WriteOutcome::Create(CreateOutcome::Created { slot, .. }) =
            commit.await.unwrap().unwrap()
        else {
            panic!("the first request creates a real admitted record");
        };
        drop(slot);
        let replay = executor
            .commit(TaskWrite::Create {
                request: &request(),
                task: &task(),
                backend: "fixture",
            })
            .await
            .unwrap();
        assert!(matches!(
            replay,
            WriteOutcome::Create(CreateOutcome::Existing(_))
        ));
        assert_no_queued_event(&mut listener);
        service.shutdown().await.unwrap();
    })
    .await
    .expect("the entire create/notification control is bounded");
}

#[tokio::test]
async fn recovery_notifies_after_durable_commit_and_terminal_recheck_is_silent() {
    timeout(BOUND, async {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("tasks");
        let subscriptions = test_subscriptions();
        let (service, executor) =
            open_runtime(&dir, 1, StoreLimits::default(), Arc::clone(&subscriptions))
                .await
                .unwrap();
        let created = task();
        let id = created.id().to_owned();
        let seed = executor
            .commit(TaskWrite::Create {
                request: &request(),
                task: &created,
                backend: "fixture",
            })
            .await
            .unwrap();
        let WriteOutcome::Create(CreateOutcome::Created { slot, .. }) = seed else {
            panic!("real durable seed")
        };
        drop(slot);
        let mut listener = subscriptions.subscribe().unwrap();
        let (entered, release, hook) = before_directory_sync();
        service.store.set_hook(Some(hook)).await;
        let producer = Arc::clone(&executor);
        // The same selector and Recover commit arm invoked by production startup.
        let recovery = tokio::spawn(async move { producer.recover_interrupted().await });
        entered
            .await
            .expect("recovery reached the actual durability boundary");
        assert_no_queued_event(&mut listener);
        assert_eq!(service.get(OWNER, &id).unwrap().revision, 1);
        release.send(()).unwrap();
        let event = listener.recv().await.unwrap();
        let disk = assert_visible(&service, &dir, &id, 2, "completed", &event);
        assert_eq!(
            disk.pointer("/model/task/result/_meta/io.mcp-gateway~1executionOutcome"),
            Some(&json!("not_executed"))
        );
        recovery.await.unwrap().unwrap();
        executor.recover_interrupted().await.unwrap();
        assert_no_queued_event(&mut listener);
        service.shutdown().await.unwrap();
    })
    .await
    .expect("the entire recovery/notification control is bounded");
}
