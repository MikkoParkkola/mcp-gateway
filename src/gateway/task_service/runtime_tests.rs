// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Startup contract of `open_runtime`: the store's own secure creator owns the
//! directory.
//!
//! Creation is not a convenience the entry point may perform ahead of the store.
//! A directory made with default permissions is a directory the store then has
//! to refuse, so an absent path must be created by the one creator that makes it
//! private, and an existing directory that is already readable by others must be
//! refused as found rather than repaired.

use std::sync::Arc;

use super::{ServiceError, StoreLimits, open_runtime};

/// Startup recovery of records a previous process left mid-flight.
mod recovery;
use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};

fn test_subscriptions() -> Arc<SubscriptionRegistry> {
    Arc::new(SubscriptionRegistry::new(DEFAULT_MAX_LISTENERS))
}

#[tokio::test]
async fn open_runtime_creates_an_absent_store_directory_privately_and_reopens_it() {
    let root = tempfile::tempdir().expect("a fixture root");
    let store_dir = root.path().join("nested").join("tasks");
    let subscriptions = test_subscriptions();
    let (service, _executor) = open_runtime(
        &store_dir,
        1,
        StoreLimits::default(),
        Arc::clone(&subscriptions),
    )
    .await
    .expect("an absent store path is created by the store's own creator");
    assert!(store_dir.is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&store_dir).unwrap().permissions().mode() & 0o7777,
            0o700,
            "the created store directory is private to its owner"
        );
    }
    // `close` consumes the service and the executor still holds an `Arc`, so
    // custody is released through the service's non-consuming form of it.
    service.shutdown().await.expect("custody is released");

    // The directory the first open created is one a second open accepts: the
    // reuse path the entry point must not disturb.
    let (reopened, _reopened_executor) =
        open_runtime(&store_dir, 1, StoreLimits::default(), subscriptions)
            .await
            .expect("the released private directory opens again");
    reopened.shutdown().await.expect("custody is released");
}

#[cfg(unix)]
#[tokio::test]
async fn open_runtime_refuses_an_existing_group_readable_directory_unchanged() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().expect("a fixture root");
    let store_dir = root.path().join("tasks");
    fs::create_dir(&store_dir).unwrap();
    fs::write(store_dir.join("witness"), b"untouched").unwrap();
    fs::set_permissions(&store_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let refused = open_runtime(&store_dir, 1, StoreLimits::default(), test_subscriptions()).await;
    assert!(
        matches!(refused, Err(ServiceError::Unavailable)),
        "an existing world-readable store directory is never accepted"
    );
    assert_eq!(
        fs::metadata(&store_dir).unwrap().permissions().mode() & 0o7777,
        0o755,
        "the refused directory is left exactly as found, never repaired"
    );
    let names: Vec<_> = fs::read_dir(&store_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        names,
        vec![std::ffi::OsString::from("witness")],
        "the refusal precedes custody, so no lease sidecar is left behind"
    );
    assert_eq!(fs::read(store_dir.join("witness")).unwrap(), b"untouched");
}

/// A restart must import durable task ownership into the SAME authority the
/// synchronous gateway uses, before the constructor returns ready to serve.
#[tokio::test]
async fn shared_runtime_restores_task_bindings_before_synchronous_admission() {
    use crate::idempotency::admission::{Admission, ExecutionAdmission, Mode, Refusal, Request};
    use crate::protocol::tasks::{Task, TaskOptions};
    use serde_json::json;
    use tokio::sync::Semaphore;

    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("tasks");
    let operation = json!({"backend":"fixture", "tool":"write"});
    let representation = json!({"wire":"modern"});
    let request = |mode| Request {
        principal: "verified-owner",
        key: "durable-client-key",
        operation: &operation,
        representation: &representation,
        mode,
    };
    let fresh_admission = || ExecutionAdmission::new(Arc::new(|| 1_000));
    let admission = fresh_admission();
    let (service, executor) = super::open_runtime_with_admission(
        &directory,
        1,
        StoreLimits::default(),
        test_subscriptions(),
        Arc::clone(&admission),
    )
    .await
    .expect("first startup");
    let task = Task::create_at(
        "write",
        chrono::Utc::now(),
        TaskOptions {
            ttl_ms: Some(86_400_000),
            poll_interval_ms: Some(1_000),
        },
    );
    let workers = Arc::new(Semaphore::new(1));
    let created = service
        .create(request(Mode::Task), &task, "fixture", move || {
            workers.try_acquire_owned().ok()
        })
        .await
        .unwrap();
    assert!(
        matches!(created, super::CreateOutcome::Created { .. }),
        "the restart fixture must originate in a real committed task"
    );
    drop(created);
    assert!(
        matches!(admission.admit(request(Mode::Sync)), Err(Refusal::Mismatch)),
        "the first startup also shares its admission authority"
    );
    service.shutdown().await.expect("release durable custody");
    drop(executor);
    drop(service);
    drop(admission);

    // The second authority is new: no retained in-memory slot can make this
    // restart assertion pass. Its initial admission is acquired and released.
    let restored_admission = fresh_admission();
    let probe = restored_admission.admit(request(Mode::Sync)).unwrap();
    assert!(
        matches!(probe, Admission::Owned(_)),
        "fresh authority has no binding"
    );
    drop(probe);
    let (restored, restored_executor) = super::open_runtime_with_admission(
        &directory,
        1,
        StoreLimits::default(),
        test_subscriptions(),
        Arc::clone(&restored_admission),
    )
    .await
    .expect("startup imports the durable task");
    let fetched = restored
        .get("verified-owner", task.id())
        .expect("restored task is readable");
    assert_eq!(fetched.task.id(), task.id());
    assert!(
        matches!(
            restored_admission.admit(request(Mode::Sync)),
            Err(Refusal::Mismatch)
        ),
        "a restored task key must refuse synchronous admission before any dispatch"
    );
    // Refusal is about the restored owner/key, not a broken or saturated index.
    let fresh_key = restored_admission.admit(Request {
        key: "unclaimed-key",
        ..request(Mode::Sync)
    });
    assert!(matches!(fresh_key, Ok(Admission::Owned(_))));
    drop(fresh_key);
    let foreign = restored_admission.admit(Request {
        principal: "another-owner",
        ..request(Mode::Sync)
    });
    assert!(matches!(foreign, Ok(Admission::Owned(_))));
    drop(foreign);
    restored.shutdown().await.unwrap();
    drop(restored_executor);
}
