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

/// MIK-8202 P2: the admission clock `open_runtime` builds.
mod admission_clock;
/// Startup recovery of records a previous process left mid-flight.
mod recovery;
use crate::gateway::subscription_registry::{DEFAULT_MAX_LISTENERS, SubscriptionRegistry};

fn test_subscriptions() -> Arc<SubscriptionRegistry> {
    Arc::new(SubscriptionRegistry::new(
        DEFAULT_MAX_LISTENERS,
        crate::gateway::test_helpers::auth_state(&crate::config::AuthConfig::default()),
    ))
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
    // POSIX mode bits: asserts 0600 owner-only; Windows enforces owner-only through DACLs (win_acl).
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

// POSIX mode bits: builds a group/world-readable fixture with chmod; Windows uses DACLs (win_acl).
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

mod expiry;

/// The premise of the chart's writable `state` volume, pinned both ways.
///
/// A store under a home the process cannot write is a fatal startup error, not
/// a fallback (`tasks.rs`), which is why a read-only root filesystem with no
/// writable `HOME` kept every chart pod from starting. The control proves the
/// same path opens once the parent is writable, so the refusal is about the
/// parent and nothing else. The refusal must be the store's own
/// (`Unavailable`) with nothing created under the home, so an unrelated
/// failure cannot pass it, and the premise is probed for both files and
/// directories so a deny that holds for only one fails loudly (MIK-7749).
#[tokio::test]
async fn task_store_under_readonly_home_is_fatal() {
    use std::fs;

    let root = tempfile::tempdir().expect("a fixture root");
    let home = root.path().join("home");
    fs::create_dir(&home).unwrap();
    // Unix takes the write mode away; Windows denies the user write and append (DACL).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&home, fs::Permissions::from_mode(0o500)).unwrap();
    }
    #[cfg(windows)]
    crate::private_fs::test_support::deny_user("readonly-home", &home, "WD,AD");
    let store_dir = home.join(".mcp-gateway").join("tasks");

    // Root ignores the mode bits, so the premise cannot be observed there. Both
    // a file and a directory are probed: the store creates directories, and a
    // deny that stops only files would leave its path open.
    let premise_holds = fs::write(home.join("probe"), b"").is_err()
        && fs::create_dir(home.join("probe-dir")).is_err();
    if !premise_holds {
        make_writable(&home);
        // A skip in CI would make this pin pass without testing anything, so
        // CI must run it unprivileged; only a local root shell may skip.
        assert!(
            std::env::var_os("CI").is_none(),
            "CI runs this test as a uid that ignores directory modes, so it proves nothing"
        );
        eprintln!("skipped: running with a uid that ignores directory modes");
        return;
    }

    let refused = open_runtime(&store_dir, 1, StoreLimits::default(), test_subscriptions()).await;
    // The refusal is the store's own (unavailable), and nothing was created
    // under the home: an unrelated failure after creation would leave the
    // store's directory behind.
    assert!(
        matches!(refused, Err(ServiceError::Unavailable)),
        "a store under an unwritable home must refuse to open as unavailable"
    );
    assert!(
        !home.join(".mcp-gateway").exists(),
        "nothing may be created under the unwritable home"
    );

    make_writable(&home);
    let (service, _executor) =
        open_runtime(&store_dir, 1, StoreLimits::default(), test_subscriptions())
            .await
            .expect("the same path opens once its parent is writable");
    service.shutdown().await.expect("custody is released");
}

/// Undo the fixture's write denial on `dir`.
fn make_writable(dir: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[cfg(windows)]
    crate::private_fs::test_support::remove_deny("readonly-home", dir);
}
