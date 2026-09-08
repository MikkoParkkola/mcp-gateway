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
