// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Windows: every lock constructor creates its sidecar owner-only, and an
//! existing sidecar another account could open is replaced with an
//! owner-only one before it is locked.

use std::path::Path;
use std::time::Duration;

use super::ExclusiveFileLock;
use crate::private_fs::test_support::{assert_owner_only, plant_any, user_sid};

/// The three constructors, each taking the lock once and dropping it.
fn take(how: &str, path: &Path) {
    match how {
        "acquire" => drop(ExclusiveFileLock::acquire(path).expect("acquire")),
        "try_lease" => drop(
            ExclusiveFileLock::try_lease(path)
                .expect("try_lease")
                .expect("uncontended"),
        ),
        "lease" => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("runtime");
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let lease = runtime.block_on(ExclusiveFileLock::lease(
                path,
                Duration::from_millis(10),
                deadline,
            ));
            drop(lease.expect("lease"));
        }
        other => unreachable!("{other}"),
    }
}

const CONSTRUCTORS: [&str; 3] = ["acquire", "try_lease", "lease"];

#[test]
fn every_constructor_creates_an_owner_only_sidecar() {
    for how in CONSTRUCTORS {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join(".store.lock");
        take(how, &path);
        assert_owner_only(how, &path, false);
    }
}

#[test]
fn every_constructor_replaces_an_existing_sidecar_others_can_open() {
    for how in CONSTRUCTORS {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join(".store.lock");
        std::fs::write(&path, b"").expect("plant");
        let user = user_sid();
        let planted = plant_any(how, &path, &format!("O:{user}D:(A;;FA;;;WD)"));
        assert!(
            planted.contains("S-1-1-0"),
            "{how}: Everyone planted: {planted}"
        );
        take(how, &path);
        assert_owner_only(how, &path, false);
    }
}
