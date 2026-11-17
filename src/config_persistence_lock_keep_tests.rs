// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config lock's detached thread keeps the temp dir a test registered
//! until its work returns, even after the caller left, and reports a plain one
//! at spawn (family test-temp-sidecar-leak, rows K15 and K15p).

use std::time::{Duration, Instant};

use super::*;
use crate::test_dir_keep::{expect_unkept, held_then_gone, kept_tempdir};
use crate::test_pause::{Release, within};

fn this_test() -> String {
    std::thread::current()
        .name()
        .expect("a test thread")
        .to_owned()
}

/// K15. A `lock_config` call whose thread is held before its work starts, and
/// whose caller then leaves, keeps the test's dir after the test drops its
/// share; the dir goes once the thread's work returns.
/// Mutant: `off_runtime_in` without the keep.
#[tokio::test]
async fn the_config_lock_thread_keeps_its_dir_after_its_caller_leaves() {
    let dir = kept_tempdir();
    let root = dir.path().to_path_buf();
    let config = root.join("gateway.yaml");
    std::fs::write(&config, "{}\n").expect("a config");
    let hold = crate::spawn_keep::hold_for(&config);
    let (reached, release) = hold.arm();
    let release = Release(release);
    let caller = tokio::spawn({
        let config = config.clone();
        async move {
            let _ = lock_config(&config, Instant::now() + Duration::from_secs(10)).await;
        }
    });
    within("the lock thread reached its hold", reached.notified()).await;
    caller.abort();
    let left = caller.await;
    assert!(
        left.as_ref()
            .is_err_and(tokio::task::JoinError::is_cancelled),
        "the caller did not leave: {left:?}"
    );
    drop(dir);
    held_then_gone(&root, || release.now()).await;
}

/// K15p. A `lock_config` call in a plain temp dir is recorded once, at spawn,
/// with its kind, the config path and this test; the lock is still taken.
/// Mutant: the keep taken but not reported.
#[tokio::test]
async fn a_plain_dir_config_lock_is_recorded_with_its_kind() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let config = dir.path().join("gateway.yaml");
    std::fs::write(&config, "{}\n").expect("a config");
    let unkept = expect_unkept();
    let locked = lock_config(&config, Instant::now() + Duration::from_secs(10)).await;
    assert!(locked.is_ok(), "premise: the lock was taken");
    assert_eq!(
        unkept.recorded(),
        vec![("config lock", config.clone(), this_test())]
    );
    drop(locked);
}
