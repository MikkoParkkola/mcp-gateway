// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config lock's detached thread keeps the temp dir a test registered
//! until its work returns, even after the caller left; a plain dir is reported
//! only when its caller is cancelled while the thread still runs
//! (family test-temp-sidecar-leak, rows K15, K15p and K15c).

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

/// K15p. A `lock_config` call awaited in a plain temp dir records nothing: its
/// thread cannot outlive the caller, so no write can land after the test. The
/// lock is still taken.
/// Mutant: the report taken at spawn again.
#[tokio::test]
async fn an_awaited_config_lock_in_a_plain_dir_records_nothing() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let config = dir.path().join("gateway.yaml");
    std::fs::write(&config, "{}\n").expect("a config");
    let unkept = expect_unkept();
    let locked = lock_config(&config, Instant::now() + Duration::from_secs(10)).await;
    assert!(locked.is_ok(), "premise: the lock was taken");
    assert_eq!(unkept.recorded(), vec![], "an awaited caller was reported");
    drop(locked);
}

/// K15c. A `lock_config` caller cancelled while its thread still runs, in a
/// plain temp dir, is recorded once, at the cancel, with its kind, the config
/// path and this test; nothing is recorded before the cancel. Taking the lock
/// again afterwards, awaited, proves the cancelled thread let it go before the
/// dir is removed.
/// Mutant: no report on cancel.
#[tokio::test]
async fn a_config_lock_caller_cancelled_mid_thread_is_recorded_at_the_cancel() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let config = dir.path().join("gateway.yaml");
    std::fs::write(&config, "{}\n").expect("a config");
    let hold = crate::spawn_keep::hold_for(&config);
    let (reached, release) = hold.arm();
    let release = Release(release);
    let unkept = expect_unkept();
    let caller = tokio::spawn({
        let config = config.clone();
        async move {
            let _ = lock_config(&config, Instant::now() + Duration::from_secs(10)).await;
        }
    });
    within("the lock thread reached its hold", reached.notified()).await;
    assert_eq!(unkept.recorded(), vec![], "recorded before the cancel");
    caller.abort();
    let left = caller.await;
    assert!(
        left.as_ref()
            .is_err_and(tokio::task::JoinError::is_cancelled),
        "the caller did not leave: {left:?}"
    );
    assert_eq!(
        unkept.recorded(),
        vec![("config lock", config.clone(), this_test())],
        "not recorded once at the cancel"
    );
    release.now();
    let again = lock_config(&config, Instant::now() + Duration::from_secs(10)).await;
    assert!(again.is_ok(), "the cancelled thread kept the lock");
    assert_eq!(
        unkept.recorded().len(),
        1,
        "the awaited relock was reported"
    );
    drop(again);
}
