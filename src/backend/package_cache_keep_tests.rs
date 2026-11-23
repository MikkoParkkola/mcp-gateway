// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The package cache's detached deletes keep the temp dir a test registered
//! until they return, and report a plain one at spawn (family
//! test-temp-sidecar-leak, rows K13-K14p). A delete still walking a tree when
//! the test's dir is removed can make that removal fail and leave the dir.

use super::*;
use crate::test_dir_keep::{expect_unkept, held_then_gone, kept_tempdir};
use crate::test_pause::{Release, within};

fn this_test() -> String {
    std::thread::current()
        .name()
        .expect("a test thread")
        .to_owned()
}

/// A tombstone the gateway marked, with a file in it, under `root`.
fn tombstone_in(root: &Path) -> PathBuf {
    let tombstone = root.join(format!("cache{TOMBSTONE_MARK}1"));
    std::fs::create_dir_all(tombstone.join("pkg")).expect("a tombstone tree");
    std::fs::write(tombstone.join(TOMBSTONE_PROOF), b"").expect("the gateway's proof");
    std::fs::write(tombstone.join("pkg").join("index.js"), b"x").expect("a cached file");
    tombstone
}

/// K13. A tombstone delete, held before it starts, keeps the test's dir after
/// the test drops its share; the dir goes once the delete returns, and the
/// tombstone was deleted.
/// Mutant: `discard_tombstone` without the keep.
#[tokio::test]
async fn a_tombstone_delete_keeps_its_dir_until_it_returns() {
    let dir = kept_tempdir();
    let root = dir.path().to_path_buf();
    let tombstone = tombstone_in(&root);
    let hold = crate::spawn_keep::hold_for(&tombstone);
    let (reached, release) = hold.arm();
    let release = Release(release);
    discard_tombstone(tombstone.clone());
    within("the delete reached its hold", reached.notified()).await;
    drop(dir);
    held_then_gone(&root, || release.now()).await;
}

/// K14. The startup sweep of a cache root, held before it reads the root,
/// keeps the test's dir after the test drops its share; the dir goes once the
/// sweep returns.
/// Mutant: `sweep_tombstones_once` without the keep.
#[tokio::test]
async fn a_tombstone_sweep_keeps_its_dir_until_it_returns() {
    let dir = kept_tempdir();
    let root = dir.path().to_path_buf();
    tombstone_in(&root);
    let hold = crate::spawn_keep::hold_for(&root);
    let (reached, release) = hold.arm();
    let release = Release(release);
    sweep_tombstones_once(&root);
    within("the sweep reached its hold", reached.notified()).await;
    drop(dir);
    held_then_gone(&root, || release.now()).await;
}

/// K13p. A tombstone delete in a plain temp dir is recorded once, at spawn,
/// with its kind, the tombstone and this test; the delete still runs.
/// Mutant: the keep taken but not reported.
#[tokio::test]
async fn a_plain_dir_tombstone_delete_is_recorded_with_its_kind() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let tombstone = tombstone_in(dir.path());
    let unkept = expect_unkept();
    discard_tombstone(tombstone.clone());
    assert_eq!(
        unkept.recorded(),
        vec![("package cache", tombstone.clone(), this_test())]
    );
    let gone = crate::test_wait::wait_real_time(std::time::Duration::from_secs(30), || {
        !tombstone.exists()
    })
    .await;
    assert!(gone.is_ok(), "the delete did not run");
}

/// K14p. The startup sweep of a plain temp dir is recorded once, at spawn,
/// with its kind, the root and this test; the sweep still deletes the
/// gateway's tombstone.
/// Mutant: the keep taken but not reported.
#[tokio::test]
async fn a_plain_dir_tombstone_sweep_is_recorded_with_its_kind() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let root = dir.path().to_path_buf();
    let tombstone = tombstone_in(&root);
    let unkept = expect_unkept();
    sweep_tombstones_once(&root);
    assert_eq!(
        unkept.recorded(),
        vec![("package cache", root.clone(), this_test())]
    );
    let gone = crate::test_wait::wait_real_time(std::time::Duration::from_secs(30), || {
        !tombstone.exists()
    })
    .await;
    assert!(gone.is_ok(), "the sweep did not run");
}

/// A cache rename that is still blocked inside its task, plus the start that
/// waited on it and gave up. The rename runs once `go` is sent.
async fn abandoned_rename(cache: &Path) -> std::sync::mpsc::Sender<()> {
    let guard = Arc::clone(&repair_lock(cache)).lock_owned().await;
    let (began, began_rx) = std::sync::mpsc::channel::<()>();
    let (go, go_rx) = std::sync::mpsc::channel::<()>();
    let gave_up = retire_within(
        cache,
        guard,
        move |_| {
            began.send(()).expect("the row waits for the rename");
            go_rx.recv().expect("the row lets the rename finish");
            Retired::AlreadyGone
        },
        |_| {},
        // limit-under-test (fires-only): the start must give up while the rename is held
        std::time::Duration::from_millis(50),
    )
    .await;
    assert!(gave_up.is_err(), "the start was meant to give up first");
    began_rx
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("the rename task began");
    go
}

/// K16. A rename whose start gave up keeps the test's dir after the test
/// drops its share, and reports nothing; the dir goes once the rename returns.
/// Mutant: `retire_cache_dir` spawning its rename without a keep.
#[tokio::test]
async fn a_rename_its_start_gave_up_on_is_held_until_it_returns() {
    let dir = kept_tempdir();
    let root = dir.path().to_path_buf();
    let unkept = expect_unkept();
    let go = abandoned_rename(&root.join("cache")).await;
    assert!(unkept.recorded().is_empty(), "a kept dir was reported");
    drop(dir);
    held_then_gone(&root, || go.send(()).expect("the rename is waiting")).await;
}

/// K16p. A rename in a plain temp dir is recorded once, when it is spawned,
/// with its kind, the cache path and this test; the rename still runs.
/// Mutant: the keep taken but not reported.
#[tokio::test]
async fn a_plain_dir_rename_is_recorded_with_its_kind() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let cache = dir.path().join("cache");
    let unkept = expect_unkept();
    let go = abandoned_rename(&cache).await;
    assert_eq!(
        unkept.recorded(),
        vec![("package cache", cache.clone(), this_test())]
    );
    go.send(()).expect("the rename is waiting");
}
