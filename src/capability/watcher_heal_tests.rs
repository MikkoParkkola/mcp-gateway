// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8651 heal rows added after the final review: incomplete-reload retry,
//! symlinks, hidden files, a missing directory, and a symlink loop. A child of
//! `watcher_tests`, so it shares that module's helpers and imports.

use tokio::sync::{broadcast, mpsc};
use tracing::Level;

use super::*;

/// MIK-8651.HEAL.1: an incomplete reload retries after its directory returns
/// with identical files; the retry warn fires. Red now: the fingerprint
/// equals the old baseline, so nothing reloads.
#[tokio::test(flavor = "current_thread")]
async fn an_incomplete_reload_is_retried_after_its_directory_returns() {
    let (_guard, mut counts) = crate::test_log_capture::live_counts_at(&[
        (Level::INFO, "Capability stale check armed"),
        (Level::WARN, "reload incomplete; retrying"),
    ]);
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v1")).expect("write v1");
    let backend = backend_over(dir.path()).await;
    let (event_tx, event_rx) = mpsc::channel(100);
    let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let tuning = ReloadTuning {
        stale_check: Some(Duration::from_millis(200)),
        debounce: Duration::from_millis(50),
        ..ReloadTuning::default()
    };
    CapabilityWatcher::spawn_reload_task_tuned(
        Arc::clone(&backend),
        event_rx,
        shutdown_rx,
        None,
        tuning,
    );
    tokio::time::timeout(crate::test_wait::HANG_BOUND, counts.wait_for(|v| v[0] >= 1))
        .await
        .expect("the armed baseline within the hang bound")
        .expect("the log counter is alive");
    let away = dir.path().with_extension("away");
    std::fs::rename(dir.path(), &away).expect("rename the dir away");
    event_tx.send(()).await.expect("the task takes the event");
    let _ = eventually(crate::test_wait::HANG_BOUND, || {
        description_of(&backend, "a").is_none()
    })
    .await;
    std::fs::rename(&away, dir.path()).expect("rename the dir back");
    assert!(
        eventually(crate::test_wait::HANG_BOUND, || {
            description_of(&backend, "a").as_deref() == Some("v1")
        })
        .await,
        "the returned directory heals without any new event"
    );
    tokio::time::timeout(crate::test_wait::HANG_BOUND, counts.wait_for(|v| v[1] >= 1))
        .await
        .expect("a retry warn within the hang bound")
        .expect("the log counter is alive");
}

/// MIK-8651.HEAL.1: a symlinked capability heals when its target is edited.
/// Red now: the walk skips symlinks, so the edit never differs.
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn a_symlinked_capability_heals() {
    let (_guard, mut counts) =
        crate::test_log_capture::live_counts_at(&[(Level::INFO, "Capability stale check armed")]);
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    let real = tempfile::tempdir().expect("a tempdir for the target");
    std::fs::write(real.path().join("x.yaml"), cap_yaml("a", "v1")).expect("write v1");
    std::os::unix::fs::symlink(real.path().join("x.yaml"), dir.path().join("link.yaml"))
        .expect("link the capability");
    let backend = backend_over(dir.path()).await;
    let (event_tx, event_rx) = mpsc::channel(100);
    drop(event_tx);
    let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let tuning = ReloadTuning {
        stale_check: Some(Duration::from_millis(200)),
        debounce: Duration::from_millis(50),
        ..ReloadTuning::default()
    };
    CapabilityWatcher::spawn_reload_task_tuned(
        Arc::clone(&backend),
        event_rx,
        shutdown_rx,
        None,
        tuning,
    );
    tokio::time::timeout(crate::test_wait::HANG_BOUND, counts.wait_for(|v| v[0] >= 1))
        .await
        .expect("the armed baseline within the hang bound")
        .expect("the log counter is alive");
    std::fs::write(real.path().join("x.yaml"), cap_yaml("a", "v2-much-longer")).expect("write v2");
    assert!(
        eventually(crate::test_wait::HANG_BOUND, || {
            description_of(&backend, "a").as_deref() == Some("v2-much-longer")
        })
        .await,
        "the symlinked edit heals"
    );
}

/// MIK-8651 control: a hidden file is ignored by the stale check; the
/// catalogue generation is unchanged after 600 ms.
#[tokio::test(flavor = "current_thread")]
async fn a_hidden_file_is_ignored_by_the_stale_check() {
    let (_guard, mut counts) =
        crate::test_log_capture::live_counts_at(&[(Level::INFO, "Capability stale check armed")]);
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v1")).expect("write v1");
    let backend = backend_over(dir.path()).await;
    let (event_tx, event_rx) = mpsc::channel(100);
    drop(event_tx);
    let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let tuning = ReloadTuning {
        stale_check: Some(Duration::from_millis(200)),
        debounce: Duration::from_millis(50),
        ..ReloadTuning::default()
    };
    CapabilityWatcher::spawn_reload_task_tuned(
        Arc::clone(&backend),
        event_rx,
        shutdown_rx,
        None,
        tuning,
    );
    tokio::time::timeout(crate::test_wait::HANG_BOUND, counts.wait_for(|v| v[0] >= 1))
        .await
        .expect("the armed baseline within the hang bound")
        .expect("the log counter is alive");
    std::fs::write(dir.path().join(".hidden.yaml"), cap_yaml("hidden", "h")).expect("write hidden");
    let generation = backend.catalogue_generation();
    // timing: absence
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        backend.catalogue_generation(),
        generation,
        "no reload runs for a hidden file"
    );
}

/// MIK-8651.LOW, LOUD.1: a missing configured directory warns at start that
/// it is not watched. Red now: the start logs at debug, so no warn appears.
#[tokio::test(flavor = "current_thread")]
async fn a_missing_directory_warns_at_start() {
    let (_guard, mut counts) =
        crate::test_log_capture::live_counts_at(&[(Level::WARN, "does not exist")]);
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    let backend = Arc::new(CapabilityBackend::new(
        "caps",
        Arc::new(CapabilityExecutor::new()),
    ));
    let missing = dir
        .path()
        .join("missing-dir")
        .to_string_lossy()
        .into_owned();
    backend.register_directories(&[missing]);
    let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let _watcher = CapabilityWatcher::start(Arc::clone(&backend), shutdown_rx, None, 60)
        .expect("start with a missing dir succeeds");
    tokio::time::timeout(crate::test_wait::HANG_BOUND, counts.wait_for(|v| v[0] >= 1))
        .await
        .expect("a missing-dir warn within the hang bound")
        .expect("the log counter is alive");
    // timing: absence
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        counts.borrow()[0],
        1,
        "the missing-dir warn fires exactly once"
    );
}

/// MIK-8651.HEAL.1: a symlink loop (a directory linking to its own parent)
/// cannot spin the stale check: the walk stops at its depth bound, warns that
/// the tree exceeds the bounds, and the task still stops on a real shutdown.
/// Red now: the walk does not follow symlinked directories, so no bounds warn.
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
async fn a_symlink_loop_ends_at_the_walk_bounds_and_warns() {
    let (_guard, mut counts) =
        crate::test_log_capture::live_counts_at(&[(Level::WARN, "exceeds the walk bounds")]);
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v1")).expect("write v1");
    // Loaded before the loop exists: the loader's own handling of a loop is
    // reported separately and is not under test here.
    let backend = backend_over(dir.path()).await;
    std::os::unix::fs::symlink(dir.path(), dir.path().join("loop"))
        .expect("link the directory to itself");
    let (event_tx, event_rx) = mpsc::channel(100);
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let tuning = ReloadTuning {
        stale_check: Some(Duration::from_millis(200)),
        debounce: Duration::from_millis(50),
        ..ReloadTuning::default()
    };
    CapabilityWatcher::spawn_reload_task_tuned(
        Arc::clone(&backend),
        event_rx,
        shutdown_rx,
        None,
        tuning,
    );
    tokio::time::timeout(crate::test_wait::HANG_BOUND, counts.wait_for(|v| v[0] >= 1))
        .await
        .expect("the bounds warn within the hang bound")
        .expect("the log counter is alive");
    shutdown_tx.send(()).expect("the task holds a receiver");
    assert!(
        eventually(crate::test_wait::HANG_BOUND, || event_tx.is_closed()).await,
        "a real shutdown still stops the task with the loop present"
    );
}

/// Set while [`stalling_walk`] must block; the guard in the row clears it.
static STALL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// A fingerprint walk that blocks until [`STALL`] clears, then walks.
fn stalling_walk(dirs: &[String]) -> Option<crate::capability::watcher::fingerprint::Fingerprint> {
    while STALL.load(std::sync::atomic::Ordering::Acquire) {
        // timing: fixture
        std::thread::sleep(Duration::from_millis(10));
    }
    crate::capability::watcher::fingerprint::fingerprint(dirs)
}

/// Clears [`STALL`] on drop, so a failing row never leaves a walk blocked.
struct Unstall;

impl Drop for Unstall {
    fn drop(&mut self) {
        STALL.store(false, std::sync::atomic::Ordering::Release);
    }
}

/// MIK-8651.HEAL.1: a stalled arming or periodic fingerprint walk does not
/// hold a pending reload hostage: past `reload_slow` the reload runs without
/// a before-fingerprint. Red on 7463fac2d: the reload waits for the walk.
#[tokio::test(flavor = "current_thread")]
async fn a_stalled_walk_does_not_hold_a_pending_reload() {
    let _unstall = Unstall;
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v1")).expect("write v1");
    let backend = backend_over(dir.path()).await;
    let (event_tx, event_rx) = mpsc::channel(100);
    let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let tuning = ReloadTuning {
        stale_check: Some(Duration::from_millis(100)),
        reload_slow: Duration::from_millis(300),
        debounce: Duration::from_millis(50),
        walk: stalling_walk,
    };
    CapabilityWatcher::spawn_reload_task_tuned(
        Arc::clone(&backend),
        event_rx,
        shutdown_rx,
        None,
        tuning,
    );
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v2-much-longer")).expect("write v2");
    event_tx.send(()).await.expect("the task takes the event");
    assert!(
        eventually(crate::test_wait::HANG_BOUND, || {
            description_of(&backend, "a").as_deref() == Some("v2-much-longer")
        })
        .await,
        "the pending reload runs although the arming walk is stalled"
    );
}
