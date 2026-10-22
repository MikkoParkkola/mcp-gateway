// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Failing-first tests for MIK-8651: the capability hot-reload task must warn
//! loudly instead of stopping silently, and a stale-catalogue check must heal
//! a dead event source.
//!
//! The tests drive `CapabilityWatcher::spawn_reload_task` directly with a real
//! `CapabilityBackend` over a tempdir; the real `notify` watcher is not
//! exercised here. Log assertions use
//! `crate::test_log_capture::live_counts_at`, which counts records on this
//! thread, so every test runs on a current-thread runtime and holds the one
//! capture guard for the whole test.

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{broadcast, mpsc};
use tracing::Level;

use super::*;
use crate::capability::{CapabilityBackend, CapabilityExecutor};

/// A minimal rest capability with `name` and `description`.
fn cap_yaml(name: &str, desc: &str) -> String {
    format!(
        "name: {name}\ndescription: {desc}\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://api.invalid\n      path: /k\n"
    )
}

/// A backend named `caps` loaded over `dir`.
async fn backend_over(dir: &Path) -> Arc<CapabilityBackend> {
    let backend = CapabilityBackend::new("caps", Arc::new(CapabilityExecutor::new()));
    backend
        .load_from_directory(dir.to_str().expect("the tempdir path is utf-8"))
        .await
        .expect("the fixture directory loads");
    Arc::new(backend)
}

/// The served description of `name`, if the catalogue lists it.
fn description_of(backend: &CapabilityBackend, name: &str) -> Option<String> {
    backend
        .get_tools()
        .into_iter()
        .find(|tool| tool.name == name)
        .and_then(|tool| tool.description)
}

/// Polls `f` every 20 ms of real time until it holds or `deadline` passes.
async fn eventually(deadline: Duration, f: impl Fn() -> bool) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    f()
}

/// MIK-8651 control: starting with no directories does not panic.
#[test]
fn test_watcher_creation() {
    // Basic smoke test - actual file watching tested in integration tests
    let (_tx, rx) = tokio::sync::broadcast::channel(1);
    let executor = Arc::new(crate::capability::CapabilityExecutor::new());
    let backend = Arc::new(crate::capability::CapabilityBackend::new("test", executor));

    // Should not panic with empty directories
    let watcher = CapabilityWatcher::start(backend, rx, None);
    assert!(watcher.is_ok());
}

/// MIK-8651.CAUSE.1 a, LOUD.1: two shutdown sends on a capacity-1 channel warn
/// about the lag exactly once, then the retained shutdown still stops the task.
#[tokio::test(flavor = "current_thread")]
async fn lagged_shutdown_warns_then_stops() {
    let (_guard, mut counts) = crate::test_log_capture::live_counts_at(&[(Level::WARN, "Lagged")]);
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v1")).expect("write v1");
    let backend = backend_over(dir.path()).await;
    let (event_tx, event_rx) = mpsc::channel(100);
    let shutdown_tx = broadcast::channel(1).0;
    let shutdown_rx = shutdown_tx.subscribe();
    shutdown_tx.send(()).expect("the first shutdown send lands");
    shutdown_tx
        .send(())
        .expect("the second shutdown send lands");
    CapabilityWatcher::spawn_reload_task(backend, event_rx, shutdown_rx, None);
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[0] >= 1))
        .await
        .expect("a warn naming Lagged within 2 s")
        .expect("the log counter is alive");
    assert!(
        eventually(Duration::from_secs(2), || event_tx.is_closed()).await,
        "the retained shutdown stops the task"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(counts.borrow()[0], 1, "Lagged warns exactly once");
}

/// MIK-8651.CAUSE.1 a, LOUD.1: a dropped shutdown sender warns once and the
/// task keeps reloading on file events; the warn stays at exactly one.
#[tokio::test(flavor = "current_thread")]
async fn closed_shutdown_keeps_reloading() {
    let (_guard, mut counts) =
        crate::test_log_capture::live_counts_at(&[(Level::WARN, "shutdown channel closed")]);
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v1")).expect("write v1");
    let backend = backend_over(dir.path()).await;
    let (event_tx, event_rx) = mpsc::channel(100);
    let shutdown_tx = broadcast::channel(1).0;
    let shutdown_rx = shutdown_tx.subscribe();
    drop(shutdown_tx);
    CapabilityWatcher::spawn_reload_task(Arc::clone(&backend), event_rx, shutdown_rx, None);
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v2-much-longer")).expect("write v2");
    // On today's code the task may already have exited on `Closed`; the send
    // result is not the assertion, the reload below is.
    let _event_accepted = event_tx.send(()).await;
    assert!(
        eventually(Duration::from_secs(3), || {
            description_of(&backend, "a").as_deref() == Some("v2-much-longer")
        })
        .await,
        "the edit still reloads with the shutdown channel closed"
    );
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[0] >= 1))
        .await
        .expect("a warn that the shutdown channel closed within 2 s")
        .expect("the log counter is alive");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        counts.borrow()[0],
        1,
        "the closed-channel warn fires exactly once"
    );
}

/// MIK-8651 control: one real shutdown still stops the reload task.
#[tokio::test(flavor = "current_thread")]
async fn a_real_shutdown_still_stops() {
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v1")).expect("write v1");
    let backend = backend_over(dir.path()).await;
    let (event_tx, event_rx) = mpsc::channel(100);
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    CapabilityWatcher::spawn_reload_task(backend, event_rx, shutdown_rx, None);
    shutdown_tx.send(()).expect("the shutdown send lands");
    assert!(
        eventually(Duration::from_secs(2), || event_tx.is_closed()).await,
        "a real shutdown stops the task"
    );
}

/// MIK-8651.HEAL.1: with the event sender open but silent, the stale check
/// heals an edit by mtime and warns once that no file event arrived. Waits
/// for the INFO "Capability stale check armed" baseline before mutating; on
/// base that line never appears, so this fails at that wait (red: no check).
#[tokio::test(flavor = "current_thread")]
async fn a_dead_event_source_heals_by_mtime_open_sender() {
    let (_guard, mut counts) = crate::test_log_capture::live_counts_at(&[
        (Level::INFO, "Capability stale check armed"),
        (Level::WARN, "no file event arrived"),
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
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[0] >= 1))
        .await
        .expect("the armed baseline within 2 s")
        .expect("the log counter is alive");
    // `event_tx` stays alive and never sends: the event source is silent.
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v2-much-longer")).expect("write v2");
    assert!(
        eventually(Duration::from_secs(3), || {
            description_of(&backend, "a").as_deref() == Some("v2-much-longer")
        })
        .await,
        "the stale check heals the edit with no file event"
    );
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[1] >= 1))
        .await
        .expect("a heal warn within 2 s")
        .expect("the log counter is alive");
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(counts.borrow()[1], 1, "the heal warns exactly once");
    drop(event_tx);
}

/// MIK-8651.HEAL.1: with the event sender dropped, the stale check still heals
/// by mtime; the task warns once that the event source is gone and once that
/// no file event arrived. One capture holds all three texts for the whole
/// test. Waits for INFO "Capability stale check armed" before mutating; on
/// base that line never appears, so this fails at that wait (red: no check).
#[tokio::test(flavor = "current_thread")]
async fn a_dead_event_source_heals_by_mtime_dropped_sender() {
    let (_guard, mut counts) = crate::test_log_capture::live_counts_at(&[
        (Level::INFO, "Capability stale check armed"),
        (Level::WARN, "event source is gone"),
        (Level::WARN, "no file event arrived"),
    ]);
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
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[0] >= 1))
        .await
        .expect("the armed baseline within 2 s")
        .expect("the log counter is alive");
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[1] >= 1))
        .await
        .expect("a warn that the event source is gone within 2 s")
        .expect("the log counter is alive");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v2-much-longer")).expect("write v2");
    assert!(
        eventually(Duration::from_secs(3), || {
            description_of(&backend, "a").as_deref() == Some("v2-much-longer")
        })
        .await,
        "the stale check heals the edit with the event sender dropped"
    );
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[2] >= 1))
        .await
        .expect("a heal warn within 2 s")
        .expect("the log counter is alive");
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        counts.borrow()[1],
        1,
        "the gone-source warn fires exactly once"
    );
    assert_eq!(counts.borrow()[2], 1, "the heal warns exactly once");
}

/// MIK-8651.HEAL.1: with the event source dead, the stale check picks up an
/// added file and warns once. Waits for INFO "Capability stale check armed"
/// before mutating; on base that line never appears, so this fails at that
/// wait (red: no stale check).
#[tokio::test(flavor = "current_thread")]
async fn heal_sees_a_file_added() {
    let (_guard, mut counts) = crate::test_log_capture::live_counts_at(&[
        (Level::INFO, "Capability stale check armed"),
        (Level::WARN, "no file event arrived"),
    ]);
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v1")).expect("write a");
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
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[0] >= 1))
        .await
        .expect("the armed baseline within 2 s")
        .expect("the log counter is alive");
    std::fs::write(dir.path().join("b.yaml"), cap_yaml("b", "b-added-here")).expect("write b");
    assert!(
        eventually(Duration::from_secs(3), || {
            description_of(&backend, "b").as_deref() == Some("b-added-here")
                && description_of(&backend, "a").as_deref() == Some("v1")
        })
        .await,
        "the added file appears in the catalogue"
    );
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[1] >= 1))
        .await
        .expect("a heal warn within 2 s")
        .expect("the log counter is alive");
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(counts.borrow()[1], 1, "the heal warns exactly once");
}

/// MIK-8651.HEAL.1: with the event source dead, the stale check drops a
/// removed file from the catalogue and warns once. Waits for INFO "Capability
/// stale check armed" before mutating; on base that line never appears, so
/// this fails at that wait (red: no stale check).
#[tokio::test(flavor = "current_thread")]
async fn heal_sees_a_file_removed() {
    let (_guard, mut counts) = crate::test_log_capture::live_counts_at(&[
        (Level::INFO, "Capability stale check armed"),
        (Level::WARN, "no file event arrived"),
    ]);
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v1")).expect("write a");
    std::fs::write(dir.path().join("b.yaml"), cap_yaml("b", "b-v1")).expect("write b");
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
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[0] >= 1))
        .await
        .expect("the armed baseline within 2 s")
        .expect("the log counter is alive");
    std::fs::remove_file(dir.path().join("b.yaml")).expect("remove b");
    assert!(
        eventually(Duration::from_secs(3), || {
            description_of(&backend, "b").is_none()
                && description_of(&backend, "a").as_deref() == Some("v1")
        })
        .await,
        "the removed file leaves the catalogue while the rest stays"
    );
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[1] >= 1))
        .await
        .expect("a heal warn within 2 s")
        .expect("the log counter is alive");
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(counts.borrow()[1], 1, "the heal warns exactly once");
}

/// MIK-8651.HEAL.1: an edit made during a reload (in the `changes` callback,
/// after the swap, before the baseline is recorded) is not absorbed: a second
/// reload through the stale check serves v3 with no further events. Waits for
/// INFO "Capability stale check armed" before mutating; on base that line
/// never appears, so this fails at that wait (red: no stale check). Red too
/// under a wrong baseline taken after the reload.
#[tokio::test(flavor = "current_thread")]
async fn an_edit_made_during_a_reload_is_not_absorbed() {
    let (_guard, mut counts) = crate::test_log_capture::live_counts_at(&[
        (Level::INFO, "Capability stale check armed"),
        (Level::WARN, "no file event arrived"),
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
    let caps_dir = dir.path().to_path_buf();
    let v3_done = Arc::new(AtomicBool::new(false));
    let v3_flag = Arc::clone(&v3_done);
    let changes: CatalogueChanged = Arc::new(move |_name: &str| {
        if !v3_flag.swap(true, Ordering::SeqCst) {
            std::fs::write(
                caps_dir.join("a.yaml"),
                cap_yaml("a", "v3-much-much-longer"),
            )
            .expect("the callback rewrites a.yaml to v3");
        }
    });
    CapabilityWatcher::spawn_reload_task_tuned(
        Arc::clone(&backend),
        event_rx,
        shutdown_rx,
        Some(changes),
        tuning,
    );
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[0] >= 1))
        .await
        .expect("the armed baseline within 2 s")
        .expect("the log counter is alive");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v2-longer")).expect("write v2");
    event_tx.send(()).await.expect("the task takes the event");
    // No further events: only the stale check can bring v3.
    assert!(
        eventually(Duration::from_secs(3), || {
            description_of(&backend, "a").as_deref() == Some("v3-much-much-longer")
        })
        .await,
        "the edit made during the reload heals to v3"
    );
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[1] >= 1))
        .await
        .expect("a heal warn for the second reload within 2 s")
        .expect("the log counter is alive");
}

/// MIK-8651.HEAL.1: a same-length edit heals by mtime alone (len unchanged,
/// mtime pushed +5 s) with a dead event source. Waits for INFO "Capability
/// stale check armed" before mutating; on base that line never appears, so
/// this fails at that wait (red: no stale check).
#[tokio::test(flavor = "current_thread")]
async fn a_same_length_edit_heals_by_mtime() {
    let (_guard, mut counts) = crate::test_log_capture::live_counts_at(&[
        (Level::INFO, "Capability stale check armed"),
        (Level::WARN, "no file event arrived"),
    ]);
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
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[0] >= 1))
        .await
        .expect("the armed baseline within 2 s")
        .expect("the log counter is alive");
    let path = dir.path().join("a.yaml");
    std::fs::write(&path, cap_yaml("a", "v2")).expect("write v2 same length");
    std::fs::File::options()
        .write(true)
        .open(&path)
        .expect("open for mtime")
        .set_modified(std::time::SystemTime::now() + Duration::from_secs(5))
        .expect("push the mtime +5 s");
    assert!(
        eventually(Duration::from_secs(3), || {
            description_of(&backend, "a").as_deref() == Some("v2")
        })
        .await,
        "the same-length edit heals by mtime"
    );
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[1] >= 1))
        .await
        .expect("a heal warn within 2 s")
        .expect("the log counter is alive");
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(counts.borrow()[1], 1, "the heal warns exactly once");
}

/// MIK-8651 control: with the stale check off, an edit behind a dead event
/// source never reloads.
#[tokio::test(flavor = "current_thread")]
async fn heal_off_when_none() {
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v1")).expect("write v1");
    let backend = backend_over(dir.path()).await;
    let (event_tx, event_rx) = mpsc::channel(100);
    drop(event_tx);
    let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let tuning = ReloadTuning {
        stale_check: None,
        ..ReloadTuning::default()
    };
    CapabilityWatcher::spawn_reload_task_tuned(
        Arc::clone(&backend),
        event_rx,
        shutdown_rx,
        None,
        tuning,
    );
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v2-much-longer")).expect("write v2");
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        description_of(&backend, "a").as_deref(),
        Some("v1"),
        "with the stale check off, nothing reloads"
    );
}

/// MIK-8651 control, HEAL.1: with no edits, the stale check ticks without
/// reloading: the catalogue generation is unchanged after 600 ms and at least
/// two TRACE "Capability stale check tick" records appear. Waits for INFO
/// "Capability stale check armed" first; on base that line never appears, so
/// this fails at that wait (red: no stale check).
#[tokio::test(flavor = "current_thread")]
async fn no_spurious_heal() {
    let (_guard, mut counts) = crate::test_log_capture::live_counts_at(&[
        (Level::INFO, "Capability stale check armed"),
        (Level::TRACE, "Capability stale check tick"),
    ]);
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v1")).expect("write v1");
    let backend = backend_over(dir.path()).await;
    let (event_tx, event_rx) = mpsc::channel(100);
    let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let tuning = ReloadTuning {
        stale_check: Some(Duration::from_millis(100)),
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
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[0] >= 1))
        .await
        .expect("the armed baseline within 2 s")
        .expect("the log counter is alive");
    let generation = backend.catalogue_generation();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        backend.catalogue_generation(),
        generation,
        "no reload runs when nothing changed"
    );
    assert!(
        counts.borrow()[1] >= 2,
        "at least two ticks ran, so the check provably ran"
    );
    drop(event_tx);
}

/// MIK-8651.CAUSE.1 a: a Lagged wait in `report_startup_scan` warns once
/// naming Lagged, then the retained shutdown still stops the wait, instead of
/// dropping it silently. The backend starts with its initial scan incomplete
/// via `begin_initial_scan`, so no production change was needed.
#[tokio::test(flavor = "current_thread")]
async fn a_lagged_startup_scan_wait_does_not_drop_the_baseline_report() {
    let (_guard, mut counts) = crate::test_log_capture::live_counts_at(&[(Level::WARN, "Lagged")]);
    let backend = Arc::new(CapabilityBackend::new(
        "caps",
        Arc::new(CapabilityExecutor::new()),
    ));
    backend.begin_initial_scan();
    assert!(
        !backend.initial_scan_complete(),
        "the scan starts incomplete"
    );
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let changes: CatalogueChanged = Arc::new(|_name: &str| {});
    let _watcher = CapabilityWatcher::start(backend, shutdown_rx, Some(changes))
        .expect("start with no directories succeeds");
    // No await between spawn and sends: on a current-thread runtime the report
    // task cannot run until the wait below, so both sends land first and the
    // first recv is Lagged deterministically.
    shutdown_tx.send(()).expect("the first shutdown send lands");
    shutdown_tx
        .send(())
        .expect("the second shutdown send lands");
    tokio::time::timeout(Duration::from_secs(2), counts.wait_for(|v| v[0] >= 1))
        .await
        .expect("a warn naming Lagged within 2 s")
        .expect("the log counter is alive");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(counts.borrow()[0], 1, "Lagged warns exactly once");
}

/// MIK-8651.LOUD.1 candidate e: the in-flight bookkeeping warns once at
/// `reload_slow`, naming the stage ("scan" | "reload" | "callback"), and is
/// silent before and after. Non-cancellation is structural (the reload runs in
/// its own spawned task and the loop never awaits it); the full-loop version
/// needs a seam this PR does not add. Red on base: the shell returns None.
#[test]
fn slow_reload_warns_once_and_is_not_cancelled() {
    let started = Instant::now();
    let mut inflight = InFlight {
        started,
        stage: Arc::new(std::sync::atomic::AtomicU8::new(2)),
        warned: false,
    };
    let slow = Duration::from_secs(60);
    assert_eq!(
        inflight.slow_warning(started + Duration::from_secs(59), slow),
        None,
        "silent before the deadline"
    );
    let message = inflight
        .slow_warning(started + Duration::from_secs(60), slow)
        .expect("warns once at the deadline");
    assert!(
        message.contains("reload"),
        "the warn names the stage: {message}"
    );
    assert_eq!(
        inflight.slow_warning(started + Duration::from_secs(61), slow),
        None,
        "silent after warning once"
    );
}
