// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Failing-first tests for MIK-8651: the capability hot-reload task must warn
//! loudly instead of stopping silently, and a stale-catalogue check must heal
//! a dead event source.
//!
//! The tests drive `CapabilityWatcher::spawn_reload_task` directly with a real
//! `CapabilityBackend` over a tempdir; the real `notify` watcher is not
//! exercised here. Log assertions use `crate::test_log_capture::live_count`,
//! which counts records on this thread, so every test runs on a
//! current-thread runtime and holds the capture guard for the whole test.

use tokio::sync::{broadcast, mpsc};

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
/// about the lag, then the retained shutdown still stops the task.
#[tokio::test(flavor = "current_thread")]
async fn lagged_shutdown_warns_then_stops() {
    let (_guard, mut lagged) = crate::test_log_capture::live_count("Lagged");
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
    tokio::time::timeout(Duration::from_secs(2), lagged.wait_for(|n| *n >= 1))
        .await
        .expect("a warn naming Lagged within 2 s")
        .expect("the log counter is alive");
    assert!(
        eventually(Duration::from_secs(2), || event_tx.is_closed()).await,
        "the retained shutdown stops the task"
    );
}

/// MIK-8651.CAUSE.1 a, LOUD.1: a dropped shutdown sender warns once and the
/// task keeps reloading on file events.
#[tokio::test(flavor = "current_thread")]
async fn closed_shutdown_keeps_reloading() {
    let (_guard, mut closed) = crate::test_log_capture::live_count("shutdown channel closed");
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
    tokio::time::timeout(Duration::from_secs(2), closed.wait_for(|n| *n >= 1))
        .await
        .expect("a warn that the shutdown channel closed within 2 s")
        .expect("the log counter is alive");
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
/// heals an edit by mtime and warns that no file event arrived.
#[tokio::test(flavor = "current_thread")]
async fn a_dead_event_source_heals_by_mtime_open_sender() {
    let (_guard, mut healed) = crate::test_log_capture::live_count("no file event arrived");
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
    // `event_tx` stays alive and never sends: the event source is silent.
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v2-much-longer")).expect("write v2");
    assert!(
        eventually(Duration::from_secs(3), || {
            description_of(&backend, "a").as_deref() == Some("v2-much-longer")
        })
        .await,
        "the stale check heals the edit with no file event"
    );
    tokio::time::timeout(Duration::from_secs(2), healed.wait_for(|n| *n >= 1))
        .await
        .expect("a heal warn within 2 s")
        .expect("the log counter is alive");
    drop(event_tx);
}

/// MIK-8651.HEAL.1: with the event sender dropped, the stale check still heals
/// by mtime; the task warns that the event source is gone and that no file
/// event arrived.
#[tokio::test(flavor = "current_thread")]
async fn a_dead_event_source_heals_by_mtime_dropped_sender() {
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
    {
        let (_guard, mut gone) = crate::test_log_capture::live_count("event source is gone");
        CapabilityWatcher::spawn_reload_task_tuned(
            Arc::clone(&backend),
            event_rx,
            shutdown_rx,
            None,
            tuning,
        );
        tokio::time::timeout(Duration::from_secs(2), gone.wait_for(|n| *n >= 1))
            .await
            .expect("a warn that the event source is gone within 2 s")
            .expect("the log counter is alive");
    }
    let (_guard, mut healed) = crate::test_log_capture::live_count("no file event arrived");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v2-much-longer")).expect("write v2");
    assert!(
        eventually(Duration::from_secs(3), || {
            description_of(&backend, "a").as_deref() == Some("v2-much-longer")
        })
        .await,
        "the stale check heals the edit with the event sender dropped"
    );
    tokio::time::timeout(Duration::from_secs(2), healed.wait_for(|n| *n >= 1))
        .await
        .expect("a heal warn within 2 s")
        .expect("the log counter is alive");
}

/// MIK-8651.HEAL.1: with the event source dead, the stale check picks up an
/// added file.
#[tokio::test(flavor = "current_thread")]
async fn heal_sees_a_file_added() {
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
    std::fs::write(dir.path().join("b.yaml"), cap_yaml("b", "b-added-here")).expect("write b");
    assert!(
        eventually(Duration::from_secs(3), || {
            description_of(&backend, "b").as_deref() == Some("b-added-here")
                && description_of(&backend, "a").as_deref() == Some("v1")
        })
        .await,
        "the added file appears in the catalogue"
    );
}

/// MIK-8651.HEAL.1: with the event source dead, the stale check drops a
/// removed file from the catalogue.
#[tokio::test(flavor = "current_thread")]
async fn heal_sees_a_file_removed() {
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
    std::fs::remove_file(dir.path().join("b.yaml")).expect("remove b");
    assert!(
        eventually(Duration::from_secs(3), || {
            description_of(&backend, "b").is_none()
                && description_of(&backend, "a").as_deref() == Some("v1")
        })
        .await,
        "the removed file leaves the catalogue while the rest stays"
    );
}

/// MIK-8651.HEAL.1: an edit that lands just after a reload-triggering event is
/// not lost: the catalogue ends up at the latest write.
#[tokio::test(flavor = "current_thread")]
async fn an_edit_during_a_reload_is_not_lost() {
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v1")).expect("write v1");
    let backend = backend_over(dir.path()).await;
    let (event_tx, event_rx) = mpsc::channel(100);
    let (_shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let tuning = ReloadTuning {
        stale_check: Some(Duration::from_millis(200)),
        ..ReloadTuning::default()
    };
    CapabilityWatcher::spawn_reload_task_tuned(
        Arc::clone(&backend),
        event_rx,
        shutdown_rx,
        None,
        tuning,
    );
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v2-longer")).expect("write v2");
    event_tx.send(()).await.expect("the task takes the event");
    // Immediately: the second edit lands inside the debounce window, so one
    // reload serves v3. That already holds today; this row guards against
    // losing the edit, it does not discriminate the heal.
    std::fs::write(
        dir.path().join("a.yaml"),
        cap_yaml("a", "v3-much-much-longer"),
    )
    .expect("write v3");
    assert!(
        eventually(Duration::from_secs(3), || {
            description_of(&backend, "a").as_deref() == Some("v3-much-much-longer")
        })
        .await,
        "the second edit is not lost"
    );
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

/// MIK-8651 control: with no edits, the stale check ticks without reloading.
#[tokio::test(flavor = "current_thread")]
async fn no_spurious_heal() {
    let (_guard, reloads) = crate::test_log_capture::live_count("Hot-reloading capabilities");
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
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(*reloads.borrow(), 0, "no reload runs when nothing changed");
    drop(event_tx);
}
