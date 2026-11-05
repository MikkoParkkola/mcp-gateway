// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The watcher starts no reload while the startup capability scan is still
//! running: the scan's own pin-mismatch check must never run beside a
//! watcher reload, or it can unload bytes that reload just restored. A held
//! reload is not lost: it runs once the scan completes, and one held past
//! the slow bound is named in a warning.

use super::*;

/// The scan-wait warning, as the loop logs it.
const HELD_WARN: &str = "capability reload waits for the startup capability scan";

/// A reload task over `dir` whose backend is still in its startup scan, and
/// the event sender that nudges it.
async fn held_over(dir: &Path, tuning: ReloadTuning) -> (Arc<CapabilityBackend>, mpsc::Sender<()>) {
    let backend = backend_over(dir).await;
    backend.begin_initial_scan();
    let (event_tx, event_rx) = mpsc::channel(100);
    let shutdown_rx = broadcast::channel(1).0.subscribe();
    CapabilityWatcher::spawn_reload_task_tuned(
        Arc::clone(&backend),
        event_rx,
        shutdown_rx,
        None,
        tuning,
    );
    (backend, event_tx)
}

/// One edit during the scan: held until the scan completes, then applied.
async fn held_then_applied(tuning: ReloadTuning) {
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v1")).expect("write v1");
    let (backend, event_tx) = held_over(dir.path(), tuning).await;
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v2-much-longer")).expect("write v2");
    event_tx.send(()).await.expect("the event lands");
    // timing: absence
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        description_of(&backend, "a").as_deref(),
        Some("v1"),
        "no reload while the startup scan runs"
    );
    backend.mark_initial_scan_complete();
    assert!(
        eventually(crate::test_wait::HANG_BOUND, || {
            description_of(&backend, "a").as_deref() == Some("v2-much-longer")
        })
        .await,
        "the held reload runs once the scan completes"
    );
}

/// Mutant: the gate removed: the edit reloads during the scan.
#[tokio::test(flavor = "current_thread")]
async fn a_file_event_during_the_startup_scan_reloads_only_after_it() {
    held_then_applied(ReloadTuning {
        // Off explicitly: the default turns the stale check on.
        stale_check: None,
        debounce: Duration::from_millis(50),
        ..ReloadTuning::default()
    })
    .await;
}

/// The stale check's before-fingerprint path is held the same way.
/// Mutant: the gate removed: the edit reloads during the scan.
#[tokio::test(flavor = "current_thread")]
async fn with_the_stale_check_on_a_reload_also_waits_for_the_scan() {
    held_then_applied(ReloadTuning {
        stale_check: Some(Duration::from_millis(200)),
        debounce: Duration::from_millis(50),
        ..ReloadTuning::default()
    })
    .await;
}

/// A reload held past the slow bound is named once, not silently dropped,
/// however often file events keep arriving meanwhile.
/// Mutants: the warning removed, or timed from the last event: none logged.
#[tokio::test(flavor = "current_thread")]
async fn a_reload_held_past_the_slow_bound_is_warned_once() {
    let (_guard, counts) = crate::test_log_capture::live_counts_at(&[(Level::WARN, HELD_WARN)]);
    let dir = tempfile::tempdir().expect("a tempdir for caps");
    std::fs::write(dir.path().join("a.yaml"), cap_yaml("a", "v1")).expect("write v1");
    let (_backend, event_tx) = held_over(
        dir.path(),
        ReloadTuning {
            debounce: Duration::from_millis(50),
            reload_slow: Duration::from_millis(200),
            ..ReloadTuning::default()
        },
    )
    .await;
    // Events keep arriving, each past the debounce but inside the slow
    // bound: the wait is timed from the first held reload, so it still warns.
    for _ in 0..8 {
        event_tx.send(()).await.expect("the event lands");
        // timing: absence
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Asserted before the quiet period: a timer reset by each event would
    // still be silent here, and would only fire once the events stop.
    assert_eq!(counts.borrow()[0], 1, "warned while events kept arriving");
    // timing: absence
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(counts.borrow()[0], 1, "one warning for one held reload");
}
