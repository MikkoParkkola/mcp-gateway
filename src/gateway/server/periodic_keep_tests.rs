// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A periodic saver keeps the temp dir a test registered while each tick's
//! save runs, and reports a plain one once, at start (family
//! test-temp-sidecar-leak, rows K8, K8b, K8p, K11 and K11b).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::*;
use crate::test_dir_keep::{expect_unkept, held_then_gone, kept_tempdir};
use crate::test_pause::Release;

/// An interval no row waits out in real time: every row pauses the clock.
const EVERY: Duration = Duration::from_secs(300);

/// How long a row waits for a signal from a save thread, or for a dir to go.
const BOUND: Duration = Duration::from_secs(30);

fn this_test() -> String {
    std::thread::current()
        .name()
        .expect("a test thread")
        .to_owned()
}

/// Drive one tick of the saver writing `root` up to its pre-save gate, then
/// abort and await the saver: only the tick's own thread is left running.
async fn hold_one_tick(
    seams: &PeriodicSeams,
    reached: Arc<tokio::sync::Notify>,
    every: Duration,
    saver: tokio::task::JoinHandle<()>,
) {
    crate::test_pause::within("the saver's loop started", seams.loop_started.notified()).await;
    tokio::time::advance(every).await;
    crate::test_pause::within("the tick's thread spawned", seams.writer_spawned.notified()).await;
    // Blocking: the runtime's only thread must not let the paused clock
    // auto-advance into another tick meanwhile.
    crate::test_pause::reached_blocking("the tick's pre-save gate", &reached);
    saver.abort();
    let ended = saver.await;
    assert!(
        ended
            .as_ref()
            .is_err_and(tokio::task::JoinError::is_cancelled),
        "the saver was not cancelled: {ended:?}"
    );
}

/// K8. One tick's save in a kept dir, held before it runs while the saver is
/// aborted and the test drops its share: the dir stays until that save
/// returns, then goes, and the save ran exactly once.
/// Mutant: `spawn_periodic_save` left without the per-tick keep.
#[tokio::test(start_paused = true)]
async fn a_periodic_save_keeps_its_dir_until_the_ticks_save_returns() {
    let dir = kept_tempdir();
    let root = dir.path().to_path_buf();
    let file = root.join("saved.json");
    let seams = periodic_seams(&file);
    let (reached, release) = seams.pre_save.arm();
    let runs = Arc::new(AtomicUsize::new(0));
    let saver = spawn_periodic_save("k8 save", EVERY, None, Some(file.clone()), {
        let (runs, file) = (Arc::clone(&runs), file.clone());
        move || {
            runs.fetch_add(1, Ordering::SeqCst);
            let _ = std::fs::write(&file, b"{}");
        }
    });
    hold_one_tick(&seams, reached, EVERY, saver).await;
    drop(dir);
    let release = Release(release);
    held_then_gone(&root, || release.now()).await;
    assert_eq!(
        runs.load(Ordering::SeqCst),
        1,
        "the tick's save ran other than once"
    );
}

/// K8b. Between ticks the saver keeps its dir: the test drops its share while
/// the saver lives and no tick runs, the dir is still there, the next tick's
/// save lands in it, and the dir goes once the saver ends.
/// Mutant: `spawn_periodic_save` without the keep it holds for its life (each
/// tick looking the dir up again).
#[tokio::test(start_paused = true)]
async fn a_periodic_saver_keeps_its_dir_between_ticks() {
    let dir = kept_tempdir();
    let root = dir.path().to_path_buf();
    let file = root.join("saved.json");
    let seams = periodic_seams(&file);
    let runs = Arc::new(AtomicUsize::new(0));
    let saver = spawn_periodic_save("k8b save", EVERY, None, Some(file.clone()), {
        let (runs, file) = (Arc::clone(&runs), file.clone());
        // Counted after the write, so a counted save has landed or failed.
        move || {
            let _ = std::fs::write(&file, b"{}");
            runs.fetch_add(1, Ordering::SeqCst);
        }
    });
    crate::test_pause::within("the saver's loop started", seams.loop_started.notified()).await;
    drop(dir);
    assert!(
        root.exists(),
        "the dir was removed between ticks while its saver lives"
    );
    tokio::time::advance(EVERY).await;
    let ran = crate::test_wait::wait_real_time(BOUND, || runs.load(Ordering::SeqCst) >= 1).await;
    assert!(ran.is_ok(), "the next tick did not run its save");
    assert!(
        file.exists(),
        "the tick's save did not land in the kept dir"
    );
    saver.abort();
    let _ = saver.await;
    let gone = crate::test_wait::wait_real_time(BOUND, || !root.exists()).await;
    assert!(
        gone.is_ok(),
        "the dir stayed after the saver ended; left: {:?}",
        crate::test_dir_keep::listing(&root)
    );
}

/// K8p. A periodic saver on a plain temp dir is recorded once, when
/// `spawn_periodic_save` returns, before any tick; three ticks later the count
/// is still one. The save writes nothing, so no tick can leave a file behind.
/// Mutant: the report taken per tick, or on a tick's thread.
#[tokio::test(start_paused = true)]
async fn a_plain_dir_periodic_saver_is_recorded_once_at_start() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let file = dir.path().join("saved.json");
    // The loop-started signal only: the saver's interval starts inside its
    // task, so a tick advanced before the task first ran would never come.
    let seams = periodic_seams(&file);
    let runs = Arc::new(AtomicUsize::new(0));
    let unkept = expect_unkept();
    let saver = spawn_periodic_save("k8p save", EVERY, None, Some(file.clone()), {
        let runs = Arc::clone(&runs);
        move || {
            runs.fetch_add(1, Ordering::SeqCst);
        }
    });
    let want = vec![("periodic save", file.clone(), this_test())];
    assert_eq!(unkept.recorded(), want, "not recorded once at start");
    crate::test_pause::within("the saver's loop started", seams.loop_started.notified()).await;
    for tick in 1..=3 {
        tokio::time::advance(EVERY).await;
        let ran =
            crate::test_wait::wait_real_time(BOUND, || runs.load(Ordering::SeqCst) >= tick).await;
        assert!(ran.is_ok(), "tick {tick} did not run its save");
    }
    assert_eq!(unkept.recorded(), want, "a tick recorded another line");
    saver.abort();
    let _ = saver.await;
}

/// The periodic saver call sites in `files`, excluding the definition.
fn periodic_callers(files: &[(String, String)]) -> Vec<String> {
    let calls = super::shutdown_keep_tests::production_matches(files, "spawn_periodic_save(");
    let defined = super::shutdown_keep_tests::production_matches(files, "fn spawn_periodic_save(");
    let mut callers = calls;
    for definition in defined {
        let at = callers
            .iter()
            .position(|c| *c == definition)
            .expect("the definition is also a match");
        callers.remove(at);
    }
    callers
}

/// K11. Exactly the five callers the design's table lists start a periodic
/// saver (counters, health save, health sample, stdio telemetry, costs), so
/// a new one fails here until its root is decided; a planted sixth caller
/// fails by name.
#[test]
fn exactly_five_callers_start_a_periodic_saver() {
    let files = super::shutdown_keep_tests::source_files();
    let callers = periodic_callers(&files);
    let mut names: Vec<&str> = callers
        .iter()
        .filter_map(|c| std::path::Path::new(c).file_name()?.to_str())
        .collect();
    names.sort_unstable();
    // By file, so a caller swapped for an uncovered one fails too, not only a sixth.
    assert_eq!(
        names,
        [
            "counter_wiring.rs",
            "health_wiring.rs",
            "health_wiring.rs",
            "persistence.rs",
            "stdio_loop.rs"
        ],
        "periodic saver callers: {callers:?}"
    );
    let mut planted = files;
    planted.push((
        "planted/sixth.rs".to_owned(),
        "fn sixth() { spawn_periodic_save(\"x\", EVERY, None, None, || ()); }".to_owned(),
    ));
    let callers = periodic_callers(&planted);
    assert_eq!(callers.len(), 6);
    assert!(
        callers.iter().any(|c| c == "planted/sixth.rs"),
        "the planted caller is not named: {callers:?}"
    );
}

/// K11c. The stdio protocol-telemetry saver names its data dir as the dir to
/// keep, so a tick's save in a test cannot outlive that test's dir. The saver
/// starts inside the stdio loop, so this reads the call rather than running
/// a stdio gateway.
/// Mutant: `stdio_loop.rs` passing `None` as that argument.
#[test]
fn the_stdio_telemetry_saver_names_its_data_dir_to_keep() {
    let files = super::shutdown_keep_tests::source_files();
    let (_, text) = files
        .iter()
        .find(|(path, _)| path.ends_with("stdio_loop.rs"))
        .expect("the stdio loop's source");
    let call = text
        .split("spawn_periodic_save(")
        .nth(1)
        .expect("the stdio loop starts a periodic saver");
    let args: Vec<&str> = call.split(',').take(4).map(str::trim).collect();
    assert_eq!(
        args.get(3).copied(),
        Some("Some(data_dir.clone())"),
        "the stdio saver's dir to keep: {args:?}"
    );
}

/// K11b. The counter saver keeps counters.json's dir while a tick's save runs.
#[tokio::test(start_paused = true)]
async fn the_counter_saver_keeps_its_dir_through_a_tick() {
    let dir = kept_tempdir();
    let root = dir.path().to_path_buf();
    let seams = periodic_seams(&root.join("counters.json"));
    let (reached, release) = seams.pre_save.arm();
    let meta =
        crate::gateway::meta_mcp::MetaMcp::new(Arc::new(crate::backend::BackendRegistry::new()));
    let (stop, _) = tokio::sync::broadcast::channel(1);
    let (counters, saver) = super::super::counter_wiring::start(&root, &meta, stop.subscribe());
    hold_one_tick(
        &seams,
        reached,
        super::super::counter_wiring::COUNTER_SAVE_INTERVAL,
        saver,
    )
    .await;
    drop((counters, dir));
    let release = Release(release);
    held_then_gone(&root, || release.now()).await;
}

/// K11b. The health saver keeps health.json's dir while a tick's save runs.
#[tokio::test(start_paused = true)]
async fn the_health_saver_keeps_its_dir_through_a_tick() {
    let dir = kept_tempdir();
    let root = dir.path().to_path_buf();
    let seams = periodic_seams(&root.join("health.json"));
    let (reached, release) = seams.pre_save.arm();
    let (stop, _) = tokio::sync::broadcast::channel(1);
    let (health, saver) = super::super::health_wiring::start_history(
        &root,
        crate::clock::unix_secs().expect("a clock"),
        crate::health_history::Restores::Counted(0),
        stop.subscribe(),
    );
    hold_one_tick(
        &seams,
        reached,
        super::super::counter_wiring::COUNTER_SAVE_INTERVAL,
        saver,
    )
    .await;
    drop((health, dir));
    let release = Release(release);
    held_then_gone(&root, || release.now()).await;
}

/// K11b. The cost saver keeps its data dir while a tick's save runs.
#[cfg(feature = "cost-governance")]
#[tokio::test(start_paused = true)]
async fn the_cost_saver_keeps_its_dir_through_a_tick() {
    let dir = kept_tempdir();
    let root = dir.path().to_path_buf();
    let seams = periodic_seams(&root);
    let (reached, release) = seams.pre_save.arm();
    let cfg = CostGovernanceConfig {
        enabled: true,
        ..CostGovernanceConfig::default()
    };
    let registry = Arc::new(CostRegistry::new(&cfg));
    let enforcer = Arc::new(BudgetEnforcer::new(cfg, registry));
    let tracker = Arc::new(crate::cost_accounting::CostTracker::new());
    let saver = spawn_cost_saver(enforcer, tracker, root.clone(), EVERY, None);
    hold_one_tick(&seams, reached, EVERY, saver).await;
    drop(dir);
    let release = Release(release);
    held_then_gone(&root, || release.now()).await;
}
