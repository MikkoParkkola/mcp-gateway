// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! L rows: the checkpoint passes run at the signal and every second
//! after, a stalled write holds back no other class, the passes stop before the
//! last one, which ends at its deadline, and the drains leave it its slice.
//!
//! Saves run on OS threads, so the rows wait for them in real time
//! (`wait_real_time`) while tokio's clock stays paused: no wall-clock window
//! decides a pass's time.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::time::Duration;

use tokio::time::Instant;

use super::*;
use crate::test_wait::wait_real_time;

/// Real time a save thread's call may take to show.
const SHOW: Duration = Duration::from_secs(5);
/// Real time given to a call that must not happen. An absence window: a stall
/// can only hide a wrong call, never fail the row. A deterministic signal from
/// the save path would remove the wait.
const QUIET: Duration = Duration::from_secs(1);

/// A class whose saves count their calls and report a write.
fn counting(name: &'static str) -> (Class, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let (checkpoints, lasts) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (c, l) = (Arc::clone(&checkpoints), Arc::clone(&lasts));
    let class = Class {
        name,
        root: None,
        checkpoint: Arc::new(move || {
            c.fetch_add(1, SeqCst);
            true
        }),
        last: Arc::new(move || {
            l.fetch_add(1, SeqCst);
            true
        }),
    };
    (class, checkpoints, lasts)
}

/// A save that blocks until its guard drops, so a failed row frees its thread.
struct Stall(Arc<AtomicBool>);

impl Stall {
    fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    fn save(&self) -> Save {
        let released = Arc::clone(&self.0);
        Arc::new(move || {
            while !released.load(SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            true
        })
    }
}

impl Drop for Stall {
    fn drop(&mut self) {
        self.0.store(true, SeqCst);
    }
}

async fn reaches(count: &AtomicUsize, n: usize, what: &str) {
    if let Err(e) = wait_real_time(SHOW, || count.load(SeqCst) == n).await {
        panic!("{what}: {n} calls {e}; saw {}", count.load(SeqCst));
    }
}

async fn quiet() {
    let _ = wait_real_time(QUIET, || false).await;
}

/// L-first (D1): the first pass runs at the signal, before any time passes.
#[tokio::test(start_paused = true)]
async fn l_first_the_first_pass_runs_at_the_signal() {
    let (class, calls, _) = counting("x");
    let checkpoints = Checkpoints::new(vec![class]);
    let t0 = Instant::now();
    checkpoints.start();
    reaches(&calls, 1, "the first pass").await;
    assert_eq!(
        t0.elapsed(),
        Duration::ZERO,
        "the first pass waited for time to pass"
    );
}

/// L-interval (D5): passes at 0, 1, 2 and 3 s, and none between.
#[tokio::test(start_paused = true)]
async fn l_interval_a_pass_runs_every_second() {
    let (class, calls, _) = counting("x");
    let checkpoints = Checkpoints::new(vec![class]);
    checkpoints.start();
    reaches(&calls, 1, "the pass at 0 s").await;
    for n in 2..=4 {
        tokio::time::advance(Duration::from_secs(1)).await;
        reaches(&calls, n, "a pass one second after the last").await;
    }
    // limit-under-test (paused-clock): moves the paused clock to mid-second, between two passes
    tokio::time::advance(Duration::from_millis(500)).await;
    quiet().await;
    assert_eq!(calls.load(SeqCst), 4, "a pass ran between the seconds");
}

/// L-stall (D1/D5): one class's write stalls; the other class still runs at
/// passes 2 and 3.
#[tokio::test(start_paused = true)]
async fn l_stall_a_stalled_write_holds_back_no_other_class() {
    let stall = Stall::new();
    let stalled = Class {
        name: "stalled",
        root: None,
        checkpoint: stall.save(),
        last: Arc::new(|| true),
    };
    let (other, calls, _) = counting("other");
    let checkpoints = Checkpoints::new(vec![stalled, other]);
    checkpoints.start();
    reaches(&calls, 1, "pass 1").await;
    for n in 2..=3 {
        tokio::time::advance(Duration::from_secs(1)).await;
        reaches(&calls, n, "a pass while the other class's write is stalled").await;
    }
    drop(stall);
}

/// L-last (D5): after `finish` no pass runs, and the last pass writes every
/// class once, waiting its turn.
#[tokio::test(start_paused = true)]
async fn l_last_the_passes_stop_and_one_last_pass_follows() {
    let (a, a_passes, a_last) = counting("a");
    let (b, b_passes, b_last) = counting("b");
    let checkpoints = Checkpoints::new(vec![a, b]);
    checkpoints.start();
    reaches(&a_passes, 1, "a's pass 1").await;
    reaches(&b_passes, 1, "b's pass 1").await;
    checkpoints
        .finish(Instant::now() + Duration::from_secs(5))
        .await;
    reaches(&a_last, 1, "a's last pass").await;
    reaches(&b_last, 1, "b's last pass").await;
    tokio::time::advance(Duration::from_secs(3)).await;
    quiet().await;
    assert_eq!(
        (a_passes.load(SeqCst), b_passes.load(SeqCst)),
        (1, 1),
        "a pass ran after the last one"
    );
    assert_eq!(
        (a_last.load(SeqCst), b_last.load(SeqCst)),
        (1, 1),
        "the last pass wrote a class more than once"
    );
}

/// L-stall-last (D5 budget): with one class's last write blocked forever, the
/// last pass returns at its deadline exactly, and the other class has written.
#[tokio::test(start_paused = true)]
async fn l_stall_last_the_last_pass_ends_at_its_deadline() {
    let stall = Stall::new();
    let stuck = Class {
        name: "stuck",
        root: None,
        checkpoint: Arc::new(|| true),
        last: stall.save(),
    };
    let (quick, _, quick_last) = counting("quick");
    let checkpoints = Checkpoints::new(vec![stuck, quick]);
    let t0 = Instant::now();
    let given = Duration::from_secs(2);
    let ended = tokio::time::timeout(Duration::from_secs(60), checkpoints.finish(t0 + given)).await;
    assert!(ended.is_ok(), "the last pass outlived its deadline");
    assert_eq!(
        t0.elapsed(),
        given,
        "the last pass did not end at its deadline"
    );
    reaches(&quick_last, 1, "the other class's last write").await;
    drop(stall);
}

/// L-budget (D5): at the default 30 s total, Dp falls 17.35 s after the
/// trigger (30 - 10.4 backend - 2.25 terminal); the drains end 100 ms before
/// it and the last pass ends at it.
#[tokio::test(start_paused = true)]
async fn l_budget_the_drains_leave_the_last_pass_its_slice() {
    let t0 = Instant::now();
    let budget = StopBudget::fixed_at(t0, Duration::from_secs(30));
    let dp = t0 + Duration::from_millis(17_350);
    assert_eq!(
        budget.post_listener_end(),
        dp,
        "premise: Dp at the default total"
    );
    assert_eq!(drains_end(&budget), t0 + Duration::from_millis(17_250));
    assert_eq!(
        drain_window(&budget, t0),
        Duration::from_secs(10),
        "a drain from the trigger keeps its 10 s cap"
    );
    assert_eq!(
        drain_window(&budget, t0 + Duration::from_secs(10)),
        Duration::from_millis(7_250)
    );
    assert_eq!(
        drain_window(&budget, t0 + Duration::from_millis(17_250)),
        Duration::ZERO
    );
    assert_eq!(
        last_deadline(&budget),
        dp,
        "the last pass does not end at Dp"
    );
}

/// L-classes (D1): the real pass set names every class the stop saves, in the
/// order a pass starts them; each class's checkpoint writes its file; health's
/// is the periodic save, so a restart read from its file finds no clean stop.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn l_classes_the_real_pass_set() {
    use crate::health_history::{DowntimeSource, HealthHistory, Restores};
    let dir = crate::test_dir_keep::kept_tempdir();
    let data = dir.path();
    let now = crate::clock::unix_secs().unwrap();
    let ranker = Arc::new(crate::ranking::SearchRanker::new());
    ranker.record_use("s", "t");
    let tracker = Arc::new(crate::transition::TransitionTracker::new());
    let cost_config = crate::cost_accounting::config::CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    let (_, enforcer) = super::super::persistence::boot_cost_governance(&cost_config, data);
    let counters = super::super::counter_wiring::restore(data);
    let (_stop, stopped) = tokio::sync::broadcast::channel(1);
    let (health, _saver) =
        super::super::health_wiring::start_history(data, now, Restores::Counted(1), stopped);
    // The start saved health.json once; the pass must write it again.
    std::fs::remove_file(data.join("health.json")).unwrap();
    let all = classes(
        (ranker, data.join("usage.json")),
        (tracker, data.join("transitions.json")),
        enforcer.map(|enforcer| {
            let costs = Arc::new(crate::cost_accounting::CostTracker::new());
            (enforcer, costs, data.to_path_buf())
        }),
        &counters,
        &health,
    );
    let names: Vec<&str> = all.iter().map(|class| class.name).collect();
    assert_eq!(
        names,
        ["usage", "transitions", "cost", "counters", "health"]
    );
    // Each class keeps the file or dir it writes (K10, `crate::spawn_keep`).
    let roots: Vec<Option<std::path::PathBuf>> =
        all.iter().map(|class| class.root.clone()).collect();
    assert_eq!(
        roots,
        [
            Some(data.join("usage.json")),
            Some(data.join("transitions.json")),
            Some(data.to_path_buf()),
            Some(data.join("counters.json")),
            Some(data.join("health.json")),
        ]
    );
    // Retried: the cost lock is process-wide, so another row's save can make
    // one checkpoint skip.
    for class in &all {
        let wrote = wait_real_time(SHOW, || (class.checkpoint)()).await;
        assert!(wrote.is_ok(), "{}'s checkpoint never wrote", class.name);
    }
    for file in [
        "usage.json",
        "transitions.json",
        "costs.json",
        "counters.json",
        "health.json",
    ] {
        assert!(data.join(file).exists(), "the pass did not write {file}");
    }
    let downtime = || {
        let bytes = std::fs::read(data.join("health.json")).unwrap();
        let (_, started) = HealthHistory::start(Some(&bytes), Restores::Counted(2), now + 60);
        started.restart.expect("premise: a restart").downtime_source
    };
    assert_eq!(
        downtime(),
        DowntimeSource::Estimated,
        "a checkpoint recorded a clean stop"
    );
    // Both sides: the shutdown's own save records one.
    health.shutdown_save().run_now();
    assert_eq!(
        downtime(),
        DowntimeSource::Measured,
        "premise: a clean stop reads as measured"
    );
}
