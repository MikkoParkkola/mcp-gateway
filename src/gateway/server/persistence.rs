// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::fmt::Display;
use std::path::{Path, PathBuf};
#[cfg(feature = "cost-governance")]
use std::sync::PoisonError;

use tracing::{info, warn};

#[cfg(feature = "cost-governance")]
use crate::cost_accounting::{
    CostTracker, config::CostGovernanceConfig, enforcer::BudgetEnforcer, registry::CostRegistry,
};
use std::sync::Arc;

pub(super) fn standard_data_dir() -> PathBuf {
    crate::config_persistence::gateway_data_dir()
}

pub(super) fn ensure_data_dir(path: &Path) {
    if let Err(e) = std::fs::create_dir_all(path) {
        warn!(error = %e, "Failed to create data directory");
    }
}

pub(super) fn load_if_exists<F, E>(
    path: &Path,
    load: F,
    error_message: &'static str,
    success_message: &'static str,
) where
    F: FnOnce(&Path) -> Result<(), E>,
    E: Display,
{
    if path.exists() {
        if let Err(e) = load(path) {
            warn!(error = %e, "{error_message}");
        } else {
            info!("{success_message}");
        }
    }
}

pub(super) fn save_with_logging<F, E>(
    path: &Path,
    save: F,
    error_message: &'static str,
    success_message: &'static str,
) -> bool
where
    F: FnOnce(&Path) -> Result<(), E>,
    E: Display,
{
    if let Err(e) = save(path) {
        warn!(error = %e, "{error_message}");
        false
    } else {
        info!("{success_message}");
        true
    }
}

/// The shutdown step that writes today's spend, as an abandoned step is logged
/// at ERROR: it names the file an operator will find stale (MIK-8157.SAVE.3).
#[cfg(feature = "cost-governance")]
pub(super) const COST_SAVE_STEP: &str = "final cost save (costs.json)";

/// Build the cost registry and budget enforcer when governance is enabled,
/// seeded from `costs.json` in `data_dir` so a restart keeps today's spend.
///
/// `costs.json` is per-process state: every replica keeps its own copy.
#[cfg(feature = "cost-governance")]
pub(super) fn boot_cost_governance(
    cfg: &CostGovernanceConfig,
    data_dir: &Path,
) -> (Option<Arc<CostRegistry>>, Option<Arc<BudgetEnforcer>>) {
    use crate::cost_accounting::persistence;

    if !cfg.enabled {
        return (None, None);
    }
    let registry = Arc::new(CostRegistry::new(cfg));
    let enforcer = Arc::new(BudgetEnforcer::new(cfg.clone(), Arc::clone(&registry)));
    load_if_exists(
        &data_dir.join("costs.json"),
        |path| persistence::load(path).map(|persisted| enforcer.restore(&persisted)),
        "Failed to load persisted cost data",
        "Loaded persisted cost data",
    );
    let restored = enforcer.snapshot();
    info!(
        global_daily_usd = restored.global_daily_usd,
        tools = restored.tool_daily.len(),
        keys = restored.key_daily.len(),
        "Cost governance enabled"
    );
    (Some(registry), Some(enforcer))
}

/// How often a running gateway saves today's spend to `costs.json`. A hard
/// kill loses at most this much.
#[cfg(feature = "cost-governance")]
pub(super) const COST_SAVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

/// How often a stdio session saves its protocol-revision window (MIK-8364).
/// A hard crash loses the observations since the last completed save:
/// normally at most this interval plus one write's duration.
pub(super) const PROTOCOL_TELEMETRY_SAVE_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(1);

/// Save today's spend to `<data_dir>/costs.json`. Returns whether it wrote.
#[cfg(feature = "cost-governance")]
pub(super) fn save_costs(
    enforcer: &BudgetEnforcer,
    tracker: &CostTracker,
    data_dir: &Path,
) -> bool {
    let turn = COST_WRITE.lock().unwrap_or_else(PoisonError::into_inner);
    write_costs(enforcer, tracker, data_dir, &turn)
}

/// One `costs.json` write at a time, each snapshotting the spend under the
/// lock: whichever write lands last holds the newest spend, so no save has to
/// wait for another to stop first (MIK-8157).
#[cfg(feature = "cost-governance")]
static COST_WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The data directory of each periodic save skipped because `COST_WRITE` was
/// held: a test observes its own skip instead of guessing when it happened
/// (MIK-8216). Keyed by directory, since the lock is process-wide.
#[cfg(all(test, feature = "cost-governance"))]
static SKIPPED_SAVES: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

#[cfg(feature = "cost-governance")]
fn write_costs(
    enforcer: &BudgetEnforcer,
    tracker: &CostTracker,
    data_dir: &Path,
    _turn: &std::sync::MutexGuard<'_, ()>,
) -> bool {
    let Ok(snapshot) = enforcer.snapshot_for_save() else {
        tracing::warn!("Clock reads before 1970; cost save skipped, the last saved spend stands");
        return false;
    };
    let persisted = super::support::build_persisted_costs(&snapshot);
    let wrote = save_with_logging(
        &data_dir.join("costs.json"),
        |path| crate::cost_accounting::persistence::save(path, &persisted),
        "Failed to save cost governance data",
        "Saved cost governance data",
    );
    // The history follows in this same turn. A history that fails to write
    // is logged by its saver and leaves this result alone.
    if let Ok(now) = crate::clock::unix_secs() {
        crate::cost_accounting::spend_history::save(tracker, data_dir, now);
    }
    wrote
}

/// The periodic save: skipped while an earlier write still holds the file
/// (stuck on a stalled mount), so stuck writes never pile up. Returns whether
/// it wrote.
#[cfg(feature = "cost-governance")]
pub(super) fn save_costs_unless_busy(
    enforcer: &BudgetEnforcer,
    tracker: &CostTracker,
    data_dir: &Path,
) -> bool {
    match COST_WRITE.try_lock() {
        Ok(turn) => write_costs(enforcer, tracker, data_dir, &turn),
        Err(std::sync::TryLockError::Poisoned(poisoned)) => {
            write_costs(enforcer, tracker, data_dir, &poisoned.into_inner())
        }
        Err(std::sync::TryLockError::WouldBlock) => {
            warn!("periodic cost save skipped: the previous costs.json write has not finished");
            #[cfg(test)]
            SKIPPED_SAVES
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(data_dir.to_path_buf());
            false
        }
    }
}

/// Save today's spend every `every` until `shutdown` fires, or until the
/// returned task is aborted when `shutdown` is `None`.
#[cfg(feature = "cost-governance")]
pub(super) fn spawn_cost_saver(
    enforcer: Arc<BudgetEnforcer>,
    tracker: Arc<CostTracker>,
    data_dir: PathBuf,
    every: std::time::Duration,
    shutdown: Option<tokio::sync::broadcast::Receiver<()>>,
) -> tokio::task::JoinHandle<()> {
    spawn_periodic_save(
        "cost save",
        every,
        shutdown,
        Some(data_dir.clone()),
        move || {
            save_costs_unless_busy(&enforcer, &tracker, &data_dir);
        },
    )
}

/// Run `save` every `every` until `shutdown` fires, or until the returned
/// task is aborted when `shutdown` is `None`. One loop for every periodic
/// saver (the cost saver, the stdio protocol-telemetry saver; MIK-8364).
///
/// The first tick is consumed, so the first save comes one interval after
/// start. Each save runs on its own named, detached thread: a write stuck on
/// a stalled mount blocks neither a runtime thread nor, being off the
/// blocking pool, the runtime's drop (MIK-8157). `save` keeps at most one
/// write in flight itself (a busy guard), so a slow write skips ticks rather
/// than piling up threads.
///
/// `root` is the file or dir the save writes (none for a saver that writes
/// nothing): a test's temp dir holding it is kept by the saver for its whole
/// life, and by each tick's thread until that save returns.
pub(super) fn spawn_periodic_save(
    name: &'static str,
    every: std::time::Duration,
    shutdown: Option<tokio::sync::broadcast::Receiver<()>>,
    root: Option<PathBuf>,
    save: impl Fn() + Send + Sync + 'static,
) -> tokio::task::JoinHandle<()> {
    let save = Arc::new(save);
    #[cfg(test)]
    let seams = periodic_seams_for(root.as_deref());
    // Taken and reported once, here, before the loop: an unkept saver prints
    // one line, not one per tick. The saver holds it between ticks, so a test
    // that dropped its share cannot lose the dir before the next tick writes.
    let kept = root
        .map(|root| crate::spawn_keep::kept_at_spawn(crate::spawn_keep::PERIODIC_SAVE, &root))
        .unwrap_or_default();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(every);
        interval.tick().await;
        #[cfg(test)]
        if let Some(seams) = &seams {
            seams.loop_started.notify_one();
        }
        let stopped = async move {
            match shutdown {
                Some(mut rx) => drop(rx.recv().await),
                None => std::future::pending().await,
            }
        };
        tokio::pin!(stopped);
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let save = Arc::clone(&save);
                    // The tick's thread holds its own clone to its end, past
                    // a saver that was aborted meanwhile.
                    let kept = kept.clone();
                    #[cfg(test)]
                    let gate = seams.clone();
                    let spawned = std::thread::Builder::new()
                        .name(name.to_owned())
                        .spawn(move || {
                            #[cfg(test)]
                            if let Some(gate) = gate {
                                gate.pre_save.pause_on_thread();
                            }
                            crate::spawn_keep::holding(kept, || save());
                        });
                    match spawned {
                        Ok(_) => {
                            #[cfg(test)]
                            if let Some(seams) = &seams {
                                seams.writer_spawned.notify_one();
                            }
                        }
                        Err(error) => {
                            warn!(%error, saver = name, "periodic save could not start a thread; skipped");
                        }
                    }
                }
                () = &mut stopped => break,
            }
        }
    })
}

/// Test-only signals and a gate for one periodic saver, found by its root
/// (K8, K11b), so parallel rows each reach their own saver, through any
/// caller's wiring.
#[cfg(test)]
#[derive(Default)]
pub(super) struct PeriodicSeams {
    /// Sent once the loop has consumed the interval's first tick.
    pub(super) loop_started: tokio::sync::Notify,
    /// Sent right after a tick's save thread is spawned.
    pub(super) writer_spawned: tokio::sync::Notify,
    /// Holds a tick's save thread before the save runs (one-shot).
    pub(super) pre_save: crate::test_pause::Slot,
}

/// The seams each row registered, by the root its saver writes.
#[cfg(test)]
static PERIODIC_SEAMS: parking_lot::Mutex<Vec<(PathBuf, Arc<PeriodicSeams>)>> =
    parking_lot::Mutex::new(Vec::new());

/// Register seams for the periodic saver that writes `root`.
#[cfg(test)]
pub(super) fn periodic_seams(root: &Path) -> Arc<PeriodicSeams> {
    let seams = Arc::new(PeriodicSeams::default());
    PERIODIC_SEAMS
        .lock()
        .push((root.to_path_buf(), Arc::clone(&seams)));
    seams
}

#[cfg(test)]
fn periodic_seams_for(root: Option<&Path>) -> Option<Arc<PeriodicSeams>> {
    let root = root?;
    PERIODIC_SEAMS
        .lock()
        .iter()
        .find(|(registered, _)| registered == root)
        .map(|(_, seams)| Arc::clone(seams))
}

impl super::Gateway {
    /// Point this gateway's data directory at `dir` (the in-process tests'
    /// tempdir), so a test never reads or writes the developer's own.
    #[cfg(test)]
    pub(super) fn with_data_dir(mut self, dir: PathBuf) -> Self {
        self.test_seams.data_dir = Some(dir);
        self
    }

    /// Attach already-started custody, so an in-process test reaches the
    /// account installer at each serve call site without the issuer fetch
    /// `start_account_custody` performs for a managed descriptor.
    #[cfg(test)]
    pub(super) fn with_account_custody(
        mut self,
        custody: std::sync::Arc<crate::personal_accounts::GatewayCustody>,
    ) -> Self {
        self.custody = Some(custody);
        self
    }
}

/// How long an HTTP gateway's shutdown gives its state saves (MIK-8157).
pub(super) const SHUTDOWN_SAVES_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// One state save run at shutdown.
pub(super) struct ShutdownSave {
    /// Its name, for the log.
    step: &'static str,
    /// The file or dir the save writes: a test's temp dir holding it is kept
    /// while the save runs (`crate::spawn_keep`). None for a save that writes
    /// nothing.
    root: Option<PathBuf>,
    /// The write.
    save: Box<dyn FnOnce() + Send>,
    /// Holds the save's thread before the write, for the one row that built
    /// this save; parallel rows never share it.
    #[cfg(test)]
    gate: Option<Arc<crate::test_pause::Slot>>,
}

impl ShutdownSave {
    pub(super) fn new(
        step: &'static str,
        root: Option<PathBuf>,
        save: Box<dyn FnOnce() + Send>,
    ) -> Self {
        Self {
            step,
            root,
            save,
            #[cfg(test)]
            gate: None,
        }
    }

    /// This save, held at `gate` on its thread before the write.
    #[cfg(test)]
    pub(super) fn gated(mut self, gate: Arc<crate::test_pause::Slot>) -> Self {
        self.gate = Some(gate);
        self
    }

    /// The root this save keeps while it runs (K10).
    #[cfg(test)]
    pub(super) fn root(&self) -> Option<&Path> {
        self.root.as_deref()
    }

    /// Run the write here and now, on this thread: for a row that checks
    /// what the save writes, with no detached thread to keep a dir for.
    #[cfg(test)]
    pub(super) fn run_now(self) {
        (self.save)();
    }
}

/// Every save `run_shutdown_saves` started, with the root it carried: K10
/// reads a site's root here by its own temp path, so parallel rows do not mix.
#[cfg(test)]
pub(super) static STARTED_ROOTS: parking_lot::Mutex<Vec<(&'static str, Option<PathBuf>)>> =
    parking_lot::Mutex::new(Vec::new());

/// Run `saves` together under one `deadline`, each on its own detached thread
/// (MIK-8157), so one write stuck on a stalled mount takes no time from the
/// others. A save still running at the deadline is abandoned and logged by
/// name; being off the blocking pool, it holds neither the shutdown nor the
/// runtime's drop after it.
pub(super) async fn run_shutdown_saves(deadline: tokio::time::Instant, saves: Vec<ShutdownSave>) {
    let mut running = Vec::new();
    for one in saves {
        // The gate moves out first, outside the pattern: a cfg on a field
        // pattern is valid Rust, but the gates' source parser cannot read it.
        #[cfg(test)]
        let gate = one.gate;
        let ShutdownSave {
            step, root, save, ..
        } = one;
        #[cfg(test)]
        STARTED_ROOTS.lock().push((step, root.clone()));
        // Taken here, before the thread exists, while the caller (a test)
        // still holds its share of the dir; the save thread holds it to its end.
        let kept = root
            .as_deref()
            .map(|root| crate::spawn_keep::kept_at_spawn(crate::spawn_keep::SHUTDOWN_SAVE, root))
            .unwrap_or_default();
        let (done, finished) = tokio::sync::oneshot::channel();
        let spawned = std::thread::Builder::new()
            .name(format!("shutdown: {step}"))
            .spawn(move || {
                #[cfg(test)]
                if let Some(gate) = gate {
                    gate.pause_on_thread();
                }
                // The thread holds the keep until the save returns.
                crate::spawn_keep::holding(kept, save);
                let _ = done.send(());
            });
        match spawned {
            Ok(_) => running.push((step, finished)),
            Err(error) => warn!(step, %error, "shutdown save could not start a thread; skipped"),
        }
    }
    for (step, finished) in running {
        super::stdio_shutdown::bounded_step(deadline, step, finished).await;
    }
}

/// What the final cost save needs: the enforcer, the tracker (its history
/// file) and the data directory.
/// Uninhabited without cost governance.
#[cfg(feature = "cost-governance")]
pub(super) type CostShutdown = (Arc<BudgetEnforcer>, Arc<CostTracker>, PathBuf);
#[cfg(not(feature = "cost-governance"))]
pub(super) type CostShutdown = std::convert::Infallible;

/// The HTTP shutdown's saves of search ranking, transition tracking and, with
/// cost governance on, today's spend, all together under the stop budget's
/// `deadline`. The periodic saver needs no stopping first:
/// cost writes take turns and each snapshots the spend as it writes.
pub(super) async fn save_state_on_shutdown(
    ranker: Arc<crate::ranking::SearchRanker>,
    ranker_path: PathBuf,
    tracker: Arc<crate::transition::TransitionTracker>,
    transition_path: PathBuf,
    cost: Option<CostShutdown>,
    more: Vec<ShutdownSave>,
    deadline: tokio::time::Instant,
) {
    #[allow(unused_mut)]
    let mut saves: Vec<ShutdownSave> = vec![
        ShutdownSave::new(
            "search ranking save",
            Some(ranker_path.clone()),
            Box::new(move || {
                save_with_logging(
                    &ranker_path,
                    |path| ranker.save(path),
                    "Failed to save search ranker usage data",
                    "Saved search ranking usage data",
                );
            }),
        ),
        ShutdownSave::new(
            "transition tracking save",
            Some(transition_path.clone()),
            Box::new(move || {
                save_with_logging(
                    &transition_path,
                    |path| tracker.save(path),
                    "Failed to save transition tracking data",
                    "Saved transition tracking data",
                );
            }),
        ),
    ];
    #[cfg(feature = "cost-governance")]
    if let Some((enforcer, costs, data_dir)) = cost {
        saves.push(ShutdownSave::new(
            COST_SAVE_STEP,
            Some(data_dir.clone()),
            Box::new(move || {
                save_costs(&enforcer, &costs, &data_dir);
            }),
        ));
    }
    #[cfg(not(feature = "cost-governance"))]
    let _ = cost;
    saves.extend(more);
    run_shutdown_saves(deadline, saves).await;
}

/// How many ticks a periodic-save test may advance, and how long each may take
/// to land: together the 30 s the tests gave a single tick before MIK-8216.
#[cfg(all(test, feature = "cost-governance"))]
const CATCH_UP_TICKS: u32 = 3;
#[cfg(all(test, feature = "cost-governance"))]
const TICK_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// Advance the paused clock one cost-save interval at a time until `costs`
/// exists, giving each tick real time to land, for up to [`CATCH_UP_TICKS`] ticks.
///
/// A tick that finds `COST_WRITE` held is skipped, and the next tick catches
/// up (MIK-8157). Paused time packs intervals into almost no real time, so a
/// previous save thread, or another test's save in this process, can still
/// hold the lock at the first tick (MIK-8216). One advance alone cannot
/// recover from that skip.
// Test-only and crate-internal. Callers: the stdio and HTTP periodic-save tests
// (server/tests) and this module's catch-up row (MIK-8216 AC2).
#[cfg(all(test, feature = "cost-governance"))]
pub(super) async fn advance_until_saved(costs: &std::path::Path) -> Result<(), String> {
    for _ in 0..CATCH_UP_TICKS {
        tokio::time::advance(COST_SAVE_INTERVAL + std::time::Duration::from_secs(1)).await;
        if crate::test_wait::wait_real_time(TICK_BOUND, || costs.exists())
            .await
            .is_ok()
        {
            return Ok(());
        }
    }
    Err(format!(
        "did not land in {CATCH_UP_TICKS} ticks of {TICK_BOUND:?} real time each"
    ))
}

#[cfg(tp4)]
#[cfg(test)]
#[path = "persistence_tests.rs"]
mod tests;

#[cfg(tp4)]
#[cfg(test)]
#[path = "shutdown_keep_tests.rs"]
mod shutdown_keep_tests;

#[cfg(tp4)]
#[cfg(all(test, feature = "cost-governance"))]
#[path = "spend_history_save_tests.rs"]
mod spend_history_save_tests;

#[cfg(tp4)]
#[cfg(test)]
#[path = "periodic_keep_tests.rs"]
mod periodic_keep_tests;

// Stays inline: its timing windows are checked as new code at any new path.
#[cfg(tp4)]
#[cfg(test)]
mod shutdown_deadline_tests {
    use super::*;

    /// `MIK-8157.SAVE.1` and `.2`: a shutdown save stuck on a stalled mount is
    /// abandoned at the deadline, so the shutdown returns; another save that
    /// finishes inside the bound completes, whatever its place in the list.
    #[tokio::test]
    async fn a_stuck_shutdown_save_is_abandoned_at_the_deadline() {
        let (release, stuck) = std::sync::mpsc::channel::<()>();
        let (finished, done) = std::sync::mpsc::channel::<()>();
        // The stuck save first: the quick one still runs, in the same window.
        let saves: Vec<ShutdownSave> = vec![
            ShutdownSave::new(
                "stuck save",
                None,
                Box::new(move || {
                    let _ = stuck.recv();
                }),
            ),
            ShutdownSave::new(
                "quick save",
                None,
                Box::new(move || {
                    let _ = finished.send(());
                }),
            ),
        ];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        let shutdown = tokio::spawn(run_shutdown_saves(deadline, saves));
        // While the stuck save is still held: saves start together, so the
        // quick one finishes well inside the window. Saves run in sequence
        // would not even start it before the 2 s deadline; 1 s leaves room for
        // a slow thread start on either side.
        let quick = tokio::task::spawn_blocking(move || {
            done.recv_timeout(std::time::Duration::from_secs(1))
        })
        .await
        .expect("the waiter ran");
        assert!(quick.is_ok(), "the quick save waited behind the stuck one");
        // The stuck save is still held: the shutdown returns at the deadline.
        let returned = tokio::time::timeout(std::time::Duration::from_secs(5), shutdown).await;
        drop(release);
        assert!(returned.is_ok(), "a stuck save held the shutdown");
    }

    /// `MIK-8867.BUDGET.1`: the HTTP stop's state saves end at the deadline
    /// the stop budget hands them, not at a timeout of their own. The clock is
    /// paused, so the elapsed time is the deadline itself and no wall-clock
    /// window decides the row.
    #[tokio::test(start_paused = true)]
    async fn the_state_saves_end_at_the_deadline_they_are_given() {
        let dir = crate::test_dir_keep::kept_tempdir();
        let (release, stuck) = std::sync::mpsc::channel::<()>();
        let stuck_save = ShutdownSave::new(
            "stuck save",
            None,
            Box::new(move || {
                let _ = stuck.recv();
            }),
        );
        let start = tokio::time::Instant::now();
        let given = std::time::Duration::from_secs(2);
        save_state_on_shutdown(
            Arc::new(crate::ranking::SearchRanker::new()),
            dir.path().join("ranker.json"),
            Arc::new(crate::transition::TransitionTracker::new()),
            dir.path().join("transitions.json"),
            None,
            vec![stuck_save],
            start + given,
        )
        .await;
        let elapsed = start.elapsed();
        drop(release);
        // Paused time moves only to the next timer, so the stop ends at the given
        // deadline exactly: neither a timeout of its own nor skipped saves ends it
        // at another instant.
        assert_eq!(
            elapsed, given,
            "the saves did not end at the deadline they were given"
        );
    }
}
