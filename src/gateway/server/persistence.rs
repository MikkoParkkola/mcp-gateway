// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::fmt::Display;
use std::path::{Path, PathBuf};
#[cfg(feature = "cost-governance")]
use std::sync::PoisonError;

use tracing::{info, warn};

#[cfg(feature = "cost-governance")]
use crate::cost_accounting::{
    config::CostGovernanceConfig, enforcer::BudgetEnforcer, registry::CostRegistry,
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
) where
    F: FnOnce(&Path) -> Result<(), E>,
    E: Display,
{
    if let Err(e) = save(path) {
        warn!(error = %e, "{error_message}");
    } else {
        info!("{success_message}");
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

/// Save today's spend to `<data_dir>/costs.json`.
#[cfg(feature = "cost-governance")]
pub(super) fn save_costs(enforcer: &BudgetEnforcer, data_dir: &Path) {
    let turn = COST_WRITE.lock().unwrap_or_else(PoisonError::into_inner);
    write_costs(enforcer, data_dir, &turn);
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
fn write_costs(enforcer: &BudgetEnforcer, data_dir: &Path, _turn: &std::sync::MutexGuard<'_, ()>) {
    let Ok(snapshot) = enforcer.snapshot_for_save() else {
        tracing::warn!("Clock reads before 1970; cost save skipped, the last saved spend stands");
        return;
    };
    let persisted = super::support::build_persisted_costs(&snapshot);
    save_with_logging(
        &data_dir.join("costs.json"),
        |path| crate::cost_accounting::persistence::save(path, &persisted),
        "Failed to save cost governance data",
        "Saved cost governance data",
    );
}

/// The periodic save: skipped while an earlier write still holds the file
/// (stuck on a stalled mount), so stuck writes never pile up.
#[cfg(feature = "cost-governance")]
fn save_costs_unless_busy(enforcer: &BudgetEnforcer, data_dir: &Path) {
    match COST_WRITE.try_lock() {
        Ok(turn) => write_costs(enforcer, data_dir, &turn),
        Err(std::sync::TryLockError::Poisoned(poisoned)) => {
            write_costs(enforcer, data_dir, &poisoned.into_inner());
        }
        Err(std::sync::TryLockError::WouldBlock) => {
            warn!("periodic cost save skipped: the previous costs.json write has not finished");
            #[cfg(test)]
            SKIPPED_SAVES
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(data_dir.to_path_buf());
        }
    }
}

/// Save today's spend every `every` until `shutdown` fires, or until the
/// returned task is aborted when `shutdown` is `None`.
#[cfg(feature = "cost-governance")]
pub(super) fn spawn_cost_saver(
    enforcer: Arc<BudgetEnforcer>,
    data_dir: PathBuf,
    every: std::time::Duration,
    shutdown: Option<tokio::sync::broadcast::Receiver<()>>,
) -> tokio::task::JoinHandle<()> {
    spawn_periodic_save("cost save", every, shutdown, move || {
        save_costs_unless_busy(&enforcer, &data_dir);
    })
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
pub(super) fn spawn_periodic_save(
    name: &'static str,
    every: std::time::Duration,
    shutdown: Option<tokio::sync::broadcast::Receiver<()>>,
    save: impl Fn() + Send + Sync + 'static,
) -> tokio::task::JoinHandle<()> {
    let save = Arc::new(save);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(every);
        interval.tick().await;
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
                    let spawned = std::thread::Builder::new()
                        .name(name.to_owned())
                        .spawn(move || save());
                    if let Err(error) = spawned {
                        warn!(%error, saver = name, "periodic save could not start a thread; skipped");
                    }
                }
                () = &mut stopped => break,
            }
        }
    })
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

/// One state save run at shutdown: its name, for the log, and the write.
pub(super) type ShutdownSave = (&'static str, Box<dyn FnOnce() + Send>);

/// Run `saves` together under one `deadline`, each on its own detached thread
/// (MIK-8157), so one write stuck on a stalled mount takes no time from the
/// others. A save still running at the deadline is abandoned and logged by
/// name; being off the blocking pool, it holds neither the shutdown nor the
/// runtime's drop after it.
pub(super) async fn run_shutdown_saves(deadline: tokio::time::Instant, saves: Vec<ShutdownSave>) {
    let mut running = Vec::new();
    for (step, save) in saves {
        let (done, finished) = tokio::sync::oneshot::channel();
        let spawned = std::thread::Builder::new()
            .name(format!("shutdown: {step}"))
            .spawn(move || {
                save();
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

/// What the final cost save needs: the enforcer and the data directory.
/// Uninhabited without cost governance.
#[cfg(feature = "cost-governance")]
pub(super) type CostShutdown = (Arc<BudgetEnforcer>, PathBuf);
#[cfg(not(feature = "cost-governance"))]
pub(super) type CostShutdown = std::convert::Infallible;

/// The HTTP shutdown's saves of search ranking, transition tracking and, with
/// cost governance on, today's spend, all together under
/// [`SHUTDOWN_SAVES_TIMEOUT`]. The periodic saver needs no stopping first:
/// cost writes take turns and each snapshots the spend as it writes.
pub(super) async fn save_state_on_shutdown(
    ranker: Arc<crate::ranking::SearchRanker>,
    ranker_path: PathBuf,
    tracker: Arc<crate::transition::TransitionTracker>,
    transition_path: PathBuf,
    cost: Option<CostShutdown>,
    more: Vec<ShutdownSave>,
) {
    let deadline = tokio::time::Instant::now() + SHUTDOWN_SAVES_TIMEOUT;
    #[allow(unused_mut)]
    let mut saves: Vec<ShutdownSave> = vec![
        (
            "search ranking save",
            Box::new(move || {
                save_with_logging(
                    &ranker_path,
                    |path| ranker.save(path),
                    "Failed to save search ranker usage data",
                    "Saved search ranking usage data",
                );
            }),
        ),
        (
            "transition tracking save",
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
    if let Some((enforcer, data_dir)) = cost {
        saves.push((
            COST_SAVE_STEP,
            Box::new(move || save_costs(&enforcer, &data_dir)),
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

#[cfg(test)]
#[path = "persistence_tests.rs"]
mod tests;

// Stays inline: its timing windows are checked as new code at any new path.
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
            (
                "stuck save",
                Box::new(move || {
                    let _ = stuck.recv();
                }),
            ),
            (
                "quick save",
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
}
