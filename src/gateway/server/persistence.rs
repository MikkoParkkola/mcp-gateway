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

#[cfg(feature = "cost-governance")]
fn write_costs(enforcer: &BudgetEnforcer, data_dir: &Path, _turn: &std::sync::MutexGuard<'_, ()>) {
    let persisted = super::support::build_persisted_costs(&enforcer.snapshot());
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
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(every);
        // Consume the immediate first tick, so the first save comes one
        // interval after start rather than before anything is spent.
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
                // On a detached thread: a write stuck on a stalled mount
                // blocks neither a runtime thread nor, being off the blocking
                // pool, the runtime's drop (MIK-8157).
                _ = interval.tick() => {
                    let (enforcer, data_dir) = (Arc::clone(&enforcer), data_dir.clone());
                    let spawned = std::thread::Builder::new()
                        .name("cost save".to_owned())
                        .spawn(move || save_costs_unless_busy(&enforcer, &data_dir));
                    if let Err(error) = spawned {
                        warn!(%error, "periodic cost save could not start a thread; skipped");
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

impl super::AbortOnDrop {
    /// Abort the task and wait until it has ended, so nothing it was doing
    /// can land after this returns.
    #[cfg_attr(
        not(any(feature = "cost-governance", test)),
        expect(dead_code, reason = "only the stdio cost saver is stopped this way")
    )]
    pub(crate) async fn stop(mut self) {
        self.0.abort();
        // Cancelled is the expected outcome; a panic is reported by the runtime.
        drop((&mut self.0).await);
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
    run_shutdown_saves(deadline, saves).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn standard_data_dir_uses_gateway_subdir() {
        match std::env::var("MCP_GATEWAY_CONFIG_DIR") {
            Ok(path) => assert_eq!(standard_data_dir(), PathBuf::from(path)),
            Err(_) => assert_eq!(
                standard_data_dir()
                    .file_name()
                    .and_then(|name| name.to_str()),
                Some(".mcp-gateway")
            ),
        }
    }

    #[test]
    fn load_if_exists_skips_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let called = Cell::new(false);

        load_if_exists(
            &path,
            |_| {
                called.set(true);
                Ok::<(), std::io::Error>(())
            },
            "load failed",
            "loaded",
        );

        assert!(!called.get());
    }

    #[test]
    fn save_with_logging_runs_callback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let called = Cell::new(false);

        save_with_logging(
            &path,
            |_| {
                called.set(true);
                Ok::<(), std::io::Error>(())
            },
            "save failed",
            "saved",
        );

        assert!(called.get());
    }

    #[cfg(feature = "cost-governance")]
    fn enforcer_with_spend(usd: f64) -> Arc<BudgetEnforcer> {
        let cfg = CostGovernanceConfig {
            enabled: true,
            ..CostGovernanceConfig::default()
        };
        let registry = Arc::new(CostRegistry::new(&cfg));
        let enforcer = Arc::new(BudgetEnforcer::new(cfg, registry));
        enforcer.record_spend("tool", Some("key"), usd);
        enforcer
    }

    /// What `boot_cost_governance` would restore from `dir`, as global spend.
    #[cfg(feature = "cost-governance")]
    fn restored_global(dir: &Path) -> f64 {
        let cfg = CostGovernanceConfig {
            enabled: true,
            ..CostGovernanceConfig::default()
        };
        let (_, enforcer) = boot_cost_governance(&cfg, dir);
        enforcer.expect("enabled").snapshot().global_daily_usd
    }

    #[cfg(feature = "cost-governance")]
    #[test]
    fn save_costs_writes_what_the_next_boot_restores() {
        let dir = tempfile::tempdir().unwrap();
        save_costs(&enforcer_with_spend(0.25), dir.path());
        let global = restored_global(dir.path());
        assert!((global - 0.25).abs() < 1e-9, "the next boot reads {global}");
    }

    /// The saver writes on its interval and ends when shutdown is sent.
    #[cfg(feature = "cost-governance")]
    #[tokio::test]
    async fn cost_saver_stops_on_shutdown() {
        let dir = tempfile::tempdir().unwrap();
        let costs = dir.path().join("costs.json");
        let (tx, rx) = tokio::sync::broadcast::channel(1);
        let enforcer = enforcer_with_spend(0.2);
        let task = spawn_cost_saver(
            Arc::clone(&enforcer),
            dir.path().to_path_buf(),
            std::time::Duration::from_millis(50),
            Some(rx),
        );
        // Each tick saves the spend as it is then, not a snapshot taken once.
        for (spent, expected) in [(0.0, 0.2), (0.3, 0.5)] {
            enforcer.record_spend("tool", Some("key"), spent);
            let saved = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !costs.exists() || (restored_global(dir.path()) - expected).abs() > 1e-9 {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await;
            assert!(
                saved.is_ok(),
                "the saver never wrote {expected}; the next boot reads {}",
                restored_global(dir.path())
            );
        }
        tx.send(()).expect("the saver is listening");
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("the saver kept running after shutdown")
            .expect("the saver panicked");
    }

    /// `stop` returns only once the aborted task's future has been dropped.
    #[tokio::test]
    async fn stop_waits_for_the_aborted_task() {
        let held = Arc::new(());
        let inside = Arc::clone(&held);
        let guard = super::super::AbortOnDrop::new(tokio::spawn(async move {
            std::future::pending::<()>().await;
            drop(inside);
        }));
        // Let the task start and take its clone.
        tokio::task::yield_now().await;
        guard.stop().await;
        assert_eq!(
            Arc::strong_count(&held),
            1,
            "stop returned while the aborted task still held its state"
        );
    }

    /// `MIK-8157.SAVE.3`: an abandoned cost save is logged by its step name,
    /// so that name must point the operator at the file left stale.
    #[cfg(feature = "cost-governance")]
    #[test]
    fn an_abandoned_cost_save_names_costs_json() {
        assert!(COST_SAVE_STEP.contains("costs.json"));
    }

    /// `MIK-8157.SAVE.1` and `.2`: a shutdown save stuck on a stalled mount is
    /// abandoned at the deadline, so the shutdown returns; another save that
    /// finishes inside the bound completes, whatever its place in the list.
    #[tokio::test]
    async fn a_stuck_shutdown_save_is_abandoned_at_the_deadline() {
        let (release, stuck) = std::sync::mpsc::channel::<()>();
        let (finished, done) = std::sync::mpsc::channel();
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
                    let _ = finished.send(std::time::Instant::now());
                }),
            ),
        ];
        let window = std::time::Duration::from_millis(200);
        let (started, deadline) = (
            std::time::Instant::now(),
            tokio::time::Instant::now() + window,
        );
        let returned = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run_shutdown_saves(deadline, saves),
        )
        .await;
        drop(release);
        assert!(returned.is_ok(), "a stuck save held the shutdown");
        // Inside the window, not merely before the test looked: saves start
        // together, so a stuck one ahead in the list delays no other.
        let finished_at = done
            .try_recv()
            .expect("the save that fits the bound did not run");
        assert!(
            finished_at.duration_since(started) < window,
            "the quick save waited behind the stuck one"
        );
    }
}
