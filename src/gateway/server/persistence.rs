// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::fmt::Display;
use std::path::{Path, PathBuf};

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
    let persisted = super::support::build_persisted_costs(&enforcer.snapshot());
    save_with_logging(
        &data_dir.join("costs.json"),
        |path| crate::cost_accounting::persistence::save(path, &persisted),
        "Failed to save cost governance data",
        "Saved cost governance data",
    );
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
                // Off the runtime's threads: a write stuck on a stalled
                // mount must not block one (MIK-8157).
                _ = interval.tick() => {
                    let (enforcer, data_dir) = (Arc::clone(&enforcer), data_dir.clone());
                    drop(tokio::task::spawn_blocking(move || save_costs(&enforcer, &data_dir)).await);
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

/// Run `saves` in order under one `deadline`, each on its own detached thread
/// (MIK-8157). A write stuck on a stalled mount is abandoned at the deadline
/// and logged by name, so it can neither hold the shutdown nor, being off the
/// blocking pool, the runtime's drop after it.
pub(super) async fn run_shutdown_saves(deadline: tokio::time::Instant, saves: Vec<ShutdownSave>) {
    // Stub: waits for every save without a bound, as the shutdown did.
    let _ = deadline;
    for (_, save) in saves {
        drop(tokio::task::spawn_blocking(save).await);
    }
}

/// What the final cost save needs: the enforcer, the periodic saver to stop
/// first, and the data directory. Uninhabited without cost governance.
#[cfg(feature = "cost-governance")]
pub(super) type CostShutdown = (
    Arc<BudgetEnforcer>,
    Option<tokio::task::JoinHandle<()>>,
    PathBuf,
);
#[cfg(not(feature = "cost-governance"))]
pub(super) type CostShutdown = std::convert::Infallible;

/// The HTTP shutdown's saves of search ranking, transition tracking and, with
/// cost governance on, today's spend, under [`SHUTDOWN_SAVES_TIMEOUT`]. The
/// periodic cost saver is stopped first so an older save cannot land after the
/// final one; if it does not stop in time the final cost save is skipped
/// rather than raced, as stdio does.
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
    if let Some((enforcer, saver, data_dir)) = cost {
        let stopped = match saver {
            Some(saver) => super::stdio_shutdown::bounded_step(deadline, "cost saver stop", saver)
                .await
                .is_some(),
            None => true,
        };
        if stopped {
            saves.push((
                "final cost save",
                Box::new(move || save_costs(&enforcer, &data_dir)),
            ));
        } else {
            warn!("final cost snapshot skipped: the periodic saver is still running");
        }
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

    /// `MIK-8157.SAVE.1` and `.2`: a shutdown save stuck on a stalled mount is
    /// abandoned at the deadline, so the shutdown returns; a save that
    /// finishes inside the bound completes.
    #[tokio::test]
    async fn a_stuck_shutdown_save_is_abandoned_at_the_deadline() {
        let (release, stuck) = std::sync::mpsc::channel::<()>();
        let (finished, done) = std::sync::mpsc::channel();
        let saves: Vec<ShutdownSave> = vec![
            (
                "quick save",
                Box::new(move || {
                    let _ = finished.send(());
                }),
            ),
            (
                "stuck save",
                Box::new(move || {
                    let _ = stuck.recv();
                }),
            ),
        ];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(200);
        let returned = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            run_shutdown_saves(deadline, saves),
        )
        .await;
        drop(release);
        assert!(returned.is_ok(), "a stuck save held the shutdown");
        assert!(
            done.try_recv().is_ok(),
            "the save that fits the bound did not run to completion"
        );
    }
}
