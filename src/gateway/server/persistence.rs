// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::fmt::Display;
use std::path::{Path, PathBuf};

use tracing::{info, warn};

#[cfg(feature = "cost-governance")]
use crate::cost_accounting::{
    config::CostGovernanceConfig, enforcer::BudgetEnforcer, registry::CostRegistry,
};
#[cfg(any(feature = "cost-governance", test))]
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
                _ = interval.tick() => save_costs(&enforcer, &data_dir),
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
        self.data_dir = Some(dir);
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

    /// Whether the saver asked for a sealing snapshot. A stub, so no test
    /// seals the process-wide registry other tests count through.
    static SEAL_REQUESTED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);

    fn stub_counts(seal: bool) -> crate::protocol_revision_telemetry::window::SegmentCounts {
        if seal {
            SEAL_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        crate::protocol_revision_telemetry::window::SegmentCounts::empty()
    }

    #[tokio::test]
    async fn protocol_window_saver_seals_its_segment_on_the_shutdown_broadcast() {
        // Nothing drains here: the saver seals on the broadcast itself,
        // because a post-drain seal is SIGKILLed while an SSE stream is open,
        // and it asks for the sealing snapshot that refuses later requests.
        let dir = tempfile::tempdir().expect("tempdir");
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        let saver = spawn_protocol_window_saver(
            dir.path().to_path_buf(),
            crate::protocol_revision_telemetry::window::WriterIdentity {
                listen: "127.0.0.1:39401".to_string(),
                exe: "/opt/mcp-gateway/mcp-gateway".to_string(),
                process_started_at: 1,
            },
            std::time::Duration::from_secs(3600),
            Box::new(stub_counts),
            shutdown_tx.subscribe(),
        );
        shutdown_tx.send(()).expect("a subscriber exists");
        tokio::time::timeout(std::time::Duration::from_secs(5), saver)
            .await
            .expect("the saver seals without waiting for a drain")
            .expect("the saver task does not panic");
        let window =
            crate::protocol_revision_telemetry::window::load(dir.path()).expect("a v2 window");
        assert_eq!(window.http_segments.len(), 1);
        assert!(window.http_segments[0].closed_cleanly);
        assert!(SEAL_REQUESTED.load(std::sync::atomic::Ordering::SeqCst));
    }
}

/// How often an HTTP process rewrites its U1 window segment.
const PROTOCOL_WINDOW_SAVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Keep this HTTP process's U1 segment current, and seal it on shutdown.
///
/// The seal is written on the shutdown broadcast, not after the drain: open
/// connections get `server.shutdown_timeout` (30 s by default) and launchd
/// sends SIGKILL after 20 s, so a post-drain seal would never land while an SSE
/// stream is open. Sealing takes the counts and refuses every later HTTP
/// request in one critical section (`global_segment_counts(Some(seal))`), so a
/// request is either in the sealed counts or refused unserved (503). A call
/// counted before the seal finishes normally, however long it runs.
/// A sink that fails to open is retried every tick; counts are cumulative
/// from process start, so a late open still records everything.
pub(super) fn spawn_window_saver(
    data_dir: PathBuf,
    listen: std::net::SocketAddr,
    seal: std::sync::Arc<std::sync::atomic::AtomicBool>,
    shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    use crate::protocol_revision_telemetry::window::{WriterIdentity, unix_seconds_now};
    let identity = WriterIdentity {
        listen: listen.to_string(),
        exe: std::env::current_exe()
            .map_or_else(|_| "unknown".to_string(), |path| path.display().to_string()),
        process_started_at: unix_seconds_now(),
    };
    spawn_protocol_window_saver(
        data_dir,
        identity,
        PROTOCOL_WINDOW_SAVE_INTERVAL,
        Box::new(move |close: bool| {
            crate::protocol_revision_telemetry::window::global_segment_counts(
                close.then_some(seal.as_ref()),
            )
        }),
        shutdown,
    )
}

fn spawn_protocol_window_saver(
    data_dir: PathBuf,
    identity: crate::protocol_revision_telemetry::window::WriterIdentity,
    every: std::time::Duration,
    counts: Box<dyn Fn(bool) -> crate::protocol_revision_telemetry::window::SegmentCounts + Send>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    use crate::protocol_revision_telemetry::window::HttpSegmentSink;
    tokio::spawn(async move {
        let mut sink: Option<HttpSegmentSink> = None;
        let mut interval = tokio::time::interval(every);
        loop {
            let close = tokio::select! {
                _ = interval.tick() => false,
                _ = shutdown.recv() => true,
            };
            let now = crate::protocol_revision_telemetry::window::unix_seconds_now();
            if sink.is_none() {
                match HttpSegmentSink::open(&data_dir, identity.clone(), now) {
                    Ok(opened) => sink = Some(opened),
                    Err(error) => warn!(
                        %error,
                        data_dir = %data_dir.display(),
                        "HTTP protocol-revision telemetry is not durable; do not start the measurement window"
                    ),
                }
            }
            // Taken whether or not the sink is open: the seal must refuse later
            // requests even when this process's segment could not be written.
            let segment_counts = counts(close);
            if let Some(sink) = sink.as_mut()
                && let Err(error) = sink.checkpoint(&segment_counts, now, close)
            {
                warn!(%error, "failed to checkpoint the HTTP protocol-revision window segment");
            }
            if close {
                break;
            }
        }
    })
}
