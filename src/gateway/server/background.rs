// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Background tasks the serve modes start: SIEM export, health checks and the idle reaper (moved from `server/mod.rs`, MIK-8144).

use std::sync::Arc;

use tracing::{debug, info, warn};

use super::expand_home_path;
use crate::backend::BackendRegistry;
use crate::config::Config;

/// Spawn the SIEM evidence-export background task (MIK-6703).
///
/// Returns `Some(status)` when export is enabled and both log exporters open;
/// the task then tails the invocation + governance transparency logs on a timer
/// and forwards verified entries to the NDJSON sink. Non-blocking: it reads the
/// on-disk logs off the async runtime via `spawn_blocking`, so tool invocations
/// (which append to the logs) never wait on export. HMAC secret is threaded so
/// re-anchored entries are signature-verified (SIEM.SIG.1, needs MIK-6700).
pub(super) fn spawn_export_task(
    config: &Config,
    control_plane_base: &crate::control_plane::role_mapping::ControlPlaneBaseInfo,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> Option<Arc<crate::control_plane::ExportStatus>> {
    use crate::control_plane::{
        ExportSink, ExportSource, ExportStatus, FileExportSink, LogExporter, default_cursor_path,
    };
    use std::sync::Mutex;

    let ecfg = &config.control_plane.export;
    if !ecfg.enabled {
        return None;
    }
    if !config.auth.enabled {
        warn!("SIEM export configured but auth is off; the governance log may be absent");
    }

    let inv_path = expand_home_path(&config.security.transparency_log.path);
    let gov_path = control_plane_base.path.join("audit.jsonl");
    let secret = config.security.transparency_log.shared_secret.clone();
    let sink_path = expand_home_path(&ecfg.sink_path);

    let sink: Arc<dyn ExportSink> = match FileExportSink::open(sink_path.clone()) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            warn!(error = %e, path = %sink_path.display(), "SIEM export sink unavailable; export disabled");
            return None;
        }
    };

    let open = |source, path: &std::path::Path| {
        LogExporter::open(source, path.to_path_buf(), default_cursor_path(path)).map(|e| {
            e.with_max_batch(ecfg.max_batch)
                .with_signing_secret(secret.clone())
        })
    };
    let inv = match open(ExportSource::Invocation, &inv_path) {
        Ok(e) => Arc::new(Mutex::new(e)),
        Err(e) => {
            warn!(error = %e, "SIEM export: invocation exporter open failed; export disabled");
            return None;
        }
    };
    let gov = match open(ExportSource::Governance, &gov_path) {
        Ok(e) => Arc::new(Mutex::new(e)),
        Err(e) => {
            warn!(error = %e, "SIEM export: governance exporter open failed; export disabled");
            return None;
        }
    };

    let status = Arc::new(ExportStatus::default());
    let interval_secs = ecfg.poll_interval_secs.max(1);
    let (task_status, task_sink) = (Arc::clone(&status), Arc::clone(&sink));

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    poll_export_source(&inv, &task_sink, &task_status.invocation, "invocation").await;
                    poll_export_source(&gov, &task_sink, &task_status.governance, "governance").await;
                }
                _ = shutdown_rx.recv() => break,
            }
        }
        info!("SIEM export task stopped");
    });

    info!(sink = %sink_path.display(), "SIEM export task started");
    Some(status)
}

/// Poll one exporter off the async runtime and fold the outcome into `status`.
pub(super) async fn poll_export_source(
    exporter: &Arc<std::sync::Mutex<crate::control_plane::LogExporter>>,
    sink: &Arc<dyn crate::control_plane::ExportSink>,
    status: &crate::control_plane::SourceExportStatus,
    label: &str,
) {
    let (exporter_arc, sink_ref) = (Arc::clone(exporter), Arc::clone(sink));
    // The exporter reads the on-disk log synchronously; run it on the blocking
    // pool so the async runtime is never stalled by a large tail read.
    let result = tokio::task::spawn_blocking(move || {
        // Recover the guard on poison rather than panicking the blocking
        // task (MIK-6909 item 3) — matches the established pattern in
        // `crate::attestation::validator` (e.g. `AuditRingBuffer::push`).
        // A prior panic while holding the lock invalidated no in-progress
        // write here (the guard is dropped before any partial mutation is
        // possible), so the recovered exporter state is safe to keep using.
        let mut e = exporter_arc
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        e.poll(sink_ref.as_ref())
    })
    .await;
    match result {
        Ok(Ok(outcome)) => {
            status.record(&outcome);
            let lag = u32::try_from(outcome.lag_entries).unwrap_or(u32::MAX);
            telemetry_metrics::gauge!("siem_export_lag_entries", "source" => label.to_string())
                .set(f64::from(lag));
            if outcome.forwarded > 0 || outcome.reanchored {
                debug!(
                    source = label,
                    forwarded = outcome.forwarded,
                    lag = outcome.lag_entries,
                    reanchored = outcome.reanchored,
                    "SIEM export poll"
                );
            }
        }
        Ok(Err(e)) => {
            status.record_error();
            warn!(source = label, error = %e, "SIEM export poll failed");
        }
        Err(e) => {
            status.record_error();
            warn!(source = label, error = %e, "SIEM export blocking task join failed");
        }
    }
}

/// Spawn the backend idle reaper.
///
/// Two jobs on one 60s tick: evict per-user transport slots idle past a fixed TTL
/// (MIK-6735), and stop backends that opted into `stop_when_idle_for`.
///
/// Called from BOTH the HTTP serve path and `run_stdio`. Living only in the
/// former would mean a stdio-mode gateway accepted the setting, validated it, and
/// then never acted on it - indistinguishable from the dead `idle_timeout` this
/// replaces.
///
/// `shutdown` is `None` in stdio mode, where the process exits with its read loop
/// and there is no broadcast channel to observe.
/// Aborts the task it owns when dropped.
///
/// Stdio mode has no broadcast shutdown channel, so its background tasks are
/// stopped by aborting their handles. Aborting only on the EOF path is not
/// enough: an embedded host that cancels `run_stdio` never reaches that line,
/// and a dropped `JoinHandle` DETACHES its task rather than stopping it. The
/// task then keeps the backend registry alive and keeps probing backends after
/// the gateway is gone. Tying the abort to a guard's lifetime makes every exit
/// path behave the same.
#[must_use = "dropping this guard aborts the task immediately"]
pub(crate) struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl AbortOnDrop {
    pub(crate) const fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self(handle)
    }

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

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Probe backends periodically so a dead one recovers without operator action.
///
/// `shutdown` is `Some` in HTTP mode, which has a broadcast channel; stdio mode
/// passes `None` and owns the returned handle instead.
pub(super) fn spawn_health_loop(
    backends: Arc<BackendRegistry>,
    health_config: &crate::config::HealthCheckConfig,
    shutdown: Option<tokio::sync::broadcast::Receiver<()>>,
) -> tokio::task::JoinHandle<()> {
    let (enabled, tick, probe_timeout) = (
        health_config.enabled,
        health_config.interval,
        health_config.timeout,
    );
    tokio::spawn(async move {
        if !enabled {
            return;
        }
        let mut shutdown = shutdown;
        let mut ticker = crate::backend::HealthTicker::new(tick);

        loop {
            tokio::select! {
                () = ticker.tick() => {
                    for backend in backends.all() {
                        // Probe running backends (liveness) AND backends whose
                        // breaker is tripped (recovery). The old guard only
                        // probed running backends — but a backend that died
                        // and tripped its breaker reports `is_running()==false`,
                        // so it was skipped exactly when it needed recovery.
                        // Cleanly-idle backends (closed breaker, not running)
                        // are left alone so the idle reaper can shut them down.
                        if backend.is_running() || backend.is_circuit_tripped() {
                            // `health_probe` bypasses the breaker, resets it on
                            // success, and rebuilds the transport on failure —
                            // the automatic equivalent of gateway_revive_server.
                            if let Err(e) = backend.health_probe(probe_timeout).await {
                                // A start in flight (perhaps a login) is a
                                // skipped tick, not a failed check (MIK-7982).
                                if e.is_authorization_wait() {
                                    debug!(backend = %backend.name, error = %e, "Health check skipped");
                                } else {
                                    warn!(backend = %backend.name, error = %e, "Health check failed");
                                }
                            }
                        }
                    }
                }
                // `Option::None` never resolves, so stdio mode simply loops
                // until its handle is aborted.
                Some(()) = async {
                    match shutdown.as_mut() {
                        Some(rx) => rx.recv().await.ok(),
                        None => std::future::pending().await,
                    }
                } => {
                    break;
                }
            }
        }
    })
}

pub(super) fn spawn_idle_reaper(
    backends: Arc<BackendRegistry>,
    shutdown: Option<tokio::sync::broadcast::Receiver<()>>,
) -> tokio::task::JoinHandle<()> {
    /// Per-user slots keep their own fixed TTL. Pointing them at
    /// `stop_when_idle_for` would silently repurpose a backend-lifetime setting
    /// into a per-user session lifetime, discarding stateful HTTP sessions and
    /// OAuth refresh state at that cadence.
    const PER_USER_IDLE_TTL: std::time::Duration = std::time::Duration::from_secs(300);
    const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SWEEP_INTERVAL);
        let mut shutdown = shutdown;
        loop {
            let tick = interval.tick();
            if let Some(rx) = shutdown.as_mut() {
                tokio::select! {
                    _ = tick => {}
                    _ = rx.recv() => break,
                }
            } else {
                tick.await;
            }

            for backend in backends.all() {
                let closed = backend.evict_idle_per_user_entries(PER_USER_IDLE_TTL);
                if closed > 0 {
                    debug!(
                        backend = %backend.name,
                        closed,
                        "Evicted idle per-user transport slots"
                    );
                }

                // No-op unless this backend opted in AND the gateway owns its
                // process; declines while work is in flight.
                if backend.stop_if_idle().await {
                    debug!(
                        backend = %backend.name,
                        "Stopped idle backend; next request restarts it"
                    );
                }
            }
        }
    })
}
