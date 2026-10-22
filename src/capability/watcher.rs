// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Hot-reload file watcher for capabilities
//!
//! Watches capability directories for changes and triggers reload
//! when files are added, modified, or removed.
//!
//! A reload runs in its own spawned task, which the loop polls on its 100 ms
//! tick rather than awaits, so one hung reload cannot starve the loop or the
//! stale check. A reload still running past `reload_slow` (60 s in production)
//! warns once, naming the stage it is stuck in, and is never cancelled: a
//! cancelled write could leave a half-built catalogue, and the swap is atomic
//! only at the end.
//!
//! ## Stale check (MIK-8651 HEAL.1)
//!
//! File events can stop arriving without any error (a dead event source), so
//! every `stale_check_secs` (default 60; `0` turns the check off) the loop
//! fingerprints the watched trees and compares the result with the
//! fingerprint taken before the last complete reload. On drift, with no reload
//! pending or in flight, it warns and reloads through the normal debounced
//! path. The fingerprint is the sorted `(directory index, relative path,
//! length, mtime)` of every `*.yaml`/`*.yml` under the watched roots. The
//! baseline advances only to the fingerprint taken *before* a reload that
//! returned `Ok` with every directory loaded, so an edit made during a reload
//! still differs on the next tick and reloads again, while a failed reload
//! keeps the old baseline and retries with a warn.
//!
//! Limits: a change that keeps the same length within the filesystem's mtime
//! granularity is missed; a hung reload is reported, never cancelled or
//! healed; the walk stops at depth 16 and 10 000 entries, past either of
//! which that tick warns and skips healing.
//!
//! ## Warn lines
//!
//! Every path that used to stop silently now warns. Once per task: the
//! shutdown channel closed; the file event source is gone; a file event
//! found the reload task gone; the watched tree exceeded the walk bounds.
//! Once per reload: the reload is still running past `reload_slow`. Once per
//! drift: the files changed but no file event arrived. On every occurrence:
//! the shutdown channel lagged; a reload that failed or left a directory
//! unloaded, which will be retried.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use super::CapabilityBackend;
use crate::Result;

/// Told the capability backend's name whenever its catalogue may have changed:
/// once its startup scan completes, and after every successful reload (F24,
/// `MIK-8127`). The listener decides whether anything visible moved.
pub type CatalogueChanged = Arc<dyn Fn(&str) + Send + Sync>;

/// File watcher for hot-reloading capabilities
pub struct CapabilityWatcher {
    /// The underlying watcher
    _watcher: Mutex<Option<RecommendedWatcher>>,
}

/// Timing knobs for the reload task. Production builds them from
/// `capabilities.stale_check_secs` via
/// [`ReloadTuning::from_config_secs`] in [`CapabilityWatcher::start`];
/// tests build their own.
#[derive(Clone, Copy, Debug)]
struct ReloadTuning {
    /// Stale-catalogue check interval; `None` = off.
    stale_check: Option<Duration>,
    /// A reload still running after this logs a warn.
    reload_slow: Duration,
    /// Quiet time after the last event before a reload.
    debounce: Duration,
}

impl Default for ReloadTuning {
    fn default() -> Self {
        Self {
            stale_check: Some(Duration::from_secs(60)),
            reload_slow: Duration::from_secs(60),
            debounce: Duration::from_millis(500),
        }
    }
}

impl ReloadTuning {
    /// Production tuning from config: `0` turns the stale check off, any
    /// other value is its interval in seconds. Restart-only, like the key.
    fn from_config_secs(stale_check_secs: u64) -> Self {
        let stale_check = if stale_check_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(stale_check_secs))
        };
        Self {
            stale_check,
            ..Self::default()
        }
    }
}

#[path = "watcher_fingerprint.rs"]
mod fingerprint;

use fingerprint::{Fingerprint, blocking_fingerprint};

/// In-flight reload bookkeeping (MIK-8651 LOUD.1, candidate e): the loop holds
/// the spawned reload's start time and the stage it last reported, and warns
/// once when the reload runs past `reload_slow`. A hung reload is reported,
/// never cancelled or healed.
struct InFlight {
    started: Instant,
    stage: Arc<std::sync::atomic::AtomicU8>,
    warned: bool,
}

impl InFlight {
    /// The slow-reload warning, at most once: `Some(message)` when `now` has
    /// reached `started + reload_slow` and no warning has fired yet, `None`
    /// before that and on every later call.
    fn slow_warning(&mut self, now: Instant, reload_slow: Duration) -> Option<String> {
        if self.warned {
            return None;
        }
        if now.saturating_duration_since(self.started) < reload_slow {
            return None;
        }
        self.warned = true;
        let stage = match self.stage.load(std::sync::atomic::Ordering::SeqCst) {
            1 => "scan",
            2 => "reload",
            3 => "callback",
            // 0, and anything else: the task reports 1-3 before each step.
            _ => "starting",
        };
        let slow_secs = reload_slow.as_secs();
        Some(format!(
            "capability reload still running after {slow_secs}s: stage {stage}"
        ))
    }
}

/// Mutable state of the reload loop, threaded through its tick helpers.
#[derive(Default)]
struct LoopState {
    /// The file event channel is still open; `false` once it closes.
    events_open: bool,
    /// A reload is wanted once the debounce has elapsed.
    pending_reload: bool,
    /// When the last file event (or stale heal) arrived.
    last_event: Option<Instant>,
    /// The running reload, if any: its join handle, its slow-warning
    /// bookkeeping, and the fingerprint taken before it started.
    in_flight: Option<(tokio::task::JoinHandle<bool>, InFlight, Option<Fingerprint>)>,
    /// The fingerprint taken before the last complete reload; `None` with
    /// the stale check off, or while the first arm is still pending.
    baseline: Option<Fingerprint>,
    /// One-time log lines already emitted.
    logged: LoggedOnce,
}

/// One-time log lines of the reload loop, each emitted at most once.
#[derive(Default)]
struct LoggedOnce {
    /// The "stale check armed" line.
    stale_armed: bool,
    /// The walk-bounds skip warning.
    bounds_skip: bool,
}

/// Wait for a real shutdown on a broadcast channel that may also lag or lose
/// its senders. `Ok(())` is a real shutdown and returns; `Lagged` warns and
/// the wait continues, since a lagged receiver still holds the latest send;
/// `Closed` warns once and then waits forever, since no sender is left to
/// deliver a real shutdown and exiting would stop the watcher on one.
async fn real_shutdown(rx: &mut tokio::sync::broadcast::Receiver<()>) {
    loop {
        match rx.recv().await {
            Ok(()) => return,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(
                    skipped = skipped,
                    "Capability watcher: shutdown channel Lagged; still running"
                );
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                warn!("Capability watcher: shutdown channel closed; watcher keeps running");
                // Never resolves, so the warn above fires once per task.
                std::future::pending::<()>().await;
            }
        }
    }
}

impl CapabilityWatcher {
    /// Start watching capability directories for changes
    ///
    /// This spawns a background task that watches for file changes and
    /// triggers `backend.reload()` when changes are detected.
    ///
    /// # Errors
    ///
    /// Returns an error if the file watcher cannot be created.
    ///
    /// `changes` hears the backend's name once its startup scan completes and
    /// after every successful reload, so listeners get `tools/list_changed`
    /// when the catalogue they see changed (F24).
    ///
    /// `stale_check_secs` tunes the stale-catalogue check: the check runs
    /// every that many seconds, and `0` turns it off. Restart-only, like
    /// the key.
    pub fn start(
        backend: Arc<CapabilityBackend>,
        shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        changes: Option<CatalogueChanged>,
        stale_check_secs: u64,
    ) -> Result<Self> {
        let tuning = ReloadTuning::from_config_secs(stale_check_secs);
        if let Some(changes) = &changes {
            // Before any early return: without a file watcher the catalogue
            // can still change (a manual reload), so its baseline is needed.
            Self::report_startup_scan(
                Arc::clone(&backend),
                shutdown_rx.resubscribe(),
                Arc::clone(changes),
            );
        }
        let directories = backend.watched_directories();
        debug!(directories = ?directories, "Starting capability watcher");

        if directories.is_empty() {
            info!("No capability directories to watch");
            return Ok(Self {
                _watcher: Mutex::new(None),
            });
        }

        // Channel for file events
        let (event_tx, event_rx) = mpsc::channel(100);

        // Create watcher
        let watcher = Self::create_watcher(event_tx, &directories)?;
        debug!("File watcher created successfully");

        // Spawn debounced reload task
        Self::spawn_reload_task_tuned(backend, event_rx, shutdown_rx, changes, tuning);
        debug!("Reload task spawned");

        Ok(Self {
            _watcher: Mutex::new(Some(watcher)),
        })
    }

    /// Create the file system watcher
    fn create_watcher(
        event_tx: mpsc::Sender<()>,
        directories: &[String],
    ) -> Result<RecommendedWatcher> {
        // Warns once when the reload task is gone: after that every event
        // would warn the same thing.
        let reload_task_gone = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut watcher = RecommendedWatcher::new(
            move |result: std::result::Result<Event, notify::Error>| {
                match result {
                    Ok(event) => {
                        // Only react to relevant events on YAML files
                        let is_relevant = matches!(
                            event.kind,
                            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                        ) && event.paths.iter().any(|p| {
                            p.extension()
                                .is_some_and(|ext| ext == "yaml" || ext == "yml")
                        });

                        if is_relevant {
                            debug!(paths = ?event.paths, kind = ?event.kind, "Capability file change");
                            // A `()` channel that is full already holds a
                            // pending reload, so a `Full` drop loses nothing
                            // and stays silent; only a closed channel — the
                            // reload task is gone — is worth a warn.
                            if let Err(tokio::sync::mpsc::error::TrySendError::Closed(())) =
                                event_tx.try_send(())
                                && !reload_task_gone
                                    .swap(true, std::sync::atomic::Ordering::SeqCst)
                            {
                                warn!("capability file event dropped: the reload task is gone");
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "File watcher error");
                    }
                }
            },
            Config::default().with_poll_interval(Duration::from_secs(2)),
        )
        .map_err(|e| crate::Error::ConfigWatcher(format!("Failed to create file watcher: {e}")))?;

        // Watch all directories
        for dir in directories {
            let path = Path::new(dir);
            if path.exists() {
                if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
                    warn!(directory = %dir, error = %e, "Failed to watch directory");
                } else {
                    info!(directory = %dir, "Watching for capability changes");
                }
            } else {
                debug!(directory = %dir, "Directory does not exist, skipping watch");
            }
        }

        Ok(watcher)
    }

    /// Report the catalogue once its startup scan completes: that result is
    /// the baseline every later reload is compared with (`MIK-8127`).
    fn report_startup_scan(
        backend: Arc<CapabilityBackend>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        changes: CatalogueChanged,
    ) {
        tokio::spawn(async move {
            // ponytail: polled at the reload task's own 100 ms tick, since the
            // scan has no completion signal; add one if this ever matters.
            let mut tick = tokio::time::interval(Duration::from_millis(100));
            // One wait for the whole task: a fresh wait every round would
            // warn a closed channel on every tick, not once.
            let shutdown_wait = real_shutdown(&mut shutdown_rx);
            tokio::pin!(shutdown_wait);
            loop {
                tokio::select! {
                    () = &mut shutdown_wait => return,
                    _ = tick.tick() => {
                        if backend.initial_scan_complete() {
                            changes(&backend.name);
                            return;
                        }
                    }
                }
            }
        });
    }

    /// Spawn the background reload task with debouncing, at production
    /// timing. Callers that tune the timing use
    /// [`spawn_reload_task_tuned`](Self::spawn_reload_task_tuned) instead.
    #[cfg(test)]
    fn spawn_reload_task(
        backend: Arc<CapabilityBackend>,
        event_rx: mpsc::Receiver<()>,
        shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        changes: Option<CatalogueChanged>,
    ) {
        Self::spawn_reload_task_tuned(
            backend,
            event_rx,
            shutdown_rx,
            changes,
            ReloadTuning::default(),
        );
    }

    /// Spawn the reload task with explicit timing knobs (MIK-8651): the
    /// debounced event path, the stale-catalogue check, and the supervised
    /// reload described in the module docs.
    fn spawn_reload_task_tuned(
        backend: Arc<CapabilityBackend>,
        mut event_rx: mpsc::Receiver<()>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        changes: Option<CatalogueChanged>,
        tuning: ReloadTuning,
    ) {
        tokio::spawn(async move {
            let debounce = tuning.debounce;
            let reload_slow = tuning.reload_slow;
            let mut state = LoopState {
                events_open: true,
                ..LoopState::default()
            };
            // The stale baseline, armed before the loop so the first tick
            // already compares against the catalogue as the task found it.
            // With the check off the baseline stays `None` and the stale
            // branch below waits forever.
            if tuning.stale_check.is_some() {
                state.baseline = blocking_fingerprint(backend.watched_directories()).await;
            }
            if state.baseline.is_some() {
                state.logged.stale_armed = true;
                info!("Capability stale check armed");
            }

            let mut interval = tokio::time::interval(Duration::from_millis(100));
            let mut stale_interval = tuning.stale_check.map(tokio::time::interval);
            // One wait for the whole task: a fresh wait every round would
            // warn a closed channel on every tick, not once.
            let shutdown_wait = real_shutdown(&mut shutdown_rx);
            tokio::pin!(shutdown_wait);
            loop {
                tokio::select! {
                    maybe = event_rx.recv(), if state.events_open => {
                        if let Some(()) = maybe {
                            state.last_event = Some(Instant::now());
                            state.pending_reload = true;
                        } else {
                            state.events_open = false;
                            warn!(
                                "Capability watcher: file event source is gone; relying on the stale check"
                            );
                        }
                    }
                    _ = interval.tick() => {
                        Self::on_tick(&mut state, &backend, changes.as_ref(), debounce, reload_slow).await;
                    }
                    () = async {
                        if let Some(stale) = stale_interval.as_mut() {
                            stale.tick().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        Self::on_stale_tick(&mut state, &backend, debounce).await;
                    }
                    () = &mut shutdown_wait => {
                        info!("Capability watcher shutting down");
                        break;
                    }
                }
            }
        });
    }

    /// One 100 ms tick of the reload loop: reap a finished reload,
    /// warn about a slow one, and start a pending reload past its
    /// debounce.
    async fn on_tick(
        state: &mut LoopState,
        backend: &Arc<CapabilityBackend>,
        changes: Option<&CatalogueChanged>,
        debounce: Duration,
        reload_slow: Duration,
    ) {
        Self::reap_in_flight(state, backend).await;
        // Report a reload running past `reload_slow`, once; the reload
        // itself is never cancelled.
        if let Some((_, active, _)) = state.in_flight.as_mut()
            && let Some(message) = active.slow_warning(Instant::now(), reload_slow)
        {
            warn!("{message}");
        }
        // Start a reload when one is pending, the debounce has elapsed
        // and none is in flight.
        if state.pending_reload
            && state.in_flight.is_none()
            && state.last_event.is_some_and(|at| at.elapsed() >= debounce)
        {
            // The fingerprint is taken before the reload starts; the
            // baseline advances to it only when the reload completes
            // (see `reap_in_flight`).
            let before = blocking_fingerprint(backend.watched_directories()).await;
            let (handle, active) = Self::spawn_reload(Arc::clone(backend), changes.cloned());
            state.in_flight = Some((handle, active, before));
            state.pending_reload = false;
            state.last_event = None;
        }
    }

    /// Reap a finished reload. The baseline advances to the fingerprint
    /// taken before the reload, so an edit made during the reload still
    /// differs on the next tick and reloads again.
    async fn reap_in_flight(state: &mut LoopState, backend: &CapabilityBackend) {
        let finished = state
            .in_flight
            .as_ref()
            .is_some_and(|(handle, _, _)| handle.is_finished());
        if finished && let Some((handle, _, before)) = state.in_flight.take() {
            match handle.await {
                Ok(reloaded) => {
                    if reloaded
                        && backend.initial_scan_loaded_every_directory()
                        && let Some(found) = before
                    {
                        state.baseline = Some(found);
                    } else {
                        warn!("capability reload incomplete; will retry");
                    }
                }
                Err(join_error) => {
                    if join_error.is_panic() {
                        // Dev fails as release aborts
                        // (r3): re-raise the panic.
                        std::panic::resume_unwind(join_error.into_panic());
                    }
                    warn!("capability reload cancelled; will retry");
                }
            }
        }
    }

    /// One stale-check tick: fingerprint the watched trees and, on drift
    /// with no reload pending or in flight, warn and queue a reload
    /// through the normal debounced path.
    async fn on_stale_tick(state: &mut LoopState, backend: &CapabilityBackend, debounce: Duration) {
        trace!("Capability stale check tick");
        match blocking_fingerprint(backend.watched_directories()).await {
            None => {
                if !state.logged.bounds_skip {
                    state.logged.bounds_skip = true;
                    warn!("stale check skipped: watched tree exceeds the walk bounds");
                }
            }
            Some(found) => {
                if state.baseline.is_none() {
                    // First-arm path: the start-of-task walk exceeded the
                    // bounds, so try again.
                    state.baseline = Some(found);
                    if !state.logged.stale_armed {
                        state.logged.stale_armed = true;
                        info!("Capability stale check armed");
                    }
                } else if state.baseline.as_ref().is_some_and(|base| found != *base)
                    && !state.pending_reload
                    && state.in_flight.is_none()
                {
                    warn!("capability files changed but no file event arrived; reloading");
                    state.pending_reload = true;
                    // Due on the next 100 ms tick: the reload starts there,
                    // not here, so both paths share the one guarded start
                    // in `on_tick`.
                    let now = Instant::now();
                    state.last_event = Some(now.checked_sub(debounce).unwrap_or(now));
                }
            }
        }
    }

    /// Spawn one reload and return its join handle with the in-flight
    /// bookkeeping. The handle resolves to `true` when `reload()` returned
    /// `Ok`. The loop polls the handle on its tick instead of awaiting it,
    /// so a hung reload is reported, never cancelled.
    fn spawn_reload(
        backend: Arc<CapabilityBackend>,
        changes: Option<CatalogueChanged>,
    ) -> (tokio::task::JoinHandle<bool>, InFlight) {
        let stage = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let inflight = InFlight {
            started: Instant::now(),
            stage: Arc::clone(&stage),
            warned: false,
        };
        let handle = tokio::spawn(async move {
            // Stage 1: the rug-pull scan (Invariant Labs tool-poisoning
            // guard). Before any reload, verify every pinned capability
            // YAML still matches its embedded sha256. Mismatches are
            // quarantined LOUDLY and unloaded so the reload cannot
            // silently restore them.
            stage.store(1, std::sync::atomic::Ordering::SeqCst);
            let rug_pulls = backend.detect_rug_pulls().await;
            if !rug_pulls.is_empty() {
                warn!(
                    backend = %backend.name,
                    count = rug_pulls.len(),
                    "Rug-pull events detected; affected capabilities quarantined",
                );
            }
            // Stage 2: the reload itself.
            stage.store(2, std::sync::atomic::Ordering::SeqCst);
            info!(backend = %backend.name, "Hot-reloading capabilities...");
            let reloaded = match backend.reload().await {
                Ok(count) => {
                    info!(
                        backend = %backend.name,
                        capabilities = count,
                        "Hot-reload complete"
                    );
                    true
                }
                Err(e) => {
                    error!(
                        backend = %backend.name,
                        error = %e,
                        "Hot-reload failed"
                    );
                    false
                }
            };
            // Stage 3: the `changes` callback, on success only.
            if reloaded {
                stage.store(3, std::sync::atomic::Ordering::SeqCst);
                if let Some(changes) = &changes {
                    changes(&backend.name);
                }
            }
            reloaded
        });
        (handle, inflight)
    }
}

#[cfg(test)]
#[path = "watcher_tests.rs"]
mod tests;
