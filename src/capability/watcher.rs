// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Hot-reload file watcher for capabilities
//!
//! Watches capability directories for changes and triggers reload
//! when files are added, modified, or removed.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

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
    pub fn start(
        backend: Arc<CapabilityBackend>,
        shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        changes: Option<CatalogueChanged>,
    ) -> Result<Self> {
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
        Self::spawn_reload_task(backend, event_rx, shutdown_rx, changes);
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
                            // Non-blocking send - if channel is full, skip this event
                            let _ = event_tx.try_send(());
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

    /// Spawn the background reload task with debouncing
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
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => return,
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

    fn spawn_reload_task(
        backend: Arc<CapabilityBackend>,
        mut event_rx: mpsc::Receiver<()>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
        changes: Option<CatalogueChanged>,
    ) {
        tokio::spawn(async move {
            // Debounce: wait 500ms after last event before reloading
            const DEBOUNCE_MS: u64 = 500;
            let mut last_event: Option<Instant> = None;
            let mut pending_reload = false;

            let mut interval = tokio::time::interval(Duration::from_millis(100));

            loop {
                tokio::select! {
                    Some(()) = event_rx.recv() => {
                        last_event = Some(Instant::now());
                        pending_reload = true;
                    }
                    _ = interval.tick() => {
                        // Check if we should trigger reload
                        if pending_reload
                            && let Some(last) = last_event
                                && last.elapsed() >= Duration::from_millis(DEBOUNCE_MS) {
                                    pending_reload = false;
                                    last_event = None;

                                    // ── Rug-pull scan (Invariant Labs tool-poisoning guard) ──
                                    // Before any reload, verify every pinned
                                    // capability YAML still matches its
                                    // embedded sha256. Mismatches are
                                    // quarantined LOUDLY and unloaded so the
                                    // reload cannot silently restore them.
                                    let rug_pulls = backend.detect_rug_pulls().await;
                                    if !rug_pulls.is_empty() {
                                        warn!(
                                            backend = %backend.name,
                                            count = rug_pulls.len(),
                                            "Rug-pull events detected; affected capabilities quarantined",
                                        );
                                    }

                                    info!(backend = %backend.name, "Hot-reloading capabilities...");
                                    match backend.reload().await {
                                        Ok(count) => {
                                            info!(
                                                backend = %backend.name,
                                                capabilities = count,
                                                "Hot-reload complete"
                                            );
                                            if let Some(changes) = &changes {
                                                changes(&backend.name);
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                backend = %backend.name,
                                                error = %e,
                                                "Hot-reload failed"
                                            );
                                        }
                                    }
                                }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Capability watcher shutting down");
                        break;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watcher_creation() {
        // Basic smoke test - actual file watching tested in integration tests
        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        let executor = Arc::new(crate::capability::CapabilityExecutor::new());
        let backend = Arc::new(crate::capability::CapabilityBackend::new("test", executor));

        // Should not panic with empty directories
        let watcher = CapabilityWatcher::start(backend, rx, None);
        assert!(watcher.is_ok());
    }
}
