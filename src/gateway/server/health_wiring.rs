// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's own health history at runtime: restored and saved once at
//! startup before anything is served, sampled every minute, saved with the
//! counters, and stopped cleanly at shutdown. None of it can stop the
//! gateway from starting: a failed write is logged and the run's history is
//! marked incomplete until a save succeeds.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::counter_wiring::{COUNTER_SAVE_INTERVAL, Counters};
use super::persistence::{ShutdownSave, spawn_periodic_save};
use crate::health_history::{HealthHistory, file};

/// How often memory and the session count are sampled.
const SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// The history and the file it saves to.
pub(super) struct Health {
    pub(super) history: Arc<HealthHistory>,
    path: PathBuf,
}

/// Restore the history from `data_dir`, save it once, and start its periodic
/// save, which ends on `shutdown`. Call right after the counters start.
pub(super) fn start(
    data_dir: &Path,
    counters: &Counters,
    shutdown: tokio::sync::broadcast::Receiver<()>,
) -> (Health, tokio::task::JoinHandle<()>) {
    let now = crate::clock::unix_secs().unwrap_or_default();
    // counters.json's Restart marker for this start goes to disk now, so a
    // crash before its periodic save cannot hide this run (best effort).
    counters.save_now(now);
    let path = data_dir.join("health.json");
    let previous = file::read(&path);
    let (history, started) =
        HealthHistory::start(previous.as_deref(), Some(counters.store.restores()), now);
    if started.missed_run {
        tracing::info!(
            "health history: a run it did not record happened; that time is shown as unaccounted"
        );
    }
    let history = Arc::new(history);
    file::save(&history, &path, now);
    file::install(Arc::clone(&history));
    let saver = spawn_periodic_save("health save", COUNTER_SAVE_INTERVAL, Some(shutdown), {
        let (history, path) = (Arc::clone(&history), path.clone());
        move || {
            if let Ok(now) = crate::clock::unix_secs() {
                file::save(&history, &path, now);
            }
        }
    });
    (Health { history, path }, saver)
}

impl Health {
    /// Sample memory and `sessions()` every minute until `shutdown`.
    pub(super) fn spawn_sampler(
        &self,
        sessions: impl Fn() -> usize + Send + Sync + 'static,
        shutdown: tokio::sync::broadcast::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        let history = Arc::clone(&self.history);
        spawn_periodic_save(
            "health sample",
            SAMPLE_INTERVAL,
            Some(shutdown),
            move || {
                if let Ok(now) = crate::clock::unix_secs() {
                    let memory = crate::gateway::health_metrics::process::resident_memory_bytes();
                    history.sample(memory, sessions() as u64, now);
                    history.tick(now);
                }
            },
        )
    }

    /// The shutdown step: a clean stop, then the save.
    pub(super) fn shutdown_save(&self) -> ShutdownSave {
        let (history, path) = (Arc::clone(&self.history), self.path.clone());
        (
            "health save (health.json)",
            Box::new(move || {
                if let Ok(now) = crate::clock::unix_secs() {
                    history.stop(now);
                    file::save(&history, &path, now);
                }
            }),
        )
    }
}
