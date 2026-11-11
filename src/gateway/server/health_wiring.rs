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
    /// `None` when saves are off for this run.
    path: Option<PathBuf>,
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
        HealthHistory::start(previous.as_deref(), counters.store.restores(), now);
    if started.missed_run {
        tracing::info!(
            "health history: a run it did not record happened; that time is shown as unaccounted"
        );
    } else if let Some(restart) = started.restart {
        tracing::info!(
            down_secs = restart.started_at.saturating_sub(restart.stopped_at),
            source = ?restart.downtime_source,
            "health history: restart recorded"
        );
    } else if started.fresh {
        tracing::info!("health history: first start, nothing to restore");
    }
    // An undecodable file is moved aside, as counters.json is; when that
    // fails, this run never saves, so the old bytes are not overwritten.
    let path = save_path(
        started.set_aside,
        path,
        now,
        &history,
        crate::counters::persist::quarantine,
    );
    let history = Arc::new(history);
    if let Some(path) = &path {
        file::save(&history, path, now, file::Wait::Block);
    }
    file::install(Arc::clone(&history));
    let saver = spawn_periodic_save("health save", COUNTER_SAVE_INTERVAL, Some(shutdown), {
        let (history, path) = (Arc::clone(&history), path.clone());
        move || {
            if let (Some(path), Ok(now)) = (&path, crate::clock::unix_secs()) {
                file::save(&history, path, now, file::Wait::SkipIfBusy);
            }
        }
    });
    (Health { history, path }, saver)
}

/// Where this run saves health.json: `path`, unless an undecodable file was
/// there and could not be moved aside by `move_aside`: then nowhere, so the
/// old bytes survive, and the run's history is marked incomplete.
pub(super) fn save_path(
    set_aside: bool,
    path: PathBuf,
    now: u64,
    history: &HealthHistory,
    move_aside: impl FnOnce(&Path, u64) -> std::io::Result<PathBuf>,
) -> Option<PathBuf> {
    if !set_aside {
        return Some(path);
    }
    match move_aside(&path, now) {
        Ok(aside) => {
            tracing::warn!(aside = %aside.display(), "health.json did not decode; moved aside, the health history starts again");
            Some(path)
        }
        Err(e) => {
            tracing::error!(error = %e, "health.json did not decode and could not be moved aside; health saves are off for this run");
            history.set_incomplete(true);
            None
        }
    }
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
                    let memory = crate::gateway::health_metrics::memory::resident_memory_bytes();
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
                    if let Some(path) = &path {
                        file::save(&history, path, now, file::Wait::Block);
                    }
                }
            }),
        )
    }
}
