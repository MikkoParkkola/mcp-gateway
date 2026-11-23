// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway's own health history at runtime: restored and saved once at
//! startup before anything is served, sampled every minute, saved with the
//! counters, and stopped cleanly at shutdown. None of it can stop the
//! gateway from starting: a failed write is logged and the run's history is
//! marked incomplete until a save succeeds.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use super::counter_wiring::{COUNTER_SAVE_INTERVAL, Counters};
use super::persistence::{ShutdownSave, spawn_periodic_save};
use crate::health_history::gate::HealthGate;
use crate::health_history::{HealthHistory, file};

/// The wall clock the closures and the floor adapter read; production passes
/// `crate::clock::unix_secs`, rows a fixed clock.
pub(super) type Clock = fn() -> Result<u64, crate::clock::ClockBeforeEpoch>;

/// What the sampler reads each minute, shared with the floor adapter's replay
/// so both read the same sources whichever is built first.
pub(super) struct SampleInputs {
    pub(super) memory: fn() -> Option<u64>,
    pub(super) sessions: Arc<dyn Fn() -> usize + Send + Sync>,
}

/// How often memory and the session count are sampled.
const SAMPLE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// The history and the file it saves to.
pub(super) struct Health {
    pub(super) history: Arc<HealthHistory>,
    /// `None` when saves are off for this run.
    pub(super) path: Option<PathBuf>,
    /// The health floor's gate, shared by the saver, the sampler and the adapter.
    pub(super) gate: Arc<HealthGate>,
    /// Set by `spawn_sampler`.
    pub(super) sample_inputs: Arc<OnceLock<SampleInputs>>,
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
    start_history(data_dir, now, counters.store.restores(), shutdown)
}

/// Everything `start` does after the counters' marker: restore, the first
/// save, and the periodic save behind the health floor's gate.
pub(super) fn start_history(
    data_dir: &Path,
    now: u64,
    restores: crate::health_history::Restores,
    shutdown: tokio::sync::broadcast::Receiver<()>,
) -> (Health, tokio::task::JoinHandle<()>) {
    let path = data_dir.join("health.json");
    let previous = file::read(&path);
    let (history, started) = HealthHistory::start(previous.as_deref(), restores, now);
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
    let gate = Arc::new(HealthGate::default());
    let saver = spawn_periodic_save(
        "health save",
        COUNTER_SAVE_INTERVAL,
        Some(shutdown),
        path.clone(),
        saver_closure(
            Arc::clone(&gate),
            Arc::clone(&history),
            path.clone(),
            crate::clock::unix_secs,
        ),
    );
    let health = Health {
        history,
        path,
        gate,
        sample_inputs: Arc::default(),
    };
    (health, saver)
}

/// The periodic save, behind the gate (start's closure; rows build the same).
pub(super) fn saver_closure(
    gate: Arc<HealthGate>,
    history: Arc<HealthHistory>,
    path: Option<PathBuf>,
    clock: Clock,
) -> impl Fn() + Send + Sync + 'static {
    let save = gated_save(gate, history, path, clock, file::Wait::SkipIfBusy);
    move || {
        save();
    }
}

/// A save behind the gate that never records a stop, returning whether it
/// wrote: the periodic save (`SkipIfBusy`), and the stop checkpoints' health
/// entry, which skips like it and waits (`Block`) in the last pass.
pub(super) fn gated_save(
    gate: Arc<HealthGate>,
    history: Arc<HealthHistory>,
    path: Option<PathBuf>,
    clock: Clock,
    wait: file::Wait,
) -> impl Fn() -> bool + Send + Sync + 'static {
    move || match (&path, clock()) {
        (Some(path), Ok(now)) => {
            file::save_gated(&history, path, now, &gate, wait) == file::SaveOutcome::Saved
        }
        _ => false,
    }
}

/// The periodic sample, behind the gate (`spawn_sampler`'s closure; rows build
/// the same). Without inputs set it does nothing.
pub(super) fn sampler_closure(
    gate: Arc<HealthGate>,
    history: Arc<HealthHistory>,
    inputs: Arc<OnceLock<SampleInputs>>,
    clock: Clock,
) -> impl Fn() + Send + Sync + 'static {
    move || {
        if let (Some(inputs), Ok(now)) = (inputs.get(), clock()) {
            let memory = (inputs.memory)();
            history.sample_and_tick_gated(&gate, memory, (inputs.sessions)() as u64, now);
        }
    }
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
        // One sampler per run: a second call keeps the first inputs.
        let _ = self.sample_inputs.set(SampleInputs {
            memory: crate::gateway::health_metrics::memory::resident_memory_bytes,
            sessions: Arc::new(sessions),
        });
        spawn_periodic_save(
            "health sample",
            SAMPLE_INTERVAL,
            Some(shutdown),
            // Samples into memory only: no file, nothing to keep.
            None,
            sampler_closure(
                Arc::clone(&self.gate),
                Arc::clone(&self.history),
                Arc::clone(&self.sample_inputs),
                crate::clock::unix_secs,
            ),
        )
    }

    /// The health floor adapter for a restart attempt (restart slice 6b),
    /// over this run's gate, history, path and sample inputs.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "staged: the restart coordinator, a later part, calls this"
        )
    )]
    pub(super) fn floor_adapter(&self, clock: Clock) -> super::health_floor::HealthFloor {
        super::health_floor::HealthFloor::new(
            Arc::clone(&self.gate),
            Arc::clone(&self.history),
            self.path.clone(),
            Arc::clone(&self.sample_inputs),
            clock,
        )
    }

    /// The stop checkpoints' health entry: the periodic save, which never
    /// records a stop, skipping while a save runs; in the last pass it waits.
    pub(super) fn checkpoint_class(&self) -> super::stop_checkpoints::Class {
        let save = |wait| -> super::stop_checkpoints::Save {
            Arc::new(gated_save(
                Arc::clone(&self.gate),
                Arc::clone(&self.history),
                self.path.clone(),
                crate::clock::unix_secs,
                wait,
            ))
        };
        super::stop_checkpoints::Class {
            name: "health",
            root: self.path.clone(),
            checkpoint: save(file::Wait::SkipIfBusy),
            last: save(file::Wait::Block),
        }
    }

    /// The shutdown step: a clean stop, then the save.
    pub(super) fn shutdown_save(&self) -> ShutdownSave {
        let (history, path) = (Arc::clone(&self.history), self.path.clone());
        ShutdownSave::new(
            "health save (health.json)",
            path.clone(),
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
