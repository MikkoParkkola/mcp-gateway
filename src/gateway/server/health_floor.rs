// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The health floor adapter (restart slice 6b): the health history's part of
//! a restart checkpoint. `pause` closes the gate the periodic saver and the
//! sampler check under their own locks; `checkpoint` saves one coherent cut on
//! a worker the adapter owns, under SAVES and then the history lock; the
//! sync calls reopen, release or finish the gate without waiting. Unwired
//! until the restart coordinator (a later part) builds it.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Arc, OnceLock};

use futures::future::BoxFuture;
use tokio::time::Instant;

use super::health_wiring::{Clock, SampleInputs};
use crate::gateway::restart_floor::{FloorAdapter, FloorFault, FloorOwner};
use crate::health_history::HealthHistory;
use crate::health_history::file::{self, SaveOutcome};
use crate::health_history::gate::{Closure, GateState, HealthGate};

/// See the module doc.
pub(crate) struct HealthFloor {
    gate: Arc<HealthGate>,
    history: Arc<HealthHistory>,
    path: Option<PathBuf>,
    sample_inputs: Arc<OnceLock<SampleInputs>>,
    clock: Clock,
    /// The latest checkpoint's worker and its attempt's live flag.
    worker: Option<(tokio::task::JoinHandle<SaveOutcome>, Arc<AtomicBool>)>,
    /// Resume replays not yet seen finished (pruned by resume).
    replays: Vec<std::thread::JoinHandle<()>>,
    /// The last checkpoint returned Ok and nothing since reopened the gate.
    certified: bool,
    #[cfg(test)]
    panic_next: bool,
    #[cfg(test)]
    fail_spawn_next: bool,
}

/// Moved into the checkpoint future: dropped before the worker's result was
/// taken (at the deadline, polled or not), it ends the attempt, so a worker
/// still waiting on SAVES writes nothing when it gets the lock.
struct LiveGuard(Option<Arc<AtomicBool>>);

impl LiveGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        if let Some(live) = self.0.take() {
            live.store(false, SeqCst);
        }
    }
}

impl HealthFloor {
    pub(super) fn new(
        gate: Arc<HealthGate>,
        history: Arc<HealthHistory>,
        path: Option<PathBuf>,
        sample_inputs: Arc<OnceLock<SampleInputs>>,
        clock: Clock,
    ) -> Self {
        Self {
            gate,
            history,
            path,
            sample_inputs,
            clock,
            worker: None,
            replays: Vec::new(),
            certified: false,
            #[cfg(test)]
            panic_next: false,
            #[cfg(test)]
            fail_spawn_next: false,
        }
    }

    /// End the current attempt: its worker, if still before its live check,
    /// writes nothing.
    fn end_attempt(&self) {
        if let Some((_, live)) = &self.worker {
            live.store(false, SeqCst);
        }
    }

    fn worker_done(&self) -> bool {
        self.worker
            .as_ref()
            .is_none_or(|(handle, _)| handle.is_finished())
    }

    /// Run the claimed sample, then the claimed save (with Block), each
    /// through the normal gated path, on one thread of its own.
    fn spawn_replay(
        &mut self,
        sample: bool,
        save: bool,
    ) -> std::io::Result<std::thread::JoinHandle<()>> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_spawn_next) {
            return Err(std::io::Error::other(
                "the replay spawn was refused for a test",
            ));
        }
        let (gate, history, path) = (
            Arc::clone(&self.gate),
            Arc::clone(&self.history),
            self.path.clone(),
        );
        let (inputs, clock) = (Arc::clone(&self.sample_inputs), self.clock);
        std::thread::Builder::new()
            .name("health replay".to_owned())
            .spawn(move || {
                if sample {
                    #[cfg(test)]
                    crate::health_history::pause_points::at(
                        crate::health_history::pause_points::Point::ReplayBeforeSample,
                        &history.key(),
                    );
                    if inputs.get().is_none() {
                        tracing::debug!(
                            "health replay: no sampler started; the coalesced sample is dropped"
                        );
                    }
                    super::health_wiring::sampler_closure(
                        Arc::clone(&gate),
                        Arc::clone(&history),
                        inputs,
                        clock,
                    )();
                }
                if save && let (Some(path), Ok(now)) = (&path, clock()) {
                    file::save_gated(&history, path, now, &gate, file::Wait::Block);
                }
            })
    }

    /// Whether the checkpoint worker, if any, has ended (a test probe).
    #[cfg(test)]
    pub(crate) fn worker_finished(&self) -> bool {
        self.worker_done()
    }

    /// Whether the last checkpoint certified (a test probe).
    #[cfg(test)]
    pub(crate) fn certified(&self) -> bool {
        self.certified
    }

    /// Make the next checkpoint worker panic (the WorkerLost row).
    #[cfg(test)]
    pub(crate) fn panic_next_worker(&mut self) {
        self.panic_next = true;
    }

    /// Make the next replay thread fail to spawn (the self-heal row).
    #[cfg(test)]
    pub(crate) fn fail_next_replay_spawn(&mut self) {
        self.fail_spawn_next = true;
    }
}

/// A refusal's ready future.
fn refused<'a>() -> BoxFuture<'a, Result<(), FloorFault>> {
    Box::pin(std::future::ready(Err(FloorFault::Unavailable)))
}

impl FloorAdapter for HealthFloor {
    fn owner(&self) -> FloorOwner {
        FloorOwner::Health
    }

    /// Open -> Paused, stored here, before the (ready) future: an unpolled or
    /// dropped pause still leaves the gate closed for resume or release.
    fn pause(&mut self, _deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        let outcome = if self.gate.state() == GateState::Open {
            self.gate.store(GateState::Paused);
            self.certified = false;
            Ok(())
        } else {
            Err(FloorFault::Unavailable)
        };
        Box::pin(std::future::ready(outcome))
    }

    /// One worker per attempt, started and stored before the future exists,
    /// so a dropped future leaves it tracked by `settled`. The deadline is the
    /// coordinator's: this future only waits, and its guard ends the attempt
    /// if it is dropped first.
    fn checkpoint(&mut self, _deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        if self.gate.state() != GateState::Paused || !self.worker_done() {
            return refused();
        }
        let (Some(path), Ok(now)) = (self.path.clone(), (self.clock)()) else {
            return refused();
        };
        let live = Arc::new(AtomicBool::new(true));
        let (history, worker_live) = (Arc::clone(&self.history), Arc::clone(&live));
        #[cfg(test)]
        let panic_now = std::mem::take(&mut self.panic_next);
        let handle = tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            assert!(!panic_now, "the WorkerLost row's worker panic");
            file::checkpoint_save(&history, &path, now, &worker_live)
        });
        self.worker = Some((handle, Arc::clone(&live)));
        let mut guard = LiveGuard(Some(live));
        Box::pin(async move {
            let Some((handle, _)) = self.worker.as_mut() else {
                return Err(FloorFault::WorkerLost);
            };
            let outcome = handle.await;
            guard.disarm();
            match outcome {
                Ok(SaveOutcome::Saved) => {
                    self.certified = true;
                    Ok(())
                }
                Ok(SaveOutcome::Failed) => Err(FloorFault::SaveFailed),
                Ok(SaveOutcome::Superseded | SaveOutcome::Busy | SaveOutcome::GateSkipped) => {
                    Err(FloorFault::Unavailable)
                }
                Err(_) => Err(FloorFault::WorkerLost),
            }
        })
    }

    /// Reopen and replay what was coalesced: claim each mark (the claimant
    /// owns the single run) and run the claimed work on one new thread.
    fn resume(&mut self) {
        if matches!(self.gate.state(), GateState::Released | GateState::Terminal) {
            return;
        }
        self.end_attempt();
        self.certified = false;
        self.gate.store(GateState::Open);
        let sample = self.gate.claim(Closure::Sample);
        let save = self.gate.claim(Closure::Save);
        self.replays.retain(|replay| !replay.is_finished());
        if !(sample || save) {
            return;
        }
        match self.spawn_replay(sample, save) {
            Ok(replay) => self.replays.push(replay),
            Err(error) => {
                tracing::warn!(%error, "health replay could not start a thread; the next periodic tick saves and samples")
            }
        }
    }

    fn release_for_stop(&mut self) {
        if matches!(self.gate.state(), GateState::Released | GateState::Terminal) {
            return;
        }
        self.end_attempt();
        self.certified = false;
        self.gate.store(GateState::Released);
    }

    fn commit(&mut self) {
        if self.gate.state() == GateState::Paused && self.certified {
            self.gate.store(GateState::Terminal);
        } else {
            tracing::debug!("health floor: commit without a certified checkpoint; ignored");
        }
    }

    fn settled(&self) -> bool {
        self.worker_done()
            && self
                .replays
                .iter()
                .all(std::thread::JoinHandle::is_finished)
    }
}

#[cfg(test)]
#[path = "health_floor_tests.rs"]
mod tests;
