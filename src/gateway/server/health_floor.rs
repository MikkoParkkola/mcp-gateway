// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The health floor adapter (restart slice 6b): the health history's part of
//! a restart checkpoint. `pause` closes the gate the periodic saver and the
//! sampler check under their own locks; `checkpoint` saves one coherent cut on
//! a worker the adapter owns, under SAVES and then the history lock; the
//! sync calls reopen, release or finish the gate without waiting. Unwired
//! until the restart coordinator (a later part) builds it.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use futures::future::BoxFuture;
use tokio::time::Instant;

use super::health_wiring::{Clock, SampleInputs};
use crate::gateway::restart_floor::{FloorAdapter, FloorFault, FloorOwner};
use crate::health_history::HealthHistory;
use crate::health_history::gate::HealthGate;

/// See the module doc.
pub(crate) struct HealthFloor {
    gate: Arc<HealthGate>,
    history: Arc<HealthHistory>,
    path: Option<PathBuf>,
    sample_inputs: Arc<OnceLock<SampleInputs>>,
    clock: Clock,
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
        }
    }

    /// Whether the checkpoint worker, if any, has ended (a test probe).
    // red-phase: stub, there is no worker.
    #[cfg(test)]
    pub(crate) fn worker_finished(&self) -> bool {
        true
    }

    /// Whether the last checkpoint certified (a test probe).
    // red-phase: stub, never certified.
    #[cfg(test)]
    pub(crate) fn certified(&self) -> bool {
        false
    }

    /// Make the next checkpoint worker panic (the WorkerLost row).
    // red-phase: stub, there is no worker to fail.
    #[cfg(test)]
    pub(crate) fn panic_next_worker(&mut self) {}

    /// Make the next replay thread fail to spawn (the self-heal row).
    // red-phase: stub, there is no replay to fail.
    #[cfg(test)]
    pub(crate) fn fail_next_replay_spawn(&mut self) {}
}

// red-phase: every call is a stub: no gate, no worker, no replay.
impl FloorAdapter for HealthFloor {
    fn owner(&self) -> FloorOwner {
        FloorOwner::Health
    }

    fn pause(&mut self, deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        let _ = deadline;
        Box::pin(async { Ok(()) })
    }

    fn checkpoint(&mut self, deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        let _ = (
            deadline,
            &self.gate,
            &self.history,
            &self.path,
            &self.sample_inputs,
            self.clock,
        );
        Box::pin(async { Ok(()) })
    }

    fn resume(&mut self) {}

    fn release_for_stop(&mut self) {}

    fn commit(&mut self) {}

    fn settled(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[path = "health_floor_tests.rs"]
mod tests;
