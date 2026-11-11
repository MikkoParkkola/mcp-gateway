// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The restart cancel floor: exactly three owners (task store, config state,
//! health state) must certify a checkpoint before a restart commits. Any other
//! failed save is logged and the stop proceeds, as on a normal SIGTERM stop.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the restart coordinator and real adapters, later slices, call it"
    )
)]

use std::time::Instant;

use serde_json::{Map, Value};

/// The only owners whose failed checkpoint cancels a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FloorOwner {
    TaskStore,
    Config,
    Health,
}

/// Where in the checkpoint a cancel happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FloorStage {
    Pause,
    Checkpoint,
}

/// What an adapter reports when its pause or checkpoint did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FloorFault {
    SaveFailed,
    WorkerLost,
    Unavailable,
}

/// Why a restart was cancelled before the commit edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CancelReason {
    SaveFailed,
    WorkerLost,
    Unavailable,
    DeadlineExceeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Cancelled {
    pub(crate) owner: FloorOwner,
    pub(crate) stage: FloorStage,
    pub(crate) reason: CancelReason,
}

/// A floor owner as the coordinator drives it. `resume` is idempotent.
pub(crate) trait FloorAdapter {
    fn owner(&self) -> FloorOwner;
    fn pause(&mut self) -> Result<(), FloorFault>;
    fn checkpoint(&mut self) -> Result<(), FloorFault>;
    fn resume(&mut self);
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FloorSetupError {
    NotExactlyThreeOwners,
}

/// Pauses are held until [`Certified::abort`] (or the later commit slice).
pub(crate) struct Certified<'a> {
    adapters: &'a mut [Box<dyn FloorAdapter>],
}

impl Certified<'_> {
    pub(crate) fn abort(self) {
        for adapter in self.adapters.iter_mut() {
            adapter.resume();
        }
    }
}

pub(crate) fn run_checkpoint<'a>(
    adapters: &'a mut [Box<dyn FloorAdapter>],
    deadline: Instant,
) -> Result<Certified<'a>, Cancelled> {
    let outcome = checkpoint_all(adapters, deadline);
    if outcome.is_err() {
        for adapter in adapters.iter_mut() {
            adapter.resume();
        }
    }
    outcome.map(|()| Certified { adapters })
}

fn checkpoint_all(
    adapters: &mut [Box<dyn FloorAdapter>],
    deadline: Instant,
) -> Result<(), Cancelled> {
    for adapter in adapters.iter_mut() {
        let owner = adapter.owner();
        past_deadline(owner, FloorStage::Pause, deadline)?;
        adapter
            .pause()
            .map_err(|f| cancelled(owner, FloorStage::Pause, f))?;
    }
    for adapter in adapters.iter_mut() {
        let owner = adapter.owner();
        past_deadline(owner, FloorStage::Checkpoint, deadline)?;
        adapter
            .checkpoint()
            .map_err(|f| cancelled(owner, FloorStage::Checkpoint, f))?;
        // A save that returned after the deadline still means the window is gone.
        past_deadline(owner, FloorStage::Checkpoint, deadline)?;
    }
    Ok(())
}

fn past_deadline(owner: FloorOwner, stage: FloorStage, deadline: Instant) -> Result<(), Cancelled> {
    if Instant::now() >= deadline {
        return Err(Cancelled {
            owner,
            stage,
            reason: CancelReason::DeadlineExceeded,
        });
    }
    Ok(())
}

fn cancelled(owner: FloorOwner, stage: FloorStage, fault: FloorFault) -> Cancelled {
    let reason = match fault {
        FloorFault::SaveFailed => CancelReason::SaveFailed,
        FloorFault::WorkerLost => CancelReason::WorkerLost,
        FloorFault::Unavailable => CancelReason::Unavailable,
    };
    Cancelled {
        owner,
        stage,
        reason,
    }
}

pub(crate) fn validate_owners(adapters: &[Box<dyn FloorAdapter>]) -> Result<(), FloorSetupError> {
    let has = |o| adapters.iter().filter(|a| a.owner() == o).count() == 1;
    if adapters.len() == 3
        && has(FloorOwner::TaskStore)
        && has(FloorOwner::Config)
        && has(FloorOwner::Health)
    {
        Ok(())
    } else {
        Err(FloorSetupError::NotExactlyThreeOwners)
    }
}

impl Cancelled {
    /// The audit and UI reason: owner, stage and reason, nothing else.
    pub(crate) fn audit_detail(&self) -> Map<String, Value> {
        let owner = match self.owner {
            FloorOwner::TaskStore => "task_store",
            FloorOwner::Config => "config",
            FloorOwner::Health => "health",
        };
        let stage = match self.stage {
            FloorStage::Pause => "pause",
            FloorStage::Checkpoint => "checkpoint",
        };
        let reason = match self.reason {
            CancelReason::SaveFailed => "save_failed",
            CancelReason::WorkerLost => "worker_lost",
            CancelReason::Unavailable => "unavailable",
            CancelReason::DeadlineExceeded => "deadline_exceeded",
        };
        [("owner", owner), ("stage", stage), ("reason", reason)]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), Value::from(v)))
            .collect()
    }
}

/// Owners whose save runs in the ordinary stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StopSaveOwner {
    Floor(FloorOwner),
    Counters,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum StopSaveOutcome {
    Saved,
    FailedLoggedProceeding,
}

/// An ordinary-stop save never cancels: a failure is logged and the stop goes
/// on, exactly as on a SIGTERM stop. Only the checkpoint before the commit edge
/// can cancel.
pub(crate) fn settle_stop_save<E: std::fmt::Display>(
    owner: StopSaveOwner,
    result: Result<(), E>,
) -> StopSaveOutcome {
    match result {
        Ok(()) => StopSaveOutcome::Saved,
        Err(error) => {
            tracing::warn!(?owner, %error, "state save failed during stop; continuing");
            StopSaveOutcome::FailedLoggedProceeding
        }
    }
}
