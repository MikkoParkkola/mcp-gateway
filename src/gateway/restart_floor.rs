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

use futures::future::BoxFuture;
use tokio::time::Instant;

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

/// A floor owner as the coordinator drives it (restart plan steps 4-6).
pub(crate) trait FloorAdapter: Send {
    fn owner(&self) -> FloorOwner;
    fn pause(&mut self, deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>>;
    fn checkpoint(&mut self, deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>>;
    fn resume(&mut self);
    fn release_for_stop(&mut self);
    fn commit(&mut self);
    fn settled(&self) -> bool;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FloorSetupError {
    NotExactlyThreeOwners,
}

/// A commit-or-abort decision that came after the checkpoint deadline.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LateDecision;

/// RED STUB: the contract's rows are written against this before the code.
pub(crate) struct Certified<'a> {
    adapters: &'a mut [Box<dyn FloorAdapter>],
}

impl Certified<'_> {
    pub(crate) fn commit(self) -> Result<(), LateDecision> {
        Ok(())
    }

    pub(crate) fn abort(self) {
        for adapter in self.adapters.iter_mut() {
            adapter.resume();
        }
    }
}

pub(crate) fn all_settled(_adapters: &[Box<dyn FloorAdapter>]) -> bool {
    true
}

pub(crate) async fn run_checkpoint(
    adapters: &mut [Box<dyn FloorAdapter>],
    _deadline: Instant,
) -> Result<Certified<'_>, Cancelled> {
    let fresh = Instant::now() + std::time::Duration::from_secs(10);
    let mut outcome = Ok(());
    for adapter in adapters.iter_mut() {
        let owner = adapter.owner();
        if let Err(f) = adapter.pause(fresh).await {
            outcome = Err(cancelled(owner, FloorStage::Pause, f));
            break;
        }
    }
    if outcome.is_ok() {
        for adapter in adapters.iter_mut() {
            let owner = adapter.owner();
            if let Err(f) = adapter.checkpoint(fresh).await {
                outcome = Err(cancelled(owner, FloorStage::Checkpoint, f));
                break;
            }
        }
    }
    match outcome {
        Ok(()) => Ok(Certified { adapters }),
        Err(c) => {
            for adapter in adapters.iter_mut() {
                adapter.resume();
            }
            Err(c)
        }
    }
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
    pub(crate) fn audit_detail(self) -> Map<String, Value> {
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
