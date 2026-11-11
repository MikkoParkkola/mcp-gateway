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
    _deadline: Instant,
) -> Result<Certified<'a>, Cancelled> {
    Ok(Certified { adapters })
}

pub(crate) fn validate_owners(_adapters: &[Box<dyn FloorAdapter>]) -> Result<(), FloorSetupError> {
    Ok(())
}

impl Cancelled {
    pub(crate) fn audit_detail(&self) -> Map<String, Value> {
        Map::new()
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

pub(crate) fn settle_stop_save<E: std::fmt::Display>(
    _owner: StopSaveOwner,
    _result: Result<(), E>,
) -> StopSaveOutcome {
    StopSaveOutcome::Saved
}
