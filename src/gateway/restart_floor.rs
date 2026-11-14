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
///
/// Every adapter keeps its pause state itself, never only in a returned
/// future: `pause` and `checkpoint` return their future at once and never
/// block a poll, and dropped at any await point the adapter is recovered by
/// `resume` or `release_for_stop`. The coordinator alone reports an elapsed
/// deadline. The four synchronous calls never wait and never panic.
pub(crate) trait FloorAdapter: Send {
    fn owner(&self) -> FloorOwner;
    /// Gate new submissions, holding no lock an accepted worker needs.
    fn pause(&mut self, deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>>;
    /// Settle admitted work and certify the snapshot.
    fn checkpoint(&mut self, deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>>;
    /// Cancel recovery: clear any applied or partial gate and enqueue what was
    /// coalesced, ahead of newly admitted work.
    fn resume(&mut self);
    /// A stop signal won: clear any gate so parked work completes, cancel
    /// pending checkpoint admission, replay nothing.
    fn release_for_stop(&mut self);
    /// The commit edge: reject new external submissions; work parked before
    /// the commit and internal completion work proceed.
    fn commit(&mut self);
    /// False while late work of an earlier attempt still runs.
    fn settled(&self) -> bool;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FloorSetupError {
    NotExactlyThreeOwners,
}

/// A commit-or-abort decision that came after the checkpoint deadline.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LateDecision;

/// Holds the adapters while a checkpoint or its decision is pending. Dropped
/// still armed (the run was dropped because a stop signal won, a panic
/// unwound, or a certified attempt was never decided), it releases every
/// adapter for the ordinary stop. Every decided exit disarms it first.
struct StopRelease<'a>(Option<&'a mut [Box<dyn FloorAdapter>]>);

impl<'a> StopRelease<'a> {
    fn adapters(&mut self) -> &mut [Box<dyn FloorAdapter>] {
        self.0.as_deref_mut().unwrap_or_default()
    }

    fn disarm(&mut self) -> &'a mut [Box<dyn FloorAdapter>] {
        self.0.take().unwrap_or_default()
    }
}

impl Drop for StopRelease<'_> {
    fn drop(&mut self) {
        for adapter in self.0.take().unwrap_or_default() {
            if mutant!("s9514.m6", true, false) {
                adapter.resume();
            } else if mutant!("s9514.m5", false, true) {
                adapter.release_for_stop();
            }
        }
    }
}

/// Every pause certified and held until [`Self::commit`] or [`Self::abort`].
/// The decision is synchronous: nothing awaits between disarming and the end
/// of the adapter loop.
pub(crate) struct Certified<'a> {
    held: StopRelease<'a>,
    deadline: Instant,
}

impl Certified<'_> {
    /// Commit every adapter, unless the deadline has passed: then resume
    /// every adapter and report the decision late.
    pub(crate) fn commit(mut self) -> Result<(), LateDecision> {
        let adapters = self.held.disarm();
        if mutant!("s9514.m9", false, Instant::now() >= self.deadline) {
            for adapter in adapters {
                adapter.resume();
            }
            return Err(LateDecision);
        }
        let keep = mutant!("s9514.m8", adapters.len().saturating_sub(1), adapters.len());
        for adapter in adapters.iter_mut().take(keep) {
            adapter.commit();
        }
        Ok(())
    }

    pub(crate) fn abort(mut self) {
        for adapter in self.held.disarm() {
            adapter.resume();
        }
    }
}

/// Whether no adapter still runs late work of an earlier attempt. The
/// coordinator refuses a new attempt (busy) until this is true.
pub(crate) fn all_settled(adapters: &[Box<dyn FloorAdapter>]) -> bool {
    mutant!("s9514.m11", true, adapters.iter().all(|adapter| adapter.settled()))
}

/// Pause every owner, then checkpoint every owner, each call bounded by the
/// one `deadline`. A failure resumes every owner; a run dropped mid-way
/// releases every owner for the stop.
pub(crate) async fn run_checkpoint(
    adapters: &mut [Box<dyn FloorAdapter>],
    deadline: Instant,
) -> Result<Certified<'_>, Cancelled> {
    let mut held = StopRelease(Some(adapters));
    let outcome = checkpoint_all(held.adapters(), deadline).await;
    match outcome {
        Ok(()) => Ok(Certified { held, deadline }),
        Err(cancel) => {
            for adapter in mutant!("s9514.m7", held.adapters(), held.disarm()) {
                adapter.resume();
            }
            Err(cancel)
        }
    }
}

async fn checkpoint_all(
    adapters: &mut [Box<dyn FloorAdapter>],
    deadline: Instant,
) -> Result<(), Cancelled> {
    for stage in [FloorStage::Pause, FloorStage::Checkpoint] {
        for adapter in adapters.iter_mut() {
            bounded(adapter.as_mut(), stage, deadline).await?;
        }
    }
    Ok(())
}

/// One call under the deadline: refused if already past it, dropped at it,
/// and a late success still cancels at this owner and stage. A late fault
/// keeps its own reason.
async fn bounded(
    adapter: &mut (dyn FloorAdapter + 'static),
    stage: FloorStage,
    deadline: Instant,
) -> Result<(), Cancelled> {
    let owner = adapter.owner();
    if mutant!("s9514.m13", false, true) {
        past_deadline(owner, stage, deadline)?;
    }
    let call = match stage {
        FloorStage::Pause => adapter.pause(deadline),
        FloorStage::Checkpoint => adapter.checkpoint(mutant!(
            "s9514.m10",
            deadline + std::time::Duration::from_secs(1),
            deadline
        )),
    };
    let bound = match stage {
        FloorStage::Pause => mutant!("s9514.m1", deadline + std::time::Duration::from_secs(3600), deadline),
        FloorStage::Checkpoint => mutant!("s9514.m2", deadline + std::time::Duration::from_secs(3600), deadline),
    };
    match tokio::time::timeout_at(bound, call).await {
        Err(_elapsed) => Err(Cancelled {
            owner,
            stage,
            reason: CancelReason::DeadlineExceeded,
        }),
        Ok(Err(fault)) => Err(if mutant!("s9514.m12", Instant::now() >= deadline, false) {
            Cancelled {
                owner,
                stage,
                reason: CancelReason::DeadlineExceeded,
            }
        } else {
            cancelled(owner, stage, fault)
        }),
        Ok(Ok(())) => {
            if mutant!("s9514.m3", stage == FloorStage::Pause, false)
                || mutant!("s9514.m4", stage == FloorStage::Checkpoint, false)
            {
                Ok(())
            } else {
                past_deadline(owner, stage, deadline)
            }
        }
    }
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
