// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The periodic expiry owner: one cadence, one guard, one deletion at a time.
//!
//! Expiry is startup-owned. The gateway starts this after the recovered runtime
//! exists and joins its guard before the store closes, so a record's deletion is
//! never in flight against a store that has given custody back.
//!
//! Each tick takes a compact snapshot of what the committed image says is
//! deletable — terminal, and past the retention its own creation stamped — and
//! hands each pair to the store's atomic expiry transaction. Nothing here
//! rewrites a record, reads the directory, or holds a lock across an await.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use super::TaskExecutor;
use crate::gateway::task_service::service::ServiceError;
use crate::gateway::task_service::store::StoreError;

impl TaskExecutor {
    /// Start the periodic sweep and hand back the guard that stops it.
    ///
    /// A zero interval is not a cadence: it is refused, and refusing it spawns
    /// nothing. The spawned loop holds only a `std::sync::Weak` reference while
    /// it is idle, so a running sweep never keeps the executor — or the runtime
    /// behind it — alive past the moment its owner drops.
    ///
    /// Restartable: the guard owns the loop it started, so a stopped owner can
    /// be started again over the same executor.
    pub(crate) fn start_expiry(
        self: &Arc<Self>,
        interval: Duration,
    ) -> Result<ExpirySweep, ServiceError> {
        if interval.is_zero() {
            tracing::error!("task expiry interval is zero; the periodic sweep was not started");
            return Err(ServiceError::Unavailable);
        }
        let (stop, mut stopped) = watch::channel(false);
        let executor = Arc::downgrade(self);
        let joined = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // A tick missed while a deletion was in flight is one tick, not a
            // backlog to catch up on: the next sweep sees the same candidates.
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            let mut failure = None;
            loop {
                tokio::select! {
                    // Stop wins at every loop boundary, so a guard that has
                    // signalled never buys another sweep from a ready tick.
                    biased;
                    _ = stopped.changed() => return finish(failure),
                    _ = ticker.tick() => {}
                }
                let Some(executor) = executor.upgrade() else {
                    return finish(failure);
                };
                // Run to completion, and only then look at the stop signal: a
                // deletion is atomic in the store and is never abandoned here.
                if let Err(error) = sweep(&executor).await {
                    failure = failure.or(Some(error));
                }
                // Idle holds nothing: the executor is released before the wait.
                drop(executor);
            }
        });
        Ok(ExpirySweep {
            stop,
            joined: Some(joined),
        })
    }
}

/// The gateway's handle on a running sweep.
///
/// Dropping it signals the loop to stop at its next boundary without cutting a
/// deletion short; [`Self::shutdown`] additionally joins the loop, which is what
/// a caller about to close the store needs.
pub(crate) struct ExpirySweep {
    stop: watch::Sender<bool>,
    /// Taken by [`Self::shutdown`], which is why this is an `Option`: a type
    /// with a `Drop` cannot be destructured, and the join has to move the
    /// handle out.
    joined: Option<JoinHandle<Result<(), ServiceError>>>,
}

impl ExpirySweep {
    /// Signal the loop and join it, INCLUDING a deletion already in flight.
    ///
    /// Returns once the sweep has actually stopped, carrying the first genuine
    /// storage failure the loop met. A stop that could not be joined is
    /// reported as unavailability rather than as a clean one.
    pub(crate) async fn shutdown(mut self) -> Result<(), ServiceError> {
        let _ = self.stop.send(true);
        let Some(joined) = self.joined.take() else {
            return Ok(());
        };
        match joined.await {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::error!(%error, "the task expiry sweep did not stop cleanly");
                Err(ServiceError::Unavailable)
            }
        }
    }
}

impl Drop for ExpirySweep {
    fn drop(&mut self) {
        // Signal only. The loop is left to observe it, so a deletion whose
        // blocking write is in flight still finishes its own transaction.
        let _ = self.stop.send(true);
    }
}

fn finish(failure: Option<ServiceError>) -> Result<(), ServiceError> {
    failure.map_or(Ok(()), Err)
}

/// One pass: snapshot, then delete each candidate through the store's own
/// atomic expiry transaction.
///
/// A candidate that moved or is already gone between the snapshot and its
/// deletion is benign — the store re-checks the record and its revision under
/// its ordering lock, and refusing there is that check working. A genuine
/// storage failure is logged and carried out to the guard, so a stop can never
/// report success over a directory it could not delete from.
async fn sweep(executor: &Arc<TaskExecutor>) -> Result<(), ServiceError> {
    let service = Arc::clone(&executor.service);
    let candidates = service.store.expired_candidates(Utc::now());
    let mut outcome = Ok(());
    for (id, revision) in candidates {
        match service
            .store
            .expire(&id, revision, service.admission_arc())
            .await
        {
            Ok(()) => tracing::debug!(task_id = %id, "expired task record deleted"),
            Err(StoreError::NotFound | StoreError::RevisionConflict) => {}
            // Terminal is absorbing, so a candidate cannot legitimately be
            // running by the time it is deleted; if one is, it is not expiry's
            // to end and the row simply stays.
            Err(StoreError::InvalidTransition) => {}
            Err(error) => {
                tracing::warn!(%error, task_id = %id, "expired task record not deleted");
                outcome = Err(ServiceError::Unavailable);
            }
        }
    }
    outcome
}
