// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The worker's settlement: one bounded rule for a lost compare-and-set and a
//! host clock before 1970 (MIK-8202 P4a design r4 "Worker settle: one rule,
//! bounded", r4.1). Moved out of `worker.rs` to keep it under its ceiling.

use chrono::{DateTime, Utc};
use tokio::sync::watch;

use super::super::input_round::{ClockWait, readable_now};
use super::super::{CommitFailure, CommittedTask, TaskExecutor, TransitionWrite};
use crate::gateway::gateway_writes::WriteRecord;
use crate::gateway::task_service::ErrorAuthor;
use crate::gateway::task_service::record::Provenance;
use crate::protocol::tasks::{TaskStatus, TaskTransition};

/// What one settle attempt came to, and what the rule does next.
enum Next {
    /// Stop with this answer: `true` when the stored row delivers backend
    /// output a relay receipt may be committed for.
    Done(bool),
    /// Commit again at this revision.
    Retry(u64),
}

impl TaskExecutor {
    pub(in crate::gateway::task_service::execution) async fn settle_cas(
        &self,
        principal: &str,
        id: &str,
        revision: u64,
        event: TaskTransition,
        cancel_rx: &mut watch::Receiver<bool>,
    ) -> bool {
        // The gateway's own outcome: nothing in it is a member it noted.
        self.settle_cas_by(
            (principal, id, revision),
            (event, Provenance::default()),
            ErrorAuthor::Gateway,
            WriteRecord::default(),
            cancel_rx,
        )
        .await
    }

    /// [`Self::settle_cas`] committing a plan's dispatched `targets` in the same
    /// write as the outcome. A settlement that does not fit the record budget
    /// becomes a bounded `Failed` with no output (see `settle_bounded`).
    ///
    /// `writes` names the members of a `Complete` result the gateway wrote,
    /// stored with it so a later read's receipt leaves them out (MIK-7993).
    pub(in crate::gateway::task_service::execution) async fn settle_cas_with(
        &self,
        ids: (&str, &str, u64),
        outcome: (TaskTransition, Provenance),
        writes: WriteRecord,
        cancel_rx: &mut watch::Receiver<bool>,
    ) -> bool {
        self.settle_cas_by(ids, outcome, ErrorAuthor::Gateway, writes, cancel_rx)
            .await
    }

    /// [`Self::settle_cas_with`], recording who wrote a `Fail` event's error
    /// (MIK-7887.RECEIPT.1). `true` when the stored row delivers backend
    /// output a relay receipt may be committed for.
    ///
    /// MIK-8202 P4a r4: every attempt follows one rule. The time source `at`
    /// starts as the store clock (`None`) and, once a wait has read a time, is
    /// that time for every later attempt, so the clock is read for a wait at
    /// most once. Budgets: one conflict retry and one clock wait. An expired
    /// wait hands the ORIGINAL outcome to [`Self::settle_dated_last_known`].
    /// So at most 3 commits here, or 2 here and 2 there (r4.1). The outcome is
    /// lost only on a second lost compare-and-set, a store that cannot be
    /// re-read, or a store write that fails, and each is logged.
    pub(in crate::gateway::task_service::execution) async fn settle_cas_by(
        &self,
        (principal, id, revision): (&str, &str, u64),
        (event, targets): (TaskTransition, Provenance),
        author: ErrorAuthor,
        writes: WriteRecord,
        cancel_rx: &mut watch::Receiver<bool>,
    ) -> bool {
        let mut at: Option<DateTime<Utc>> = None;
        let (mut conflict_retries, mut clock_waits) = (1_u8, 1_u8);
        let mut revision = revision;
        loop {
            let write = TransitionWrite::Settle {
                principal,
                id,
                revision,
                event: event.clone(),
                targets: targets.clone(),
                author,
                writes: writes.clone(),
            };
            let next = match self.commit_dated(write, at).await {
                Ok(stored) => Next::Done(stored_backend_output(&stored)),
                Err(CommitFailure::RevisionConflict) if conflict_retries > 0 => {
                    conflict_retries -= 1;
                    self.reread(principal, id)
                }
                Err(CommitFailure::RevisionConflict) => {
                    tracing::error!(task_id = %id, "task settlement lost a second compare-and-set: outcome not stored");
                    Next::Done(false)
                }
                // Only a `None` commit reads the clock, so with `at` set this
                // arm cannot be reached; it is named so no wildcard takes it.
                Err(CommitFailure::ClockUnreadable) if clock_waits > 0 && at.is_none() => {
                    clock_waits -= 1;
                    match readable_now(&self.service.store, id, cancel_rx).await {
                        ClockWait::Read(read, _) => {
                            at = Some(read);
                            // The wait may have been long: the revision is read again.
                            self.reread(principal, id)
                        }
                        // The task was cancelled; its cancel is the outcome.
                        ClockWait::Stopped => Next::Done(false),
                        ClockWait::Expired => {
                            return self
                                .settle_dated_last_known(
                                    principal,
                                    id,
                                    (event, targets),
                                    author,
                                    writes,
                                )
                                .await;
                        }
                    }
                }
                // `ClockUnreadable` past this point cannot happen: only a `None`
                // commit reads the clock, and a wait either dates `at` or
                // returns. It stays named, beside the `Service` failure it
                // shares its ending with, so no wildcard takes it.
                Err(error @ (CommitFailure::ClockUnreadable | CommitFailure::Service(_))) => {
                    tracing::error!(
                        task_id = %id,
                        ?error,
                        "task settlement write failed: outcome not stored"
                    );
                    Next::Done(false)
                }
            };
            match next {
                Next::Done(delivered) => return delivered,
                Next::Retry(current) => revision = current,
            }
        }
    }

    /// The one non-waiting settle (MIK-8202 P4a r3/r4): every site whose clock
    /// wait expired lands here, so none waits a second time. It commits
    /// `outcome` dated at the record's own `last_updated_at`, a real time the
    /// record already carries, never 1969 or 0. The expiry sweep never fails a
    /// `working` row, so leaving it for the TTL would strand the task.
    ///
    /// Bounded: on a conflict it re-reads once and commits once more; a second
    /// conflict is logged and stops. A terminal record on any re-read stops
    /// with no receipt. `true` as for [`Self::settle_cas_by`].
    pub(in crate::gateway::task_service::execution) async fn settle_dated_last_known(
        &self,
        principal: &str,
        id: &str,
        (event, targets): (TaskTransition, Provenance),
        author: ErrorAuthor,
        writes: WriteRecord,
    ) -> bool {
        let mut retried = false;
        loop {
            let Some((revision, at)) = self.dated_reread(principal, id) else {
                return false;
            };
            let write = TransitionWrite::Settle {
                principal,
                id,
                revision,
                event: event.clone(),
                targets: targets.clone(),
                author,
                writes: writes.clone(),
            };
            match self.commit_dated(write, Some(at)).await {
                Ok(stored) => return stored_backend_output(&stored),
                Err(CommitFailure::RevisionConflict) if !retried => retried = true,
                Err(CommitFailure::RevisionConflict) => {
                    tracing::error!(task_id = %id, "task settlement lost a second compare-and-set: outcome not stored");
                    return false;
                }
                // A commit dated `Some` never reads the clock, so a
                // `ClockUnreadable` here is unreachable by construction. It
                // stays named, beside the `Service` failure it shares its
                // ending with, so no wildcard swallows it.
                Err(error @ (CommitFailure::ClockUnreadable | CommitFailure::Service(_))) => {
                    tracing::error!(
                        task_id = %id,
                        ?error,
                        "task settlement write failed: outcome not stored"
                    );
                    return false;
                }
            }
        }
    }

    /// The revision to retry at, or `Done(false)` when the record is terminal
    /// (this worker's outcome was not stored, so it is never receipted, r4.1)
    /// or cannot be read (logged at error level: the outcome is lost).
    fn reread(&self, principal: &str, id: &str) -> Next {
        self.dated_reread(principal, id)
            .map_or(Next::Done(false), |(revision, _)| Next::Retry(revision))
    }

    /// A working record's `(revision, last_updated_at)`; `None` for a terminal
    /// record or a store re-read that failed (the latter logged).
    fn dated_reread(&self, principal: &str, id: &str) -> Option<(u64, DateTime<Utc>)> {
        let current = self
            .service
            .owner(principal)
            .ok()
            .and_then(|owner| self.service.store.get(owner.as_digest(), id).ok());
        let Some(current) = current else {
            tracing::error!(task_id = %id, "outcome not stored: store re-read failed");
            return None;
        };
        if is_terminal(current.task.status()) {
            return None;
        }
        Some((current.revision, current.task.last_updated_at()))
    }
}

/// Whether a settlement stored backend output a relay receipt may be
/// committed for: a completed result, or (MIK-7887.RECEIPT.1) an error the
/// gateway established as the peer's. A bounded settlement stores neither,
/// nor does a round refused before its backend (its answer is the gateway's).
fn stored_backend_output(stored: &CommittedTask) -> bool {
    (stored.task.status() == TaskStatus::Completed
        && !stored.output_free
        && stored.error_author != Some(ErrorAuthor::Gateway))
        || stored.backend_error().is_some()
}

fn is_terminal(status: TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
    )
}
