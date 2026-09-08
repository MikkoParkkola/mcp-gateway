// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Startup recovery, and the digest-level transition it shares with settle.
//!
//! A restart inherits a directory, not a process. Nothing here re-invokes,
//! resubmits, or consults a backend: each interrupted row is settled by what its
//! own record can still prove, through the same commit seam a worker settles on.

use chrono::Utc;
use serde_json::Value;

use super::settlement::interrupted_result;
use super::{CommitFailure, CommitStage, TaskExecutor, TaskWrite, WriteOutcome};
use crate::gateway::task_service::service::ServiceError;
use crate::gateway::task_service::store::StoreError;
use crate::protocol::tasks::TaskTransition;

impl TaskExecutor {
    /// Settle every row a previous process left mid-flight, before the runtime
    /// is handed to a caller.
    ///
    /// The snapshots are owned: the store takes and drops its own lock inside
    /// the selector, so nothing is held across the writes below. Failure is a
    /// startup failure — a store this cannot settle is not served half-recovered.
    pub(crate) async fn recover_interrupted(&self) -> Result<(), ServiceError> {
        for row in self.service.store.interrupted() {
            let event = TaskTransition::Complete(restart_result(row.never_dispatched));
            match self
                .commit(TaskWrite::Recover {
                    owner_digest: &row.owner_digest,
                    id: &row.id,
                    revision: row.revision,
                    event,
                })
                .await
            {
                Ok(WriteOutcome::Transitioned(_)) => {}
                // No worker and no request can hold this record yet, so a
                // refusal here is a store that cannot be recovered rather than a
                // race worth re-reading.
                Ok(WriteOutcome::Create(_)) => return Err(ServiceError::Unavailable),
                Err(error) => {
                    tracing::error!(
                        task_id = %row.id,
                        ?error,
                        "interrupted task not recovered; startup refuses to serve"
                    );
                    return Err(ServiceError::Unavailable);
                }
            }
        }
        Ok(())
    }

    /// The one store transition, over the digest an owner is already known by.
    ///
    /// Below the raw-principal adapter deliberately: a request-side caller
    /// reaches it only through `transition_write`, which asks admission to hash
    /// its principal first, while recovery reaches it with the digest the record
    /// itself persisted — never hashed a second time. The store still checks
    /// exactly that owner, id and revision.
    pub(super) async fn transition_digest_write(
        &self,
        owner_digest: &str,
        id: &str,
        revision: u64,
        event: TaskTransition,
    ) -> Result<(WriteOutcome, bool, CommitStage, String), CommitFailure> {
        match self
            .service
            .store
            .transition(owner_digest, id, revision, event, Utc::now())
            .await
        {
            Ok(committed) => {
                let wrote = committed.revision != revision;
                Ok((
                    WriteOutcome::Transitioned(committed),
                    wrote,
                    CommitStage::Transitioned,
                    id.to_owned(),
                ))
            }
            Err(StoreError::RevisionConflict) => Err(CommitFailure::RevisionConflict),
            Err(StoreError::NotFound) => Err(CommitFailure::Service(ServiceError::NotFound)),
            Err(_) => Err(CommitFailure::Service(ServiceError::Unavailable)),
        }
    }
}

/// The two answers a record can still prove (§13.5 rows 2–4). Both are tool
/// errors: an interrupted task did not succeed, whatever the backend did.
fn restart_result(never_dispatched: bool) -> Value {
    if never_dispatched {
        interrupted_result(
            "not_executed",
            "gateway_restart_before_dispatch",
            "The gateway restarted before this task reached the backend.",
        )
    } else {
        interrupted_result(
            "unknown",
            "gateway_restart_after_dispatch",
            "The gateway restarted while this task was in flight; whether the \
             backend carried it out is unknown.",
        )
    }
}
