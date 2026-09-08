// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Durable capture of an upstream handle, and the read-time recovery it enables.
//!
//! Two halves, kept apart on purpose. Capture runs on the trusted dispatch path
//! and is the only writer of the recovery descriptor. Recovery runs on an
//! owner-authenticated read, is handed the caller's OWN current-policy verdict
//! rather than deciding authorization itself, and reaches the wire through an
//! adapter whose whole vocabulary is one read of one handle.
//!
//! Nothing here resubmits, retries or continues the original operation, and
//! nothing here reconstructs an identity: the owner is named only by the digest
//! the record persisted.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::Mutex;

use super::settlement::strip_http_status;
use super::{CommitFailure, TaskExecutor, TaskWrite, UpstreamAnswer, UpstreamHandle, WriteOutcome};
use crate::gateway::task_service::record::UpstreamRecord;
use crate::gateway::task_service::store::StoreError;
use crate::protocol::JsonRpcError;
use crate::protocol::tasks::{TaskStatus, TaskTransition};

/// What the dispatch path durably captured about one submitted upstream job.
///
/// It carries the original target because the record must, but that value never
/// travels to an adapter: it is read only by the authorization the next owner
/// read performs against the current caller.
pub(crate) struct UpstreamCapture {
    pub backend: String,
    pub tool: String,
    pub arguments: Value,
    pub handle: String,
}

/// Why a read issued zero upstream queries.
///
/// Every variant is a refusal reached BEFORE the wire, which is the property
/// worth asserting rather than a log line.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RecoveryRefusal {
    /// No adapter installed, or none that claims this backend now.
    Unclaimed,
    /// Terminal, absent, foreign, or carrying no consistent durable handle.
    NotRecoverable,
    /// The current caller may not invoke the original target now.
    Denied,
    /// The store could not be read or written.
    Unavailable,
}

/// What one authorized read did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RecoveredRead {
    /// A terminal outcome was committed through the ordinary revision-checked
    /// durable path.
    Settled,
    /// The job is still live upstream, or could not be reached. The handle and
    /// the `working` record are retained for a later authenticated read.
    Retained,
}

#[cfg(test)]
#[path = "upstream/failed_policy_tests.rs"]
mod failed_policy_tests;

impl TaskExecutor {
    /// Durably attach the handle and its recovery descriptor to a working row.
    ///
    /// Called once, immediately after the peer's `CreateTask` envelope is
    /// recognised and before anything else is done with it. A refusal — moved
    /// revision, terminal row, oversized descriptor, unwritable store — leaves
    /// the row exactly as it was: dispatched, no handle, `unknown`. That is the
    /// one-write-wide received-not-persisted window, and it stays open.
    pub(crate) async fn capture_upstream(
        &self,
        principal: &str,
        id: &str,
        revision: u64,
        capture: UpstreamCapture,
    ) -> bool {
        let Ok(owner) = self.service.owner(principal) else {
            return false;
        };
        // The descriptor's binding to this record is the record's own admitted
        // operation digest, read here rather than recomputed: a digest derived
        // a second time from request data could bind a descriptor to a call the
        // record was never admitted for.
        let Some(operation_digest) = self
            .service
            .store
            .operation_digest_of(owner.as_digest(), id)
        else {
            return false;
        };
        let record = UpstreamRecord {
            handle: capture.handle,
            backend: capture.backend,
            tool: capture.tool,
            arguments: capture.arguments,
            operation_digest,
        };
        match self
            .service
            .store
            .mark_upstream(owner.as_digest(), id, revision, record)
            .await
        {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    task_id = %id,
                    ?error,
                    "upstream handle not made durable; this task stays unrecoverable"
                );
                false
            }
        }
    }

    /// The owner-scoped recovery descriptor a reader must authorize against.
    ///
    /// Foreign or absent is [`RecoveryRefusal::NotRecoverable`], which is the
    /// same answer the ordinary owner-scoped lookup gives — and it is reached
    /// without any upstream call.
    pub(crate) fn recovery_target(
        &self,
        owner_digest: &str,
        id: &str,
    ) -> Result<UpstreamRecord, RecoveryRefusal> {
        let (descriptor, _, status) =
            self.service
                .store
                .upstream_of(owner_digest, id)
                .map_err(|error| match error {
                    StoreError::NotFound => RecoveryRefusal::NotRecoverable,
                    _ => RecoveryRefusal::Unavailable,
                })?;
        // A terminal row is served unchanged; an interrupted input round keeps
        // its reviewed I3 treatment and is not continued here.
        if status != TaskStatus::Working {
            return Err(RecoveryRefusal::NotRecoverable);
        }
        descriptor.ok_or(RecoveryRefusal::NotRecoverable)
    }

    /// One bounded read-only query for an already-authorized owner read.
    ///
    /// `authorized` is the READER's verdict, computed against the current
    /// `RouterAuthorizer`, current tool policy and a fresh attestation token
    /// before this is called; `false` issues zero queries. `finish` is the
    /// ordinary post-dispatch processing the reader supplies — an `Err` means a
    /// configured output policy refused the recovered payload, and that refusal
    /// is committed as the task's outcome rather than quietly discarded.
    /// `finish_error` is the same reader's error policy: a recovered FAILURE is
    /// upstream content too, and it passes that before it can reach disk or the
    /// owner. Its return type keeps a raw upstream error from ever becoming a
    /// successful output-schema result.
    pub(crate) async fn recover_upstream_read<F, E>(
        &self,
        owner_digest: &str,
        id: &str,
        authorized: bool,
        finish: F,
        finish_error: E,
        deadline: Duration,
    ) -> Result<RecoveredRead, RecoveryRefusal>
    where
        F: FnOnce(Value) -> Result<Value, JsonRpcError>,
        E: FnOnce(JsonRpcError) -> JsonRpcError,
    {
        if !authorized {
            return Err(RecoveryRefusal::Denied);
        }
        let Some(adapter) = self.recovery() else {
            return Err(RecoveryRefusal::Unclaimed);
        };
        let descriptor = self.recovery_target(owner_digest, id)?;
        // Trust is re-evaluated against CURRENT configuration and the peer's own
        // declaration. An adapter dropped, or a backend untrusted since the
        // submission, refuses here — before the wire, not after.
        if !adapter.claims(&descriptor.backend).await {
            return Err(RecoveryRefusal::Unclaimed);
        }

        // Serialized per record. The query is read-only; its commit is not, so
        // two concurrent reads of one row would each settle it and the second
        // would find a revision that moved.
        let slot = self.query_slot(id).await;
        let outcome = {
            let _held = slot.lock().await;
            self.query_and_commit(owner_digest, id, adapter, finish, finish_error, deadline)
                .await
        };
        // The lock is released above; the directory entry goes with it once
        // nobody else holds one.
        self.release_query_slot(id, slot).await;
        outcome
    }

    /// The guarded half: re-read, one query, one settlement. Called only from
    /// [`Self::recover_upstream_read`], holding that record's slot.
    async fn query_and_commit<F, E>(
        &self,
        owner_digest: &str,
        id: &str,
        adapter: &Arc<dyn super::UpstreamRecovery>,
        finish: F,
        finish_error: E,
        deadline: Duration,
    ) -> Result<RecoveredRead, RecoveryRefusal>
    where
        F: FnOnce(Value) -> Result<Value, JsonRpcError>,
        E: FnOnce(JsonRpcError) -> JsonRpcError,
    {
        // Re-read under the gate: a concurrent read that already settled this
        // row must not be queried a second time.
        let descriptor = self.recovery_target(owner_digest, id)?;
        let handle = UpstreamHandle {
            backend: descriptor.backend.clone(),
            handle: descriptor.handle.clone(),
        };

        let event = match adapter.query(&handle, deadline).await {
            // Still running, waiting on an input round this gateway cannot
            // continue, or unreachable. The handle and the working record are
            // retained; nothing is faked terminal and nothing is resubmitted.
            UpstreamAnswer::Live | UpstreamAnswer::Unavailable => {
                return Ok(RecoveredRead::Retained);
            }
            UpstreamAnswer::Completed(result) => match finish(result) {
                Ok(processed) => TaskTransition::Complete(processed),
                // The same configured output policy that guards a live dispatch
                // refused this payload. Its refusal is the task's outcome.
                Err(error) => TaskTransition::Fail(strip_http_status(error)),
            },
            // A peer's failure is upstream content, not a gateway verdict: its
            // message and nested data pass the reader's configured error policy
            // BEFORE this settles, so nothing unscreened reaches the durable
            // record or the read that serves it. The code is preserved.
            UpstreamAnswer::Failed(error) => {
                TaskTransition::Fail(finish_error(strip_http_status(error)))
            }
        };

        // Ordinary revision-checked durable settlement, over the digest the
        // record persisted. The revision is re-read because the query took
        // time; the one the caller first saw is not the one to compare against.
        let revision = self
            .service
            .store
            .get(owner_digest, id)
            .map_err(|_| RecoveryRefusal::Unavailable)?
            .revision;
        match self
            .commit(TaskWrite::Recover {
                owner_digest,
                id,
                revision,
                event,
            })
            .await
        {
            Ok(WriteOutcome::Transitioned(_)) => Ok(RecoveredRead::Settled),
            // Another writer settled it first. The committed record is the
            // honest answer and this read simply serves it.
            Ok(WriteOutcome::Create(_)) | Err(CommitFailure::RevisionConflict) => {
                Ok(RecoveredRead::Retained)
            }
            Err(_) => Err(RecoveryRefusal::Unavailable),
        }
    }

    /// The per-record serialization slot, created on first use.
    ///
    /// Handed out as an `Arc` and dropped from the directory by
    /// [`Self::release_query_slot`] once nobody holds it, so a store that has
    /// been read many times does not accumulate one mutex per task id forever.
    async fn query_slot(&self, id: &str) -> Arc<Mutex<()>> {
        let mut gate = self.query_gate.lock().await;
        Arc::clone(gate.entry(id.to_owned()).or_default())
    }

    /// Drop the slot for `id` if this was its last holder.
    ///
    /// The directory lock is taken first, so a concurrent [`Self::query_slot`]
    /// cannot hand out a clone of the very entry being removed: it either sees
    /// the entry with a live strong count, or creates a fresh one afterwards.
    async fn release_query_slot(&self, id: &str, slot: Arc<Mutex<()>>) {
        let mut gate = self.query_gate.lock().await;
        // Two: the directory's own reference and `slot`.
        if Arc::strong_count(&slot) <= 2 {
            gate.remove(id);
        }
    }
}
