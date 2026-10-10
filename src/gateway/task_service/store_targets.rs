// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The durable write of a plan's dispatched targets (#2450): the backend calls
//! a playbook or code-mode program actually made, recorded before the task
//! settles so a stored result can be re-authorized against what produced it.

use std::sync::Arc;

use chrono::{DateTime, Timelike as _, Utc};

use super::{Shared, StoreError, TaskStore, owned, record_name, serialize};
use crate::gateway::gateway_writes::WriteRecord;
use crate::gateway::task_service::record::{
    CommittedTask, ERROR_AUTHOR_VERSION, ErrorAuthor, MAX_UPSTREAM_HANDLE_BYTES, Record,
    TARGET_VERSION, Target, UPSTREAM_CANCEL_VERSION, UpstreamRecord,
};
use crate::protocol::JsonRpcError;
use crate::protocol::tasks::{Task, TaskStatus, TaskTransition};

impl TaskStore {
    /// Merge `targets` into a non-terminal row at `expected_revision`.
    ///
    /// The `mark_upstream` idiom: same ordering lock, no revision bump (so the
    /// settle compare-and-set is untouched), the row raised to
    /// [`TARGET_VERSION`]. The targets count against the record budget and a
    /// list that does not fit is refused with `Capacity`, never truncated.
    ///
    /// # Errors
    /// `RevisionConflict` for a moved row, `InvalidTransition` for a terminal
    /// one, `Capacity` when the record would exceed its byte budget.
    pub(crate) async fn add_targets(
        &self,
        owner: &str,
        id: &str,
        expected_revision: u64,
        targets: Vec<Target>,
    ) -> Result<(), StoreError> {
        let shared = Arc::clone(&self.0);
        let (owner, id) = (owner.to_owned(), id.to_owned());
        tokio::task::spawn_blocking(move || {
            shared.add_targets_blocking(&owner, &id, expected_revision, targets)
        })
        .await
        .map_err(|_| StoreError::Storage)?
    }

    /// [`Self::settle_bounded_by`] with the gateway as the author: the tests'
    /// shorthand.
    #[cfg(test)]
    pub(crate) async fn settle_bounded(
        &self,
        owner: &str,
        id: &str,
        revision: u64,
        (event, targets): (TaskTransition, Option<Vec<Target>>),
        at: DateTime<Utc>,
    ) -> Result<CommittedTask, StoreError> {
        self.settle_bounded_by(
            owner,
            id,
            revision,
            (event, targets, WriteRecord::default()),
            ErrorAuthor::Gateway,
            at,
        )
        .await
    }

    /// [`Self::transition`] committing a plan's `targets` with the outcome, in
    /// ONE write, and never leaving the task working for want of room.
    ///
    /// The outcome and the targets are measured together against the record
    /// budget. If they do not fit, the task settles `Failed` with a bounded
    /// error and no output (keeping the targets if THAT fits), so a result is
    /// never stored without the targets that produced it.
    ///
    /// # Errors
    /// The `transition` errors; `Capacity` only if even the bounded failure
    /// cannot be stored.
    ///
    /// `author` records who wrote a `Fail` event's error (MIK-7887.RECEIPT.1);
    /// the bounded fallback is always the gateway's. `writes` names the
    /// members of a `Complete` result the gateway wrote (MIK-7993); it is
    /// stored only with that result, and never costs the result its room.
    pub(crate) async fn settle_bounded_by(
        &self,
        owner: &str,
        id: &str,
        revision: u64,
        (event, targets, writes): (TaskTransition, Option<Vec<Target>>, WriteRecord),
        author: ErrorAuthor,
        at: DateTime<Utc>,
    ) -> Result<CommittedTask, StoreError> {
        let shared = Arc::clone(&self.0);
        let (owner, id) = (owner.to_owned(), id.to_owned());
        tokio::task::spawn_blocking(move || {
            shared.settle_bounded_blocking(
                &owner,
                &id,
                revision,
                (event, targets, author, writes),
                at,
            )
        })
        .await
        .map_err(|_| StoreError::Storage)?
    }

    /// Test-only: the targets stored for `id`, whatever owner holds it.
    #[cfg(test)]
    pub(crate) fn targets_for_test(&self, id: &str) -> Vec<Target> {
        let state = self.0.state();
        state
            .entries
            .get(id)
            .map(|entry| entry.record.targets.clone())
            .unwrap_or_default()
    }

    /// Test-only: turn `id` into a row written before targets existed, with no
    /// upstream descriptor to name its call.
    #[cfg(test)]
    pub(crate) fn strip_targets_for_test(&self, id: &str) {
        let mut state = self.0.state();
        let entry = state.entries.get_mut(id).expect("the fixture task exists");
        entry.record.targets.clear();
        entry.record.upstream = None;
        entry.record.version = entry.record.version.min(3);
    }

    /// Test-only: give `id` the upstream descriptor a legacy row keeps when
    /// its call went to an upstream task, bound to its own operation digest.
    #[cfg(test)]
    pub(crate) fn set_upstream_for_test(&self, id: &str, (server, tool): (&str, &str)) {
        let mut state = self.0.state();
        let entry = state.entries.get_mut(id).expect("the fixture task exists");
        entry.record.upstream = Some(crate::gateway::task_service::record::UpstreamRecord {
            handle: "peer-task-1".to_owned(),
            backend: server.to_owned(),
            tool: tool.to_owned(),
            arguments: serde_json::json!({}),
            operation_digest: entry.record.admission.operation_digest.clone(),
        });
    }
}

impl Shared {
    fn add_targets_blocking(
        &self,
        owner: &str,
        id: &str,
        expected_revision: u64,
        targets: Vec<Target>,
    ) -> Result<(), StoreError> {
        let _order = self.order();
        let (task, mut record): (Task, Record) = {
            let state = self.state();
            if !state.ready {
                return Err(StoreError::Unavailable);
            }
            let entry = owned(&state, owner, id)?;
            if entry.record.revision != expected_revision {
                return Err(StoreError::RevisionConflict);
            }
            if matches!(
                entry.task.status(),
                TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
            ) {
                return Err(StoreError::InvalidTransition);
            }
            (entry.task.clone(), entry.record.clone())
        };
        for target in targets {
            if !record.targets.contains(&target) {
                record.targets.push(target);
            }
        }
        record.version = record.version.max(TARGET_VERSION);
        let bytes = serialize(&record)?;
        if bytes.len() > self.limits.record_bytes {
            return Err(StoreError::Capacity);
        }
        self.commit(&record_name(task.id()), &bytes)?;
        self.publish(task, record);
        Ok(())
    }

    fn settle_bounded_blocking(
        &self,
        owner: &str,
        id: &str,
        revision: u64,
        (event, targets, author, writes): (
            TaskTransition,
            Option<Vec<Target>>,
            ErrorAuthor,
            WriteRecord,
        ),
        at: DateTime<Utc>,
    ) -> Result<CommittedTask, StoreError> {
        let _order = self.order();
        let (task, record) = {
            let state = self.state();
            if !state.ready {
                return Err(StoreError::Unavailable);
            }
            let entry = owned(&state, owner, id)?;
            if entry.record.revision != revision {
                return Err(StoreError::RevisionConflict);
            }
            (entry.task.clone(), entry.record.clone())
        };
        Ok(
            match self.settle_durable(&task, &record, (event, targets, author, writes), at)? {
                Some((task, record)) => self.publish(task, record),
                None => CommittedTask::of(task, &record),
            },
        )
    }

    /// Write `task` settled by `event`, falling back to the bounded failure
    /// when the outcome does not fit; durable, NOT yet published. `None` when
    /// the transition changes nothing. Callers hold the ordering lock. Also
    /// the recovery of a repaired row before its key is imported (MIK-8121).
    pub(super) fn settle_durable(
        &self,
        task: &Task,
        record: &Record,
        (event, targets, author, writes): (
            TaskTransition,
            Option<Vec<Target>>,
            ErrorAuthor,
            WriteRecord,
        ),
        at: DateTime<Utc>,
    ) -> Result<Option<(Task, Record)>, StoreError> {
        // Last resort: an output-free record. It discards the targets and the
        // recovery descriptor, and it is marked so delivery knows its only
        // content is the gateway's own error. Every live row was admitted
        // with room for it ([`fallback_bytes`]).
        let recorded = !writes.is_empty();
        let attempt = (
            event.clone(),
            targets.clone(),
            false,
            author,
            writes.clone(),
        );
        match self.settle_attempt(task, record, attempt, at) {
            Err(StoreError::Capacity) => {}
            settled => return settled,
        }
        // MIK-7993 F1 (lead ruling c): a row with no room for its record keeps
        // its result without the members the record would have exempted, so
        // the gateway's own text is never stored unrecorded and never
        // receipted as backend text on a later read.
        if recorded && let TaskTransition::Complete(mut result) = event {
            let stripped = crate::gateway::gateway_writes::strip_recorded(&mut result, &writes);
            let attempt = (
                TaskTransition::Complete(result),
                targets,
                false,
                author,
                WriteRecord::default(),
            );
            match self.settle_attempt(task, record, attempt, at) {
                Err(StoreError::Capacity) => {}
                settled => {
                    if settled.is_ok() && !stripped.is_empty() {
                        tracing::warn!(
                            task_id = %task.id(),
                            stripped = ?stripped,
                            "task result stored without the gateway members its write \
                             record would have exempted: the row had no room for the record"
                        );
                    }
                    return settled;
                }
            }
        }
        self.settle_attempt(
            task,
            record,
            (
                bounded(),
                None,
                true,
                ErrorAuthor::Gateway,
                WriteRecord::default(),
            ),
            at,
        )
    }

    fn settle_attempt(
        &self,
        task: &Task,
        record: &Record,
        settlement: (
            TaskTransition,
            Option<Vec<Target>>,
            bool,
            ErrorAuthor,
            WriteRecord,
        ),
        at: DateTime<Utc>,
    ) -> Result<Option<(Task, Record)>, StoreError> {
        let Some((task, record)) = settled(task, record, settlement, at)? else {
            return Ok(None);
        };
        let bytes = serialize(&record)?;
        if bytes.len() > self.limits.record_bytes {
            return Err(StoreError::Capacity);
        }
        self.commit(&record_name(task.id()), &bytes)?;
        Ok(Some((task, record)))
    }
}

/// The gateway's own bounded failure: what a row settles as when its real
/// outcome does not fit the record budget.
fn bounded() -> TaskTransition {
    TaskTransition::Fail(JsonRpcError {
        code: -32603,
        message: "the task's result exceeds the record size limit".to_owned(),
        data: None,
    })
}

/// `task` and `record` as a settlement by `event` writes them, before the
/// size check; `None` when the transition changes nothing (a settled row).
fn settled(
    task: &Task,
    record: &Record,
    (event, targets, discard, author, writes): (
        TaskTransition,
        Option<Vec<Target>>,
        bool,
        ErrorAuthor,
        WriteRecord,
    ),
    at: DateTime<Utc>,
) -> Result<Option<(Task, Record)>, StoreError> {
    let (mut task, mut record) = (task.clone(), record.clone());
    // Only a Fail has an error to attribute; any other outcome clears it.
    let fails = matches!(event, TaskTransition::Fail(_));
    let completes = matches!(event, TaskTransition::Complete(_));
    let change = task
        .transition(event, at)
        .map_err(|_| StoreError::InvalidTransition)?;
    if !change.changed {
        return Ok(None);
    }
    record.revision = record.revision.checked_add(1).ok_or(StoreError::Capacity)?;
    record.set_model(&task);
    // Only a completed result holds what the gateway wrote into it
    // (MIK-7993); any other outcome, and an output-free row, clears it.
    record.gateway_writes = if completes && !discard {
        writes
    } else {
        WriteRecord::default()
    };
    // Only the peer's authorship is recorded: absent reads as "not
    // established", which is what every gateway error is.
    record.error_author = None;
    if fails && author == ErrorAuthor::Peer && keep_provenance(&task, &mut record) {
        record.error_author = Some(ErrorAuthor::Peer);
        record.version = record.version.max(ERROR_AUTHOR_VERSION);
    }
    if discard {
        record.targets.clear();
        record.upstream = None;
        record.output_free = true;
        record.version = record.version.max(TARGET_VERSION);
    }
    if let Some(targets) = targets {
        for target in targets {
            if !record.targets.contains(&target) {
                record.targets.push(target);
            }
        }
        record.version = record.version.max(TARGET_VERSION);
    }
    Ok(Some((task, record)))
}

/// The encoded size of `record` cancelled, at its widest: the largest
/// revision and a nine-digit settle instant (MIK-7642). The dispatch preflight
/// admits an upstream descriptor only if the row still fits once cancelled:
/// a cancel that overflowed would settle as the bounded failure instead,
/// discarding the descriptor its one upstream `tasks/cancel` is sent from.
/// 0 for a settled row.
pub(super) fn cancelled_bytes(
    task: &Task,
    record: &Record,
    now: DateTime<Utc>,
) -> Result<usize, StoreError> {
    let at = now.max(task.last_updated_at());
    let at = at.with_nanosecond(999_999_999).unwrap_or(at);
    let Some((_, mut cancelled)) = settled(
        task,
        record,
        (
            TaskTransition::Cancel,
            None,
            false,
            ErrorAuthor::Gateway,
            WriteRecord::default(),
        ),
        at,
    )?
    else {
        return Ok(0);
    };
    cancelled.revision = u64::MAX;
    Ok(serialize(&cancelled)?.len())
}

/// The encoded size of the bounded failure `record` would settle as, at its
/// widest: the largest revision, and a settle instant printed with all nine
/// fractional digits (the serde form trims to 0, 3, 6 or 9). 0 for a settled
/// row, which never settles again (MIK-7651).
///
/// Built by the same [`settled`] the fallback write runs, so the measured and
/// the written record cannot drift. The fallback keeps the model (its issued
/// input keys and status message) and drops targets, the upstream descriptor
/// and the input round: a write that grows a KEPT field must check this
/// against the record budget. Today those are creation and a new input round;
/// the loader checks every live row it reads.
pub(super) fn fallback_bytes(
    task: &Task,
    record: &Record,
    now: DateTime<Utc>,
) -> Result<usize, StoreError> {
    let at = now.max(task.last_updated_at());
    let at = at.with_nanosecond(999_999_999).unwrap_or(at);
    let Some((_, mut fallback)) = settled(
        task,
        record,
        (
            bounded(),
            None,
            true,
            ErrorAuthor::Gateway,
            WriteRecord::default(),
        ),
        at,
    )?
    else {
        return Ok(0);
    };
    fallback.revision = u64::MAX;
    Ok(serialize(&fallback)?.len())
}

/// Before a row is raised past [`TARGET_VERSION`], its calls must be stored on
/// it: a legacy row names them only through its upstream descriptor, which a
/// current version no longer consults, so raising it bare would read as
/// "dispatched nothing" and skip the delivery check. `false` when a legacy row
/// has no call to keep: its authorship is then not recorded (fail closed).
fn keep_provenance(task: &crate::protocol::tasks::Task, record: &mut Record) -> bool {
    if record.version >= TARGET_VERSION {
        return true;
    }
    let legacy = CommittedTask::of(task.clone(), record).targets;
    if legacy.is_empty() {
        return false;
    }
    record.targets = legacy;
    true
}

// The one durable claim on a cancelled row's upstream `tasks/cancel`
// (MIK-7642 PR.D, design r7 R7.3 / r8 R8.4).
//
// Every sender — the cancel transition, the worker's dispatch-phase cancel
// arm, and the worker's offer after a refused capture — asks here, and sends only on
// [`CancelClaim::Claimed`]. The claim is one compare on
// `Record::upstream_cancel_sent` under the store's ordering lock, so exactly
// one sender wins per row whatever order they arrive in.

/// What one claim on a row's upstream cancel decided.
#[derive(Debug, PartialEq)]
pub(crate) enum CancelClaim {
    /// This caller won: send one `tasks/cancel` naming this descriptor's handle.
    Claimed(UpstreamRecord),
    /// Another sender already claimed it. Send nothing.
    AlreadyClaimed,
    /// Not a cancelled row, or no handle is known for it yet. Nothing is
    /// claimed, so a sender that learns the handle later can still win.
    NotOurs,
}

impl TaskStore {
    /// Claim the single upstream `tasks/cancel` of a cancelled row.
    ///
    /// `offered` is the descriptor a sender holds but the row may not: the
    /// worker that has a handle the capture never made durable. A descriptor
    /// already on the row wins over it (first handle wins), and an offered one
    /// must name the row's own admitted operation. The winning descriptor is
    /// returned to the sender and taken off the row. The revision is not
    /// bumped: like `mark_upstream`, no reader's compare-and-set depends on
    /// this field.
    ///
    /// # Errors
    /// `NotFound` for a foreign or absent row; `Capacity` when the descriptor
    /// would exceed the record budget; a storage failure as itself.
    pub(crate) async fn claim_upstream_cancel(
        &self,
        owner: &str,
        id: &str,
        offered: Option<UpstreamRecord>,
    ) -> Result<CancelClaim, StoreError> {
        let shared = Arc::clone(&self.0);
        let (owner, id) = (owner.to_owned(), id.to_owned());
        tokio::task::spawn_blocking(move || {
            shared.claim_upstream_cancel_blocking(&owner, &id, offered)
        })
        .await
        .map_err(|_| StoreError::Storage)?
    }
}

impl Shared {
    fn claim_upstream_cancel_blocking(
        &self,
        owner: &str,
        id: &str,
        offered: Option<UpstreamRecord>,
    ) -> Result<CancelClaim, StoreError> {
        let _order = self.order();
        let (task, mut record) = {
            let state = self.state();
            if !state.ready {
                return Err(StoreError::Unavailable);
            }
            let entry = owned(&state, owner, id)?;
            if entry.task.status() != TaskStatus::Cancelled {
                return Ok(CancelClaim::NotOurs);
            }
            if entry.record.upstream_cancel_sent {
                return Ok(CancelClaim::AlreadyClaimed);
            }
            (entry.task.clone(), entry.record.clone())
        };
        let durable = record
            .upstream
            .clone()
            .filter(|upstream| upstream.consistent_with(&record.admission));
        let offered = offered.filter(|upstream| {
            upstream.handle.len() <= MAX_UPSTREAM_HANDLE_BYTES
                && upstream.consistent_with(&record.admission)
        });
        let Some(descriptor) = durable.or(offered) else {
            return Ok(CancelClaim::NotOurs);
        };
        // The descriptor leaves the row with the claim. A terminal row is never
        // queried again, and taking it off is what guarantees the marker fits:
        // the cancelled row already met its budget with the descriptor on it.
        // A legacy row named its call only through the descriptor: keep that
        // provenance as targets before the descriptor leaves (the row is raised
        // past the version that reads targets). The winning descriptor, offered
        // or durable, is the one read.
        record.upstream = Some(descriptor.clone());
        let _ = keep_provenance(&task, &mut record);
        record.upstream = None;
        record.upstream_cancel_sent = true;
        record.version = record.version.max(UPSTREAM_CANCEL_VERSION);
        let bytes = serialize(&record)?;
        if bytes.len() > self.limits.record_bytes {
            return Err(StoreError::Capacity);
        }
        self.commit(&record_name(task.id()), &bytes)?;
        self.publish(task, record);
        Ok(CancelClaim::Claimed(descriptor))
    }
}
