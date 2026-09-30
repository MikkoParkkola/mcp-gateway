// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The durable write of a plan's dispatched targets (#2450): the backend calls
//! a playbook or code-mode program actually made, recorded before the task
//! settles so a stored result can be re-authorized against what produced it.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use super::{Shared, StoreError, TaskStore, owned, record_name, serialize};
use crate::gateway::task_service::record::{CommittedTask, Record, TARGET_VERSION, Target};
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
    pub(crate) async fn settle_bounded(
        &self,
        owner: &str,
        id: &str,
        revision: u64,
        (event, targets): (TaskTransition, Option<Vec<Target>>),
        at: DateTime<Utc>,
    ) -> Result<CommittedTask, StoreError> {
        let shared = Arc::clone(&self.0);
        let (owner, id) = (owner.to_owned(), id.to_owned());
        tokio::task::spawn_blocking(move || {
            shared.settle_bounded_blocking(&owner, &id, revision, (event, targets), at)
        })
        .await
        .map_err(|_| StoreError::Storage)?
    }

    /// Test-only: turn `id` into a row written before targets existed.
    #[cfg(test)]
    pub(crate) fn strip_targets_for_test(&self, id: &str) {
        let mut state = self.0.state();
        let entry = state.entries.get_mut(id).expect("the fixture task exists");
        entry.record.targets.clear();
        entry.record.version = entry.record.version.min(3);
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
        (event, targets): (TaskTransition, Option<Vec<Target>>),
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
        let bounded = TaskTransition::Fail(JsonRpcError {
            code: -32603,
            message: "the task's result exceeds the record size limit".to_owned(),
            data: None,
        });
        // Last resort: the bounded failure carries no output, so it needs no
        // targets; a plan row is still marked as written by a recording gateway.
        let none = targets.as_ref().map(|_| Vec::new());
        let attempts = [
            (event, targets.clone()),
            (bounded.clone(), targets),
            (bounded, none),
        ];
        for (event, targets) in attempts {
            match self.settle_attempt(&task, &record, (event, targets), at) {
                Err(StoreError::Capacity) => {}
                settled => return settled,
            }
        }
        Err(StoreError::Capacity)
    }

    fn settle_attempt(
        &self,
        task: &Task,
        record: &Record,
        (event, targets): (TaskTransition, Option<Vec<Target>>),
        at: DateTime<Utc>,
    ) -> Result<CommittedTask, StoreError> {
        let (mut task, mut record) = (task.clone(), record.clone());
        let change = task
            .transition(event, at)
            .map_err(|_| StoreError::InvalidTransition)?;
        if !change.changed {
            return Ok(CommittedTask::of(task, &record));
        }
        record.revision = record.revision.checked_add(1).ok_or(StoreError::Capacity)?;
        record.set_model(&task);
        if let Some(targets) = targets {
            for target in targets {
                if !record.targets.contains(&target) {
                    record.targets.push(target);
                }
            }
            record.version = record.version.max(TARGET_VERSION);
        }
        let bytes = serialize(&record)?;
        if bytes.len() > self.limits.record_bytes {
            return Err(StoreError::Capacity);
        }
        self.commit(&record_name(task.id()), &bytes)?;
        Ok(self.publish(task, record))
    }
}
