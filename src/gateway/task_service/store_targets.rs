// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The durable write of a plan's dispatched targets (#2450): the backend calls
//! a playbook or code-mode program actually made, recorded before the task
//! settles so a stored result can be re-authorized against what produced it.

use std::sync::Arc;

use super::{Shared, StoreError, TaskStore, owned, record_name, serialize};
use crate::gateway::task_service::record::{Record, TARGET_VERSION, Target};
use crate::protocol::tasks::{Task, TaskStatus};

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
}
