// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8176: the task store's sealed-hold readers. A row's payload travels
//! with clones of the holds it carries (`Entry.holds`, kept by `publish`).
//! Split from `store.rs` to keep it under the 800-line ceiling.

use super::{CommittedTask, StoreError, TaskStore, owned};
use crate::gateway::meta_mcp::sealed_hold::{CarriedHolds, Held};

impl TaskStore {
    /// [`Self::get`] for a reader that may put the row's payload on the
    /// wire: the payload travels with clones of the holds it carries, taken
    /// under the same lock, so it can only be delivered by adopting them
    /// (MIK-8176 D4).
    pub(crate) fn get_held(
        &self,
        owner: &str,
        id: &str,
    ) -> Result<Held<CommittedTask>, StoreError> {
        let state = self.0.state();
        if !state.ready {
            return Err(StoreError::Unavailable);
        }
        let entry = owned(&state, owner, id)?;
        Ok(Held::new(
            CommittedTask::of(entry.task.clone(), &entry.record),
            entry.holds.clone(),
        ))
    }

    /// The holds of `id`'s parked round, cloned for the resume worker to
    /// adopt before it commits the answers and redeems (MIK-8176 D3).
    pub(crate) fn round_holds(&self, owner: &str, id: &str) -> CarriedHolds {
        let state = self.0.state();
        owned(&state, owner, id).map_or_else(|_| CarriedHolds::none(), |entry| entry.holds.clone())
    }

    /// MIK-8176: a committed row's status, whatever owner holds it, read
    /// without a delivery (a `tasks/get` would hand off its holds).
    #[cfg(test)]
    pub(crate) fn status_for_test(&self, id: &str) -> Option<crate::protocol::tasks::TaskStatus> {
        self.0
            .state()
            .entries
            .get(id)
            .map(|entry| entry.task.status())
    }

    /// MIK-8176 B11: the bytes `id`'s committed record takes as the store
    /// writes it, so a row can pin a record cap between two sizes.
    #[cfg(test)]
    pub(crate) fn record_bytes_for_test(&self, id: &str) -> Option<usize> {
        let state = self.0.state();
        let entry = state.entries.get(id)?;
        super::serialize(&entry.record)
            .ok()
            .map(|bytes| bytes.len())
    }
}
