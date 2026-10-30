// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a settle and a park record about how a task's outcome was produced:
//! the plan's dispatched targets and the binding every call ran under
//! (#2450, MIK-8407).

use super::Settling;
use crate::gateway::task_service::record::Target;
use crate::gateway::task_service::store::StoreError;

impl Settling<'_> {
    /// The calls a plan actually dispatched, for the settlement to commit with
    /// its outcome. `None` for a call whose one target was recorded at creation.
    pub(super) fn plan_targets(&self) -> Option<Vec<Target>> {
        crate::gateway::meta_mcp::is_composite_meta_tool(&self.call.tool).then(|| {
            self.owned
                .dispatch_log()
                .snapshot()
                .into_iter()
                .map(|(server, tool)| Target { server, tool })
                .collect()
        })
    }

    /// What a settle records with its outcome: the plan's targets and the
    /// binding every call so far ran under (MIK-8407), from the dispatch log.
    pub(super) fn provenance(&self) -> crate::gateway::task_service::record::Provenance {
        crate::gateway::task_service::record::Provenance {
            targets: self.plan_targets(),
            bindings: self.owned.dispatch_log().bindings(),
        }
    }

    /// Record a parked plan's calls so far; the resume's log starts empty.
    /// The owner the round parks under, or `None` when they are NOT durable
    /// (or the principal cannot be hashed) and the round must not be parked.
    pub(super) async fn park_targets(&self) -> Option<crate::idempotency::admission::TaskOwner> {
        // Every parked row records its bindings (MIK-8407), a single call's
        // too: its pending input requests are backend output.
        let crate::gateway::task_service::record::Provenance { targets, bindings } =
            self.provenance();
        // A plan's calls must be durable before it parks; a single call's one
        // target was recorded at creation.
        let plan = targets.is_some();
        let targets = targets.unwrap_or_default();
        let owner = self.executor.service.owner(self.principal).ok()?;
        let stored = self
            .executor
            .service
            .store
            .add_targets(
                owner.as_digest(),
                self.id,
                self.revision,
                (targets, bindings),
            )
            .await;
        // A row a cancel already moved is not parked either way. For a single
        // call a closed store refuses the park write too, which logs its cause
        // and writes nothing, so no row parks without its bindings (MIK-8407).
        let parks = match stored {
            Ok(()) | Err(StoreError::RevisionConflict) => true,
            Err(StoreError::Unavailable) => !plan,
            Err(_) => false,
        };
        parks.then_some(owner)
    }
}
