// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The executor's test-only hooks, moved out of `execution.rs` to keep it
//! under its size ceiling. Production compiles none of this.

use std::time::Duration;

use super::TaskExecutor;
use crate::gateway::task_service::record::{ErrorAuthor, UpstreamRecord};
use crate::protocol::tasks::TaskTransition;

impl TaskExecutor {
    /// Test-only: workers running now, the pool less its free permits.
    pub(crate) fn busy_workers_for_test(&self) -> usize {
        self.max_workers
            .saturating_sub(self.workers.available_permits())
    }

    /// Test-only: how many tasks are subscribed to the handoff release signal
    /// right now, so a test can tell that an update has parked in its wait.
    pub(crate) fn release_waiters_for_test(&self) -> usize {
        self.handoffs.release_waiters()
    }

    /// Test-only: an update waits up to `wait` for the current owner instead
    /// of the produce-seam second. Set once per executor.
    pub(crate) fn stretch_produce_seam_wait_for_test(&self, wait: Duration) {
        self.produce_seam_wait
            .set(wait)
            .expect("the produce-seam wait is set once");
    }

    /// Test-only: the recovery descriptor a dispatch made durable for `id`.
    ///
    /// The one seam through which a route-level regression can tell "the
    /// candidate fitted and its descriptor was written" from "the candidate
    /// fitted, the backend ran, and the row is unrecoverable" — two outcomes
    /// that are identical at the wire. Kept here rather than in the suite so
    /// that `mod store` stays private to this package.
    pub(crate) fn durable_upstream_for_test(&self, id: &str) -> Option<UpstreamRecord> {
        self.service.store.upstream_for_test(id)
    }

    /// Test-only: commit `id`'s Cancel without signalling its worker, as a
    /// cancel does in the instant between its commit and its signal (MIK-7642).
    pub(crate) async fn commit_cancel_unsignalled_for_test(&self, id: &str) {
        let owner = self
            .service
            .store
            .owner_digest_for_test(id)
            .expect("the task exists");
        let revision = self
            .service
            .store
            .get(&owner, id)
            .expect("readable")
            .revision;
        self.transition_digest_write(
            &owner,
            id,
            revision,
            (
                TaskTransition::Cancel,
                None,
                crate::gateway::gateway_writes::WriteRecord::default(),
            ),
            ErrorAuthor::Gateway,
            None,
        )
        .await
        .expect("the cancel commits");
    }
}
