// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The executor's test-only hooks, moved out of `execution.rs` to keep it
//! under its size ceiling. Production compiles none of this.

use std::time::Duration;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::{TaskExecutor, TransitionWrite};
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

/// MIK-8202 P4a r4.1: counts each task's `commit_transition` attempts and,
/// before a chosen attempt, commits one concurrent write so that attempt
/// loses its compare-and-set. Cloneable; every clone shares one state.
#[derive(Clone, Default)]
pub(crate) struct CommitAttemptHook(Arc<parking_lot::Mutex<HookState>>);

#[derive(Default)]
struct HookState {
    attempts: HashMap<String, usize>,
    conflicts: HashSet<(String, usize)>,
}

impl CommitAttemptHook {
    /// The commit attempts made for `id` since the hook was taken.
    pub(crate) fn attempts(&self, id: &str) -> usize {
        self.0.lock().attempts.get(id).copied().unwrap_or(0)
    }

    /// Before attempt `attempt` (1-based) for `id`, commit one `StatusMessage`
    /// write at the record's current revision. Several attempts may be named.
    pub(crate) fn inject_conflict_before(&self, id: &str, attempt: usize) {
        self.0.lock().conflicts.insert((id.to_owned(), attempt));
    }

    /// Count one attempt for `id`; its number when a conflict is due before it.
    fn attempt(&self, id: &str) -> Option<usize> {
        let mut state = self.0.lock();
        let count = state.attempts.entry(id.to_owned()).or_default();
        *count += 1;
        let attempt = *count;
        state
            .conflicts
            .remove(&(id.to_owned(), attempt))
            .then_some(attempt)
    }
}

impl TransitionWrite<'_> {
    /// The task this write moves.
    pub(super) fn id(&self) -> &str {
        match self {
            Self::Settle { id, .. } | Self::Cancel { id, .. } | Self::Recover { id, .. } => id,
        }
    }
}

impl TaskExecutor {
    /// Test-only: the executor's commit-attempt hook, installed on first use.
    pub(crate) fn commit_hook_for_test(&self) -> CommitAttemptHook {
        self.commit_hook
            .get_or_init(CommitAttemptHook::default)
            .clone()
    }

    /// Called before every commit attempt. An injected write is dated at the
    /// record's own `last_updated_at`, so it never reads the store clock, and
    /// carries the attempt number: an unchanged status message is a no-op
    /// that would not move the revision.
    pub(super) async fn before_commit_attempt_for_test(&self, id: &str) {
        let Some(attempt) = self.commit_hook.get().and_then(|hook| hook.attempt(id)) else {
            return;
        };
        let owner = self
            .service
            .store
            .owner_digest_for_test(id)
            .expect("the task exists");
        let current = self.service.store.get(&owner, id).expect("readable");
        let message = format!("injected before commit attempt {attempt}");
        self.service
            .store
            .transition(
                &owner,
                id,
                current.revision,
                TaskTransition::StatusMessage(Some(message)),
                current.task.last_updated_at(),
            )
            .await
            .expect("the injected write commits");
    }
}
