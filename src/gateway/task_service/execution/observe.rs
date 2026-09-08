// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-visible commit stages, accepted-handoff ownership, drain result, and
//! the I5 recovery seam.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::watch;

use super::TaskExecutor;
use crate::protocol::JsonRpcError;
use serde_json::Value;

/// Durable-write stages the executor makes observable. Counts successful
/// writes, not attempts: a rejected CAS settle must not appear here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommitStage {
    /// The create facade committed a new record.
    Published,
    /// `mark_dispatched` wrote the durable marker.
    Dispatched,
    /// A terminal transition was committed (settle/cancel/recover).
    Transitioned,
}

/// After a successful durable write at `stage`, before the worker proceeds.
///
/// Default methods match the interlock fixture: injections are off unless a
/// test forces them. No precommit hook exists; `fail_marker` is the store
/// failure the marker write itself reports.
#[async_trait::async_trait]
pub(crate) trait CommitObserver: Send + Sync {
    async fn reached(&self, stage: CommitStage, task_id: &str);
    fn fail_marker(&self, _task_id: &str) -> bool {
        false
    }
    fn fail_state_upgrade(&self, _task_id: &str) -> bool {
        false
    }
}

/// Every handoff the executor has accepted, whether or not it has been polled.
///
/// The map is also the cancellation directory: the value is the signal the
/// owner of that task is listening on, so accepting a handoff and being
/// cancellable are the same registration and cannot drift apart.
///
/// Membership starts BEFORE the worker is scheduled, which is the whole point.
/// Worker capacity is reserved inside the create facade — on the spawned task,
/// after the idempotency lookup — so between the spawn and the child's first
/// poll there is owned work that holds no permit. A drain that only counted
/// permits could not see it.
pub(crate) struct HandoffRegistry {
    accepted: Mutex<HashMap<String, watch::Sender<bool>>>,
    /// Bumped after every removal. A generation rather than a count so that a
    /// waiter cannot miss a release that was immediately followed by a new
    /// accept: the value it compares against is the one it saw at subscribe.
    released: watch::Sender<u64>,
}

impl HandoffRegistry {
    pub(crate) fn new() -> Self {
        Self {
            accepted: Mutex::new(HashMap::new()),
            released: watch::channel(0).0,
        }
    }

    /// Record `id` as owned and hand back the signal its owner listens on.
    fn insert(&self, id: &str) -> watch::Receiver<bool> {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        self.accepted.lock().insert(id.to_owned(), cancel_tx);
        cancel_rx
    }

    /// Raise the cancellation signal for a task still owned by a worker.
    /// Silently nothing for a task nobody owns, which is the settled case.
    pub(crate) fn cancel_signal(&self, id: &str) {
        let cancel_tx = self.accepted.lock().get(id).cloned();
        if let Some(cancel_tx) = cancel_tx {
            let _ = cancel_tx.send(true);
        }
    }

    /// Wait until no accepted handoff remains.
    ///
    /// Interest is registered BEFORE the state is read, so a release landing
    /// between the two is a wake and not a lost one. The lock is taken and
    /// dropped inside [`Self::is_empty`], never held across the await.
    ///
    /// New handoffs observed before the empty check can extend the wait. Once
    /// emptiness is observed, later admission is outside this join boundary;
    /// callers that need a shutdown boundary must quiesce admission first.
    pub(crate) async fn join(&self) {
        loop {
            let mut released = self.released.subscribe();
            if self.is_empty() {
                return;
            }
            // Only when the sender is gone, which cannot happen while `&self`
            // is borrowed: it is a field of the value being borrowed.
            if released.changed().await.is_err() {
                return;
            }
        }
    }

    fn is_empty(&self) -> bool {
        self.accepted.lock().is_empty()
    }

    /// The one ownership removal. Reached only from [`Handoff::drop`].
    fn release(&self, id: &str) {
        self.accepted.lock().remove(id);
        // After the removal and outside the lock: a waiter this wakes must find
        // the map already without the entry.
        self.released
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }
}

/// Ownership of one accepted handoff.
///
/// Created before the worker is scheduled and moved into it, so completion, an
/// error or refusal, a panic, or the spawned future being dropped all release
/// the same way — through this guard's `Drop` and nothing else. Dropping the
/// initiating request does not touch it: the guard lives on the spawned task.
///
/// It carries the executor it was accepted by rather than borrowing one from
/// its holder, so the worker cannot be handed ownership of one executor's task
/// together with a different executor to run it against.
pub(crate) struct Handoff {
    executor: Arc<TaskExecutor>,
    id: String,
}

impl Handoff {
    /// Take ownership of `id`, and hand back the guard plus the cancellation
    /// signal its owner listens on.
    ///
    /// The guard is live from here, so a drain called between this call and the
    /// spawned owner's first poll already sees the handoff.
    pub(crate) fn accept(executor: &Arc<TaskExecutor>, id: &str) -> (Self, watch::Receiver<bool>) {
        let cancel_rx = executor.handoffs.insert(id);
        (
            Self {
                executor: Arc::clone(executor),
                id: id.to_owned(),
            },
            cancel_rx,
        )
    }

    pub(crate) fn executor(&self) -> &Arc<TaskExecutor> {
        &self.executor
    }
}

impl Drop for Handoff {
    fn drop(&mut self) {
        self.executor.handoffs.release(&self.id);
    }
}

/// Result of a drain: joining every accepted handoff, then acquiring every
/// worker permit. Clean means no handoff the executor had accepted was still
/// owned and every committed but unsettled task had released its permit (or
/// neither existed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DrainOutcome {
    pub timed_out: bool,
    pub acquired: usize,
}

impl DrainOutcome {
    #[cfg(test)]
    pub(crate) fn is_clean(self) -> bool {
        !self.timed_out
    }
}

/// The durable coordinates of one live upstream job: a backend and the opaque
/// identifier that backend chose. Deliberately the WHOLE vocabulary an adapter
/// receives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UpstreamHandle {
    pub backend: String,
    pub handle: String,
}

/// What one bounded read-only query learned.
///
/// `Live` and `Unavailable` are distinct only in the log: both retain the
/// handle and the `working` record so a later authenticated read can make
/// progress. Neither is ever committed as a terminal `unknown`, and neither
/// resubmits anything.
pub(crate) enum UpstreamAnswer {
    /// The job finished and the peer handed back its tool result verbatim.
    /// Still faces the ordinary post-dispatch gates before it is committed.
    Completed(Value),
    /// The job failed and the peer handed back a JSON-RPC error.
    Failed(JsonRpcError),
    /// Pending, working, or waiting on an input round this gateway cannot
    /// continue. The record stays as it is.
    Live,
    /// Transport unavailable, circuit open, timeout, refusal, or an answer this
    /// gateway could not parse. Indistinguishable from `Live` in effect.
    Unavailable,
}

/// I5 seam, reduced from r3's `checkpoint`/`query` pair.
///
/// It can name neither a tool nor arguments, so "never resubmit the original
/// operation" is structural rather than promised: there is no argument through
/// which an implementation could be handed the original call. Its vocabulary is
/// one read — `tasks/get` — and `tasks/cancel` and every other mutation are
/// outside it. `claims` reads configured trust and the peer's own declaration;
/// an unclaimed backend is never queried at all.
#[async_trait::async_trait]
pub(crate) trait UpstreamRecovery: Send + Sync {
    /// Whether this adapter is trusted for `backend` right now. Re-evaluated
    /// against current configuration on every read; historic admission
    /// authorizes nothing.
    async fn claims(&self, backend: &str) -> bool;

    /// One bounded read-only query. No retry loop, no polling across a process
    /// boundary, and no write of any kind upstream.
    async fn query(&self, handle: &UpstreamHandle, deadline: Duration) -> UpstreamAnswer;
}
