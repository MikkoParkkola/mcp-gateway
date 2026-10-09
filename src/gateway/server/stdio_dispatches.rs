// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio serve loop's spawned dispatches, by the request id each answers,
//! so a `notifications/cancelled` can abort one (MIK-7272.LIFE.1, design D5 in
//! `docs/design/2026-09-30-sub4-stdio-owner.md`).

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::mpsc::Permit;
use tokio::task::{AbortHandle, Id, JoinError, JoinSet};
use tracing::warn;

use crate::protocol::RequestId;

/// Dispatches, by task, that were cancelled or have answered, and are not yet
/// joined. Keyed by task rather than request id because a client may reuse an
/// id once it has its answer, before the serve loop reaps that dispatch.
#[derive(Default)]
struct Marks {
    /// Needed because `abort` does not stop a task that is already being polled.
    cancelled: HashSet<Id>,
    answered: HashSet<Id>,
}

#[derive(Clone, Default)]
pub(super) struct Cancelled(Arc<Mutex<Marks>>);

impl Cancelled {
    /// Queue `frame` on `permit` unless this dispatch was cancelled, and mark
    /// it answered. The check and the enqueue run under the lock `cancel`
    /// records under, so no frame is queued after the cancel was processed.
    /// Called from inside the dispatch's own task, which is what names it. The
    /// inline path answers on the serve loop's own task, which is never joined
    /// here: it leaves one stale `answered` entry, the same id every time.
    pub(super) fn send_unless_cancelled(
        &self,
        id: Option<&RequestId>,
        permit: Permit<'_, crate::gateway::outbound::OutboundFrame>,
        frame: crate::gateway::outbound::OutboundFrame,
    ) {
        let mut marks = self.0.lock();
        let task = tokio::task::try_id();
        if !task.is_some_and(|task| marks.cancelled.contains(&task)) {
            // MIK-8176: every single answer enters the writer queue here, so
            // its holds are attached here, however it was built. The writer
            // hands them off as it takes the frame; a cancelled answer is
            // never attached, and its holds give the slot back with the scope.
            permit.send(frame.carry_holds());
        }
        if let (Some(_), Some(task)) = (id, task) {
            marks.answered.insert(task);
        }
    }
}

#[derive(Default)]
pub(super) struct StdioDispatches {
    tasks: JoinSet<()>,
    by_request: HashMap<RequestId, (Id, AbortHandle)>,
    by_task: HashMap<Id, RequestId>,
    cancelled: Cancelled,
}

impl StdioDispatches {
    pub(super) fn cancelled(&self) -> Cancelled {
        self.cancelled.clone()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// Spawn the dispatch answering `id`. An id whose dispatch has answered or
    /// was cancelled is free to reuse, joined or not. A client that reuses an
    /// id still in flight keeps its first mapping: the second dispatch runs,
    /// but cannot be cancelled by id. It is not refused, which could break a
    /// lenient client.
    pub(super) fn spawn(
        &mut self,
        id: Option<RequestId>,
        task: impl Future<Output = ()> + Send + 'static,
    ) {
        let handle = self.tasks.spawn(task);
        let Some(id) = id else { return };
        match self.by_request.entry(id) {
            Entry::Occupied(mut entry) => {
                let marks = self.cancelled.0.lock();
                let (old, _) = entry.get();
                if marks.answered.contains(old) || marks.cancelled.contains(old) {
                    drop(marks);
                    self.by_task.insert(handle.id(), entry.key().clone());
                    entry.insert((handle.id(), handle));
                } else {
                    warn!(id = %entry.key(), "stdio: request id reused while in flight; it cannot be cancelled");
                }
            }
            Entry::Vacant(entry) => {
                self.by_task.insert(handle.id(), entry.key().clone());
                entry.insert((handle.id(), handle));
            }
        }
    }

    /// Record `id`'s dispatch as cancelled, then abort it. An id that is not in
    /// flight is ignored (MCP cancellation: MAY ignore); one that has answered
    /// but is not yet joined marks only its own finished task.
    pub(super) fn cancel(&mut self, id: &RequestId) {
        if let Some((task, handle)) = self.by_request.get(id) {
            self.cancelled.0.lock().cancelled.insert(*task);
            handle.abort();
        }
    }

    /// The next finished dispatch, with its entries released. Cancel-safe: the
    /// only await is `JoinSet::join_next_with_id`.
    pub(super) async fn join_next(&mut self) -> Option<Result<(), JoinError>> {
        let joined = self.tasks.join_next_with_id().await?;
        let task = match &joined {
            Ok((id, ())) => *id,
            Err(error) => error.id(),
        };
        if let Some(request) = self.by_task.remove(&task) {
            // Only the entry this task owns, so a stale completion never
            // unmaps a live dispatch.
            if self
                .by_request
                .get(&request)
                .is_some_and(|(owner, _)| *owner == task)
            {
                self.by_request.remove(&request);
            }
        }
        let mut marks = self.cancelled.0.lock();
        marks.cancelled.remove(&task);
        marks.answered.remove(&task);
        drop(marks);
        Some(joined.map(|_| ()))
    }

    pub(super) async fn shutdown(&mut self) {
        self.tasks.shutdown().await;
    }
}
