// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio serve loop's spawned dispatches, by the request id each answers,
//! so a `notifications/cancelled` can abort one (MIK-7272.LIFE.1, design D5 in
//! `docs/design/2026-09-30-sub4-stdio-owner.md`).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::task::{AbortHandle, Id, JoinError, JoinSet};
use tracing::warn;

use crate::protocol::RequestId;

/// Ids cancelled and not yet joined. A dispatch checks it immediately before
/// queueing its response, so no frame for the id is queued after the cancel
/// was processed: `abort` does not stop a task that is already being polled.
#[derive(Clone, Default)]
pub(super) struct Cancelled(Arc<Mutex<HashSet<RequestId>>>);

impl Cancelled {
    pub(super) fn contains(&self, id: &RequestId) -> bool {
        self.0.lock().contains(id)
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

    /// Spawn the dispatch answering `id`. A client that reuses an id still in
    /// flight keeps its first mapping: the second dispatch runs, but cannot be
    /// cancelled by id. It is not refused, which could break a lenient client.
    pub(super) fn spawn(
        &mut self,
        id: Option<RequestId>,
        task: impl Future<Output = ()> + Send + 'static,
    ) {
        let handle = self.tasks.spawn(task);
        let Some(id) = id else { return };
        if self.by_request.contains_key(&id) {
            warn!(%id, "stdio: request id reused while in flight; it cannot be cancelled");
            return;
        }
        self.by_task.insert(handle.id(), id.clone());
        self.by_request.insert(id, (handle.id(), handle));
    }

    /// Record `id` as cancelled, then abort its dispatch. An id that is not in
    /// flight is ignored (MCP cancellation: MAY ignore).
    pub(super) fn cancel(&mut self, id: &RequestId) {
        if let Some((_, handle)) = self.by_request.get(id) {
            self.cancelled.0.lock().insert(id.clone());
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
            self.cancelled.0.lock().remove(&request);
        }
        Some(joined.map(|_| ()))
    }

    pub(super) async fn shutdown(&mut self) {
        self.tasks.shutdown().await;
    }
}
