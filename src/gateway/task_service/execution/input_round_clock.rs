// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The input round's clock waits (MIK-8202): a worker neither parks, resumes,
//! mints nor redeems on a time it cannot read.

use std::time::Duration;

use tokio::sync::watch;

use super::{Settling, TaskCall, TaskExecutor, dispatch};
use crate::gateway::task_service::execution::OwnedCallerContext;
use crate::gateway::task_service::host::LiveHost;
use crate::protocol::JsonRpcResponse;
use crate::protocol::mrtr::RetryFields;
use crate::protocol::tasks::TaskTransition;

/// How often a worker reads a clock that read before 1970 again.
pub(super) const CLOCK_RETRY: Duration = if cfg!(test) {
    Duration::from_millis(20)
} else {
    Duration::from_secs(1)
};

/// The store's now, and the same instant in the seconds round deadlines are
/// kept in, waiting out a clock before 1970: a round is neither parked nor
/// resumed nor closed on a time it cannot read, so nothing is lost while the
/// clock is wrong (MIK-8202). `None` once the task is cancelled; executor
/// shutdown drops the worker, wait and all.
// ponytail: polls on monotonic time and holds this worker's slot while the
// clock is unreadable; a clock-recovered signal would free it sooner.
pub(super) async fn readable_now(
    store: &crate::gateway::task_service::store::TaskStore,
    id: &str,
    cancel_rx: &mut watch::Receiver<bool>,
) -> Option<(chrono::DateTime<chrono::Utc>, u64)> {
    let mut warned = false;
    loop {
        if *cancel_rx.borrow() {
            return None;
        }
        if let Ok(at) = store.now() {
            return Some((at, u64::try_from(at.timestamp()).unwrap_or_default()));
        }
        // Once per round: the operator learns why a worker is held.
        if !warned {
            warned = true;
            telemetry_metrics::counter!("mcp_task_clock_waits_total").increment(1);
            tracing::warn!(
                task_id = %id,
                "the host clock reads before 1970: this input round waits for it, holding a task worker"
            );
        }
        tokio::select! {
            biased;
            // A dropped sender can no longer cancel: stop, as `dispatch` does.
            changed = cancel_rx.changed() => changed.ok()?,
            () = tokio::time::sleep(CLOCK_RETRY) => {}
        }
    }
}

/// [`dispatch`], retried while the funnel refuses the redemption for a clock
/// it cannot read (MIK-8202 AC13).
///
/// The refusal is the typed flag the funnel set, never the message: the
/// sample is taken before the open, so the continuation is unspent and
/// undispatched and the same retry may go again once the clock reads. A real
/// expiry is a readable sample and returns as the response it always was.
/// `None` once the task is cancelled; executor shutdown drops the wait.
pub(super) async fn redeeming_dispatch(
    (state, owned, call, retry): (&LiveHost, &OwnedCallerContext, &TaskCall, &RetryFields),
    (executor, id): (&TaskExecutor, &str),
    cancel_rx: &mut watch::Receiver<bool>,
) -> Option<JsonRpcResponse> {
    let store = &executor.service.store;
    loop {
        owned.dispatch_log().worker().arm(store);
        let response = dispatch(state, owned, call, retry, cancel_rx).await?;
        if !owned.dispatch_log().worker().take_redemption_unreadable() {
            return Some(response);
        }
        readable_now(store, id, cancel_rx).await?;
    }
}

/// What became of the round a clock-blind funnel withheld.
pub(super) enum Resealed {
    /// The funnel withheld nothing.
    Nothing,
    /// Sealed at the carried time, the one the round is also parked at.
    Sealed(Box<JsonRpcResponse>, (chrono::DateTime<chrono::Utc>, u64)),
    /// Cancelled or settled here; nothing is left to run.
    Done,
}

impl Settling<'_> {
    /// AC12: wait for a clock that reads, then mint the withheld round's
    /// continuation with that one checked time and its original binding.
    pub(super) async fn reseal_withheld(&self, cancel_rx: &mut watch::Receiver<bool>) -> Resealed {
        let Some(withheld) = self.owned.dispatch_log().worker().take_withheld() else {
            return Resealed::Nothing;
        };
        let store = &self.executor.service.store;
        let Some((at, now)) = readable_now(store, self.id, cancel_rx).await else {
            return Resealed::Done;
        };
        let continuation = self.state.meta_mcp().continuation();
        let Some(result) = withheld.seal(&continuation, now).await else {
            let abandoned = TaskTransition::Complete(super::abandoned_input_round());
            self.settle(abandoned, false).await;
            return Resealed::Done;
        };
        let response = JsonRpcResponse::success(crate::protocol::RequestId::Number(0), result);
        let mut response = super::inspect_settled(self.state, self.call, self.id, response);
        self.state
            .meta_mcp()
            .release_unsent_hold(&mut response)
            .await; // MIK-8131
        Resealed::Sealed(Box::new(response), (at, now))
    }
}
