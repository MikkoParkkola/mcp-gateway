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

/// What a wait for a readable clock came to.
pub(super) enum ClockWait {
    /// The store's now, and the same instant in the seconds round deadlines
    /// are kept in.
    Read(chrono::DateTime<chrono::Utc>, u64),
    /// The task was cancelled; nothing is left to run.
    Stopped,
    /// The clock stayed unreadable for the task's whole retention, measured on
    /// monotonic time: the task must end failed ([`clock_expired`]).
    Expired,
}

/// The failure a task ends with when the clock stays before 1970 for its
/// whole retention (MIK-8202).
pub(super) fn clock_expired() -> crate::protocol::JsonRpcError {
    crate::protocol::JsonRpcError {
        code: -32603,
        message: "host clock reads before 1970; the task's ttl ran out while waiting for it"
            .to_owned(),
        data: None,
    }
}

/// The store's now, waiting out a clock before 1970: a round is neither
/// parked nor resumed nor closed on a time it cannot read, so nothing is lost
/// while the clock is wrong (MIK-8202). Bounded: once the task's own `ttlMs`
/// has elapsed on monotonic time since the wait began, the wait ends
/// [`ClockWait::Expired`], since that clock cannot date the record's expiry;
/// an unlimited task is bounded by the release default ttl. Executor shutdown
/// drops the worker, wait and all.
// ponytail: polls on monotonic time and holds this worker's slot while the
// clock is unreadable; a clock-recovered signal would free it sooner.
pub(super) async fn readable_now(
    store: &crate::gateway::task_service::store::TaskStore,
    id: &str,
    cancel_rx: &mut watch::Receiver<bool>,
) -> ClockWait {
    let mut since: Option<tokio::time::Instant> = None;
    loop {
        if *cancel_rx.borrow() {
            return ClockWait::Stopped;
        }
        if let Ok(at) = store.now() {
            return ClockWait::Read(at, u64::try_from(at.timestamp()).unwrap_or_default());
        }
        match since {
            None => {
                since = Some(tokio::time::Instant::now());
                // Once per round: the operator learns why a worker is held.
                telemetry_metrics::counter!("mcp_task_clock_waits_total").increment(1);
                tracing::warn!(
                    task_id = %id,
                    "the host clock reads before 1970: this input round waits for it, holding a task worker"
                );
            }
            Some(began) => match store.clock_wait_bound(id) {
                // The row left the store: nothing is left to wait for.
                None => return ClockWait::Stopped,
                Some(bound) if began.elapsed() >= bound => {
                    tracing::warn!(task_id = %id, "the host clock stayed before 1970 for the task's ttl: the task fails");
                    return ClockWait::Expired;
                }
                Some(_) => {}
            },
        }
        tokio::select! {
            biased;
            // A dropped sender can no longer cancel: stop, as `dispatch` does.
            changed = cancel_rx.changed() => if changed.is_err() {
                return ClockWait::Stopped;
            },
            () = tokio::time::sleep(CLOCK_RETRY) => {}
        }
    }
}

/// [`readable_now`] where no [`Settling`] is at hand: an expired wait fails the
/// task here. `None` once the task is cancelled or failed.
pub(super) async fn readable_or_fail(
    executor: &TaskExecutor,
    (principal, id, revision): (&str, &str, u64),
    cancel_rx: &mut watch::Receiver<bool>,
) -> Option<(chrono::DateTime<chrono::Utc>, u64)> {
    match readable_now(&executor.service.store, id, cancel_rx).await {
        ClockWait::Read(at, now) => Some((at, now)),
        ClockWait::Stopped => None,
        ClockWait::Expired => {
            let event = TaskTransition::Fail(clock_expired());
            executor.settle_cas(principal, id, revision, event).await;
            None
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
/// `None` once the task is cancelled, or failed because the clock stayed
/// unreadable for its bound; executor shutdown drops the wait.
pub(super) async fn redeeming_dispatch(
    (state, owned, call, retry): (&LiveHost, &OwnedCallerContext, &TaskCall, &RetryFields),
    executor: &TaskExecutor,
    ids: (&str, &str, u64),
    cancel_rx: &mut watch::Receiver<bool>,
) -> Option<JsonRpcResponse> {
    let store = &executor.service.store;
    loop {
        owned.dispatch_log().worker().arm(store);
        let response = dispatch(state, owned, call, retry, cancel_rx).await?;
        if !owned.dispatch_log().worker().take_redemption_unreadable() {
            return Some(response);
        }
        // An expired wait fails the task here, once: a caller that read the
        // clock again would start a second full wait (MIK-8202).
        readable_or_fail(executor, ids, cancel_rx).await?;
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
        let (at, now) = match readable_now(store, self.id, cancel_rx).await {
            ClockWait::Read(at, now) => (at, now),
            ClockWait::Stopped => return Resealed::Done,
            ClockWait::Expired => {
                self.settle(TaskTransition::Fail(clock_expired()), false)
                    .await;
                return Resealed::Done;
            }
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
