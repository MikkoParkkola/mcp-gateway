// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The input round's clock waits (MIK-8202): a worker neither parks, resumes,
//! mints nor redeems on a time it cannot read.

use crate::error::rpc_codes::INTERNAL_ERROR;
use std::time::Duration;

use tokio::sync::watch;

use super::{Settling, TaskCall, TaskExecutor, dispatch, settle_surfaced_refused};
use crate::gateway::task_service::ErrorAuthor;
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
pub(in crate::gateway::task_service::execution) enum ClockWait {
    /// The store's now, and the same instant in the seconds round deadlines
    /// are kept in.
    Read(chrono::DateTime<chrono::Utc>, u64),
    /// The task was cancelled; nothing is left to run.
    Stopped,
    /// The clock stayed unreadable for the task's whole retention, measured on
    /// monotonic time: the task settles without waiting again, at its own
    /// `last_updated_at` (`settle_dated_last_known`).
    Expired,
}

/// The failure a task ends with when the clock stays before 1970 for its
/// whole retention (MIK-8202).
pub(super) fn clock_expired() -> crate::protocol::JsonRpcError {
    crate::protocol::JsonRpcError {
        code: INTERNAL_ERROR,
        message: "host clock reads before 1970; the task's ttl ran out while waiting for it"
            .to_owned(),
        data: None,
    }
}

/// The store's now, waiting out a clock before 1970: nothing is parked,
/// resumed, closed or settled on a time this cannot read, so nothing is lost
/// while the clock is wrong (MIK-8202). Bounded: once the task's own `ttlMs`
/// has elapsed on monotonic time since the wait began, the wait ends
/// [`ClockWait::Expired`], since that clock cannot date the record's expiry;
/// an unlimited task is bounded by the release default ttl. Executor shutdown
/// drops the worker, wait and all.
///
/// The bound is exact (MIK-8202 P4a r4.1): each sleep is cut to what is left
/// of it, and expiry is judged before a recovered clock is accepted, so the
/// wait never runs a poll interval past the task's ttl.
// ponytail: polls on monotonic time and holds this worker's slot while the
// clock is unreadable; a clock-recovered signal would free it sooner.
pub(in crate::gateway::task_service::execution) async fn readable_now(
    store: &crate::gateway::task_service::store::TaskStore,
    id: &str,
    cancel_rx: &mut watch::Receiver<bool>,
) -> ClockWait {
    let mut since: Option<tokio::time::Instant> = None;
    loop {
        if *cancel_rx.borrow() {
            return ClockWait::Stopped;
        }
        let bound = store.clock_wait_bound(id);
        if let (Some(began), Some(bound)) = (since, bound)
            && began.elapsed() >= bound
        {
            tracing::warn!(task_id = %id, "the host clock stayed before 1970 for the task's ttl: the wait ends");
            return ClockWait::Expired;
        }
        if let Ok(at) = store.now() {
            return ClockWait::Read(at, u64::try_from(at.timestamp()).unwrap_or_default());
        }
        let began = match since {
            None => {
                let began = tokio::time::Instant::now();
                since = Some(began);
                // Once per wait: the operator learns why a worker is held.
                telemetry_metrics::counter!("mcp_task_clock_waits_total").increment(1);
                tracing::warn!(
                    task_id = %id,
                    "the host clock reads before 1970: this task waits for it, holding a task worker"
                );
                began
            }
            // The row left the store: nothing is left to wait for.
            Some(_) if bound.is_none() => return ClockWait::Stopped,
            Some(began) => began,
        };
        let left = bound.map_or(CLOCK_RETRY, |bound| bound.saturating_sub(began.elapsed()));
        // The cancel signal first, then the retry: a timeout polls its inner
        // future before its timer, as the old biased select did.
        // A dropped sender can no longer cancel: stop, as `dispatch` does. A
        // change (the loop re-reads the flag) or a due retry loops.
        if let Ok(Err(_)) = tokio::time::timeout(CLOCK_RETRY.min(left), cancel_rx.changed()).await {
            return ClockWait::Stopped;
        }
    }
}

/// [`readable_now`] where no [`Settling`] is at hand: an expired wait fails the
/// task here. `None` once the task is cancelled or failed.
pub(super) async fn readable_or_fail(
    executor: &TaskExecutor,
    (principal, id, _): (&str, &str, u64),
    cancel_rx: &mut watch::Receiver<bool>,
) -> Option<(chrono::DateTime<chrono::Utc>, u64)> {
    match readable_now(&executor.service.store, id, cancel_rx).await {
        ClockWait::Read(at, now) => Some((at, now)),
        ClockWait::Stopped => None,
        // Never through a settle that reads the clock: it would wait again
        // (MIK-8202 P4a r4, `settle_dated_last_known`).
        ClockWait::Expired => {
            let event = (
                TaskTransition::Fail(clock_expired()),
                crate::gateway::task_service::record::Provenance::default(),
            );
            let writes = crate::gateway::gateway_writes::WriteRecord::default();
            executor
                .settle_dated_last_known(principal, id, event, ErrorAuthor::Gateway, writes)
                .await;
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
/// unreadable for its bound; executor shutdown drops the wait. Each attempt
/// runs in a dispatch cell of its own, so a discarded one's refusal is not
/// the returned response's.
pub(super) async fn redeeming_dispatch(
    (state, owned, call, retry): (&LiveHost, &OwnedCallerContext, &TaskCall, &RetryFields),
    executor: &TaskExecutor,
    ids: (&str, &str, u64),
    cancel_rx: &mut watch::Receiver<bool>,
) -> Option<(JsonRpcResponse, Option<bool>)> {
    let store = &executor.service.store;
    loop {
        // A resume, or a state-only round, runs on the server the task
        // recorded, or is settled as the worker's refusal when a reload has
        // moved or removed that surfaced name since. Nothing awaits between
        // this check and the pin `dispatch` takes. A cancel is seen first, as
        // `dispatch` sees it.
        if *cancel_rx.borrow() {
            return None;
        }
        if !state
            .meta_mcp()
            .surfaced_target_holds(&call.tool, call.surfaced_server.as_ref())
        {
            let (principal, id, revision) = ids;
            settle_surfaced_refused(executor, principal, id, revision, cancel_rx).await;
            return None;
        }
        owned.dispatch_log().worker().arm(store);
        // Each attempt, a discarded one included, starts its round unrefused.
        owned.dispatch_log().reset_round();
        let (response, refused) =
            super::dispatched_in_cell(dispatch(state, owned, call, retry, cancel_rx)).await;
        let response = response?;
        if !owned.dispatch_log().worker().take_redemption_unreadable() {
            return Some((response, refused));
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
    /// A clock that stayed before 1970 for the task's ttl fails the task,
    /// dated at the record's own `last_updated_at` and never waiting again
    /// (MIK-8202 P4a r4: P2's Expired sites share the worker's fallback).
    pub(super) async fn settle_expired(&self) {
        let event = (TaskTransition::Fail(clock_expired()), self.provenance());
        let writes = crate::gateway::gateway_writes::WriteRecord::default();
        self.executor
            .settle_dated_last_known(self.principal, self.id, event, ErrorAuthor::Gateway, writes)
            .await;
        self.state.meta_mcp().commit_staged_relay(false);
    }

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
                self.settle_expired().await;
                return Resealed::Done;
            }
        };
        let continuation = self.state.meta_mcp().continuation();
        let Some(result) = withheld.seal(&continuation, now).await else {
            let abandoned = TaskTransition::Complete(super::abandoned_input_round());
            self.settle(abandoned, false, cancel_rx).await;
            return Resealed::Done;
        };
        let response = JsonRpcResponse::success(crate::protocol::RequestId::Number(0), result);
        // The slot is the worker's request scope's: handed off when the round
        // parks, given back with the scope otherwise (MIK-8176).
        let response = super::inspect_and_record(
            self.state,
            self.call,
            (self.principal, self.id),
            (response, None),
        )
        .await;
        Resealed::Sealed(Box::new(response), (at, now))
    }
}

#[cfg(test)]
#[path = "input_round_clock_tests.rs"]
mod tests;
