// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The input round on `POST /mcp` (MIK-7311.LIFECYCLE.1, design §4).
//!
//! One continuation mechanism: a backend round is parked on the record with the
//! continuation the invoke funnel sealed into the interim result, and the
//! resume redeems that continuation through the same funnel a client retry
//! takes (`redeem_retry`). Nothing here talks to a backend directly.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};
use tokio::sync::{OwnedSemaphorePermit, watch};

use super::observe::{Acceptance, Handoff};
use super::settlement::{
    DispatchSettlement, abandoned_input_round, classify_dispatch, interrupted_before_dispatch,
};
use super::worker::inspect_settled;
use super::{CommitStage, OwnedCallerContext, TaskCall, TaskExecutor};
use crate::gateway::task_service::host::LiveHost;
use crate::gateway::task_service::record::{CONTINUATION_DEADLINE_MARGIN_SECS, InputRound, Target};
use crate::gateway::task_service::store::StoreError;
use crate::gateway::task_service::store::input::{ProvideOutcome, RoundClosed};
use crate::protocol::mrtr::{InputRequired, RetryFields};
use crate::protocol::tasks::{TaskStatus, TaskTransition};
use crate::protocol::{JsonRpcError, JsonRpcResponse, RequestId};

/// Consecutive state-only rounds one worker resumes before it gives up. A
/// fixed ceiling that stops a backend looping the gateway forever.
const STATE_ONLY_CEILING: usize = 4;

/// How long an update waits for the producing worker to release the task it
/// has just parked.
const PRODUCE_SEAM_WAIT: Duration = Duration::from_secs(1);

/// The worker's view of one owned task while it settles a response.
pub(super) struct Settling<'a> {
    executor: &'a Arc<TaskExecutor>,
    state: &'a LiveHost,
    owned: &'a OwnedCallerContext,
    call: &'a TaskCall,
    principal: &'a str,
    id: &'a str,
    revision: u64,
}

impl<'a> Settling<'a> {
    pub(super) const fn new(
        executor: &'a Arc<TaskExecutor>,
        state: &'a LiveHost,
        owned: &'a OwnedCallerContext,
        call: &'a TaskCall,
        principal: &'a str,
        id: &'a str,
        revision: u64,
    ) -> Self {
        Self {
            executor,
            state,
            owned,
            call,
            principal,
            id,
            revision,
        }
    }

    /// Settle `response`, resume a state-only round in place, or park a round
    /// that asks the client. The caller owns the handoff and the permit and
    /// drops both when this returns, so a parked row has no owner.
    pub(super) async fn settle_or_ask(
        &self,
        mut response: JsonRpcResponse,
        cancel_rx: &mut watch::Receiver<bool>,
    ) {
        let mut state_only = 0;
        // Where the round being settled began in this worker's write record:
        // the first answer's notes are the whole record; a state-only round's
        // are dropped with it (MIK-7993 r2a), so only the answer stored is
        // described.
        let mut round_mark: Option<crate::gateway::gateway_writes::Mark> = None;
        loop {
            let round = match classify_dispatch(response) {
                DispatchSettlement::Complete(result) => {
                    let writes = round_mark.map_or_else(
                        crate::gateway::gateway_writes::recorded,
                        crate::gateway::gateway_writes::snapshot_since,
                    );
                    return self
                        .settle_with(TaskTransition::Complete(result), true, writes)
                        .await;
                }
                DispatchSettlement::Fail(error) => {
                    return self.settle(TaskTransition::Fail(error), false).await;
                }
                // The gateway's own sentence: nothing the backend said was delivered.
                DispatchSettlement::Abandoned => {
                    let abandoned = TaskTransition::Complete(abandoned_input_round());
                    return self.settle(abandoned, false).await;
                }
                DispatchSettlement::Input(round) => round,
            };
            if !round.requests.is_empty() {
                return self.park(round, cancel_rx).await;
            }
            // ponytail: the counter is loop-local, not on the record: a client
            // round ends this worker, so a resumed worker starts at zero,
            // which is the reset the design asks for.
            state_only += 1;
            if state_only > STATE_ONLY_CEILING {
                return self
                    .settle(TaskTransition::Complete(abandoned_input_round()), false)
                    .await;
            }
            // A state-only round reached nobody: what it staged was not delivered.
            crate::gateway::meta_mcp::invoke::relay::discard_staged();
            let retry = self.owned.continuation(round.request_state, None);
            round_mark = Some(crate::gateway::gateway_writes::mark());
            let Some(next) = dispatch(self.state, self.owned, self.call, &retry, cancel_rx).await
            else {
                return;
            };
            response = inspect_settled(self.state, self.call, self.id, next);
            self.state
                .meta_mcp()
                .release_unsent_hold(&mut response)
                .await; // MIK-8131
        }
    }

    /// The calls a plan actually dispatched, for the settlement to commit with
    /// its outcome. `None` for a call whose one target was recorded at creation.
    fn plan_targets(&self) -> Option<Vec<Target>> {
        matches!(
            self.call.tool.as_str(),
            "gateway_execute" | "gateway_run_playbook"
        )
        .then(|| {
            self.owned
                .dispatch_log()
                .snapshot()
                .into_iter()
                .map(|(server, tool)| Target { server, tool })
                .collect()
        })
    }

    /// Settle `event`. Staged relay receipts are recorded only when it is
    /// the dispatched result (`dispatched`) and the store kept it as such.
    async fn settle(&self, event: TaskTransition, dispatched: bool) {
        self.settle_with(
            event,
            dispatched,
            crate::gateway::gateway_writes::WriteRecord::default(),
        )
        .await;
    }

    /// [`Self::settle`], storing `writes`: the members of a dispatched
    /// result the gateway wrote (MIK-7993).
    async fn settle_with(
        &self,
        event: TaskTransition,
        dispatched: bool,
        writes: crate::gateway::gateway_writes::WriteRecord,
    ) {
        let stored = self
            .executor
            .settle_cas_with(
                self.principal,
                self.id,
                self.revision,
                (event, self.plan_targets()),
                writes,
            )
            .await;
        self.state
            .meta_mcp()
            .commit_staged_relay(dispatched && stored);
    }

    /// Record a parked plan's calls so far; the resume's log starts empty.
    /// `false` means they are NOT durable, and the round must not be parked.
    async fn park_targets(&self) -> bool {
        let Some(targets) = self.plan_targets() else {
            return true;
        };
        let Ok(owner) = self.executor.service.owner(self.principal) else {
            return false;
        };
        let stored = self
            .executor
            .service
            .store
            .add_targets(owner.as_digest(), self.id, self.revision, targets)
            .await;
        // A row a cancel already moved is not parked either way.
        matches!(stored, Ok(()) | Err(StoreError::RevisionConflict))
    }

    /// Commit `input_required` with the continuation, then release: the worker
    /// returns and the row waits with no owner.
    async fn park(&self, round: InputRequired, cancel_rx: &mut watch::Receiver<bool>) {
        if !self.park_targets().await {
            return self
                .settle(TaskTransition::Complete(abandoned_input_round()), false)
                .await;
        }
        let Ok(owner) = self.executor.service.owner(self.principal) else {
            return self
                .settle(TaskTransition::Complete(abandoned_input_round()), false)
                .await;
        };
        // The continuation the resume will redeem dies at its own deadline;
        // a round that could only fail is settled now, never parked.
        let store = &self.executor.service.store;
        let Some((at, now)) = readable_now(store, cancel_rx).await else {
            return;
        };
        let continuation = self.state.meta_mcp().continuation();
        let Ok(continuation_deadline) =
            round_deadline(continuation.keyring(), round.request_state.as_deref(), now)
        else {
            return self
                .settle(TaskTransition::Complete(abandoned_input_round()), false)
                .await;
        };
        let stored = InputRound {
            request_state: round.request_state.clone(),
            tool: self.call.tool.clone(),
            arguments: self.call.arguments.clone(),
            accepted_inputs: Map::new(),
            continuation_deadline,
        };
        let parked = store
            .require_input(owner.as_digest(), self.id, self.revision, round, stored, at)
            .await;
        match parked {
            Ok(committed) => {
                self.executor.published(&committed, self.id);
                self.executor
                    .notify_observer(CommitStage::InputRequired, self.id)
                    .await;
            }
            // A semantic fault in a well-formed round (empty set, reused key,
            // non-object value): terminal, never a stuck `working` row.
            Err(StoreError::InvalidTransition) => {
                self.settle(
                    TaskTransition::Fail(JsonRpcError {
                        code: -32603,
                        message: "the backend's input round is invalid".to_owned(),
                        data: None,
                    }),
                    false,
                )
                .await;
            }
            // The continuation does not fit the record: today's abandoned result.
            Err(StoreError::Capacity) => {
                self.settle(TaskTransition::Complete(abandoned_input_round()), false)
                    .await;
            }
            // A cancel already moved the row; its commit is the answer.
            Err(StoreError::RevisionConflict | StoreError::NotFound) => {}
            // The round could not be written. This worker is the row's only
            // owner, so returning would leave it `working` with nobody to
            // finish it: settle the abandoned result instead.
            Err(error) => {
                tracing::warn!(task_id = %self.id, %error, "input round not committed");
                self.settle(TaskTransition::Complete(abandoned_input_round()), false)
                    .await;
            }
        }
    }
}

/// One cancellable dispatch through the invoke funnel, carrying `retry`.
async fn dispatch(
    state: &LiveHost,
    owned: &OwnedCallerContext,
    call: &TaskCall,
    retry: &RetryFields,
    cancel_rx: &mut watch::Receiver<bool>,
) -> Option<JsonRpcResponse> {
    if *cancel_rx.borrow() {
        return None;
    }
    let authorizer = state.authorizer(owned.authorizer());
    let _key_hold = owned.hold_caller_key(state);
    let caller = owned.dispatch_context_retrying(state, &authorizer, retry);
    let dispatched = state.meta_mcp().dispatch_below_gate_native_result(
        RequestId::Number(0),
        &call.tool,
        call.arguments.clone(),
        owned.session_id(),
        &caller,
    );
    let dispatched = crate::gateway::meta_mcp::dispatch_log::with_dispatch_log(
        Arc::clone(owned.dispatch_log()),
        dispatched,
    );
    tokio::select! {
        biased;
        _ = cancel_rx.changed() => None,
        response = dispatched => Some(response),
    }
}

/// What a `tasks/update` carrying answers came to.
pub(crate) enum InputOutcome {
    /// Accepted: a partial set was stored, or the set completed and the task
    /// is `working` again under a resume worker.
    Accepted,
    /// No round is outstanding for these keys, or another update won.
    NotOutstanding,
    /// The answers would push the record past its byte cap. Nothing written.
    TooLarge,
    /// The producing worker still held the task when the wait ran out.
    Busy,
    /// No worker is free; the round stays open and the answers unapplied.
    PoolFull,
    /// The round closed at its continuation deadline or the task's TTL.
    Closed(RoundClosed),
    NotFound,
    Unavailable,
}

/// What a store refusal means to the caller of `provide_input`: one mapping,
/// for the read that precedes the write and the write itself.
fn input_outcome_of(error: StoreError) -> InputOutcome {
    match error {
        StoreError::InvalidTransition => InputOutcome::NotOutstanding,
        StoreError::Capacity => InputOutcome::TooLarge,
        StoreError::NotFound => InputOutcome::NotFound,
        _ => InputOutcome::Unavailable,
    }
}

impl TaskExecutor {
    /// Apply answers to an open round and, when they complete it, resume the
    /// call as the caller of THIS update (`caller`).
    ///
    /// Order: exclusive handoff, then one store write that takes the permit
    /// and moves the row to `working`, then the spawn. The handoff exists
    /// before the write, so a cancel racing it always finds an owner to signal.
    pub(crate) async fn provide_input(
        self: &Arc<Self>,
        caller: OwnedCallerContext,
        principal: &str,
        id: &str,
        answers: Map<String, Value>,
    ) -> InputOutcome {
        let Ok(owner) = self.service.owner(principal) else {
            return InputOutcome::NotFound;
        };
        let store = &self.service.store;
        let waiting = || {
            store
                .get(owner.as_digest(), id)
                .is_ok_and(|current| current.task.status() == TaskStatus::InputRequired)
        };
        match store.get(owner.as_digest(), id) {
            Ok(current) if current.task.status() == TaskStatus::InputRequired => {}
            Ok(_) => return InputOutcome::NotOutstanding,
            Err(error) => return input_outcome_of(error),
        }
        // How long an update waits for the current owner: the produce seam's
        // second, or what a test stretched it to.
        #[cfg(test)]
        let wait = self
            .produce_seam_wait
            .get()
            .copied()
            .unwrap_or(PRODUCE_SEAM_WAIT);
        #[cfg(not(test))]
        let wait = PRODUCE_SEAM_WAIT;
        let (handoff, cancel_rx) = match Handoff::accept_when_free(self, id, wait, waiting).await {
            Acceptance::Owned(handoff, cancel_rx) => (handoff, cancel_rx),
            Acceptance::Moved => return InputOutcome::NotOutstanding,
            Acceptance::Busy => return InputOutcome::Busy,
        };
        // The write and the spawn run in one task that owns the handoff, the
        // permit and the cancel receiver, as `commit_and_run` does at create.
        // A dropped request future cannot then leave a committed `working`
        // row with no worker: the task finishes the write, and on a resume it
        // becomes the resume worker itself. The request only waits for the
        // outcome, which arrives after the write commits.
        let (tx, rx) = tokio::sync::oneshot::channel();
        let executor = Arc::clone(self);
        let (digest, id, principal) = (
            owner.as_digest().to_owned(),
            id.to_owned(),
            principal.to_owned(),
        );
        self.spawn_worker(async move {
            let workers = Arc::clone(&executor.workers);
            // An answer stamped on a clock before 1970 is refused for now, as
            // the store refuses it, and the round stays open (MIK-8202).
            let store = &executor.service.store;
            let stamp = store.now();
            let provided = match stamp {
                Ok(at) => {
                    store
                        .provide_input(&digest, &id, answers, move || workers.try_acquire_owned().ok(), at)
                        .await
                }
                Err(_) => Err(StoreError::Unavailable),
            };
            let outcome = match provided {
                Ok(ProvideOutcome::Partial(committed)) => {
                    executor.published(&committed, &id);
                    InputOutcome::Accepted
                }
                Ok(ProvideOutcome::PoolFull) => InputOutcome::PoolFull,
                Ok(ProvideOutcome::Closed(closed)) => {
                    // Settle it now rather than at the next sweep. Either way the
                    // round is closed to answers: every later one is refused the
                    // same way, and the sweep retries a close that fails here.
                    let settled = async {
                        // Closed as of the time the answer was judged at.
                        let Ok(at) = stamp else {
                            return Ok(());
                        };
                        let current = executor
                            .service
                            .store
                            .get(&digest, &id)
                            .map_err(|_| super::CommitFailure::RevisionConflict)?;
                        executor
                            .close_round(&digest, &id, current.revision, closed.reason(), at)
                            .await
                    }
                    .await;
                    if let Err(super::CommitFailure::Service(error)) = settled {
                        tracing::warn!(task_id = %id, ?error, "closed input round not settled yet; the sweep retries");
                    }
                    InputOutcome::Closed(closed)
                }
                Ok(ProvideOutcome::Resumed { task, round, slot }) => {
                    let revision = task.revision;
                    executor.published(&task, &id);
                    // The row now reads `working` and this task keeps the
                    // handoff for the resume: a losing update parked on it
                    // re-reads the row now, not at its deadline.
                    handoff.row_moved();
                    let _ = tx.send(InputOutcome::Accepted);
                    resume(
                        Resume {
                            handoff,
                            slot,
                            owned: caller,
                            principal,
                            id,
                            revision,
                            round,
                        },
                        cancel_rx,
                    )
                    .await;
                    return;
                }
                Err(error) => input_outcome_of(error),
            };
            // Not a resume: the handoff and cancel receiver go with this task.
            drop((handoff, cancel_rx));
            let _ = tx.send(outcome);
        });
        rx.await.unwrap_or(InputOutcome::Unavailable)
    }
}

/// Everything a resume worker owns.
struct Resume {
    handoff: Handoff,
    slot: OwnedSemaphorePermit,
    owned: OwnedCallerContext,
    principal: String,
    id: String,
    revision: u64,
    round: InputRound,
}

/// The same call again, with the sealed continuation and every accepted
/// answer, through the same funnel and the same settlement as the first.
async fn resume(resume: Resume, cancel_rx: watch::Receiver<bool>) {
    // Every early exit below is a `?` or a returned expression: `None` is "the
    // round was settled or closed here, nothing left to run".
    let _ = resume_flow(resume, cancel_rx).await;
}

/// A host that is gone settles the task interrupted: the call cannot run.
async fn settle_interrupted(
    executor: &TaskExecutor,
    (principal, id, revision): (&str, &str, u64),
) -> Option<()> {
    let event = TaskTransition::Complete(interrupted_before_dispatch());
    executor.settle_cas(principal, id, revision, event).await;
    None
}

async fn resume_flow(resume: Resume, mut cancel_rx: watch::Receiver<bool>) -> Option<()> {
    let Resume {
        handoff,
        slot,
        owned,
        principal,
        id,
        revision,
        round,
    } = resume;
    let executor = Arc::clone(handoff.executor());
    // Dropped in reverse: the permit goes back before the handoff, as on the
    // create path.
    let _handoff = handoff;
    let _slot = slot;
    let ids = (principal.as_str(), id.as_str(), revision);
    let Some(state) = owned.host().upgrade() else {
        return settle_interrupted(&executor, ids).await;
    };
    // An answer taken in time can still reach dispatch late; redeeming then
    // could only fail, so the round is closed as the sweep would close it.
    let deadline = round.continuation_deadline;
    let (at, now) = readable_now(&executor.service.store, &mut cancel_rx).await?;
    let reached = deadline.is_some_and(|d| now >= d);
    executor
        .proceed_unless_late(ids, deadline, reached, at)
        .await?;
    let call = TaskCall {
        tool: round.tool,
        arguments: round.arguments,
    };
    let retry = owned.continuation(
        round.request_state,
        Some(Value::Object(round.accepted_inputs)),
    );
    let response = dispatch(&state, &owned, &call, &retry, &mut cancel_rx).await?;
    // Preparation inside the funnel can outlast the margin. A continuation
    // refused once its envelope has expired was refused for expiry: close the
    // round with that reason rather than fail the task.
    let (at, now) = readable_now(&executor.service.store, &mut cancel_rx).await?;
    let expired = deadline.is_some_and(|d| rejected_after_expiry(&response, d, now));
    executor
        .proceed_unless_late(ids, deadline, expired, at)
        .await?;
    let mut response = inspect_settled(&state, &call, &id, response);
    state.meta_mcp().release_unsent_hold(&mut response).await; // MIK-8131
    Settling::new(&executor, &state, &owned, &call, &principal, &id, revision)
        .settle_or_ask(response, &mut cancel_rx)
        .await;
    Some(())
}

/// When a parked round stops taking answers (#2429): the sealed
/// continuation's own expiry, less the margin. `Ok(None)` when no
/// continuation is stored; an error when it cannot be opened or is already
/// due, since such a round could only ever fail.
pub(super) fn round_deadline(
    keyring: &crate::protocol::continuation::Keyring,
    request_state: Option<&str>,
    now: u64,
) -> Result<Option<u64>, crate::protocol::continuation::ContinuationError> {
    let Some(token) = request_state else {
        return Ok(None);
    };
    let deadline = keyring
        .open(token, now)?
        .expires_at
        .saturating_sub(CONTINUATION_DEADLINE_MARGIN_SECS);
    if now >= deadline {
        return Err(crate::protocol::continuation::ContinuationError::Expired);
    }
    Ok(Some(deadline))
}

/// Whether `response` is the funnel refusing the continuation after the
/// envelope itself expired (the stored deadline plus the margin).
///
/// The funnel answers every refusal with one message, but past the expiry
/// the refusal of this gateway's own stored envelope is, in practice, the
/// expiry: `redeem_retry` opens the envelope before any other check, `open`
/// tests the deadline straight after authentication, and the hold checked
/// next dies with the envelope. `>` as `open` uses it.
// ponytail: an envelope opened just before expiry and then refused by the
// spent-ledger's capacity bound just after reads as expiry, settling
// `cancelled` rather than `failed`. A typed refusal through the funnel would
// separate them; add it if that window is ever observed.
fn rejected_after_expiry(response: &JsonRpcResponse, deadline: u64, now: u64) -> bool {
    let expired = crate::protocol::continuation::ContinuationError::Expired;
    now > deadline.saturating_add(CONTINUATION_DEADLINE_MARGIN_SECS)
        && response
            .error
            .as_ref()
            .is_some_and(|error| error.code == -32602 && error.message == expired.client_message())
}

/// How often a worker reads a clock that read before 1970 again.
const CLOCK_RETRY: Duration = if cfg!(test) {
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
async fn readable_now(
    store: &crate::gateway::task_service::store::TaskStore,
    cancel_rx: &mut watch::Receiver<bool>,
) -> Option<(chrono::DateTime<chrono::Utc>, u64)> {
    loop {
        if *cancel_rx.borrow() {
            return None;
        }
        if let Ok(at) = store.now() {
            return Some((at, u64::try_from(at.timestamp()).unwrap_or_default()));
        }
        tokio::select! {
            biased;
            // A dropped sender can no longer cancel: stop, as `dispatch` does.
            changed = cancel_rx.changed() => changed.ok()?,
            () = tokio::time::sleep(CLOCK_RETRY) => {}
        }
    }
}

impl TaskExecutor {
    /// Close the round as the sweep would when `late` and it has a deadline:
    /// the one place both late checks of a resume close it. `Some` means carry
    /// on; `None` means the round was closed here.
    async fn proceed_unless_late(
        &self,
        (principal, id, revision): (&str, &str, u64),
        deadline: Option<u64>,
        late: bool,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Option<()> {
        let Some(deadline) = deadline.filter(|_| late) else {
            return Some(());
        };
        self.close_late_round(principal, id, revision, deadline, at)
            .await;
        None
    }

    /// Close a resumed round that met its deadline, stamped at the time the
    /// deadline was judged at (MIK-8202: a second read could find a clock
    /// stepped before 1970). A write that fails for any reason but a moved
    /// row is tried once more, reason and all.
    // ponytail: two attempts, then the row waits for restart recovery (which
    // settles it interrupted), as every other settlement write does.
    async fn close_late_round(
        &self,
        principal: &str,
        id: &str,
        revision: u64,
        deadline: u64,
        at: chrono::DateTime<chrono::Utc>,
    ) {
        let Ok(owner) = self.service.owner(principal) else {
            return;
        };
        let reason = RoundClosed::Continuation(deadline).reason();
        match self
            .close_round(owner.as_digest(), id, revision, reason, at)
            .await
        {
            Ok(()) | Err(super::CommitFailure::RevisionConflict) => {}
            Err(_) => {
                let reason = RoundClosed::Continuation(deadline).reason();
                if self
                    .close_round(owner.as_digest(), id, revision, reason, at)
                    .await
                    .is_err()
                {
                    tracing::warn!(task_id = %id, "a late input round was not closed");
                }
            }
        }
    }

    /// Cancel a task with `reason` in one store write, then publish it (#2429).
    pub(super) async fn close_round(
        &self,
        owner_digest: &str,
        id: &str,
        revision: u64,
        reason: String,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), super::CommitFailure> {
        match self
            .service
            .store
            .close_round(owner_digest, id, revision, reason, at)
            .await
        {
            Ok(committed) => {
                self.published(&committed, id);
                self.notify_observer(CommitStage::Transitioned, id).await;
                Ok(())
            }
            Err(StoreError::RevisionConflict) => Err(super::CommitFailure::RevisionConflict),
            Err(StoreError::NotFound) => Err(super::CommitFailure::Service(
                crate::gateway::task_service::ServiceError::NotFound,
            )),
            Err(_) => Err(super::CommitFailure::Service(
                crate::gateway::task_service::ServiceError::Unavailable,
            )),
        }
    }
}

#[cfg(test)]
#[path = "input_round_deadline_tests.rs"]
mod deadline_tests;

#[cfg(test)]
mod mapping_tests {
    use super::{InputOutcome, StoreError, input_outcome_of};

    /// Each store refusal means one thing to the caller of `provide_input`,
    /// whether the read or the write raised it.
    #[test]
    fn a_store_refusal_maps_to_one_input_outcome() {
        assert!(matches!(
            input_outcome_of(StoreError::InvalidTransition),
            InputOutcome::NotOutstanding
        ));
        assert!(matches!(
            input_outcome_of(StoreError::Capacity),
            InputOutcome::TooLarge
        ));
        assert!(matches!(
            input_outcome_of(StoreError::NotFound),
            InputOutcome::NotFound
        ));
        assert!(matches!(
            input_outcome_of(StoreError::Unavailable),
            InputOutcome::Unavailable
        ));
    }
}

#[cfg(test)]
#[path = "input_round_exit_tests.rs"]
mod exit_tests;
