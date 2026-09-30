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

use chrono::Utc;
use serde_json::{Map, Value};
use tokio::sync::{OwnedSemaphorePermit, watch};

use super::observe::{Acceptance, Handoff};
use super::settlement::{
    DispatchSettlement, abandoned_input_round, classify_dispatch, interrupted_before_dispatch,
};
use super::worker::inspect_settled;
use super::{CommitStage, OwnedCallerContext, TaskCall, TaskExecutor, WriteOutcome};
use crate::gateway::router::AppState;
use crate::gateway::task_service::record::{InputRound, Target};
use crate::gateway::task_service::store::StoreError;
use crate::gateway::task_service::store::input::ProvideOutcome;
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
    state: &'a Arc<AppState>,
    owned: &'a OwnedCallerContext,
    call: &'a TaskCall,
    principal: &'a str,
    id: &'a str,
    revision: u64,
}

impl<'a> Settling<'a> {
    pub(super) const fn new(
        executor: &'a Arc<TaskExecutor>,
        state: &'a Arc<AppState>,
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
        loop {
            let round = match classify_dispatch(response) {
                DispatchSettlement::Complete(result) => {
                    return self.settle(TaskTransition::Complete(result)).await;
                }
                DispatchSettlement::Fail(error) => {
                    return self.settle(TaskTransition::Fail(error)).await;
                }
                DispatchSettlement::Input(round) => round,
            };
            if !round.requests.is_empty() {
                return self.park(round).await;
            }
            // ponytail: the counter is loop-local, not on the record: a client
            // round ends this worker, so a resumed worker starts at zero,
            // which is the reset the design asks for.
            state_only += 1;
            if state_only > STATE_ONLY_CEILING {
                return self
                    .settle(TaskTransition::Complete(abandoned_input_round()))
                    .await;
            }
            let retry = self.owned.continuation(round.request_state, None);
            let Some(next) = dispatch(self.state, self.owned, self.call, &retry, cancel_rx).await
            else {
                return;
            };
            response = inspect_settled(self.state, self.call, self.id, next);
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

    async fn settle(&self, event: TaskTransition) {
        self.executor
            .settle_cas_with(
                self.principal,
                self.id,
                self.revision,
                (event, self.plan_targets()),
            )
            .await;
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
    async fn park(&self, round: InputRequired) {
        if !self.park_targets().await {
            return self
                .settle(TaskTransition::Complete(abandoned_input_round()))
                .await;
        }
        let Ok(owner) = self.executor.service.owner(self.principal) else {
            return self
                .settle(TaskTransition::Complete(abandoned_input_round()))
                .await;
        };
        let stored = InputRound {
            request_state: round.request_state.clone(),
            tool: self.call.tool.clone(),
            arguments: self.call.arguments.clone(),
            accepted_inputs: Map::new(),
        };
        let parked = self
            .executor
            .service
            .store
            .require_input(
                owner.as_digest(),
                self.id,
                self.revision,
                round,
                stored,
                Utc::now(),
            )
            .await;
        match parked {
            Ok(committed) => {
                self.executor
                    .published(&WriteOutcome::Transitioned(committed), self.id);
                self.executor
                    .notify_observer(CommitStage::InputRequired, self.id)
                    .await;
            }
            // A semantic fault in a well-formed round (empty set, reused key,
            // non-object value): terminal, never a stuck `working` row.
            Err(StoreError::InvalidTransition) => {
                self.settle(TaskTransition::Fail(JsonRpcError {
                    code: -32603,
                    message: "the backend's input round is invalid".to_owned(),
                    data: None,
                }))
                .await;
            }
            // The continuation does not fit the record: today's abandoned result.
            Err(StoreError::Capacity) => {
                self.settle(TaskTransition::Complete(abandoned_input_round()))
                    .await;
            }
            // A cancel already moved the row; its commit is the answer.
            Err(StoreError::RevisionConflict | StoreError::NotFound) => {}
            // The round could not be written. This worker is the row's only
            // owner, so returning would leave it `working` with nobody to
            // finish it: settle the abandoned result instead.
            Err(error) => {
                tracing::warn!(task_id = %self.id, %error, "input round not committed");
                self.settle(TaskTransition::Complete(abandoned_input_round()))
                    .await;
            }
        }
    }
}

/// One cancellable dispatch through the invoke funnel, carrying `retry`.
async fn dispatch(
    state: &Arc<AppState>,
    owned: &OwnedCallerContext,
    call: &TaskCall,
    retry: &RetryFields,
    cancel_rx: &mut watch::Receiver<bool>,
) -> Option<JsonRpcResponse> {
    if *cancel_rx.borrow() {
        return None;
    }
    let authorizer = owned.authorizer().borrow(state);
    let caller = owned.dispatch_context_retrying(state, &authorizer, retry);
    let dispatched = state.meta_mcp.dispatch_below_gate_native_result(
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
    NotFound,
    Unavailable,
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
            Err(StoreError::NotFound) => return InputOutcome::NotFound,
            Err(_) => return InputOutcome::Unavailable,
        }
        let (handoff, cancel_rx) =
            match Handoff::accept_when_free(self, id, PRODUCE_SEAM_WAIT, waiting).await {
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
        tokio::spawn(async move {
            let workers = Arc::clone(&executor.workers);
            let provided = executor
                .service
                .store
                .provide_input(
                    &digest,
                    &id,
                    answers,
                    move || workers.try_acquire_owned().ok(),
                    Utc::now(),
                )
                .await;
            let outcome = match provided {
                Ok(ProvideOutcome::Partial(committed)) => {
                    executor.published(&WriteOutcome::Transitioned(committed), &id);
                    InputOutcome::Accepted
                }
                Ok(ProvideOutcome::PoolFull) => InputOutcome::PoolFull,
                Ok(ProvideOutcome::Resumed { task, round, slot }) => {
                    let revision = task.revision;
                    executor.published(&WriteOutcome::Transitioned(task), &id);
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
                Err(StoreError::InvalidTransition) => InputOutcome::NotOutstanding,
                Err(StoreError::Capacity) => InputOutcome::TooLarge,
                Err(StoreError::NotFound) => InputOutcome::NotFound,
                Err(_) => InputOutcome::Unavailable,
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
async fn resume(resume: Resume, mut cancel_rx: watch::Receiver<bool>) {
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
    let Some(state) = owned.state().upgrade() else {
        let event = TaskTransition::Complete(interrupted_before_dispatch());
        executor.settle_cas(&principal, &id, revision, event).await;
        return;
    };
    let call = TaskCall {
        tool: round.tool,
        arguments: round.arguments,
    };
    let retry = owned.continuation(
        round.request_state,
        Some(Value::Object(round.accepted_inputs)),
    );
    let Some(response) = dispatch(&state, &owned, &call, &retry, &mut cancel_rx).await else {
        return;
    };
    let response = inspect_settled(&state, &call, &id, response);
    Settling::new(&executor, &state, &owned, &call, &principal, &id, revision)
        .settle_or_ask(response, &mut cancel_rx)
        .await;
}
