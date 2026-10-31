// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The input round on `POST /mcp` (MIK-7311.LIFECYCLE.1, design §4).
//!
//! One continuation mechanism: a backend round is parked on the record with the
//! continuation the invoke funnel sealed into the interim result, and the
//! resume redeems that continuation through the same funnel a client retry
//! takes (`redeem_retry`). Nothing here talks to a backend directly.

use crate::error::rpc_codes::{INTERNAL_ERROR, INVALID_PARAMS};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};
use tokio::sync::{OwnedSemaphorePermit, watch};

use super::observe::{Acceptance, Handoff};
use super::settlement::{
    DispatchSettlement, abandoned_input_round, classify_dispatch, interrupted_before_dispatch,
};
use super::worker::{dispatched_in_cell, inspect_and_record, settle_surfaced_refused};
use super::{CommitStage, OwnedCallerContext, TaskCall, TaskExecutor};
use crate::gateway::task_service::host::LiveHost;
use crate::gateway::task_service::record::{CONTINUATION_DEADLINE_MARGIN_SECS, InputRound};
use crate::gateway::task_service::store::StoreError;
use crate::gateway::task_service::store::input::{ProvideOutcome, RoundClosed};
use crate::protocol::mrtr::{InputRequired, RetryFields};
use crate::protocol::tasks::{TaskStatus, TaskTransition};
use crate::protocol::{JsonRpcError, JsonRpcResponse, RequestId};

#[path = "input_round_clock.rs"]
mod clock;
#[path = "input_round_update.rs"]
mod update;
// MIK-8407: what a settle and a park record about how an outcome was produced.
mod provenance;
pub(super) use clock::{ClockWait, readable_now};
use clock::{Resealed, readable_or_fail, redeeming_dispatch};

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
            // MIK-8202 AC12: a round the funnel could not date is sealed here.
            let mut minted_at = None;
            match self.reseal_withheld(cancel_rx).await {
                Resealed::Nothing => {}
                Resealed::Sealed(sealed, at) => {
                    response = *sealed;
                    minted_at = Some(at);
                }
                Resealed::Done => return,
            }
            // One worker seal point (MIK-8398 C1e): the first dispatch, a
            // resume, and every state-only re-dispatch pass through here once.
            if let Some(result) = response.result.as_mut() {
                // MIK-8398 C1g: the stored result is delivered through the
                // task wire's cacheScope clamp, so it is clamped before the
                // seal. Step seals take no clamp: a step result sits inside
                // `content[0].text`, which the wire never clamps.
                crate::protocol::cacheable::clamp_delivered_scope(result);
                self.state.meta_mcp().seal_public_provenance(result);
            }
            let round = match classify_dispatch(response) {
                DispatchSettlement::Complete(result) => {
                    let writes = round_mark.map_or_else(
                        crate::gateway::gateway_writes::recorded,
                        crate::gateway::gateway_writes::snapshot_since,
                    );
                    return self
                        .settle_with(TaskTransition::Complete(result), true, writes, cancel_rx)
                        .await;
                }
                DispatchSettlement::Fail(error) => {
                    return self
                        .settle(TaskTransition::Fail(error), false, cancel_rx)
                        .await;
                }
                // The gateway's own sentence: nothing the backend said was delivered.
                DispatchSettlement::Abandoned => {
                    let abandoned = TaskTransition::Complete(abandoned_input_round());
                    return self.settle(abandoned, false, cancel_rx).await;
                }
                DispatchSettlement::Input(round) => round,
            };
            if !round.requests.is_empty() {
                return self.park(round, minted_at, cancel_rx).await;
            }
            // ponytail: the counter is loop-local, not on the record: a client
            // round ends this worker, so a resumed worker starts at zero,
            // which is the reset the design asks for.
            state_only += 1;
            if state_only > STATE_ONLY_CEILING {
                return self
                    .settle(
                        TaskTransition::Complete(abandoned_input_round()),
                        false,
                        cancel_rx,
                    )
                    .await;
            }
            // A state-only round reached nobody: what it staged was not delivered.
            crate::gateway::meta_mcp::invoke::relay::discard_staged();
            let retry = self.owned.continuation(round.request_state, None);
            round_mark = Some(crate::gateway::gateway_writes::mark());
            let Some(next) = redeeming_dispatch(
                (self.state, self.owned, self.call, &retry),
                self.executor,
                (self.principal, self.id, self.revision),
                cancel_rx,
            )
            .await
            else {
                return;
            };
            response =
                inspect_and_record(self.state, self.call, (self.principal, self.id), next).await;
        }
    }

    /// Settle `event`. Staged relay receipts are recorded only when it is
    /// the dispatched result (`dispatched`) and the store kept it as such.
    async fn settle(
        &self,
        event: TaskTransition,
        dispatched: bool,
        cancel_rx: &mut watch::Receiver<bool>,
    ) {
        let writes = crate::gateway::gateway_writes::WriteRecord::default();
        self.settle_with(event, dispatched, writes, cancel_rx).await;
    }

    /// [`Self::settle`], storing `writes`: the members of a dispatched
    /// result the gateway wrote (MIK-7993).
    async fn settle_with(
        &self,
        event: TaskTransition,
        dispatched: bool,
        writes: crate::gateway::gateway_writes::WriteRecord,
        cancel_rx: &mut watch::Receiver<bool>,
    ) {
        let ids = (self.principal, self.id, self.revision);
        let outcome = (event, self.provenance());
        let stored = self
            .executor
            .settle_cas_with(ids, outcome, writes, cancel_rx)
            .await;
        // `MIK-8408` E1: the settled row's own key, read back because a
        // lost compare-and-set settles at a later revision than this
        // worker read (the settle API returns only whether backend
        // output was stored, never the settled revision). Only with
        // relay detection on: the detection-off path does no extra
        // store read. The re-read is safe against a concurrent
        // cancel/delete/resume: the row just settled is terminal, the
        // first terminal commit wins and no later transition moves it,
        // so its revision cannot advance under different content (an
        // expiry removal only makes the read fail, capturing nothing).
        if dispatched
            && stored
            && self.state.meta_mcp().relay_active()
            && let Ok(settled) = self.executor.service.get(self.principal, self.id)
        {
            crate::gateway::meta_mcp::invoke::relay::note_task_capture(
                self.id.to_owned(),
                settled.revision,
                settled.task.ttl_ms(),
            );
        }
        self.state
            .meta_mcp()
            .commit_staged_relay(dispatched && stored);
    }

    /// Commit `input_required` with the continuation, then release: the worker
    /// returns and the row waits with no owner.
    async fn park(
        &self,
        round: InputRequired,
        minted_at: Option<(chrono::DateTime<chrono::Utc>, u64)>,
        cancel_rx: &mut watch::Receiver<bool>,
    ) {
        // The owner is resolved once, by the write that makes the round's
        // calls and bindings durable; a round that cannot record them is
        // settled now, never parked.
        let Some(owner) = self.park_targets().await else {
            return self
                .settle(
                    TaskTransition::Complete(abandoned_input_round()),
                    false,
                    cancel_rx,
                )
                .await;
        };
        // The continuation the resume will redeem dies at its own deadline;
        // a round that could only fail is settled now, never parked.
        let store = &self.executor.service.store;
        // A round sealed after a wait parks at the very time it was sealed at.
        let (at, now) = match minted_at {
            Some(read) => read,
            None => match readable_now(store, self.id, cancel_rx).await {
                ClockWait::Read(at, now) => (at, now),
                ClockWait::Stopped => return,
                ClockWait::Expired => return self.settle_expired().await,
            },
        };
        let continuation = self.state.meta_mcp().continuation();
        let Ok(continuation_deadline) =
            round_deadline(continuation.keyring(), round.request_state.as_deref(), now)
        else {
            return self
                .settle(
                    TaskTransition::Complete(abandoned_input_round()),
                    false,
                    cancel_rx,
                )
                .await;
        };
        let stored = InputRound {
            request_state: round.request_state.clone(),
            tool: self.call.tool.clone(),
            arguments: self.call.arguments.clone(),
            accepted_inputs: Map::new(),
            continuation_deadline,
            surfaced_server: self.call.surfaced_server.clone(),
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
                        code: INTERNAL_ERROR,
                        message: "the backend's input round is invalid".to_owned(),
                        data: None,
                    }),
                    false,
                    cancel_rx,
                )
                .await;
            }
            // The continuation does not fit the record: today's abandoned result.
            Err(StoreError::Capacity) => {
                self.settle(
                    TaskTransition::Complete(abandoned_input_round()),
                    false,
                    cancel_rx,
                )
                .await;
            }
            // A cancel already moved the row; its commit is the answer.
            Err(StoreError::RevisionConflict | StoreError::NotFound) => {}
            // The round could not be written. This worker is the row's only
            // owner, so returning would leave it `working` with nobody to
            // finish it: settle the abandoned result instead.
            Err(error) => {
                // Bound to a local: a field access on the head line cannot be
                // graded as run (MIK-7725).
                let task_id = self.id;
                tracing::warn!(task_id = %task_id, %error, "input round not committed");
                self.settle(
                    TaskTransition::Complete(abandoned_input_round()),
                    false,
                    cancel_rx,
                )
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
    let generation = state.generation();
    let authorizer = state.authorizer(owned.authorizer(), &generation);
    let _key_hold = owned.hold_caller_key(state);
    let caller = owned.dispatch_context_retrying(state, &authorizer, retry);
    // `redeeming_dispatch` has checked the surfaced target holds. The pin
    // covers the readmission as well as the dispatch.
    let meta = state.meta_mcp();
    let recorded = call.surfaced_server.as_ref();
    // The round judges hiding as its caller, live, readmission included.
    let round = meta.with_surfaced_pin(&call.tool, recorded, async {
        let (arguments, judged) = match state
            .readmit(call, &caller, (owned.session_id(), &generation))
            .await
        {
            Ok(readmitted) => readmitted,
            Err(refused) => return Some(*refused),
        };
        let dispatched = meta.dispatch_below_gate_native_result(
            RequestId::Number(0),
            &call.tool,
            arguments,
            owned.session_id(),
            &caller,
        );
        let dispatched = crate::gateway::meta_mcp::dispatch_log::with_dispatch_log(
            Arc::clone(owned.dispatch_log()),
            // Boxed: `with_judged` holds the whole dispatch inline, past the
            // size this block may carry on the stack (`large_futures`).
            Box::pin(crate::gateway::meta_mcp::visible::memo::with_judged(
                judged, dispatched,
            )),
        );
        tokio::select! {
            biased;
            _ = cancel_rx.changed() => None,
            response = dispatched => Some(response),
        }
    });
    state.as_caller(owned, round).await
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
    /// MIK-8204: under `FailClosed` the resuming request's grant decisions
    /// could not be appended, so no resume worker was spawned (-32005).
    AuditUnavailable,
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
    // One minted-receipt scope for the resume's dispatch and its settle
    // (MIK-8398 C1d), boxed as the request entry points are.
    let _ = crate::gateway::meta_mcp::invoke::with_minted_receipts(Box::pin(resume_flow(
        resume, cancel_rx,
    )))
    .await;
}

/// A host that is gone settles the task interrupted: the call cannot run.
async fn settle_interrupted(
    executor: &TaskExecutor,
    (principal, id, revision): (&str, &str, u64),
    cancel_rx: &mut watch::Receiver<bool>,
) -> Option<()> {
    let event = TaskTransition::Complete(interrupted_before_dispatch());
    executor
        .settle_cas(principal, id, revision, event, cancel_rx)
        .await;
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
        return settle_interrupted(&executor, ids, &mut cancel_rx).await;
    };
    // An answer taken in time can still reach dispatch late; redeeming then
    // could only fail, so the round is closed as the sweep would close it.
    let deadline = round.continuation_deadline;
    let (at, now) = readable_or_fail(&executor, ids, &mut cancel_rx).await?;
    let reached = deadline.is_some_and(|d| now >= d);
    executor
        .proceed_unless_late(ids, deadline, reached, at)
        .await?;
    let call = TaskCall {
        tool: round.tool,
        arguments: round.arguments,
        surfaced_server: round.surfaced_server,
    };
    let retry = owned.continuation(
        round.request_state,
        Some(Value::Object(round.accepted_inputs)),
    );
    #[cfg(test)]
    super::resume_seams::at(super::resume_seams::ResumePoint::BeforeRedeem).await;
    let (response, refused) = redeeming_dispatch(
        (&state, &owned, &call, &retry),
        &executor,
        ids,
        &mut cancel_rx,
    )
    .await?;
    // Preparation inside the funnel can outlast the margin. A continuation
    // refused once its envelope has expired was refused for expiry: close the
    // round with that reason rather than fail the task.
    let (at, now) = readable_or_fail(&executor, ids, &mut cancel_rx).await?;
    let expired = owned.dispatch_log().worker().take_redemption_expired()
        || deadline.is_some_and(|d| rejected_after_expiry(&response, d, now));
    executor
        .proceed_unless_late(ids, deadline, expired, at)
        .await?;
    let response =
        inspect_and_record(&state, &call, (&*principal, &*id), (response, refused)).await;
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
        && response.error.as_ref().is_some_and(|error| {
            error.code == INVALID_PARAMS && error.message == expired.client_message()
        })
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
#[path = "input_round_mapping_tests.rs"]
mod mapping_tests;

#[cfg(test)]
#[path = "input_round_exit_tests.rs"]
mod exit_tests;

#[cfg(test)]
#[path = "input_round_park_tests.rs"]
mod park_tests;
