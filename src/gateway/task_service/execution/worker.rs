// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One spawned owner: admit/create, dispatch, settle, drop permit, drop
//! ownership — in that order, and on every path including the ones that unwind.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, oneshot, watch};

use super::input_round::Settling;
use super::settle_followed::{
    FollowedJob, rebuild_task_receipt, screened_peer_failure, settle_followed,
    stage_followed_result,
};
use super::settlement::{
    backend_output, interrupted_before_dispatch, interrupted_result, strip_http_status,
};
use super::upstream::{CancelSend, QueryLease};
use super::{
    BeginOutcome, CommittedTask, CreateWrite, Handoff, TaskCall, TaskExecutor, TaskIntent,
    TransitionWrite, UpstreamAnswer, UpstreamCapture, UpstreamHandle,
};
use crate::gateway::meta_mcp::invoke::relay::AnswerShape;
use crate::gateway::meta_mcp::upstream::UpstreamSubmission;
use crate::gateway::task_service::ErrorAuthor;
use crate::gateway::task_service::Target;
use crate::gateway::task_service::service::{CreateOutcome, ServiceError};
use crate::gateway::task_service::store::StoreError;
use crate::protocol::RequestId;
use crate::protocol::tasks::{Task, TaskStatus, TaskTransition};
use crate::transport::submit_mark::{SubmitMark, with_submit_mark};
use futures::FutureExt as _;

/// The whole life of an owned handoff. `handoff` is the ownership `begin` took
/// before this future existed; every `return` below, and any panic between
/// them, releases it by dropping it, which is why no path releases it by name.
/// It also names the executor this task belongs to, so there is only one.
pub(super) async fn commit_and_run(
    handoff: Handoff,
    intent: TaskIntent,
    task: Task,
    backend: String,
    call: TaskCall,
    cancel_rx: watch::Receiver<bool>,
    tx: oneshot::Sender<Result<BeginOutcome, ServiceError>>,
) {
    let executor = Arc::clone(handoff.executor());
    let principal = intent.request.principal().to_string();

    let Ok(outcome) = executor
        .commit_create(CreateWrite {
            request: &intent.request,
            task: &task,
            backend: &backend,
            targets: creation_targets(&intent, &call),
        })
        .await
    else {
        let _ = tx.send(Err(ServiceError::Unavailable));
        return;
    };

    let (begin, slot) = split_create(outcome);
    if !matches!(begin, BeginOutcome::Created(_)) {
        let _ = tx.send(Ok(begin));
        return;
    }

    let BeginOutcome::Created(committed) = begin else {
        unreachable!("checked above");
    };
    let id = committed.task.id().to_string();
    let revision = committed.revision;
    // Ignorable: a dropped request future must not abort already-durable work.
    let _ = tx.send(Ok(BeginOutcome::Created(committed)));
    Box::pin(run_dispatched(
        executor, handoff, intent, call, cancel_rx, principal, id, revision, slot,
    ))
    .await;
}

/// The one backend call a `gateway_invoke` or surfaced-tool task makes, known
/// at creation. A plan names its calls as it dispatches them.
fn creation_targets(intent: &TaskIntent, call: &TaskCall) -> Vec<Target> {
    intent
        .owned
        .host()
        .upgrade()
        .and_then(|host| host.meta_mcp().direct_job(&call.tool, &call.arguments))
        .map(|job| Target {
            server: job.server,
            tool: job.tool,
        })
        .into_iter()
        .collect()
}

fn split_create(outcome: CreateOutcome) -> (BeginOutcome, Option<OwnedSemaphorePermit>) {
    match outcome {
        CreateOutcome::Created { task, slot } => (BeginOutcome::Created(task), Some(slot)),
        CreateOutcome::Existing(task) => (BeginOutcome::Existing(task), None),
        CreateOutcome::Mismatch => (BeginOutcome::Mismatch, None),
        CreateOutcome::InFlight => (BeginOutcome::InFlight, None),
        CreateOutcome::Capacity => (BeginOutcome::Capacity, None),
        CreateOutcome::Unavailable => (BeginOutcome::Unavailable, None),
        CreateOutcome::Sealed => (BeginOutcome::Sealed, None),
    }
}

// The input-round hand-off (`Settling`) added the last lines; the steps
// read in order here and splitting them would scatter the drop-order rule.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn run_dispatched(
    executor: Arc<TaskExecutor>,
    handoff: Handoff,
    intent: TaskIntent,
    call: TaskCall,
    mut cancel_rx: watch::Receiver<bool>,
    principal: String,
    id: String,
    revision: u64,
    slot: Option<OwnedSemaphorePermit>,
) {
    // Declared in this order, and dropped in the reverse of it: the permit goes
    // back first, so a drain that has stopped seeing this handoff cannot then
    // find the worker pool short of the permit that handoff was holding.
    let _handoff = handoff;
    let _slot = slot;
    let fail_upgrade = executor.fail_state_upgrade(&id);
    let Some(state) = (!fail_upgrade)
        .then(|| intent.owned.host().upgrade())
        .flatten()
    else {
        settle_interrupted(&executor, &principal, &id, revision).await;
        return;
    };

    if *cancel_rx.borrow() {
        return;
    }

    // The upstream slot, armed only for a supported direct backend job whose
    // backend a trusted adapter claims right now. Nothing else is armed, so a
    // playbook, a code-mode program or an unclaimed backend takes exactly the
    // dispatch it took before this increment.
    //
    // There is ONE dispatch either way: arming the slot changes which transport
    // entry point the funnel's backend leg uses, not which gates it runs.
    //
    // Resolved here, above the marker, because the capacity question below has
    // to be answered before the backend is called AND before this row claims to
    // have been dispatched: a process that dies in this window leaves a
    // `working` row with its marker unset, which startup already settles as
    // `not_executed` rather than as `unknown`.
    let mut job = executor
        .recovery()
        .and_then(|_| state.meta_mcp().direct_job(&call.tool, &call.arguments));
    // Trust is a live question with an await in it, so it cannot be a match
    // guard: asked here, after the shape is known and before anything is armed.
    // The verdict is computed first and the option cleared after, so nothing
    // borrows `job` across the assignment.
    let claimed = match (executor.recovery(), job.as_ref()) {
        (Some(adapter), Some(candidate)) => adapter.claims(&candidate.server).await,
        _ => false,
    };
    if !claimed {
        job = None;
    }

    // Capacity for the WHOLE recovery descriptor, reserved before the peer is
    // asked to start anything. A candidate whose complete
    // backend/tool/arguments descriptor cannot be made durable would be
    // dispatched, answered with a handle, and then found unrecoverable by the
    // post-response check — a backend job this gateway holds no address for.
    // Refused instead, with zero backend effect.
    //
    // The refusal is not a fallback: an armed candidate that does not fit is
    // never re-run as an ordinary dispatch, because the ordinary dispatch is the
    // very call whose result nobody could then recover.
    if let Some(candidate) = job.as_ref()
        && !executor.upstream_descriptor_fits(&principal, &id, candidate)
    {
        settle_descriptor_refused(&executor, &principal, &id, revision).await;
        return;
    }

    match executor.mark_dispatched(&principal, &id, revision).await {
        Marker::Marked => {}
        Marker::Refused => return,
        Marker::Failed => {
            settle_interrupted(&executor, &principal, &id, revision).await;
            return;
        }
    }

    if *cancel_rx.borrow() {
        return;
    }

    let authorizer = state.authorizer(intent.owned.authorizer());
    // Held through the call and an upstream job's follow, released before
    // settling: a parked round ends this worker, and its caller is idle then.
    let key_hold = intent.owned.hold_caller_key(&state);
    let caller = intent.owned.dispatch_context(&state, &authorizer);
    let session_id = intent.owned.session_id().map(str::to_owned);

    let submission = job
        .as_ref()
        .map(|job| Arc::new(UpstreamSubmission::armed_for(&job.server, &job.tool, &id)));
    // Set by the transport when the submission's response head arrives: the
    // line past which a cancel may still collect the handle (MIK-7642 R10.1).
    let submit_mark = Arc::new(SubmitMark::default());

    // The same tail the request thread takes, asked for the backend's own
    // result rather than the synchronous wrapper: design §4 settles a task on
    // that result verbatim, `isError` included, and classifies an interim
    // `input_required` round from it before anything is committed.
    let dispatch = state.meta_mcp().dispatch_below_gate_native_result(
        RequestId::Number(0),
        &call.tool,
        call.arguments.clone(),
        session_id.as_deref(),
        &caller,
    );
    let dispatch = async {
        match submission.as_ref() {
            Some(submission) => {
                Box::pin(
                    crate::gateway::meta_mcp::upstream::with_upstream_submission(
                        Arc::clone(submission),
                        with_submit_mark(Arc::clone(&submit_mark), dispatch),
                    ),
                )
                .await
            }
            None => dispatch.await,
        }
    };

    let mut dispatch = Box::pin(crate::gateway::meta_mcp::dispatch_log::with_dispatch_log(
        Arc::clone(intent.owned.dispatch_log()),
        dispatch,
    ));

    // Awaited into its own binding so the dispatch future — which borrows both
    // the caller context and the armed slot — is dropped before anything below
    // takes them again.
    let dispatched = tokio::select! {
        biased;
        _ = cancel_rx.changed() => None,
        response = &mut dispatch => Some(response),
    };
    let Some(response) = dispatched else {
        // The cancel arm (design r7 R7.2, r8 R8.1-R8.3). Only past the
        // receive-only line is `dispatch` polled again, once, outside the coop
        // budget, so a reply already buffered reaches `offer` and nothing new
        // is sent. Then the slot is read, `dispatch` dropped, and only then the
        // durable claim taken.
        if submit_mark.submitted() {
            #[cfg(test)]
            rescue_seam::before_rescue_poll(&id).await;
            let _ = tokio::task::unconstrained(&mut dispatch).now_or_never();
        }
        let held = submission.as_ref().and_then(|slot| slot.handle());
        drop(dispatch);
        if let (Some(handle), Some(job)) = (held, job.as_ref()) {
            cancel_held_upstream(&executor, &principal, &id, job, handle).await;
        }
        return;
    };
    drop(dispatch);

    // A handle in the slot means the peer really did start a task: the
    // dispatch's own return is the `working` stub, not an answer, and settling
    // on it would report a job that has not run as finished.
    if let Some(handle) = submission.as_ref().and_then(|slot| slot.handle()) {
        let job = job.expect("a handle is captured only for an armed job");
        follow_upstream_job(
            &executor,
            &state,
            &principal,
            &id,
            revision,
            (job, handle, caller.relay_caller(session_id.as_deref())),
            &mut cancel_rx,
        )
        .await;
    } else {
        drop(key_hold);
        let mut response = inspect_settled(&state, &call, &id, response);
        state.meta_mcp().release_unsent_hold(&mut response).await; // MIK-8131
        Settling::new(
            &executor,
            &state,
            &intent.owned,
            &call,
            &principal,
            &id,
            revision,
        )
        .settle_or_ask(response, &mut cancel_rx)
        .await;
    }
}

/// Own one live upstream job: make its handle durable, follow it within a
/// bounded budget, and settle what it eventually says.
///
/// Order matters. The handle is made durable BEFORE anything else is done with
/// it — a row is recoverable only once its handle is on disk, and the window
/// between the peer's answer and that write stays `unknown`. A refusal there
/// does not stop the job, which is why the follow below still runs.
async fn follow_upstream_job(
    executor: &Arc<TaskExecutor>,
    state: &crate::gateway::task_service::host::LiveHost,
    principal: &str,
    id: &str,
    revision: u64,
    dispatched: (
        crate::gateway::meta_mcp::upstream::DirectJob,
        String,
        crate::gateway::meta_mcp::invoke::relay::RelayKey<'_>,
    ),
    cancel_rx: &mut watch::Receiver<bool>,
) {
    let (job, handle, relay) = dispatched;
    let captured = capture_handle(executor, (principal, id, revision), &job, &handle).await;

    // Neither early return below can strand a refused capture's handle: a job
    // is armed only when an installed adapter claims its backend, and its
    // principal already hashed at admission. Without an adapter no cancel
    // could be sent anyway.
    let Some(adapter) = executor.recovery() else {
        return;
    };
    // The digest the record is owned by, for the durable recheck each query
    // makes under the record's slot. A principal admission cannot hash is a
    // principal nothing here can re-read, so the job is left to a later
    // authenticated read rather than followed blind.
    let Ok(owner) = executor.service.owner(principal) else {
        return;
    };
    let owner_digest = owner.as_digest();
    let upstream = UpstreamHandle {
        backend: job.server.clone(),
        handle,
    };
    let followed = tokio::select! {
        biased;
        _ = cancel_rx.changed() => {
            // The capture-side sender: a capture refused (the row cancelled
            // meanwhile, or a failed write) left the claim to this handle.
            cancel_held_upstream(executor, principal, id, &job, upstream.handle.clone()).await;
            return;
        }
        followed = poll_to_terminal(executor, owner_digest, id, adapter, &upstream) => followed,
    };
    // The lease is still held for a terminal answer, and released only after
    // the settlement below: a read that queued behind this query must find the
    // committed outcome, not a working row it would query all over again.
    let (answer, lease) = match followed {
        Followed::Terminal(answer, lease) => (answer, lease),
        // Still live, or unreachable, when this worker's budget ran out. The
        // record stays `working` with its handle; the owner's next authenticated
        // read continues from exactly here. Nothing is faked terminal.
        Followed::Retained => {
            tracing::info!(
                task_id = %id,
                captured,
                "upstream task left live; retained for the owner's next read"
            );
            return;
        }
        // An authorized read settled this row while this worker queued for the
        // record's slot. Its committed outcome is the answer; asking the peer
        // again would be a second query for one already-settled job.
        Followed::Overtaken => {
            tracing::info!(
                task_id = %id,
                captured,
                "upstream task settled by an owner read; this worker asks nothing further"
            );
            // A cancel commits before its signal: a capture refused in that gap
            // reaches here with no signal seen. The handle held here may be the
            // only one; the claim is a no-op unless the row is cancelled and
            // unclaimed (MIK-7642).
            if !captured {
                cancel_held_upstream(executor, principal, id, &job, upstream.handle.clone()).await;
            }
            return;
        }
    };
    // The identical post-dispatch processing a live dispatch applies, from the
    // same implementation, in the dispatch scope so the gates' attribution
    // notes travel with the transition (MIN.1 gap 1). The write record from
    // here on is what that processing wrote into the result (MIK-7993).
    let writes_mark = crate::gateway::gateway_writes::mark();
    let processed = crate::gateway::meta_mcp::invoke::audit::with_dispatch_scope(async {
        match answer {
            UpstreamAnswer::Completed(result) => Some((
                match state
                    .meta_mcp()
                    .recover_task_result(&job.server, &job.tool, None, id, result)
                {
                    Ok(processed) => {
                        let processed = backend_output(processed);
                        let target = (job.server.as_str(), job.tool.as_str());
                        stage_followed_result(state, relay, target, &processed);
                        TaskTransition::Complete(processed)
                    }
                    Err(error) => TaskTransition::Fail(
                        crate::gateway::meta_mcp::response_security::recovered_result_error(&error),
                    ),
                },
                ErrorAuthor::Gateway,
            )),
            // The failure half of that same processing: the peer's message and
            // nested data are screened before this settles, keeping the code.
            UpstreamAnswer::Failed(error) => Some(screened_peer_failure(state, &job, id, error)),
            // The gateway's own words, never the peer's (MIK-7887.RECEIPT.1).
            UpstreamAnswer::Substituted(error) => Some((
                TaskTransition::Fail(strip_http_status(error)),
                ErrorAuthor::Gateway,
            )),
            // [`poll_to_terminal`] hands back a lease only with a terminal answer.
            UpstreamAnswer::Live | UpstreamAnswer::Unavailable => None,
        }
    })
    .await;
    if let (Some(outcome), notes) = processed {
        let followed = FollowedJob {
            job: &job,
            relay,
            id,
            principal,
            revision,
        };
        let writes = crate::gateway::gateway_writes::snapshot_since(writes_mark);
        settle_followed(executor, state, &followed, (outcome, writes), &notes).await;
    }
    lease.release(executor, id).await;
}

/// Make `handle` durable, before anything else is done with it. A refusal
/// does not stop the job: it is followed either way, and a cancel that lands
/// meanwhile is seen by the follow's cancel arm, which offers the handle to the
/// row's one cancel claim (design r8 R8.4, the capture-side case).
async fn capture_handle(
    executor: &Arc<TaskExecutor>,
    (principal, id, revision): (&str, &str, u64),
    job: &crate::gateway::meta_mcp::upstream::DirectJob,
    handle: &str,
) -> bool {
    executor
        .notify_observer(super::CommitStage::BeforeCapture, id)
        .await;
    let capture = UpstreamCapture {
        backend: job.server.clone(),
        tool: job.tool.clone(),
        arguments: job.arguments.clone(),
        handle: handle.to_owned(),
    };
    executor
        .capture_upstream(principal, id, revision, capture)
        .await
}

/// Offer a handle this worker holds, for a row cancelled under it, to the
/// row's one durable cancel claim; send it here if this worker wins. `false`
/// when the row is not cancelled, another sender claimed, or nothing could be
/// read.
async fn cancel_held_upstream(
    executor: &Arc<TaskExecutor>,
    principal: &str,
    id: &str,
    job: &crate::gateway::meta_mcp::upstream::DirectJob,
    handle: String,
) -> bool {
    let Ok(owner) = executor.service.owner(principal) else {
        return false;
    };
    let Some(offer) = executor.offered_descriptor(owner.as_digest(), id, job, handle) else {
        return false;
    };
    executor
        .cancel_upstream_once(owner.as_digest(), id, Some(offer), CancelSend::Inline)
        .await
}

/// What following one handle within the worker's budget produced.
enum Followed {
    /// A terminal answer, with the record's query slot still held so the
    /// settlement it justifies cannot be overtaken by a queued reader.
    Terminal(UpstreamAnswer, QueryLease),
    /// Live at the end of the budget, or unreachable. Nothing to commit, and no
    /// slot retained.
    Retained,
    /// The record was already settled when this worker reached the front of the
    /// slot queue. Nothing was asked and nothing is committed.
    Overtaken,
}

/// How long one worker will follow its own upstream job before handing it back
/// to the owner's reads.
///
/// Bounded rather than open-ended: a worker holds a pool permit and a drain
/// joins it, so "wait until the peer finishes" would let one slow upstream job
/// hold a slot for its whole TTL. Giving up costs nothing — the handle is
/// durable, the record stays `working`, and the next authenticated read
/// continues from exactly where this left off.
const WORKER_POLL_BUDGET: std::time::Duration = std::time::Duration::from_secs(300);
const WORKER_POLL_GAP: std::time::Duration = std::time::Duration::from_secs(1);

/// Poll one handle to a terminal answer, within the worker's budget.
///
/// `Live` is retried until the budget runs out; `Unavailable` returns at once —
/// an unreachable peer is retained for a later read rather than hammered here.
///
/// One lease per individual query, never across the gap or the budget: this
/// worker's follow is one of the queries of this record, so it takes the
/// record's own slot exactly as an authenticated read does, and a worker that
/// held it for its whole budget would block every owner read of the row. Under
/// each lease the durable state is re-read first, so a job a predecessor
/// already settled is not queried a second time.
async fn poll_to_terminal(
    executor: &Arc<TaskExecutor>,
    owner_digest: &str,
    id: &str,
    adapter: &Arc<dyn super::UpstreamRecovery>,
    handle: &UpstreamHandle,
) -> Followed {
    let deadline = tokio::time::Instant::now() + WORKER_POLL_BUDGET;
    loop {
        let lease = executor.acquire_query_lease(id).await;
        if !executor.handle_still_live(owner_digest, id, handle) {
            lease.release(executor, id).await;
            return Followed::Overtaken;
        }
        match adapter
            .query(handle, crate::gateway::meta_mcp::upstream::QUERY_DEADLINE)
            .await
        {
            UpstreamAnswer::Live => lease.release(executor, id).await,
            UpstreamAnswer::Unavailable => {
                lease.release(executor, id).await;
                return Followed::Retained;
            }
            terminal => return Followed::Terminal(terminal, lease),
        }
        if tokio::time::Instant::now() >= deadline {
            return Followed::Retained;
        }
        tokio::time::sleep(WORKER_POLL_GAP).await;
    }
}

pub(super) enum Marker {
    Marked,
    Refused,
    Failed,
}

pub(super) async fn settle_interrupted(
    executor: &TaskExecutor,
    principal: &str,
    id: &str,
    revision: u64,
) {
    let event = TaskTransition::Complete(interrupted_before_dispatch());
    executor.settle_cas(principal, id, revision, event).await;
}

/// Settle a candidate refused by the descriptor preflight.
///
/// `not_executed`, through the ordinary revision-checked durable path and in
/// the vocabulary an interrupted-before-dispatch row already uses: the backend
/// was never called, so no other outcome would be true. Nothing upstream is
/// created, cancelled or resubmitted, because nothing upstream exists.
async fn settle_descriptor_refused(
    executor: &TaskExecutor,
    principal: &str,
    id: &str,
    revision: u64,
) {
    let event = TaskTransition::Complete(interrupted_result(
        "not_executed",
        "recovery_descriptor_too_large",
        "The gateway refused this task before calling the backend: its recovery \
         descriptor does not fit the durable record budget.",
    ));
    executor.settle_cas(principal, id, revision, event).await;
}

/// The response firewall on a native task result, under the targets the
/// synchronous call would use (#2351): a refusal is what the task settles on.
pub(super) fn inspect_settled(
    state: &crate::gateway::task_service::host::LiveHost,
    call: &TaskCall,
    id: &str,
    mut response: crate::protocol::JsonRpcResponse,
) -> crate::protocol::JsonRpcResponse {
    if response.error.is_some() || response.egress_scanned {
        return response;
    }
    // MIK-8131: a sealed question this refuses gives its slot back (the async
    // caller releases it).
    let sealed = state.meta_mcp().sealed_question("tools/call", &response);
    let Some(result) = response.result.as_mut() else {
        return response;
    };
    let backend = crate::gateway::router::backend_tool_targets_for_call(
        state.meta_mcp(),
        &call.tool,
        &call.arguments,
    );
    let targets =
        crate::gateway::meta_mcp::response_security::meta_response_targets(&call.tool, &backend);
    let snapshot = state.meta_mcp().relay_snapshot(result);
    let refused = state
        .meta_mcp()
        .inspect_task_result(&targets, id, result)
        .is_err();
    // A redaction changed what the task will deliver: its receipt is rebuilt
    // from it. A task holds the backend's native result, never a wrapper.
    state
        .meta_mcp()
        .restage_if_changed(snapshot, Some(&*result), AnswerShape::Literal);
    // A task stores the backend's native result, never a `gateway_invoke`
    // wrapper, whatever tool started it.
    rebuild_task_receipt(
        state,
        &super::settlement::stored_result(result.clone()),
        AnswerShape::Literal,
    );
    if refused {
        response = crate::protocol::JsonRpcResponse::delivery_refusal_error(
            response.id,
            -32600,
            "Response blocked by security firewall",
        );
        response.unsent_hold = sealed.map(|(_, hold_key)| hold_key);
    }
    response
}

impl TaskExecutor {
    /// Whether this record can still hold the complete recovery descriptor for
    /// `job`, plus the widest handle the store would accept for it.
    ///
    /// The owner hop is admission's one hasher, exactly as `capture_upstream`
    /// does it: this asks about the row the CALLER owns and nothing else, and
    /// it invents no identity — the digest the descriptor is bound to is read
    /// from the record inside the store.
    ///
    /// A measurement that cannot be taken is a refusal, not a pass. An
    /// unreadable store cannot tell us the descriptor fits, and dispatching on
    /// the strength of a question nobody answered is the failure this preflight
    /// exists to prevent.
    pub(super) fn upstream_descriptor_fits(
        &self,
        principal: &str,
        id: &str,
        job: &crate::gateway::meta_mcp::upstream::DirectJob,
    ) -> bool {
        let Ok(owner) = self.service.owner(principal) else {
            return false;
        };
        self.service
            .store
            .admits_upstream_descriptor(
                owner.as_digest(),
                id,
                &job.server,
                &job.tool,
                &job.arguments,
            )
            .unwrap_or(false)
    }

    pub(super) async fn mark_dispatched(&self, principal: &str, id: &str, revision: u64) -> Marker {
        if self.fail_marker(id) {
            return Marker::Failed;
        }
        let Ok(owner) = self.service.owner(principal) else {
            return Marker::Failed;
        };
        match self
            .service
            .store
            .mark_dispatched(owner.as_digest(), id, revision)
            .await
        {
            Ok(()) => {
                self.notify_observer(super::CommitStage::Dispatched, id)
                    .await;
                Marker::Marked
            }
            Err(StoreError::InvalidTransition | StoreError::RevisionConflict) => Marker::Refused,
            Err(_) => Marker::Failed,
        }
    }

    pub(super) async fn settle_cas(
        &self,
        principal: &str,
        id: &str,
        revision: u64,
        event: TaskTransition,
    ) -> bool {
        // The gateway's own outcome: nothing in it is a member it noted.
        self.settle_cas_by(
            principal,
            id,
            revision,
            (event, None),
            ErrorAuthor::Gateway,
            crate::gateway::gateway_writes::WriteRecord::default(),
        )
        .await
    }

    /// [`Self::settle_cas`] committing a plan's dispatched `targets` in the same
    /// write as the outcome. A settlement that does not fit the record budget
    /// becomes a bounded `Failed` with no output (see `settle_bounded`).
    ///
    /// `writes` names the members of a `Complete` result the gateway wrote,
    /// stored with it so a later read's receipt leaves them out (MIK-7993).
    pub(super) async fn settle_cas_with(
        &self,
        principal: &str,
        id: &str,
        revision: u64,
        outcome: (TaskTransition, Option<Vec<Target>>),
        writes: crate::gateway::gateway_writes::WriteRecord,
    ) -> bool {
        self.settle_cas_by(
            principal,
            id,
            revision,
            outcome,
            ErrorAuthor::Gateway,
            writes,
        )
        .await
    }

    /// [`Self::settle_cas_with`], recording who wrote a `Fail` event's error
    /// (MIK-7887.RECEIPT.1). `true` when the stored row delivers backend
    /// output a relay receipt may be committed for.
    pub(super) async fn settle_cas_by(
        &self,
        principal: &str,
        id: &str,
        revision: u64,
        (event, targets): (TaskTransition, Option<Vec<Target>>),
        author: ErrorAuthor,
        writes: crate::gateway::gateway_writes::WriteRecord,
    ) -> bool {
        match self
            .commit_transition(TransitionWrite::Settle {
                principal,
                id,
                revision,
                event: event.clone(),
                targets: targets.clone(),
                author,
                writes: writes.clone(),
            })
            .await
        {
            Ok(stored) => return stored_backend_output(&stored),
            Err(CommitFailure::RevisionConflict) => {}
            Err(_) => {
                tracing::warn!(task_id = %id, "task settlement write failed");
                return false;
            }
        }

        let Ok(owner) = self.service.owner(principal) else {
            return false;
        };
        let Ok(current) = self.service.store.get(owner.as_digest(), id) else {
            return false;
        };
        if is_terminal(current.task.status()) {
            return false;
        }
        let settled = self
            .commit_transition(TransitionWrite::Settle {
                principal,
                id,
                revision: current.revision,
                event,
                targets,
                author,
                writes,
            })
            .await;
        let Ok(stored) = settled else {
            tracing::warn!(task_id = %id, "task settlement lost a second compare-and-set");
            return false;
        };
        stored_backend_output(&stored)
    }
}

/// Whether a settlement stored backend output a relay receipt may be
/// committed for: a completed result, or (MIK-7887.RECEIPT.1) an error the
/// gateway established as the peer's. A bounded settlement stores neither.
fn stored_backend_output(stored: &CommittedTask) -> bool {
    (stored.task.status() == TaskStatus::Completed && !stored.output_free)
        || stored.backend_error().is_some()
}

fn is_terminal(status: TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
    )
}

/// Returned by `TaskExecutor::commit`, which is `pub(crate)`: the error type of
/// a crate-visible write has to be nameable wherever that write is.
#[derive(Debug)]
pub(crate) enum CommitFailure {
    Service(ServiceError),
    RevisionConflict,
}

/// Test seam for design r9 R9.2 (row T2c): spend this worker's coop budget
/// inside the cancel arm, immediately before the rescue poll, and record that
/// it was spent there. Inert unless a test names the task.
#[cfg(test)]
pub(crate) mod rescue_seam {
    use std::collections::HashSet;
    use std::sync::LazyLock;

    use parking_lot::Mutex;

    static EXHAUST: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Mutex::default);
    static EXHAUSTED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Mutex::default);

    /// Spend the coop budget of `task_id`'s worker before its rescue poll.
    pub(crate) fn exhaust_before_rescue(task_id: &str) {
        EXHAUST.lock().insert(task_id.to_owned());
    }

    /// Whether the budget was observed spent before the rescue poll.
    pub(crate) fn was_exhausted(task_id: &str) -> bool {
        EXHAUSTED.lock().contains(task_id)
    }

    pub(super) async fn before_rescue_poll(task_id: &str) {
        if !EXHAUST.lock().contains(task_id) {
            return;
        }
        // Until the runtime says the budget is gone: `consume_budget` is
        // Pending exactly then.
        loop {
            let mut step = std::pin::pin!(tokio::task::consume_budget());
            if futures::poll!(step.as_mut()).is_pending() {
                break;
            }
        }
        EXHAUSTED.lock().insert(task_id.to_owned());
    }
}
