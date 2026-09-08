// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One spawned owner: admit/create, dispatch, settle, drop permit, drop
//! ownership — in that order, and on every path including the ones that unwind.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, oneshot, watch};

use super::settlement::{
    DispatchSettlement, classify_dispatch, interrupted_before_dispatch, interrupted_result,
    strip_http_status,
};
use super::{
    BeginOutcome, Handoff, TaskCall, TaskExecutor, TaskIntent, TaskWrite, UpstreamAnswer,
    UpstreamCapture, UpstreamHandle, WriteOutcome,
};
use crate::gateway::meta_mcp::upstream::UpstreamSubmission;
use crate::gateway::task_service::service::{CreateOutcome, ServiceError};
use crate::gateway::task_service::store::StoreError;
use crate::protocol::RequestId;
use crate::protocol::tasks::{Task, TaskStatus, TaskTransition};

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

    let outcome = match executor
        .commit(TaskWrite::Create {
            request: &intent.request,
            task: &task,
            backend: &backend,
        })
        .await
    {
        Ok(WriteOutcome::Create(created)) => created,
        Ok(_) | Err(_) => {
            let _ = tx.send(Err(ServiceError::Unavailable));
            return;
        }
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
    run_dispatched(
        executor, handoff, intent, call, cancel_rx, principal, id, revision, slot,
    )
    .await;
}

fn split_create(outcome: CreateOutcome) -> (BeginOutcome, Option<OwnedSemaphorePermit>) {
    match outcome {
        CreateOutcome::Created { task, slot } => (BeginOutcome::Created(task), Some(slot)),
        CreateOutcome::Existing(task) => (BeginOutcome::Existing(task), None),
        CreateOutcome::Mismatch => (BeginOutcome::Mismatch, None),
        CreateOutcome::InFlight => (BeginOutcome::InFlight, None),
        CreateOutcome::Capacity => (BeginOutcome::Capacity, None),
        CreateOutcome::Unavailable => (BeginOutcome::Unavailable, None),
    }
}

#[allow(clippy::too_many_arguments)]
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
        .then(|| intent.owned.state().upgrade())
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
        .and_then(|_| state.meta_mcp.direct_job(&call.tool, &call.arguments));
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

    let authorizer = intent.owned.authorizer().borrow(&state);
    let caller = intent.owned.dispatch_context(&state, &authorizer);
    let session_id = intent.owned.session_id().map(str::to_owned);

    let submission = job
        .as_ref()
        .map(|job| Arc::new(UpstreamSubmission::armed_for(&job.server, &job.tool)));

    // The same tail the request thread takes, asked for the backend's own
    // result rather than the synchronous wrapper: design §4 settles a task on
    // that result verbatim, `isError` included, and classifies an interim
    // `input_required` round from it before anything is committed.
    let dispatch = state.meta_mcp.dispatch_below_gate_native_result(
        RequestId::Number(0),
        &call.tool,
        call.arguments.clone(),
        session_id.as_deref(),
        &caller,
    );
    let dispatch = async {
        match submission.as_ref() {
            Some(submission) => {
                crate::gateway::meta_mcp::upstream::with_upstream_submission(
                    Arc::clone(submission),
                    dispatch,
                )
                .await
            }
            None => dispatch.await,
        }
    };

    // Awaited into its own binding so the dispatch future — which borrows both
    // the caller context and the armed slot — is dropped before anything below
    // takes them again.
    let dispatched = tokio::select! {
        biased;
        _ = cancel_rx.changed() => None,
        response = dispatch => Some(response),
    };
    let Some(response) = dispatched else {
        return;
    };

    // A handle in the slot means the peer really did start a task: the
    // dispatch's own return is the `working` stub, not an answer, and settling
    // on it would report a job that has not run as finished.
    match submission.as_ref().and_then(|slot| slot.handle()) {
        Some(handle) => {
            let job = job.expect("a handle is captured only for an armed job");
            follow_upstream_job(
                &executor,
                &state,
                &principal,
                &id,
                revision,
                job,
                handle,
                &mut cancel_rx,
            )
            .await;
        }
        None => settle_response(&executor, &principal, &id, revision, response).await,
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
    state: &Arc<crate::gateway::router::AppState>,
    principal: &str,
    id: &str,
    revision: u64,
    job: crate::gateway::meta_mcp::upstream::DirectJob,
    handle: String,
    cancel_rx: &mut watch::Receiver<bool>,
) {
    let captured = executor
        .capture_upstream(
            principal,
            id,
            revision,
            UpstreamCapture {
                backend: job.server.clone(),
                tool: job.tool.clone(),
                arguments: job.arguments.clone(),
                handle: handle.clone(),
            },
        )
        .await;

    let Some(adapter) = executor.recovery() else {
        return;
    };
    let upstream = UpstreamHandle {
        backend: job.server.clone(),
        handle,
    };
    let answer = tokio::select! {
        biased;
        _ = cancel_rx.changed() => return,
        answer = poll_to_terminal(adapter, &upstream) => answer,
    };
    match answer {
        UpstreamAnswer::Completed(result) => {
            // The identical post-dispatch processing a live dispatch applies,
            // from the same implementation, before the durable settlement.
            let event =
                match state
                    .meta_mcp
                    .recover_task_result(&job.server, &job.tool, None, id, result)
                {
                    Ok(processed) => TaskTransition::Complete(processed),
                    Err(error) => TaskTransition::Fail(crate::protocol::JsonRpcError {
                        code: -32603,
                        message: error.to_string(),
                        data: None,
                    }),
                };
            executor.settle_cas(principal, id, revision, event).await;
        }
        UpstreamAnswer::Failed(error) => {
            // The failure half of that same processing: the peer's message and
            // nested data are screened before this settles, keeping the code.
            let screened = state.meta_mcp.recover_task_error(
                &job.server,
                &job.tool,
                None,
                id,
                strip_http_status(error),
            );
            executor
                .settle_cas(principal, id, revision, TaskTransition::Fail(screened))
                .await;
        }
        // Still live, or unreachable, when this worker's budget ran out. The
        // record stays `working` with its handle; the owner's next authenticated
        // read continues from exactly here. Nothing is faked terminal.
        UpstreamAnswer::Live | UpstreamAnswer::Unavailable => {
            tracing::info!(
                task_id = %id,
                captured,
                "upstream task left live; retained for the owner's next read"
            );
        }
    }
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
async fn poll_to_terminal(
    adapter: &Arc<dyn super::UpstreamRecovery>,
    handle: &UpstreamHandle,
) -> UpstreamAnswer {
    let deadline = tokio::time::Instant::now() + WORKER_POLL_BUDGET;
    loop {
        match adapter
            .query(handle, crate::gateway::meta_mcp::upstream::QUERY_DEADLINE)
            .await
        {
            UpstreamAnswer::Live => {}
            other => return other,
        }
        if tokio::time::Instant::now() >= deadline {
            return UpstreamAnswer::Live;
        }
        tokio::time::sleep(WORKER_POLL_GAP).await;
    }
}

pub(super) enum Marker {
    Marked,
    Refused,
    Failed,
}

async fn settle_interrupted(executor: &TaskExecutor, principal: &str, id: &str, revision: u64) {
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

async fn settle_response(
    executor: &TaskExecutor,
    principal: &str,
    id: &str,
    revision: u64,
    response: crate::protocol::JsonRpcResponse,
) {
    let event = match classify_dispatch(response) {
        DispatchSettlement::Complete(result) => TaskTransition::Complete(result),
        DispatchSettlement::Fail(error) => TaskTransition::Fail(error),
    };
    executor.settle_cas(principal, id, revision, event).await;
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
    ) {
        match self
            .commit(TaskWrite::Settle {
                principal,
                id,
                revision,
                event: event.clone(),
            })
            .await
        {
            Ok(_) => return,
            Err(CommitFailure::RevisionConflict) => {}
            Err(_) => {
                tracing::warn!(task_id = %id, "task settlement write failed");
                return;
            }
        }

        let Ok(owner) = self.service.owner(principal) else {
            return;
        };
        let Ok(current) = self.service.store.get(owner.as_digest(), id) else {
            return;
        };
        if is_terminal(current.task.status()) {
            return;
        }
        if self
            .commit(TaskWrite::Settle {
                principal,
                id,
                revision: current.revision,
                event,
            })
            .await
            .is_err()
        {
            tracing::warn!(task_id = %id, "task settlement lost a second compare-and-set");
        }
    }
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
