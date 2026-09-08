// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! One spawned owner: admit/create, dispatch, settle, unregister, drop permit.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, oneshot, watch};

use super::settlement::{DispatchSettlement, classify_dispatch, interrupted_before_dispatch};
use super::{BeginOutcome, TaskCall, TaskExecutor, TaskIntent, TaskWrite, WriteOutcome};
use crate::gateway::task_service::service::{CreateOutcome, ServiceError};
use crate::gateway::task_service::store::StoreError;
use crate::protocol::RequestId;
use crate::protocol::tasks::{Task, TaskStatus, TaskTransition};

pub(super) async fn commit_and_run(
    executor: Arc<TaskExecutor>,
    intent: TaskIntent,
    task: Task,
    backend: String,
    call: TaskCall,
    cancel_rx: watch::Receiver<bool>,
    tx: oneshot::Sender<Result<BeginOutcome, ServiceError>>,
) {
    let provisional_id = task.id().to_string();
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
            executor.unregister(&provisional_id);
            let _ = tx.send(Err(ServiceError::Unavailable));
            return;
        }
    };

    let (begin, slot) = split_create(outcome);
    if !matches!(begin, BeginOutcome::Created(_)) {
        executor.unregister(&provisional_id);
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
        executor, intent, call, cancel_rx, principal, id, revision, slot,
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
    intent: TaskIntent,
    call: TaskCall,
    mut cancel_rx: watch::Receiver<bool>,
    principal: String,
    id: String,
    revision: u64,
    slot: Option<OwnedSemaphorePermit>,
) {
    let _slot = slot;
    let fail_upgrade = executor.fail_state_upgrade(&id);
    let Some(state) = (!fail_upgrade)
        .then(|| intent.owned.state().upgrade())
        .flatten()
    else {
        settle_interrupted(&executor, &principal, &id, revision).await;
        executor.unregister(&id);
        return;
    };

    if *cancel_rx.borrow() {
        executor.unregister(&id);
        return;
    }

    match executor.mark_dispatched(&principal, &id, revision).await {
        Marker::Marked => {}
        Marker::Refused => {
            executor.unregister(&id);
            return;
        }
        Marker::Failed => {
            settle_interrupted(&executor, &principal, &id, revision).await;
            executor.unregister(&id);
            return;
        }
    }

    if *cancel_rx.borrow() {
        executor.unregister(&id);
        return;
    }

    let authorizer = intent.owned.authorizer().borrow(&state);
    let caller = intent.owned.dispatch_context(&state, &authorizer);
    let session_id = intent.owned.session_id().map(str::to_owned);
    // The same tail the request thread takes, asked for the backend's own
    // result rather than the synchronous wrapper: design §4 settles a task on
    // that result verbatim, `isError` included, and classifies an interim
    // `input_required` round from it before anything is committed.
    let dispatch = state.meta_mcp.dispatch_below_gate_native_result(
        RequestId::Number(0),
        &call.tool,
        call.arguments,
        session_id.as_deref(),
        &caller,
    );

    tokio::select! {
        biased;
        _ = cancel_rx.changed() => {}
        response = dispatch => {
            settle_response(&executor, &principal, &id, revision, response).await;
        }
    }
    executor.unregister(&id);
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

#[derive(Debug)]
pub(super) enum CommitFailure {
    Service(ServiceError),
    RevisionConflict,
}
