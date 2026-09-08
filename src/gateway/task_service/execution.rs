// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Task executor: one admission, one publication seam, one spawned owner.

mod context;
mod observe;
mod settlement;
mod worker;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::sync::{Semaphore, oneshot, watch};

pub(crate) use context::{OwnedAdmissionRequest, OwnedCallerContext};
pub(crate) use observe::{
    CommitObserver, CommitStage, DrainOutcome, RecoveryCheckpoint, RecoveryOutcome,
    UpstreamRecovery, remaining_implementation,
};
use worker::{CommitFailure, commit_and_run};

use super::record::CommittedTask;
use super::service::{CreateOutcome, ServiceError, TaskService};
use super::store::StoreError;
use crate::gateway::subscription_registry::SubscriptionRegistry;
use crate::protocol::tasks::{Task, TaskOptions, TaskTransition};
use crate::protocol::{JsonRpcResponse, RequestId};

/// Default worker cap when config has not yet been wired (lane 3).
pub(crate) const DEFAULT_MAX_WORKERS: usize = 16;

pub(crate) struct TaskCall {
    pub tool: String,
    pub arguments: Value,
}

/// `'static` intent: nothing borrowed from the request-thread caller.
pub(crate) struct TaskIntent {
    pub executor: Arc<TaskExecutor>,
    pub owned: OwnedCallerContext,
    pub request: OwnedAdmissionRequest,
    pub options: TaskOptions,
}

/// Request-facing outcomes never own a worker permit.
pub(crate) enum BeginOutcome {
    Created(CommittedTask),
    Existing(CommittedTask),
    Mismatch,
    InFlight,
    Capacity,
    Unavailable,
}

impl BeginOutcome {
    pub(crate) fn into_response(self, id: RequestId) -> JsonRpcResponse {
        match self {
            Self::Created(task) | Self::Existing(task) => {
                let mut value = serde_json::to_value(task.task.wire()).unwrap_or(Value::Null);
                if let Some(obj) = value.as_object_mut() {
                    obj.insert("resultType".into(), json!("task"));
                }
                JsonRpcResponse::success(id, value)
            }
            Self::Mismatch => JsonRpcResponse::error(
                Some(id),
                -32602,
                "idempotency key already used with a different request",
            ),
            Self::InFlight => JsonRpcResponse::error(
                Some(id),
                -32002,
                "a task with this idempotency key is already being created",
            ),
            Self::Capacity | Self::Unavailable => {
                JsonRpcResponse::error(Some(id), -32603, "task store unavailable")
            }
        }
    }
}

pub(crate) enum TaskWrite<'a> {
    Create {
        request: &'a OwnedAdmissionRequest,
        task: &'a Task,
        backend: &'a str,
    },
    Settle {
        principal: &'a str,
        id: &'a str,
        revision: u64,
        event: TaskTransition,
    },
    Cancel {
        principal: &'a str,
        id: &'a str,
        revision: u64,
    },
    Recover {
        principal: &'a str,
        id: &'a str,
        revision: u64,
        event: TaskTransition,
    },
}

pub(crate) enum WriteOutcome {
    Create(CreateOutcome),
    Transitioned(CommittedTask),
}

pub struct TaskExecutor {
    pub(crate) service: Arc<TaskService>,
    subscriptions: Arc<SubscriptionRegistry>,
    workers: Arc<Semaphore>,
    max_workers: usize,
    running: Mutex<HashMap<String, watch::Sender<bool>>>,
    recovery: Option<Arc<dyn UpstreamRecovery>>,
    observer: Mutex<Option<Arc<dyn CommitObserver>>>,
}

impl TaskExecutor {
    pub(crate) fn new(
        service: Arc<TaskService>,
        subscriptions: Arc<SubscriptionRegistry>,
        max_workers: usize,
    ) -> Arc<Self> {
        let max_workers = max_workers.max(1);
        Arc::new(Self {
            service,
            subscriptions,
            workers: Arc::new(Semaphore::new(max_workers)),
            max_workers,
            running: Mutex::new(HashMap::new()),
            recovery: None,
            observer: Mutex::new(None),
        })
    }

    pub(crate) fn recovery(&self) -> Option<&Arc<dyn UpstreamRecovery>> {
        self.recovery.as_ref()
    }

    pub(crate) fn observe_commits(&self, observer: Arc<dyn CommitObserver>) {
        *self.observer.lock() = Some(observer);
    }

    pub(crate) async fn begin(
        self: &Arc<Self>,
        intent: TaskIntent,
        task: Task,
        backend: String,
        call: TaskCall,
    ) -> Result<BeginOutcome, ServiceError> {
        let cancel_rx = self.register(task.id());
        let (tx, rx) = oneshot::channel();
        let executor = Arc::clone(self);
        tokio::spawn(commit_and_run(
            executor, intent, task, backend, call, cancel_rx, tx,
        ));
        rx.await.map_err(|_| ServiceError::Unavailable)?
    }

    pub(crate) async fn cancel(
        &self,
        principal: &str,
        id: &str,
        revision: u64,
    ) -> Result<CommittedTask, ServiceError> {
        let outcome = self
            .commit(TaskWrite::Cancel {
                principal,
                id,
                revision,
            })
            .await
            .map_err(commit_to_service)?;
        self.cancel_signal(id);
        match outcome {
            WriteOutcome::Transitioned(task) => Ok(task),
            WriteOutcome::Create(_) => Err(ServiceError::Unavailable),
        }
    }

    pub(crate) async fn settle(
        &self,
        id: &str,
        outcome: TaskTransition,
        principal: &str,
        revision: u64,
    ) -> Result<(), ServiceError> {
        self.settle_cas(principal, id, revision, outcome).await;
        Ok(())
    }

    pub(crate) async fn drain(&self, timeout: Duration) -> DrainOutcome {
        let acquire = async {
            let mut held = Vec::with_capacity(self.max_workers);
            for _ in 0..self.max_workers {
                let permit = self
                    .workers
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("worker semaphore is never closed");
                held.push(permit);
            }
            held
        };
        match tokio::time::timeout(timeout, acquire).await {
            Ok(held) => DrainOutcome {
                timed_out: false,
                acquired: held.len(),
            },
            Err(_) => DrainOutcome {
                timed_out: true,
                acquired: self
                    .max_workers
                    .saturating_sub(self.workers.available_permits()),
            },
        }
    }

    fn register(&self, id: &str) -> watch::Receiver<bool> {
        let (tx, rx) = watch::channel(false);
        self.running.lock().insert(id.to_owned(), tx);
        rx
    }

    pub(super) fn unregister(&self, id: &str) {
        self.running.lock().remove(id);
    }

    fn cancel_signal(&self, id: &str) {
        let tx = self.running.lock().get(id).cloned();
        if let Some(tx) = tx {
            let _ = tx.send(true);
        }
    }

    pub(crate) async fn commit(&self, write: TaskWrite<'_>) -> Result<WriteOutcome, CommitFailure> {
        let (outcome, wrote, stage, task_id) = match write {
            TaskWrite::Create {
                request,
                task,
                backend,
            } => {
                let workers = Arc::clone(&self.workers);
                let created = self
                    .service
                    .create(request.borrow(), task, backend, move || {
                        workers.try_acquire_owned().ok()
                    })
                    .await
                    .map_err(CommitFailure::Service)?;
                let wrote = matches!(created, CreateOutcome::Created { .. });
                let id = match &created {
                    CreateOutcome::Created { task, .. } | CreateOutcome::Existing(task) => {
                        task.task.id().to_owned()
                    }
                    _ => task.id().to_owned(),
                };
                (
                    WriteOutcome::Create(created),
                    wrote,
                    CommitStage::Published,
                    id,
                )
            }
            TaskWrite::Settle {
                principal,
                id,
                revision,
                event,
            }
            | TaskWrite::Recover {
                principal,
                id,
                revision,
                event,
            } => {
                self.transition_write(principal, id, revision, event)
                    .await?
            }
            TaskWrite::Cancel {
                principal,
                id,
                revision,
            } => {
                self.transition_write(principal, id, revision, TaskTransition::Cancel)
                    .await?
            }
        };
        if wrote {
            self.published(&outcome, &task_id);
            self.notify_observer(stage, &task_id).await;
        }
        Ok(outcome)
    }

    async fn transition_write(
        &self,
        principal: &str,
        id: &str,
        revision: u64,
        event: TaskTransition,
    ) -> Result<(WriteOutcome, bool, CommitStage, String), CommitFailure> {
        let owner = self
            .service
            .owner(principal)
            .map_err(CommitFailure::Service)?;
        match self
            .service
            .store
            .transition(owner.as_digest(), id, revision, event, Utc::now())
            .await
        {
            Ok(committed) => {
                let wrote = committed.revision != revision;
                Ok((
                    WriteOutcome::Transitioned(committed),
                    wrote,
                    CommitStage::Transitioned,
                    id.to_owned(),
                ))
            }
            Err(StoreError::RevisionConflict) => Err(CommitFailure::RevisionConflict),
            Err(StoreError::NotFound) => Err(CommitFailure::Service(ServiceError::NotFound)),
            Err(_) => Err(CommitFailure::Service(ServiceError::Unavailable)),
        }
    }

    fn published(&self, outcome: &WriteOutcome, task_id: &str) {
        let _ = &self.subscriptions;
        let status = match outcome {
            WriteOutcome::Create(CreateOutcome::Created { task, .. }) => {
                format!("{:?}", task.task.status())
            }
            WriteOutcome::Transitioned(task) => format!("{:?}", task.task.status()),
            WriteOutcome::Create(_) => return,
        };
        tracing::debug!(
            task_id,
            kind = "durable",
            status = %status,
            "task transition committed"
        );
    }

    pub(super) async fn notify_observer(&self, stage: CommitStage, task_id: &str) {
        let observer = self.observer.lock().clone();
        if let Some(observer) = observer {
            observer.reached(stage, task_id).await;
        }
    }

    pub(super) fn fail_marker(&self, task_id: &str) -> bool {
        self.observer
            .lock()
            .as_ref()
            .is_some_and(|observer| observer.fail_marker(task_id))
    }

    pub(super) fn fail_state_upgrade(&self, task_id: &str) -> bool {
        self.observer
            .lock()
            .as_ref()
            .is_some_and(|observer| observer.fail_state_upgrade(task_id))
    }
}

fn commit_to_service(error: CommitFailure) -> ServiceError {
    match error {
        CommitFailure::Service(error) => error,
        CommitFailure::RevisionConflict => ServiceError::Unavailable,
    }
}
