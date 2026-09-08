// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Task executor: one admission, one publication seam, one spawned owner.

mod context;
mod observe;
mod recovery;
mod settlement;
mod worker;

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::sync::{Semaphore, oneshot};

pub(crate) use context::{OwnedAdmissionRequest, OwnedCallerContext};
pub(crate) use observe::{
    CommitObserver, CommitStage, DrainOutcome, RecoveryCheckpoint, RecoveryOutcome,
    UpstreamRecovery, remaining_implementation,
};
use observe::{Handoff, HandoffRegistry};
/// Reachable at the visibility of [`TaskExecutor::commit`], which returns it.
pub(crate) use worker::CommitFailure;
use worker::commit_and_run;

use super::record::CommittedTask;
use super::service::{CreateOutcome, ServiceError, TaskService};
use crate::gateway::subscription_registry::SubscriptionRegistry;
use crate::protocol::tasks::{Task, TaskOptions, TaskStatus, TaskTransition};
use crate::protocol::{JsonRpcResponse, RequestId};

/// Default worker cap when config has not yet been wired (lane 3).
pub(crate) const DEFAULT_MAX_WORKERS: usize = 16;

pub(crate) struct TaskCall {
    pub tool: String,
    pub arguments: Value,
}

/// `'static` intent: nothing borrowed from the request-thread caller.
///
/// Public because it travels on the public `task` field of the meta-MCP caller
/// context, and opaque because nothing outside this crate can build or read
/// one: every field is `pub(crate)` and there is no constructor. An external
/// caller can still write `task: None`, which is the only shape it ever had.
pub struct TaskIntent {
    pub(crate) executor: Arc<TaskExecutor>,
    pub(crate) owned: OwnedCallerContext,
    pub(crate) request: OwnedAdmissionRequest,
    pub(crate) options: TaskOptions,
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
    /// Startup only, and the one write that names an owner by the digest the
    /// record persisted: recovery has no principal to hash, and hashing a stored
    /// digest again would address a task nobody owns.
    Recover {
        owner_digest: &'a str,
        id: &'a str,
        revision: u64,
        event: TaskTransition,
    },
}

pub(crate) enum WriteOutcome {
    Create(CreateOutcome),
    Transitioned(CommittedTask),
}

/// The one owner of a committed task record.
///
/// A `begin` accepts a handoff, spawns the future that commits and dispatches
/// it, and answers the request thread over a `oneshot`; the record belongs to
/// the spawned owner from that moment, so a request future that goes away
/// cannot take it back. [`Self::drain`] joins those owners. Nothing here closes
/// the executor: a drained executor still admits.
pub struct TaskExecutor {
    pub(crate) service: Arc<TaskService>,
    subscriptions: Arc<SubscriptionRegistry>,
    workers: Arc<Semaphore>,
    max_workers: usize,
    handoffs: HandoffRegistry,
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
            handoffs: HandoffRegistry::new(),
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
        // Ownership first, and only then the spawn: the guard is live before
        // there is a task to run it, so the window in which the executor has
        // accepted work that no drain can see does not exist.
        let (handoff, cancel_rx) = Handoff::accept(self, task.id());
        let (tx, rx) = oneshot::channel();
        tokio::spawn(commit_and_run(
            handoff, intent, task, backend, call, cancel_rx, tx,
        ));
        rx.await.map_err(|_| ServiceError::Unavailable)?
    }

    pub(crate) async fn cancel(
        &self,
        principal: &str,
        id: &str,
        revision: u64,
    ) -> Result<CommittedTask, ServiceError> {
        let outcome = match self
            .commit(TaskWrite::Cancel {
                principal,
                id,
                revision,
            })
            .await
        {
            Ok(outcome) => outcome,
            // The one race this write has: the worker settled between the
            // caller reading its revision and this transition taking the
            // store. The record is not broken and the store is not down, so
            // neither may be reported. Every other failure keeps its type.
            Err(CommitFailure::RevisionConflict) => {
                return self.cancel_lost_the_revision(principal, id).await;
            }
            Err(error) => return Err(commit_to_service(error)),
        };
        self.cancel_signal(id);
        match outcome {
            WriteOutcome::Transitioned(task) => Ok(task),
            WriteOutcome::Create(_) => Err(ServiceError::Unavailable),
        }
    }

    /// One bounded re-read after a cancel lost its revision, mirroring what
    /// `settle_cas` already does for the settle side of the same race.
    ///
    /// Already terminal: answered from the committed view, never re-cancelled
    /// and never signalled — a signal here would announce a write that did not
    /// happen. Still working: the record simply moved, so the cancel is retried
    /// once at the revision just read, and only a conflict that survives that
    /// is surrendered as unavailability. `NotFound` and a genuinely unavailable
    /// store come back through `self.service.get` with their own types.
    async fn cancel_lost_the_revision(
        &self,
        principal: &str,
        id: &str,
    ) -> Result<CommittedTask, ServiceError> {
        let current = self.service.get(principal, id)?;
        if is_terminal(current.task.status()) {
            return Ok(current);
        }
        match self
            .commit(TaskWrite::Cancel {
                principal,
                id,
                revision: current.revision,
            })
            .await
        {
            Ok(WriteOutcome::Transitioned(task)) => {
                self.cancel_signal(id);
                Ok(task)
            }
            Ok(WriteOutcome::Create(_)) => Err(ServiceError::Unavailable),
            // Bounded: the record moved again. If that move was terminal the
            // committed view is still the honest answer; otherwise this really
            // is a store nobody can write to.
            Err(CommitFailure::RevisionConflict) => {
                let latest = self.service.get(principal, id)?;
                if is_terminal(latest.task.status()) {
                    Ok(latest)
                } else {
                    Err(ServiceError::Unavailable)
                }
            }
            Err(error) => Err(commit_to_service(error)),
        }
    }

    /// Test-only bridge to the store's own `Published` commit stage, which
    /// fires between the readable-record insert and the dedupe publication —
    /// the real window in which an admitted task is `Active`.
    ///
    /// Takes no argument and returns nothing so that no caller has to name
    /// `store::CommitStage` or `store::CommitHook`: `mod store` is private to
    /// this package and stays that way. The hook itself always reports success,
    /// because a hook failure is a store failure and this seam is a barrier.
    #[cfg(test)]
    pub(crate) async fn barrier_on_publication(&self, barrier: Arc<dyn Fn() + Send + Sync>) {
        let hook: super::store::CommitHook = Arc::new(move |stage| {
            if matches!(stage, super::store::CommitStage::Published) {
                barrier();
            }
            Ok(())
        });
        self.service.store.set_hook(Some(hook)).await;
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

    /// Join every owner, then every worker permit, inside one timeout budget.
    ///
    /// Two phases and this order. Ownership is joined first because a handoff
    /// that has been accepted but not yet polled holds no permit — its capacity
    /// is reserved inside `commit`, on the spawned task — so a permit sweep
    /// alone would call an executor with queued work clean. The permits are
    /// acquired second and never first: taking the pool ahead of work that
    /// still has to reserve from it would be the deadlock, not the drain.
    ///
    /// A join, not a shutdown: nothing is closed, no admission is refused, and
    /// every permit is released before a clean answer is returned.
    pub(crate) async fn drain(&self, timeout: Duration) -> DrainOutcome {
        let join = async {
            self.handoffs.join().await;
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
        match tokio::time::timeout(timeout, join).await {
            Ok(held) => {
                let acquired = held.len();
                // Explicit, before the outcome is built: a clean drain hands
                // the whole pool back to the executor it just joined.
                drop(held);
                DrainOutcome {
                    timed_out: false,
                    acquired,
                }
            }
            Err(_) => DrainOutcome {
                timed_out: true,
                acquired: self
                    .max_workers
                    .saturating_sub(self.workers.available_permits()),
            },
        }
    }

    fn cancel_signal(&self, id: &str) {
        self.handoffs.cancel_signal(id);
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
            } => {
                self.transition_write(principal, id, revision, event)
                    .await?
            }
            // Its own arm, never merged with `Settle`: the two carry the same
            // field types and merging them would hand a stored digest to the
            // adapter that hashes a principal.
            TaskWrite::Recover {
                owner_digest,
                id,
                revision,
                event,
            } => {
                self.transition_digest_write(owner_digest, id, revision, event)
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

    /// The request-side adapter: a caller-supplied principal becomes an owner
    /// through admission's one hasher, and only then a transition. Ordinary auth
    /// is unchanged by recovery — the digest form lives below this, in
    /// `recovery::transition_digest_write`, and no request path reaches it.
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
        self.transition_digest_write(owner.as_digest(), id, revision, event)
            .await
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

/// The three states a task never leaves.
///
/// Spelled here as well as at `worker.rs:242` because that one is private to
/// the worker module; the two are the same three variants and a fourth
/// terminal status would have to be added to both by the same edit that adds
/// it to [`TaskStatus`].
fn is_terminal(status: TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
    )
}

fn commit_to_service(error: CommitFailure) -> ServiceError {
    match error {
        CommitFailure::Service(error) => error,
        CommitFailure::RevisionConflict => ServiceError::Unavailable,
    }
}
