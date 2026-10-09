// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Task executor: one admission, one publication seam, one spawned owner.

mod context;
mod expiry;
mod input_round;
mod observe;
#[cfg(debug_assertions)]
pub(crate) mod pause_hook;
mod recovery;
mod settle_followed;
mod settlement;
mod upstream;
mod worker;

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde_json::{Value, json};
use tokio::sync::{Semaphore, oneshot};

pub(crate) use context::{OwnedAdmissionRequest, OwnedCallerContext};
/// The guard the gateway holds for the periodic sweep it started.
pub(crate) use expiry::ExpirySweep;
pub(crate) use input_round::InputOutcome;
pub(crate) use observe::{
    CancelOutcome, CommitObserver, CommitStage, DrainOutcome, UpstreamAnswer, UpstreamHandle,
    UpstreamRecovery,
};
use observe::{Handoff, HandoffRegistry};
pub(in crate::gateway::task_service) use recovery::recovery_event;
pub(crate) use upstream::UpstreamCapture;
/// Reachable at the visibility of [`TaskExecutor::commit`], which returns it.
pub(crate) use worker::CommitFailure;
use worker::commit_and_run;

use super::record::{CommittedTask, ErrorAuthor, Target};
use super::service::{CreateOutcome, ServiceError, TaskService};
use crate::gateway::subscription_registry::SubscriptionRegistry;
use crate::protocol::tasks::{Task, TaskOptions, TaskStatus, TaskTransition};
use crate::protocol::{JsonRpcResponse, RequestId};

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
    /// New keyed tasks are sealed (MIK-8052).
    Sealed,
}

impl BeginOutcome {
    pub(crate) fn into_response(self, id: RequestId) -> JsonRpcResponse {
        match self {
            Self::Created(task) | Self::Existing(task) => {
                let mut value = serde_json::to_value(task.task.wire()).unwrap_or(Value::Null);
                if let Some(obj) = value.as_object_mut() {
                    obj.insert("resultType".into(), json!("task"));
                }
                // MIK-7939: the envelope is the gateway's; a receipt reads
                // only the slot it delivers.
                crate::gateway::meta_mcp::invoke::gateway_writes::note_task_envelope(&value);
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
            // The code the synchronous path gives a sealed call, so a client
            // sees one refusal for it on either path.
            Self::Sealed => {
                JsonRpcResponse::error(Some(id), 409, crate::idempotency::admission::SEALED_MESSAGE)
            }
        }
    }
}

/// A write that creates a task. Its own type, not a variant of the transitions:
/// what a create can answer (created, existing, refused) and what a transition
/// can answer (the committed record) never overlap, so neither caller has an
/// arm for the other's outcome.
pub(crate) struct CreateWrite<'a> {
    pub(crate) request: &'a OwnedAdmissionRequest,
    pub(crate) task: &'a Task,
    pub(crate) backend: &'a str,
    /// The single backend call the task makes, when it makes exactly one.
    pub(crate) targets: Vec<Target>,
}

/// A write that moves an existing task. It answers with the committed record.
pub(crate) enum TransitionWrite<'a> {
    Settle {
        principal: &'a str,
        id: &'a str,
        revision: u64,
        event: TaskTransition,
        /// A plan's dispatched calls, committed in the same write as its
        /// outcome. `None` for a call whose target was recorded at creation.
        targets: Option<Vec<Target>>,
        /// Who wrote a `Fail` event's error (MIK-7887.RECEIPT.1).
        author: ErrorAuthor,
        /// The members of a `Complete` result the gateway wrote (MIK-7993).
        writes: crate::gateway::gateway_writes::WriteRecord,
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
        /// Who wrote a `Fail` event's error (MIK-7887.RECEIPT.1).
        author: ErrorAuthor,
        /// The members of a recovered `Complete` result the gateway wrote
        /// while processing it (MIK-7993); empty for a startup settlement.
        writes: crate::gateway::gateway_writes::WriteRecord,
    },
}

/// A callback told of each committed task transition.
pub(crate) type PublicationHook =
    Arc<dyn Fn(&str, TaskStatus, chrono::DateTime<chrono::Utc>, Option<String>) + Send + Sync>;

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
    /// Installed AFTER the backends are started, from `server/mod.rs`, because
    /// an adapter needs a live backend registry and `open` runs before one
    /// exists. `OnceLock` rather than a constructor field for exactly that
    /// ordering, and write-once so a running gateway cannot have its trusted
    /// recovery vocabulary swapped underneath an in-flight read.
    recovery: std::sync::OnceLock<Arc<dyn UpstreamRecovery>>,
    /// One in-flight upstream query per record. `tasks/get` is read-only, but
    /// two concurrent reads of the same row would each commit the outcome, and
    /// the second would find a revision that moved.
    query_gate: tokio::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    observer: Mutex<Option<Arc<dyn CommitObserver>>>,
    /// Told of every committed transition (the events source), once installed.
    publication_hook: std::sync::OnceLock<PublicationHook>,
    /// The adapters startup recovery deferred to, kept so the sweep that
    /// serves a repaired row decides the same way (MIK-8121). Write-once.
    pub(super) managed: std::sync::OnceLock<Arc<[String]>>,
    /// Cancelled once, by a shutdown whose drain ran out; every worker runs
    /// under it ([`Self::spawn_worker`]).
    shutdown: tokio_util::sync::CancellationToken,
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
            recovery: std::sync::OnceLock::new(),
            query_gate: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            observer: Mutex::new(None),
            publication_hook: std::sync::OnceLock::new(),
            managed: std::sync::OnceLock::new(),
            shutdown: tokio_util::sync::CancellationToken::new(),
        })
    }

    /// Install the callback told of each committed transition with the task
    /// id, its new status and its last-change time. Write-once.
    pub(crate) fn on_publication(&self, hook: PublicationHook) -> bool {
        self.publication_hook.set(hook).is_ok()
    }

    /// Serve the sealed rows an operator repaired (MIK-8121), deciding a live
    /// one as startup did, and announce each row settled on the way.
    pub(crate) async fn reread_sealed(&self) {
        let managed = self.managed.get().cloned().unwrap_or_else(|| Arc::from([]));
        for committed in self.service.reread_sealed_deferring(managed).await {
            let id = committed.task.id().to_owned();
            self.published(&committed, &id);
        }
    }

    pub(crate) fn recovery(&self) -> Option<&Arc<dyn UpstreamRecovery>> {
        self.recovery.get()
    }

    /// Install the trusted upstream adapter, once, before the socket serves.
    ///
    /// Returns whether this call installed it. With none installed every path
    /// below is skipped and recovery behaviour is byte-identical to I3's.
    pub(crate) fn install_recovery(&self, adapter: Arc<dyn UpstreamRecovery>) -> bool {
        self.recovery.set(adapter).is_ok()
    }

    #[cfg(any(test, debug_assertions))]
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
        // A fresh id: nobody else can own it, so a refusal is not reachable.
        let (handoff, cancel_rx) =
            Handoff::try_accept(self, task.id()).ok_or(ServiceError::Unavailable)?;
        let (tx, rx) = oneshot::channel();
        self.spawn_worker(commit_and_run(
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
        let task = match self
            .commit_transition(TransitionWrite::Cancel {
                principal,
                id,
                revision,
            })
            .await
        {
            Ok(task) => task,
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
        Ok(task)
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
        self.notify_observer(CommitStage::CancelRetry, id).await;
        match self
            .commit_transition(TransitionWrite::Cancel {
                principal,
                id,
                revision: current.revision,
            })
            .await
        {
            Ok(task) => {
                self.cancel_signal(id);
                Ok(task)
            }
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

    /// Test-only twin of [`Self::barrier_on_publication`] at the store's
    /// `Write` stage: the first step of every record write, before the payload
    /// is written and before the readable row changes. A barrier held here
    /// holds an owner between taking its handoff and committing its write.
    #[cfg(test)]
    pub(crate) async fn barrier_on_record_write(&self, barrier: Arc<dyn Fn() + Send + Sync>) {
        let hook: super::store::CommitHook = Arc::new(move |stage| {
            if matches!(stage, super::store::CommitStage::Write) {
                barrier();
            }
            Ok(())
        });
        self.service.store.set_hook(Some(hook)).await;
    }

    /// Test-only: how many tasks are subscribed to the handoff release signal
    /// right now, so a test can tell that an update has parked in its wait.
    #[cfg(test)]
    pub(crate) fn release_waiters_for_test(&self) -> usize {
        self.handoffs.release_waiters()
    }

    /// Test-only: the recovery descriptor a dispatch made durable for `id`.
    ///
    /// The one seam through which a route-level regression can tell "the
    /// candidate fitted and its descriptor was written" from "the candidate
    /// fitted, the backend ran, and the row is unrecoverable" — two outcomes
    /// that are identical at the wire. Kept here rather than in the suite so
    /// that `mod store` stays private to this package.
    #[cfg(test)]
    pub(crate) fn durable_upstream_for_test(
        &self,
        id: &str,
    ) -> Option<super::record::UpstreamRecord> {
        self.service.store.upstream_for_test(id)
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

    /// End every worker spawned from now on before its first step, which is what
    /// refuses a late task start (its `begin` answers `Unavailable`).
    pub(crate) fn seal(&self) {
        self.shutdown.cancel();
    }

    /// Whether [`Self::seal`] or a cancelling shutdown has closed admission.
    #[cfg(test)]
    pub(crate) fn is_sealed(&self) -> bool {
        self.shutdown.is_cancelled()
    }

    /// Cancel every worker still running and wait, up to `bound`, for each of
    /// them to end.
    ///
    /// Terminal for this executor: the token is never reset, so a worker
    /// spawned afterwards is dropped before its first step and its `begin`
    /// answers `Unavailable`. A cancelled worker's future is dropped at the
    /// await it is parked on; its handoff and permit go with it, which is what
    /// the join observes. A store write it had started runs to its end inside
    /// `spawn_blocking`, and closing the store joins it.
    pub(crate) async fn cancel_remaining(&self, bound: Duration) -> CancelOutcome {
        let cancelled = self.handoffs.len();
        self.seal();
        let stopped = tokio::time::timeout(bound, self.handoffs.join())
            .await
            .is_ok();
        CancelOutcome { cancelled, stopped }
    }

    /// Spawn a task worker under the shutdown token. Every worker goes through
    /// here, so none can outlive a shutdown that cancelled the rest.
    fn spawn_worker(&self, worker: impl std::future::Future<Output = ()> + Send + 'static) {
        // COLLUDE.1: every worker collects its relay receipts on its own
        // task; task-locals do not cross `tokio::spawn`.
        let worker = crate::gateway::meta_mcp::invoke::relay::collecting(worker);
        // MIK-8176: and owns the slots its mints take, through the durable
        // write of what it settles.
        let worker = crate::gateway::meta_mcp::sealed_hold::scoped(worker);
        tokio::spawn(self.shutdown.clone().run_until_cancelled_owned(worker));
    }

    fn cancel_signal(&self, id: &str) {
        self.handoffs.cancel_signal(id);
    }

    pub(crate) async fn commit_create(
        &self,
        write: CreateWrite<'_>,
    ) -> Result<CreateOutcome, CommitFailure> {
        let CreateWrite {
            request,
            task,
            backend,
            targets,
        } = write;
        let workers = Arc::clone(&self.workers);
        let created = self
            .service
            .create_targeted(request.borrow(), task, (backend, targets), move || {
                workers.try_acquire_owned().ok()
            })
            .await
            .map_err(CommitFailure::Service)?;
        if let CreateOutcome::Created { task: stored, .. } = &created {
            let id = stored.task.id().to_owned();
            self.published(stored, &id);
            self.notify_observer(CommitStage::Published, &id).await;
        }
        Ok(created)
    }

    pub(crate) async fn commit_transition(
        &self,
        write: TransitionWrite<'_>,
    ) -> Result<CommittedTask, CommitFailure> {
        let (committed, changed, id) = match write {
            TransitionWrite::Settle {
                principal,
                id,
                revision,
                event,
                targets,
                author,
                writes,
            } => {
                self.transition_write(principal, id, revision, (event, targets, writes), author)
                    .await?
            }
            // Its own arm, never merged with `Settle`: the two carry the same
            // field types and merging them would hand a stored digest to the
            // adapter that hashes a principal.
            TransitionWrite::Recover {
                owner_digest,
                id,
                revision,
                event,
                author,
                writes,
            } => {
                self.transition_digest_write(
                    owner_digest,
                    id,
                    revision,
                    (event, None, writes),
                    author,
                )
                .await?
            }
            TransitionWrite::Cancel {
                principal,
                id,
                revision,
            } => {
                self.transition_write(
                    principal,
                    id,
                    revision,
                    (
                        TaskTransition::Cancel,
                        None,
                        crate::gateway::gateway_writes::WriteRecord::default(),
                    ),
                    ErrorAuthor::Gateway,
                )
                .await?
            }
        };
        if changed {
            self.published(&committed, &id);
            self.notify_observer(CommitStage::Transitioned, &id).await;
        }
        Ok(committed)
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
        outcome: (
            TaskTransition,
            Option<Vec<Target>>,
            crate::gateway::gateway_writes::WriteRecord,
        ),
        author: ErrorAuthor,
    ) -> Result<(CommittedTask, bool, String), CommitFailure> {
        let owner = self
            .service
            .owner(principal)
            .map_err(CommitFailure::Service)?;
        self.transition_digest_write(owner.as_digest(), id, revision, outcome, author)
            .await
    }

    /// The one publication seam, reached only after a durable write that
    /// changed something: a dedupe, a no-op or a failed commit never gets here,
    /// so a listener never learns of a transition that did not happen.
    pub(super) fn published(&self, task: &CommittedTask, task_id: &str) {
        let (status, changed_at) = (task.task.status(), task.task.last_updated_at());
        let owner = task.owner_digest.clone();
        if let Some(hook) = self.publication_hook.get() {
            hook(task_id, status, changed_at, Some(owner));
        }
        tracing::debug!(
            task_id,
            kind = "durable",
            status = ?status,
            "task transition committed"
        );
        // The status travels as the model serialises it, never as a debug
        // string: a client reading `Completed` here and `completed` from
        // `tasks/get` would be reading two vocabularies for one record.
        self.subscriptions.publish(json!({
            "jsonrpc": "2.0",
            "method": "notifications/tasks",
            "params": { "taskId": task_id, "status": status },
        }));
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
/// Spelled here as well as at `worker.rs:510` because that one is private to
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

#[cfg(test)]
mod scope_tests;
