// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The task executor's operations, moved whole out of the parent to keep it
//! under the file-size ceiling (MIK-8392). A pure move: every method keeps
//! its body and attributes; each visibility names the same scope it had in
//! the parent (a private method is `pub(super)` here, a `pub(super)` one is
//! `pub(in crate::gateway::task_service)`), and log events keep the parent's
//! target.

use super::{
    Arc, BeginOutcome, CancelOutcome, CommitFailure, CommitStage, CommittedTask, CreateOutcome,
    CreateWrite, DrainOutcome, Duration, EXECUTION_TARGET, ErrorAuthor, Handoff, HandoffRegistry,
    Mutex, PublicationHook, Semaphore, ServiceError, SubscriptionRegistry, Task, TaskCall,
    TaskExecutor, TaskIntent, TaskService, TaskTransition, TransitionWrite, UpstreamRecovery,
    commit_and_run, commit_to_service, is_terminal, json, oneshot, upstream,
};

// Used only by `observe_commits`, which is compiled out of release builds.
#[cfg(any(test, debug_assertions))]
use super::CommitObserver;

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
            #[cfg(test)]
            produce_seam_wait: std::sync::OnceLock::new(),
            #[cfg(test)]
            commit_hook: std::sync::OnceLock::new(),
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
    pub(crate) fn install_recovery(self: &Arc<Self>, adapter: Arc<dyn UpstreamRecovery>) -> bool {
        self.adopt_recovery(adapter)
    }

    /// Install `observer`, which the executor keeps and calls at each commit
    /// stage.
    ///
    /// An observer that reaches the `AppState` (or anything else that owns
    /// this executor) must hold it weakly and upgrade when it fires, returning
    /// without acting when the upgrade fails: the owner is gone. The
    /// executor keeps its observer, so a strong share is a cycle that is never
    /// freed: the state, its task store and the store's directory outlive the
    /// caller. In #4311 two tests left a task-store folder behind on every run
    /// this way.
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
        ))
        .await
        .map_err(|_| ServiceError::AuditUnavailable)?;
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
        // The transition-side sender (design r8 R8.4): a row that already held
        // its upstream descriptor when the cancel committed claims and sends
        // its one `tasks/cancel` here. A worker still holding an uncaptured
        // handle finds the claim taken, or takes it when this finds none.
        self.cancel_upstream_once(&task.owner_digest, id, None, upstream::CancelSend::Detach)
            .await;
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
    pub(super) async fn cancel_lost_the_revision(
        &self,
        principal: &str,
        id: &str,
    ) -> Result<CommittedTask, ServiceError> {
        let current = self.service.get(principal, id)?;
        if is_terminal(current.task.status()) {
            // A row cancelled by an earlier attempt whose claim never landed
            // still gets its one upstream cancel; any other terminal row is
            // not the claim's to take (NotOurs).
            self.cancel_upstream_once(
                &current.owner_digest,
                id,
                None,
                upstream::CancelSend::Detach,
            )
            .await;
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
                // The same transition-side sender as `cancel` above.
                self.cancel_upstream_once(
                    &task.owner_digest,
                    id,
                    None,
                    upstream::CancelSend::Detach,
                )
                .await;
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
    /// `store::StoreWriteStage` or `store::CommitHook`: `mod store` is private to
    /// this package and stays that way. The hook itself always reports success,
    /// because a hook failure is a store failure and this seam is a barrier.
    ///
    /// A barrier that reaches the `AppState` (or anything else that owns this
    /// executor or its store) must hold it weakly and upgrade when it fires,
    /// returning without acting when the upgrade fails: the store keeps the
    /// barrier, so a strong share is a cycle that is never freed, and
    /// the state, its task store and the store's directory outlive the test.
    /// In #4311 a test left a task-store folder behind on every run this way.
    #[cfg(test)]
    pub(crate) async fn barrier_on_publication(&self, barrier: Arc<dyn Fn() + Send + Sync>) {
        let hook: super::super::store::CommitHook = Arc::new(move |stage| {
            if matches!(stage, super::super::store::StoreWriteStage::Published) {
                barrier();
            }
            Ok(())
        });
        self.service.store.set_hook(Some(hook)).await;
    }

    /// Test-only: the next create fails at the store's `Published` stage,
    /// after its record is durable and its key published (MIK-8353 3c: an
    /// `Unavailable` that follows an act).
    #[cfg(test)]
    pub(crate) async fn fail_next_publication_for_test(&self) {
        use std::sync::atomic::{AtomicBool, Ordering};
        let armed = Arc::new(AtomicBool::new(true));
        let hook: super::super::store::CommitHook = Arc::new(move |stage| {
            if matches!(stage, super::super::store::StoreWriteStage::Published)
                && armed.swap(false, Ordering::SeqCst)
            {
                return Err(std::io::Error::other("injected publication failure"));
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
        let hook: super::super::store::CommitHook = Arc::new(move |stage| {
            if matches!(stage, super::super::store::StoreWriteStage::Write) {
                barrier();
            }
            Ok(())
        });
        self.service.store.set_hook(Some(hook)).await;
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
    ///
    /// MIK-8204: first, every grant decision in the caller's open slot is
    /// appended and the append has completed, so the audit log's file order
    /// shows a cause before the work it starts. Under `FailClosed` a failed
    /// append is `AuditUnavailable` and nothing is spawned; under
    /// `BestEffort` it is logged and the spawn proceeds. A caller cancelled
    /// during the append spawns nothing; its records are still written.
    ///
    /// Not an `async fn`: that would hold `worker` inline in the caller's
    /// future across the append, and `commit_and_run`'s future is large
    /// enough to overflow a debug-build stack. It is boxed before the wait.
    pub(super) fn spawn_worker(
        &self,
        worker: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> impl std::future::Future<Output = crate::Result<()>> + Send + '_ {
        let worker = Box::pin(worker);
        async move {
            crate::gateway::meta_mcp::grant_audit::flush_open_slot().await?;
            self.spawn_now(worker);
            Ok(())
        }
    }

    pub(super) fn spawn_now(&self, worker: impl std::future::Future<Output = ()> + Send + 'static) {
        // COLLUDE.1: every worker collects its relay receipts on its own
        // task; task-locals do not cross `tokio::spawn`.
        let worker = crate::gateway::meta_mcp::invoke::relay::collecting(worker);
        // MIK-8176: and owns the slots its mints take, through the durable
        // write of what it settles. The scope must travel inside the spawned
        // task, around the worker: a task-local does not cross `tokio::spawn`,
        // so a scope opened outside the spawn would leave every mint unscoped.
        // Dropping the worker on cancel (the select below) ends the scope and
        // with it the holds. Stage 4: what the worker settles or parks keeps
        // its slots on the task row (the row owns them); every other hold it
        // never handed off gives its slot back when the scope ends.
        let worker = crate::gateway::meta_mcp::sealed_hold::scoped(worker);
        // Cancellation first on every poll (MIK-7839.CANCEL.3): tokio-util's
        // `run_until_cancelled_owned` polls the worker before the token, so a
        // worker cancelled while its runtime sat idle would take one more step
        // (and could dispatch to a backend) before noticing.
        let token = self.shutdown.clone();
        #[cfg(test)]
        crate::gateway::meta_mcp::grant_audit::seams::count_worker_spawn();
        tokio::spawn(async move {
            tokio::pin!(worker);
            tokio::select! {
                biased;
                () = token.cancelled() => {}
                () = &mut worker => {}
            }
        });
        #[cfg(test)]
        crate::gateway::meta_mcp::grant_audit::seams::after_worker_spawn();
    }

    pub(super) fn cancel_signal(&self, id: &str) {
        self.handoffs.cancel_signal(id);
    }

    pub(crate) async fn commit_create(&self, write: CreateWrite<'_>) -> CreateOutcome {
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
            .await;
        if let CreateOutcome::Created { task: stored, .. } = &created {
            let id = stored.task.id().to_owned();
            self.published(stored, &id);
            self.notify_observer(CommitStage::Published, &id).await;
        }
        created
    }

    pub(crate) async fn commit_transition(
        &self,
        write: TransitionWrite<'_>,
    ) -> Result<CommittedTask, CommitFailure> {
        self.commit_dated(write, None).await
    }

    /// [`Self::commit_transition`] dating a `Settle` at `at`, a time the caller
    /// already read; `None` reads the store's clock. A worker settle that waited
    /// out a clock before 1970 commits at the time the wait read, so no later
    /// attempt reads the clock again (MIK-8202 P4a r4). `Cancel` and `Recover`
    /// keep their own dating.
    pub(in crate::gateway::task_service) async fn commit_dated(
        &self,
        write: TransitionWrite<'_>,
        at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<CommittedTask, CommitFailure> {
        #[cfg(test)]
        self.before_commit_attempt_for_test(write.id()).await;
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
                let outcome = (event, targets, writes);
                self.transition_write(principal, id, revision, outcome, author, at)
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
                // Recovery is a recorder: it dates the row at the store's
                // clock, and with none readable leaves the row for the next
                // start (MIK-8202).
                let Ok(now) = self.service.store.now() else {
                    tracing::error!(
                        target: EXECUTION_TARGET,
                        task_id = %id,
                        "host clock reads before 1970: task not settled"
                    );
                    return Err(CommitFailure::Service(ServiceError::Unavailable));
                };
                self.transition_digest_write(
                    owner_digest,
                    id,
                    revision,
                    (
                        event,
                        crate::gateway::task_service::record::Provenance::default(),
                        writes,
                    ),
                    author,
                    Some(now),
                )
                .await?
            }
            TransitionWrite::Cancel {
                principal,
                id,
                revision,
            } => {
                let cancel = || {
                    (
                        TaskTransition::Cancel,
                        crate::gateway::task_service::record::Provenance::default(),
                        crate::gateway::gateway_writes::WriteRecord::default(),
                    )
                };
                match self
                    .transition_write(
                        principal,
                        id,
                        revision,
                        cancel(),
                        ErrorAuthor::Gateway,
                        None,
                    )
                    .await
                {
                    // An owner can always cancel (MIK-8202 P4a, lead ruling): on a
                    // clock before 1970 the cancel neither waits nor refuses. It is
                    // dated at the record's own last change, a real time the record
                    // already carries, never 1969 or 0.
                    Err(CommitFailure::ClockUnreadable) => {
                        let dated = self
                            .service
                            .get(principal, id)
                            .map_err(CommitFailure::Service)?
                            .task
                            .last_updated_at();
                        self.transition_write(
                            principal,
                            id,
                            revision,
                            cancel(),
                            ErrorAuthor::Gateway,
                            Some(dated),
                        )
                        .await?
                    }
                    other => other?,
                }
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
    pub(super) async fn transition_write(
        &self,
        principal: &str,
        id: &str,
        revision: u64,
        outcome: (
            TaskTransition,
            crate::gateway::task_service::record::Provenance,
            crate::gateway::gateway_writes::WriteRecord,
        ),
        author: ErrorAuthor,
        at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(CommittedTask, bool, String), CommitFailure> {
        let owner = self
            .service
            .owner(principal)
            .map_err(CommitFailure::Service)?;
        self.transition_digest_write(owner.as_digest(), id, revision, outcome, author, at)
            .await
    }

    /// The one publication seam, reached only after a durable write that
    /// changed something: a dedupe, a no-op or a failed commit never gets here,
    /// so a listener never learns of a transition that did not happen.
    pub(in crate::gateway::task_service) fn published(&self, task: &CommittedTask, task_id: &str) {
        let (status, changed_at) = (task.task.status(), task.task.last_updated_at());
        let owner = task.owner_digest.clone();
        if let Some(hook) = self.publication_hook.get() {
            hook(task_id, status, changed_at, Some(owner));
        }
        tracing::debug!(
            target: EXECUTION_TARGET,
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

    pub(in crate::gateway::task_service) async fn notify_observer(
        &self,
        stage: CommitStage,
        task_id: &str,
    ) {
        let observer = self.observer.lock().clone();
        if let Some(observer) = observer {
            observer.reached(stage, task_id).await;
        }
    }

    pub(in crate::gateway::task_service) fn fail_marker(&self, task_id: &str) -> bool {
        self.observer
            .lock()
            .as_ref()
            .is_some_and(|observer| observer.fail_marker(task_id))
    }

    pub(in crate::gateway::task_service) fn fail_state_upgrade(&self, task_id: &str) -> bool {
        self.observer
            .lock()
            .as_ref()
            .is_some_and(|observer| observer.fail_state_upgrade(task_id))
    }
}
