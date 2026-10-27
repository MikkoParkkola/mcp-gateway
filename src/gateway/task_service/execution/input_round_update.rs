// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `tasks/update` answers to an open input round: the handoff, the store
//! write and the resume spawn.

use super::{
    Acceptance, Arc, Handoff, InputOutcome, Map, OwnedCallerContext, PRODUCE_SEAM_WAIT,
    ProvideOutcome, Resume, TaskExecutor, TaskStatus, Value, input_outcome_of, resume,
};

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
        let executor = Arc::clone(self);
        let (digest, id, principal) = (
            owner.as_digest().to_owned(),
            id.to_owned(),
            principal.to_owned(),
        );
        self.round_outcome(|tx| async move {
            #[cfg(test)]
            crate::gateway::task_service::execution::resume_seams::at(crate::gateway::task_service::execution::resume_seams::ResumePoint::Spawned).await;
            // The parked round's slot is owned by its row until
            // the resume redeems it. Adopt the row's holds into this worker's
            // scope FIRST: the completing commit below drops the row's, and
            // the slot must never be left with no owner before its redeem.
            crate::gateway::meta_mcp::sealed_hold::adopt(
                executor.service.store.round_holds(&digest, &id),
            );
            let workers = Arc::clone(&executor.workers);
            // An answer stamped on a clock before 1970 is refused for now, as
            // the store refuses it, and the round stays open.
            let store = &executor.service.store;
            let Ok(at) = store.now() else {
                // Released before the answer, as below: a retry finds it free.
                drop((handoff, cancel_rx));
                let _ = tx.send(InputOutcome::Unavailable);
                return;
            };
            let provided = store
                .provide_input(&digest, &id, answers, move || workers.try_acquire_owned().ok(), at)
                .await;
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
                        let current = executor
                            .service
                            .store
                            .get(&digest, &id)
                            .map_err(|_| crate::gateway::task_service::execution::CommitFailure::RevisionConflict)?;
                        executor
                            .close_round(&digest, &id, current.revision, closed.reason(), at)
                            .await
                    }
                    .await;
                    if let Err(crate::gateway::task_service::execution::CommitFailure::Service(error)) = settled {
                        tracing::warn!(target: "mcp_gateway::gateway::task_service::execution::input_round", task_id = %id, ?error, "closed input round not settled yet; the sweep retries");
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
        })
        .await
    }

    /// Spawn an update's worker and wait for its outcome; -32005 and no spawn
    /// when the update's grant decisions could not be written under
    /// `FailClosed`. Not an `async fn`: the worker is boxed before
    /// the wait, never held inline in the caller's future (stack overflow).
    fn round_outcome<F>(
        &self,
        worker: impl FnOnce(tokio::sync::oneshot::Sender<InputOutcome>) -> F,
    ) -> impl std::future::Future<Output = InputOutcome> + Send + '_
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let spawned = self.spawn_worker(worker(tx));
        async move {
            if spawned.await.is_err() {
                return InputOutcome::AuditUnavailable;
            }
            rx.await.unwrap_or(InputOutcome::Unavailable)
        }
    }
}
