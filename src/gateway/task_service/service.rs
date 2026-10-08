// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The task facade: admission owns identity, the store owns durability.
//!
//! This type derives nothing. Every principal digest comes from the admission
//! authority's one hasher and every persisted digest comes from the binding that
//! authorized the task, so ownership here is a comparison rather than a second
//! opinion. A foreign owner and an absent task are answered identically, which
//! is a property of the store's own lookup and is not re-decided per operation.
//!
//! Route wiring, input-required rounds, notifications, subscription filtering and
//! expiry startup belong to later increments and each has its own AC row. What is
//! here is create, owner-authorized read, cancel and the accept-and-acknowledge
//! update, over a real store in a real directory.

use std::path::Path;
use std::sync::Arc;

use serde_json::Value;
use tokio::sync::OwnedSemaphorePermit;

use super::record::{CommittedTask, PreparedTask, Target};
use super::store::{StoreError, StoreLimits, TaskStore};
use crate::idempotency::admission::{
    ExecutionAdmission, Refusal, Request, TaskAdmission, TaskOwner,
};
use crate::protocol::tasks::Task;

#[cfg(test)]
use crate::protocol::tasks::TaskTransition;
#[cfg(test)]
use chrono::{DateTime, Utc};

/// Internal create facade. Worker-cap excess is `Capacity`; every store failure
/// is `Unavailable`. `Created` carries the reserved permit out to its consumer.
pub(crate) enum CreateOutcome {
    Created {
        task: CommittedTask,
        slot: OwnedSemaphorePermit,
    },
    Existing(CommittedTask),
    Mismatch,
    InFlight,
    Capacity,
    Unavailable,
    /// New keyed tasks are sealed (MIK-8052).
    Sealed,
}

/// Why a task-service operation could not be carried out.
///
/// Public because [`super::open_runtime`] is the crate's startup entry point and
/// returns it; a private error type there would be a private type escaping
/// through a public signature, and no caller outside the crate could name what
/// an open failed with.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ServiceError {
    /// The durable store could not be opened, read, or written. Never swapped
    /// for a volatile store: an unavailable store stays unavailable.
    #[error("task store unavailable")]
    Unavailable,
    /// No task with that id is visible to the asking owner. A foreign owner and
    /// an absent task are answered identically.
    #[error("task not found")]
    NotFound,
}

/// Durable task ownership and transitions backed by an exclusively leased
/// store and the execution admission authority supplied at startup.
pub struct TaskService {
    pub(crate) store: TaskStore,
    admission: Arc<ExecutionAdmission>,
    /// This service's own share of the caller's admission seal: its stored
    /// rows whose key nobody can read (MIK-8052). Moved by re-reads, released
    /// once at shutdown; a share another holder placed is never touched.
    /// `None` once released: a re-read that finishes after shutdown cannot
    /// put a share back (seat-2 review).
    sealed: Arc<parking_lot::Mutex<Option<usize>>>,
}

impl TaskService {
    /// Open the durable store and hand its committed ownership bindings to
    /// admission BEFORE serving anything.
    ///
    /// The import is one transaction, and the caller may hold its own `Arc` to
    /// this admission index: a startup that fails leaves that shared index
    /// exactly as it found it rather than half-populated. Custody follows the
    /// same rule — a service that never came up gives the directory lease back
    /// instead of holding it for the process's lifetime.
    pub(crate) async fn open(
        path: &Path,
        limits: StoreLimits,
        admission: Arc<ExecutionAdmission>,
    ) -> Result<Self, ServiceError> {
        let store = TaskStore::open(path, limits)
            .await
            .map_err(|_| ServiceError::Unavailable)?;
        // Sealed BEFORE the import, so no admission is ever answered without
        // the seal; and apart from it, because the import returns early on an
        // empty batch and a store whose only rows are sealed must still seal.
        // A refused import puts the previous seal back: the caller's index is
        // left exactly as it was found.
        let sealed = store.skipped_records().sealed;
        admission.adjust_sealed(0, sealed);
        if admission.import_tasks(&store.restored_bindings()).is_err() {
            admission.adjust_sealed(sealed, 0);
            let _ = store.close().await;
            return Err(ServiceError::Unavailable);
        }
        Ok(Self {
            store,
            admission,
            sealed: Arc::new(parking_lot::Mutex::new(Some(sealed))),
        })
    }

    /// [`Self::reread_sealed_deferring`] with no managed adapters: the tests'
    /// shorthand.
    #[cfg(test)]
    pub(crate) async fn reread_sealed(&self) -> Vec<CommittedTask> {
        self.reread_sealed_deferring(Arc::from([])).await
    }

    /// Read the sealed rows again and lower the seal only after any repaired
    /// row's key is imported, so that key is never admitted as new in between
    /// (MIK-8052). Runs on every expiry sweep; a store with nothing sealed
    /// returns at once. A repaired row that restores is served again, a live
    /// one first settled as startup recovery would
    /// (MIK-8121). Returns the rows settled, for the caller to announce.
    /// A live row whose backend is in `managed` is deferred, exactly as
    /// startup recovery does.
    pub(crate) async fn reread_sealed_deferring(
        &self,
        managed: Arc<[String]>,
    ) -> Vec<CommittedTask> {
        // Imported under the share's lock, and only while this service still
        // holds a share: once shutdown released it, custody is gone and no key
        // is published on the caller's authority. Lock order is share, then
        // admission, as in `move_seal` and `release_seal`.
        let (share, admission) = (Arc::clone(&self.sealed), Arc::clone(&self.admission));
        let (sealed, settled) = self
            .store
            .reread_sealed(
                move |binding, id| {
                    let share = share.lock();
                    share.is_some() && admission.import_tasks(&[(binding, id)]).is_ok()
                },
                move |row| super::execution::recovery_event(row, &managed),
            )
            .await;
        self.move_seal(sealed);
        settled
    }

    /// Move this service's share of the seal to `rows`, under its own lock so
    /// two moves never interleave.
    fn move_seal(&self, rows: usize) {
        if let Some(mine) = self.sealed.lock().as_mut() {
            self.admission.adjust_sealed(*mine, rows);
            *mine = rows;
        }
    }

    /// Release this service's share for good: once, and no move after it.
    fn release_seal(&self) {
        if let Some(mine) = self.sealed.lock().take() {
            self.admission.adjust_sealed(mine, 0);
        }
    }

    /// Seal `name` as the load would, and seal admission with it (MIK-8052).
    #[cfg(test)]
    pub(crate) fn seal_for_test(&self, name: &str) {
        self.store.seal_for_test(name);
        self.move_seal(self.store.skipped_records().sealed);
    }

    /// The rows the store skipped when it opened (MIK-8023).
    pub(crate) fn skipped_records(&self) -> super::store::SkippedRecords {
        self.store.skipped_records()
    }

    /// The admin `/health` view of the task store (MIK-8052): how many rows
    /// are sealed, the exact file of each, and the one action that clears
    /// them, so an operator never has to hunt.
    pub(crate) fn health_view(&self) -> serde_json::Value {
        let files: Vec<String> = self
            .store
            .sealed_files()
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        serde_json::json!({
            "sealed_rows": files.len(),
            "sealed_files": files,
            "action": "repair or remove each file; new keyed calls resume and a repaired task reads again at the next expiry sweep",
        })
    }

    /// Admit, reserve a worker only for a new key, then prepare and commit.
    ///
    /// Admission remains the sole identity authority. Only `Owned` asks `reserve`;
    /// `Existing` returns the original handle even when the pool is saturated. A
    /// new-key worker-cap refusal writes nothing and drops the admission lease.
    /// Every store failure is `Unavailable` and releases both the permit and the
    /// unresolved publication. `Created` retains its permit for the consumer.
    #[cfg(test)]
    pub(crate) async fn create(
        &self,
        request: Request<'_>,
        task: &Task,
        backend: &str,
        reserve: impl FnOnce() -> Option<OwnedSemaphorePermit> + Send,
    ) -> Result<CreateOutcome, ServiceError> {
        self.create_targeted(request, task, (backend, Vec::new()), reserve)
            .await
    }

    /// [`Self::create`] recording the backend calls the task will make (#2450).
    pub(crate) async fn create_targeted(
        &self,
        request: Request<'_>,
        task: &Task,
        (backend, targets): (&str, Vec<Target>),
        reserve: impl FnOnce() -> Option<OwnedSemaphorePermit> + Send,
    ) -> Result<CreateOutcome, ServiceError> {
        match self.admission.admit_task(request) {
            Ok(TaskAdmission::Owned(lease)) => {
                let Some(slot) = reserve() else {
                    return Ok(CreateOutcome::Capacity);
                };
                let binding = lease.binding().clone();
                let prepared = PreparedTask::admitted_with_targets(
                    task,
                    &binding,
                    lease.into_publication(),
                    backend,
                    targets,
                );
                // A failed commit drops the publication unresolved, which gives
                // the reservation back rather than stranding the key. The permit
                // is dropped with this arm so a store refusal cannot keep a worker.
                match self.store.create(prepared).await {
                    Ok(committed) => Ok(CreateOutcome::Created {
                        task: committed,
                        slot,
                    }),
                    Err(_) => Ok(CreateOutcome::Unavailable),
                }
            }
            // The key already owns a committed task: the caller gets THAT task,
            // with the TTL and poll interval it was created with. The offered
            // task value is not committed and never becomes visible. No worker
            // is reserved — a repeat must not compete with the running task.
            Ok(TaskAdmission::Existing { task_id, binding }) => {
                match self.store.get(binding.principal_digest(), &task_id) {
                    Ok(committed) => Ok(CreateOutcome::Existing(committed)),
                    Err(_) => Ok(CreateOutcome::Unavailable),
                }
            }
            Ok(TaskAdmission::InFlight) => Ok(CreateOutcome::InFlight),
            Ok(TaskAdmission::Sealed) => Ok(CreateOutcome::Sealed),
            Err(Refusal::Mismatch) => Ok(CreateOutcome::Mismatch),
            Ok(TaskAdmission::Unavailable) | Err(_) => Ok(CreateOutcome::Unavailable),
        }
    }

    pub(crate) fn get(&self, principal: &str, id: &str) -> Result<CommittedTask, ServiceError> {
        self.store
            .get(self.owner(principal)?.as_digest(), id)
            .map_err(refused)
    }

    /// Whether `principal` owns every listed id.
    ///
    /// All-or-nothing: a partial yes would leak which of the listed ids exist.
    #[must_use]
    pub(crate) fn owns_all<'a>(
        &self,
        principal: &str,
        ids: impl IntoIterator<Item = &'a str>,
    ) -> bool {
        let Ok(owner) = self.owner(principal) else {
            return false;
        };
        ids.into_iter()
            .all(|id| self.store.get(owner.as_digest(), id).is_ok())
    }

    /// Cancel is a durable transition: the terminal view returned here is the one
    /// that was committed, and it is what every later read sees.
    ///
    /// Request-path cancel goes through [`super::execution::TaskExecutor::cancel`],
    /// which also signals the owning worker. This method is the isolated facade
    /// the service tests drive.
    #[cfg(test)]
    pub(crate) async fn cancel(
        &self,
        principal: &str,
        id: &str,
        revision: u64,
        at: DateTime<Utc>,
    ) -> Result<CommittedTask, ServiceError> {
        let owner = self.owner(principal)?;
        self.store
            .transition(owner.as_digest(), id, revision, TaskTransition::Cancel, at)
            .await
            .map_err(refused)
    }

    /// `tasks/update` is accept-and-acknowledge in 4.0: ownership is checked and
    /// the committed view is handed back unchanged.
    ///
    /// Nothing is written. §13.3 fixes TTL and poll interval as immutable, so an
    /// acknowledgement that moved either — or the revision, or the serialized
    /// task — would be a lifecycle change wearing an acknowledgement. The payload
    /// belongs to the input-required round that will consume it; interpreting it
    /// here would be that round's AC row answered by the wrong increment.
    pub(crate) fn update(
        &self,
        principal: &str,
        id: &str,
        _revision: u64,
        _payload: Value,
    ) -> impl std::future::Future<Output = Result<CommittedTask, ServiceError>> {
        std::future::ready(self.get(principal, id))
    }

    /// Tests own a by-value service. Production holds `Arc<TaskService>` and
    /// releases custody through [`Self::shutdown`].
    #[cfg(test)]
    pub(crate) async fn close(self) -> Result<(), ServiceError> {
        self.store
            .close()
            .await
            .map_err(|_| ServiceError::Unavailable)
    }

    /// Join in-flight writers and release the directory lease without consuming
    /// the `Arc` the executor still holds. The seal this store set goes back
    /// with it: a caller that keeps its admission authority after a startup
    /// that failed past the open (stdio serves on without a task store) must
    /// not keep refusing every new keyed call (MIK-8052).
    pub(crate) async fn shutdown(&self) -> Result<(), ServiceError> {
        let closed = self
            .store
            .clone()
            .close()
            .await
            .map_err(|_| ServiceError::Unavailable);
        self.release_seal();
        closed
    }

    /// The admission authority, for read-only questions.
    ///
    /// Handed out as a shared reference so a caller can ask what is already
    /// admitted without being able to admit: `&ExecutionAdmission` exposes
    /// `published_task_for` and the reclaim/settle paths this service already
    /// drives, and no lease can be minted through it that is not minted here.
    pub(crate) fn admission(&self) -> &ExecutionAdmission {
        &self.admission
    }

    /// Lend the same shared authority to the store's owned expiry transaction.
    pub(super) fn admission_arc(&self) -> &Arc<ExecutionAdmission> {
        &self.admission
    }

    /// The admission-owned digest for a principal. A principal admission refuses
    /// to hash owns nothing, so it is told what anyone naming a task they do not
    /// own is told.
    // A method, not an associated function: callers hold a service and should
    // not have to name the admission type to learn who owns a task.
    #[expect(clippy::unused_self, reason = "the service is the caller's vocabulary")]
    pub(crate) fn owner(&self, principal: &str) -> Result<TaskOwner, ServiceError> {
        ExecutionAdmission::owner(principal).map_err(|_| ServiceError::NotFound)
    }
}

/// The store's refusals, narrowed to what a caller may learn. Absence — which is
/// also how the store answers a foreign owner — is the only named outcome; every
/// other failure is unavailability rather than a description of the store.
fn refused(error: StoreError) -> ServiceError {
    match error {
        StoreError::NotFound => ServiceError::NotFound,
        _ => ServiceError::Unavailable,
    }
}
