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

use super::record::{CommittedTask, PreparedTask};
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
        if admission.import_tasks(store.restored_bindings()).is_err() {
            let _ = store.close().await;
            return Err(ServiceError::Unavailable);
        }
        Ok(Self { store, admission })
    }

    /// Admit, reserve a worker only for a new key, then prepare and commit.
    ///
    /// Admission remains the sole identity authority. Only `Owned` asks `reserve`;
    /// `Existing` returns the original handle even when the pool is saturated. A
    /// new-key worker-cap refusal writes nothing and drops the admission lease.
    /// Every store failure is `Unavailable` and releases both the permit and the
    /// unresolved publication. `Created` retains its permit for the consumer.
    pub(crate) async fn create(
        &self,
        request: Request<'_>,
        task: &Task,
        backend: &str,
        reserve: impl FnOnce() -> Option<OwnedSemaphorePermit> + Send,
    ) -> Result<CreateOutcome, ServiceError> {
        match self.admission.admit_task(request) {
            Ok(TaskAdmission::Owned(lease)) => {
                let Some(slot) = reserve() else {
                    return Ok(CreateOutcome::Capacity);
                };
                let binding = lease.binding().clone();
                let prepared =
                    PreparedTask::admitted(task, &binding, lease.into_publication(), backend);
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
            Ok(TaskAdmission::Unavailable) => Ok(CreateOutcome::Unavailable),
            Err(Refusal::Mismatch) => Ok(CreateOutcome::Mismatch),
            Err(_) => Ok(CreateOutcome::Unavailable),
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
    pub(crate) async fn update(
        &self,
        principal: &str,
        id: &str,
        _revision: u64,
        _payload: Value,
    ) -> Result<CommittedTask, ServiceError> {
        self.get(principal, id)
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
    /// the `Arc` the executor still holds.
    pub(crate) async fn shutdown(&self) -> Result<(), ServiceError> {
        self.store
            .clone()
            .close()
            .await
            .map_err(|_| ServiceError::Unavailable)
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
