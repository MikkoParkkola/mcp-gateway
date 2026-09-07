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

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::record::{CommittedTask, PreparedTask};
use super::store::{StoreError, StoreLimits, TaskStore};
use crate::gateway::task_service::model::{Task, TaskTransition};
use crate::idempotency::admission::{ExecutionAdmission, Request, TaskAdmission, TaskOwner};

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum ServiceError {
    #[error("task store unavailable")]
    Unavailable,
    #[error("task not found")]
    NotFound,
}

pub(super) struct TaskService {
    store: TaskStore,
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
    pub(super) async fn open(
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

    /// Admit, prepare and commit one task.
    ///
    /// The one-shot publication token travels INTO the store, so the durable
    /// record and the dedupe entry that recovers it are resolved together inside
    /// the store's cancellation-surviving section — after the record is readable
    /// and before this call returns, which is before anything could dispatch.
    pub(super) async fn create(
        &self,
        request: Request<'_>,
        task: &Task,
        backend: &str,
    ) -> Result<CommittedTask, ServiceError> {
        match self.admission.admit_task(request) {
            Ok(TaskAdmission::Owned(lease)) => {
                let binding = lease.binding().clone();
                let prepared =
                    PreparedTask::admitted(task, &binding, lease.into_publication(), backend);
                // A failed commit drops the publication unresolved, which gives
                // the reservation back rather than stranding the key.
                self.store.create(prepared).await.map_err(refused)
            }
            // The key already owns a committed task: the caller gets THAT task,
            // with the TTL and poll interval it was created with. The offered
            // task value is not committed and never becomes visible.
            Ok(TaskAdmission::Existing { task_id, binding }) => self
                .store
                .get(binding.principal_digest(), &task_id)
                .map_err(refused),
            // In flight, already settled as a synchronous execution, or refused —
            // a changed fingerprint or a mode switch is a `Mismatch` here. None of
            // them is a committed task, and this API has one answer for that.
            // Splitting them into distinct outcomes would be wire policy, which
            // is the route slice's to decide and not this one's to invent.
            Ok(TaskAdmission::InFlight | TaskAdmission::Unavailable) | Err(_) => {
                Err(ServiceError::Unavailable)
            }
        }
    }

    pub(super) fn get(&self, principal: &str, id: &str) -> Result<CommittedTask, ServiceError> {
        self.store
            .get(self.owner(principal)?.as_digest(), id)
            .map_err(refused)
    }

    /// Cancel is a durable transition: the terminal view returned here is the one
    /// that was committed, and it is what every later read sees.
    pub(super) async fn cancel(
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
    pub(super) async fn update(
        &self,
        principal: &str,
        id: &str,
        _revision: u64,
        _payload: Value,
    ) -> Result<CommittedTask, ServiceError> {
        self.get(principal, id)
    }

    pub(super) async fn close(self) -> Result<(), ServiceError> {
        self.store
            .close()
            .await
            .map_err(|_| ServiceError::Unavailable)
    }

    /// The admission-owned digest for a principal. A principal admission refuses
    /// to hash owns nothing, so it is told what anyone naming a task they do not
    /// own is told.
    fn owner(&self, principal: &str) -> Result<TaskOwner, ServiceError> {
        self.admission
            .owner(principal)
            .map_err(|_| ServiceError::NotFound)
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
