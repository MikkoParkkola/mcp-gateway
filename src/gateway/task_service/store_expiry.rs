// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restart enumeration and conditional durable expiry of stored tasks.

use std::fs;
use std::io;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use super::super::record::{InterruptedTask, MARKER_VERSION, UPSTREAM_VERSION};
use super::platform::sync_dir;
use super::{CommitStage, Shared, StoreError, TaskStore, fire, record_name};
use crate::protocol::tasks::TaskStatus;

/// The admission binding a stored admission block describes.
fn binding_of(
    admission: &super::super::record::AdmissionRecord,
) -> crate::idempotency::admission::RestoredBinding {
    crate::idempotency::admission::RestoredBinding {
        identity: admission.identity_digest.clone(),
        principal_digest: admission.principal_digest.clone(),
        operation: admission.operation_digest.clone(),
        representation: admission.representation_digest.clone(),
        metadata_bytes: admission.metadata_bytes,
    }
}

/// The S1 store surface: restart enumeration and the conditional durable expiry
/// that couples a record's deletion to its dedupe entry.
impl TaskStore {
    /// Every committed record's persisted binding, paired with its task id, for
    /// startup import BEFORE serving. Owned values: the state they are read from
    /// lives behind a mutex.
    pub(in crate::gateway::task_service) fn restored_bindings(
        &self,
    ) -> Vec<(crate::idempotency::admission::RestoredBinding, String)> {
        let state = self.0.state();
        // A row skipped at load whose key is kept is imported like any other:
        // a retry finds its task id, which reads as not found (MIK-8023).
        state
            .entries
            .iter()
            .map(|(id, entry)| (&entry.record.admission, id))
            .chain(state.reserved.iter().map(|(admission, id)| (admission, id)))
            .map(|(admission, id)| (binding_of(admission), id.clone()))
            .collect()
    }

    /// Read every sealed row again (MIK-8052), off the runtime, and apply what
    /// it found: a removed file leaves the seal; a repaired row whose binding
    /// `import` accepts joins the reserved rows. `import` runs outside the
    /// store's lock. Returns how many rows stay sealed, for the caller to hand to
    /// admission AFTER any import, so a repaired key is never left unguarded.
    pub(in crate::gateway::task_service) async fn reread_sealed(
        &self,
        import: impl Fn(crate::idempotency::admission::RestoredBinding, String) -> bool,
    ) -> usize {
        let names: Vec<String> = self.0.state().sealed.iter().cloned().collect();
        if names.is_empty() {
            return 0;
        }
        let shared = Arc::clone(&self.0);
        let found = tokio::task::spawn_blocking(move || {
            names
                .into_iter()
                .map(|name| {
                    let outcome = super::disk::reread_record(&shared.dir, &name, shared.limits);
                    (name, outcome)
                })
                .collect::<Vec<_>>()
        })
        .await
        .unwrap_or_default();
        for (name, outcome) in found {
            let kept = match outcome {
                super::disk::Reread::Sealed => continue,
                super::disk::Reread::Gone => None,
                super::disk::Reread::Repaired(admission, id) => {
                    if !import(binding_of(&admission), id.clone()) {
                        tracing::error!(record = %name, "repaired task record's key is refused by admission; it stays sealed");
                        continue;
                    }
                    Some((admission, id))
                }
            };
            tracing::warn!(record = %name, repaired = kept.is_some(), "sealed task record cleared");
            let mut state = self.0.state();
            state.sealed.remove(&name);
            state.reserved.extend(kept);
        }
        let sealed = self.0.state().sealed.len();
        #[allow(clippy::cast_precision_loss)]
        telemetry_metrics::gauge!("mcp_task_store_skipped_records", "class" => "sealed")
            .set(sealed as f64);
        sealed
    }

    /// The rows the load skipped, for the startup report (MIK-8023).
    pub(crate) fn skipped_records(&self) -> super::SkippedRecords {
        let state = self.0.state();
        super::SkippedRecords {
            reserved: state.reserved.len(),
            sealed: state.sealed.len(),
        }
    }

    /// Every row a previous process left mid-flight, for startup recovery BEFORE
    /// serving. Terminal rows are not selected at all, which is what keeps a
    /// settled record — and a second startup — free of any rewrite.
    pub(in crate::gateway::task_service) fn interrupted(&self) -> Vec<InterruptedTask> {
        let state = self.0.state();
        state
            .entries
            .iter()
            .filter(|(_, entry)| {
                matches!(
                    entry.task.status(),
                    TaskStatus::Working | TaskStatus::InputRequired
                )
            })
            .map(|(id, entry)| InterruptedTask {
                id: id.clone(),
                owner_digest: entry.record.admission.principal_digest.clone(),
                revision: entry.record.revision,
                never_dispatched: entry.task.status() == TaskStatus::Working
                    && entry.record.version >= MARKER_VERSION
                    && !entry.record.dispatched,
                is_working: entry.task.status() == TaskStatus::Working,
                // Only a v3+ row whose descriptor still names this record's
                // admitted operation is offered as recoverable. Everything else
                // reads as absent and takes the unchanged I3 table.
                upstream: (entry.record.version >= UPSTREAM_VERSION)
                    .then(|| entry.record.upstream.clone())
                    .flatten()
                    .filter(|upstream| upstream.consistent_with(&entry.record.admission)),
            })
            .collect()
    }

    /// Every record the periodic owner may delete at `now`: terminal, and past
    /// the retention its own creation stamped.
    ///
    /// Compact owned pairs, and the state lock is released with the snapshot —
    /// each deletion re-reads the record under the store's own ordering lock, so
    /// a pair that has since moved or gone is refused there rather than acted on
    /// from this view. Nothing here reads the directory: the committed image is
    /// the only enumeration this store has.
    pub(in crate::gateway::task_service) fn expired_candidates(
        &self,
        now: DateTime<Utc>,
    ) -> Vec<(String, u64)> {
        let state = self.0.state();
        if !state.ready {
            return Vec::new();
        }
        state
            .entries
            .iter()
            .filter(|(_, entry)| {
                matches!(
                    entry.task.status(),
                    TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
                ) && entry.task.retention_elapsed(now)
            })
            .map(|(id, entry)| (id.clone(), entry.record.revision))
            .collect()
    }

    /// Delete one terminal record and drop its dedupe entry TOGETHER, per §13.3.
    ///
    /// `revision` is the caller's expectation and is checked before anything is
    /// deleted, so a task that moved on is refused rather than removed. Nothing
    /// here resets a TTL or a poll interval: expiry ends a task's life, it does
    /// not extend it.
    pub(in crate::gateway::task_service) async fn expire(
        &self,
        id: &str,
        revision: u64,
        admission: &Arc<crate::idempotency::admission::ExecutionAdmission>,
    ) -> Result<(), StoreError> {
        let shared = Arc::clone(&self.0);
        let id = id.to_owned();
        let admission = Arc::clone(admission);
        tokio::task::spawn_blocking(move || shared.expire_blocking(&id, revision, &admission))
            .await
            .map_err(|_| StoreError::Storage)?
    }
}

impl Shared {
    /// The expiry transaction. The admission guard is opened AFTER the store's
    /// ordering lock and BEFORE the deletion, and held across the COMPLETE
    /// deletion commit — unlink, directory sync, readable-state removal — and
    /// the dedupe release. `admit_task` takes that same mutex, so no admission
    /// path can observe a half-finished expiry.
    ///
    /// The guard never crosses an `await`: this whole function runs inside one
    /// `spawn_blocking` closure.
    fn expire_blocking(
        &self,
        id: &str,
        revision: u64,
        admission: &Arc<crate::idempotency::admission::ExecutionAdmission>,
    ) -> Result<(), StoreError> {
        let _order = self.order();
        let identity = {
            let state = self.state();
            if !state.ready {
                return Err(StoreError::Unavailable);
            }
            let entry = state.entries.get(id).ok_or(StoreError::NotFound)?;
            if entry.record.revision != revision {
                return Err(StoreError::RevisionConflict);
            }
            // Conditional on the record being terminal: a running task is not
            // expiry's to end.
            if !matches!(
                entry.task.status(),
                TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
            ) {
                return Err(StoreError::InvalidTransition);
            }
            entry.record.admission.identity_digest.clone()
        };

        let guard = admission.expiry_guard(&identity);
        match guard.published_task() {
            // The dedupe entry must name THIS task: an identity that owns some
            // other id is not this record's, and deleting it would strand both.
            Some((task_id, _)) if task_id == id => {}
            _ => return Err(StoreError::NotFound),
        }

        // An already-absent record is a deletion to FINISH, not an error: a
        // previous attempt whose directory sync failed left exactly that state,
        // and refusing it would strand the entry and its capacity until restart.
        let path = self.dir.join(record_name(id));
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(%error, task = %id, "task record not deleted");
                return Err(StoreError::Storage);
            }
        }
        let hook = self.hook();
        fire(hook.as_ref(), CommitStage::DirectorySync)
            .and_then(|()| sync_dir(&self.dir))
            .map_err(|error| {
                tracing::warn!(%error, task = %id, "task record deletion not made durable");
                StoreError::Storage
            })?;
        fire(hook.as_ref(), CommitStage::Deleted).map_err(|_| StoreError::Storage)?;

        // Readable view follows the durable one, then the dedupe entry and its
        // capacity go back — all still inside the guard.
        self.state().entries.remove(id);
        guard.release();
        Ok(())
    }
}
