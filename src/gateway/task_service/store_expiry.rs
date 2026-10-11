// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restart enumeration and conditional durable expiry of stored tasks.

use std::fs;
use std::io;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use super::super::record::{
    CommittedTask, ErrorAuthor, InterruptedTask, MARKER_VERSION, Record, UPSTREAM_VERSION,
};
use super::disk::Reread;
use super::platform::sync_dir;
use super::{CommitStage, Shared, StoreError, TaskStore, fire, record_name};
use crate::protocol::tasks::{Task, TaskStatus, TaskTransition};

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

/// `id`'s row as startup recovery sees it, or `None` when it is not live.
fn interrupted_of(id: &str, task: &Task, record: &Record) -> Option<InterruptedTask> {
    let status = task.status();
    matches!(status, TaskStatus::Working | TaskStatus::InputRequired).then(|| InterruptedTask {
        id: id.to_owned(),
        owner_digest: record.admission.principal_digest.clone(),
        revision: record.revision,
        never_dispatched: status == TaskStatus::Working
            && record.version >= MARKER_VERSION
            && !record.dispatched,
        is_working: status == TaskStatus::Working,
        // Only a v3+ row whose descriptor still names this record's admitted
        // operation is offered as recoverable. Everything else reads as
        // absent and takes the unchanged I3 table.
        upstream: (record.version >= UPSTREAM_VERSION)
            .then(|| record.upstream.clone())
            .flatten()
            .filter(|upstream| upstream.consistent_with(&record.admission)),
    })
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
    /// `import` accepts is kept. A row that restores in full is served again
    /// (MIK-8121): each row is written durably, its key imported, and only
    /// then published, a live one settled first by `recover`, the decision
    /// startup recovery makes; `None` from `recover` leaves it working, as a managed
    /// deferral at startup does. Returns how many rows stay sealed, for the
    /// caller to hand to admission AFTER the imports, and the rows settled here,
    /// for the caller to announce as startup recovery does.
    pub(in crate::gateway::task_service) async fn reread_sealed(
        &self,
        import: impl Fn(crate::idempotency::admission::RestoredBinding, String) -> bool + Send + 'static,
        recover: impl Fn(&InterruptedTask) -> Option<TaskTransition> + Send + 'static,
    ) -> (usize, Vec<CommittedTask>) {
        let names: Vec<String> = self.0.state().sealed.iter().cloned().collect();
        if names.is_empty() {
            return (0, Vec::new());
        }
        let shared = Arc::clone(&self.0);
        let settled = tokio::task::spawn_blocking(move || {
            let mut settled = Vec::new();
            for name in names {
                let outcome =
                    super::disk::reread_record(&shared.dir, &name, shared.limits, shared.dir_id);
                shared.apply_reread(&name, outcome, &import, &recover, &mut settled);
            }
            settled
        })
        .await
        .unwrap_or_default();
        let (sealed, reserved) = {
            let state = self.0.state();
            if !state.sealed.is_empty() {
                // Once per sweep while sealed: loud on purpose, names only.
                let files: Vec<&str> = state.sealed.iter().map(String::as_str).collect();
                tracing::error!(
                    ?files,
                    "task records with an unreadable key: new keyed calls are refused (409) until each file is repaired (its key is kept) or removed (its key is released)"
                );
            }
            (state.sealed.len(), state.reserved.len())
        };
        for (class, count) in [("sealed", sealed), ("reserved", reserved)] {
            #[allow(clippy::cast_precision_loss)]
            telemetry_metrics::gauge!("mcp_task_store_skipped_records", "class" => class)
                .set(count as f64);
        }
        (sealed, settled)
    }

    /// Mark `name` sealed as though the load had found its key unreadable, for
    /// tests above the store that cannot plant a row before their store opens.
    #[cfg(test)]
    pub(in crate::gateway::task_service) fn seal_for_test(&self, name: &str) {
        self.0.state().sealed.insert(name.to_owned());
    }

    /// The rows the load skipped, for the startup report (MIK-8023).
    /// The full path of each sealed row's file, for the operator (MIK-8052).
    pub(crate) fn sealed_files(&self) -> Vec<std::path::PathBuf> {
        let state = self.0.state();
        // Absolute even when `tasks.store_dir` is relative, so the operator is
        // never left to resolve it against the gateway's working directory.
        state
            .sealed
            .iter()
            .map(|name| {
                let path = self.0.dir.join(name);
                std::path::absolute(&path).unwrap_or(path)
            })
            .collect()
    }

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
            .filter_map(|(id, entry)| interrupted_of(id, &entry.task, &entry.record))
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
    /// Apply one sealed row's re-read (MIK-8052, MIK-8121). A row that restores
    /// is served again under the ordering lock, which every mutation takes, so
    /// nothing reaches it by id before it is settled, published and its key
    /// imported; a refused import takes it back out and it stays sealed.
    fn apply_reread(
        &self,
        name: &str,
        outcome: Reread,
        import: &impl Fn(crate::idempotency::admission::RestoredBinding, String) -> bool,
        recover: &impl Fn(&InterruptedTask) -> Option<TaskTransition>,
        settled: &mut Vec<CommittedTask>,
    ) {
        let (admission, id, row) = match outcome {
            Reread::Sealed => return,
            Reread::Gone => {
                tracing::warn!(record = %name, repaired = false, "sealed task record cleared");
                self.state().sealed.remove(name);
                return;
            }
            Reread::Repaired(admission, id, row) => (admission, id, row),
        };
        // Every check below holds until the row is applied: a concurrent
        // re-read or mutation cannot move it in between.
        let _order = self.order();
        {
            let state = self.state();
            // A closed or poisoned store writes and serves nothing more; a row
            // another re-read already applied is not applied twice.
            if !state.ready || !state.sealed.contains(name) {
                return;
            }
        }
        // The load's per-principal cap holds for a repaired row too: a seal
        // never lifts over a directory startup would refuse.
        let held = {
            let state = self.state();
            state
                .entries
                .values()
                .map(|entry| &entry.record.admission)
                .chain(state.reserved.iter().map(|(kept, _)| kept))
                .filter(|kept| kept.principal_digest == admission.principal_digest)
                .count()
        };
        if held >= self.limits.per_principal {
            tracing::error!(record = %name, "repaired task record would exceed its owner's cap; it stays sealed");
            return;
        }
        let Some((record, task)) = row.map(|row| *row) else {
            // Its key reads but its task does not: the key is kept, unserved.
            if !import(binding_of(&admission), id.clone()) {
                tracing::error!(record = %name, "repaired task record's key is refused by admission; it stays sealed");
                return;
            }
            tracing::warn!(record = %name, repaired = true, "sealed task record cleared");
            let mut state = self.state();
            state.sealed.remove(name);
            state.reserved.push((admission, id));
            return;
        };
        let duplicate = {
            let state = self.state();
            super::reject_duplicate(&state, &id, &record).is_err()
                || state.reserved.iter().any(|(kept, kept_id)| {
                    kept_id == &id || kept.identity_digest == admission.identity_digest
                })
        };
        if duplicate {
            tracing::error!(record = %name, "repaired task record duplicates a served task or key; it stays sealed");
            return;
        }
        // Durable first, visible last: the row is written (a live one settled
        // through the bounded settle, any other written again through the
        // commit every write takes, so it is durable on every platform), then
        // its key imported, and only then published. A refused import leaves
        // nothing visible; a key imported a moment before its row is published
        // reads as a reserved row's does (MIK-8023).
        let recovered = interrupted_of(&id, &task, &record).and_then(|live| recover(&live));
        let was_live = recovered.is_some();
        let written = match recovered {
            Some(event) => {
                // A live row is dated at the store's clock. With none readable
                // it stays sealed for the next sweep: never settled at 1969.
                let Ok(now) = self.now() else {
                    tracing::warn!(record = %name, "host clock reads before 1970: repaired task record stays sealed");
                    return;
                };
                self.settle_durable(
                    &task,
                    &record,
                    (
                        event,
                        None,
                        ErrorAuthor::Gateway,
                        crate::gateway::gateway_writes::WriteRecord::default(),
                    ),
                    now,
                )
            }
            None => super::serialize(&record).and_then(|bytes| {
                if bytes.len() > self.limits.record_bytes {
                    return Err(StoreError::Capacity);
                }
                self.commit(name, &bytes).map(|()| Some((task, record)))
            }),
        };
        let Ok(Some((task, record))) = written else {
            tracing::error!(record = %name, "repaired task record could not be made durable; it stays sealed");
            return;
        };
        if !import(binding_of(&admission), id) {
            tracing::error!(record = %name, "repaired task record's key is refused by admission; it stays sealed");
            return;
        }
        let committed = self.publish(task, record, super::HoldUpdate::Drop);
        tracing::warn!(record = %name, recovered = was_live, "sealed task record served again");
        self.state().sealed.remove(name);
        if was_live {
            settled.push(committed);
        }
    }

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
