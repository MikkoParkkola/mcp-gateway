// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! S1: admission-owned task binding, restart import and the expiry
//! transaction.

use super::{
    Entry, ExecutionAdmission, METADATA_LIMIT, Mode, RETENTION_SECS, Refusal, Request, SLOT_LIMIT,
    State, Status,
};
use crate::hashing::canonical_json_sha256;
use serde_json::json;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// S1 — admission-owned task binding, restart import, expiry transaction.
// The sync-mode paths, in admission.rs, are unchanged apart from one
// refusing match arm.
// ---------------------------------------------------------------------------

/// Domain tag for the persisted principal digest. Separate from the identity
/// tag on purpose: the identity folds in the retry key, so two tasks from one
/// principal would otherwise disagree about who owns them.
pub(super) const PRINCIPAL_TAG: &str = "mcp-gateway.execution-admission.principal.v1";

/// Everything a durable task record must persist about the admission that
/// authorized it. Opaque: the task service stores and compares these values and
/// never derives them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TaskBinding {
    pub(super) identity: String,
    pub(super) principal_digest: String,
    pub(super) operation: String,
    pub(super) representation: String,
    pub(super) metadata_bytes: usize,
}

impl TaskBinding {
    pub(crate) fn identity(&self) -> &str {
        &self.identity
    }

    pub(crate) fn principal_digest(&self) -> &str {
        &self.principal_digest
    }

    pub(crate) fn operation(&self) -> &str {
        &self.operation
    }

    pub(crate) fn representation(&self) -> &str {
        &self.representation
    }

    pub(crate) fn metadata_bytes(&self) -> usize {
        self.metadata_bytes
    }

    /// Rebuild a binding from a durable record's persisted fields, validating
    /// every one of them. This is the sole door in, inside the sole identity
    /// owner: a malformed record is refused rather than trusted.
    pub(crate) fn from_persisted(restored: &RestoredBinding) -> Result<Self, Refusal> {
        for digest in [
            &restored.identity,
            &restored.principal_digest,
            &restored.operation,
            &restored.representation,
        ] {
            if digest.len() != 64
                || !digest
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
            {
                return Err(Refusal::InvalidIdentity);
            }
        }
        // Zero is impossible from `prepare` and over-limit is refused there, so
        // either means a record no admission could have written.
        if restored.metadata_bytes == 0 || restored.metadata_bytes > METADATA_LIMIT {
            return Err(Refusal::MetadataTooLarge);
        }
        Ok(Self {
            identity: restored.identity.clone(),
            principal_digest: restored.principal_digest.clone(),
            operation: restored.operation.clone(),
            representation: restored.representation.clone(),
            metadata_bytes: restored.metadata_bytes,
        })
    }
}

/// The persisted shape, OWNED: the records it comes from live behind a mutex,
/// so nothing borrowed from them could outlive the read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RestoredBinding {
    pub identity: String,
    pub principal_digest: String,
    pub operation: String,
    pub representation: String,
    pub metadata_bytes: usize,
}

/// Opaque principal digest. Callers compare this value; only admission hashes.
pub(crate) struct TaskOwner {
    pub(super) digest: String,
}

impl TaskOwner {
    pub(crate) fn as_digest(&self) -> &str {
        &self.digest
    }
}

/// A task admission outcome, SEPARATE from the Sync `Admission` enum so no
/// existing exhaustive match gains an arm.
#[derive(Debug)]
pub(crate) enum TaskAdmission {
    Owned(TaskLease),
    /// The handle this key already created, WITH the binding that authorizes
    /// it: a bare id would force the task service to hash the principal itself.
    Existing {
        task_id: String,
        binding: TaskBinding,
    },
    InFlight,
    Unavailable,
}

/// Fired immediately before `admit_task` acquires the admission mutex.
#[cfg(test)]
pub(crate) type LockWitness = Arc<dyn Fn() + Send + Sync>;

/// One non-cloneable task owner. Dropping it before publication releases the
/// slot; consuming it into a publication moves that duty to the token.
pub(crate) struct TaskLease {
    pub(super) service: Arc<ExecutionAdmission>,
    pub(super) identity: String,
    pub(super) generation: u64,
    pub(super) binding: TaskBinding,
    pub(super) handed_over: bool,
}

impl fmt::Debug for TaskLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskLease").finish_non_exhaustive()
    }
}

impl TaskLease {
    pub(crate) fn binding(&self) -> &TaskBinding {
        &self.binding
    }

    /// Consume the lease into a ONE-SHOT publication token, so a committed
    /// record and its dedupe entry cannot be separated by a dropped future.
    pub(crate) fn into_publication(mut self) -> TaskPublication {
        self.handed_over = true;
        TaskPublication {
            service: Arc::clone(&self.service),
            identity: std::mem::take(&mut self.identity),
            generation: self.generation,
            binding: std::mem::take(&mut self.binding),
            resolved: false,
        }
    }
}

impl Drop for TaskLease {
    fn drop(&mut self) {
        if !self.handed_over {
            self.service.abandon(&self.identity, self.generation);
        }
    }
}

/// Resolved exactly once, inside `TaskStore`'s blocking section, AFTER the
/// record is committed and readable and before dispatch. Dropped unresolved, it
/// releases the reservation, which is what a failed commit needs.
pub(crate) struct TaskPublication {
    pub(super) service: Arc<ExecutionAdmission>,
    pub(super) identity: String,
    pub(super) generation: u64,
    pub(super) binding: TaskBinding,
    pub(super) resolved: bool,
}

impl fmt::Debug for TaskPublication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TaskPublication").finish_non_exhaustive()
    }
}

impl TaskPublication {
    /// Returns `()`: the record is already committed, so there is no failure to
    /// report and a fallible signature would invent a path to pretend to handle.
    pub(crate) fn publish(mut self, task_id: &str) {
        self.resolved = true;
        let binding = std::mem::take(&mut self.binding);
        self.service
            .publish_task(&self.identity, self.generation, task_id, binding);
    }
}

impl Drop for TaskPublication {
    fn drop(&mut self) {
        if !self.resolved {
            self.service.abandon(&self.identity, self.generation);
        }
    }
}

/// A task-expiry transaction. Holds the admission mutex — the SAME mutex
/// `admit_task` and `admit` take — across the caller's whole deletion commit,
/// so no admission path can observe a half-finished expiry.
///
/// Never crosses an `await`: it holds a `MutexGuard` and lives inside one
/// blocking section.
pub(crate) struct TaskExpiryGuard<'a> {
    pub(super) state: parking_lot::MutexGuard<'a, State>,
    pub(super) identity: String,
}

impl TaskExpiryGuard<'_> {
    /// The published task this identity owns, read UNDER the hold, so the
    /// caller can validate before deleting anything.
    pub(crate) fn published_task(&self) -> Option<(&str, &TaskBinding)> {
        match self.state.entries.get(&self.identity).map(|e| &e.status) {
            Some(Status::Published { task, binding }) => Some((task.as_str(), binding)),
            _ => None,
        }
    }

    /// Drop the dedupe entry and give back its capacity, still under the same
    /// hold. Removes ONLY a published task entry: a bug in the store's expiry
    /// can never delete a Sync slot.
    pub(crate) fn release(mut self) {
        if matches!(
            self.state.entries.get(&self.identity).map(|e| &e.status),
            Some(Status::Published { .. })
        ) {
            let identity = std::mem::take(&mut self.identity);
            self.state.remove(&identity);
        }
    }
}

impl ExecutionAdmission {
    /// Install the lock witness. Test-only; production installs none.
    #[cfg(test)]
    pub(crate) fn set_lock_witness(&self, witness: Option<LockWitness>) {
        *self.lock_witness.lock() = witness;
    }

    #[cfg(test)]
    pub(super) fn fire_lock_witness(&self) {
        let witness = self.lock_witness.lock().clone();
        if let Some(witness) = witness {
            witness();
        }
    }

    #[cfg(not(test))]
    pub(super) fn fire_lock_witness() {}

    /// Task-mode admission. `admit` keeps its exact signature and behaviour for
    /// Sync; this is the only entry point that can mint a task lease.
    pub(crate) fn admit_task(
        self: &Arc<Self>,
        request: Request<'_>,
    ) -> Result<TaskAdmission, Refusal> {
        if request.mode != Mode::Task {
            return Err(Refusal::Mismatch);
        }
        let principal_digest = canonical_json_sha256(&json!([PRINCIPAL_TAG, request.principal]));
        let (identity, mut candidate) = request.prepare()?;
        let now = (self.clock)();
        #[cfg(test)]
        self.fire_lock_witness();
        #[cfg(not(test))]
        Self::fire_lock_witness();
        let mut state = self.state.lock();
        if state
            .entries
            .get(&identity)
            .is_some_and(|entry| entry.expired(now))
        {
            state.remove(&identity);
        }
        if let Some(entry) = state.entries.get(&identity) {
            if entry.operation != candidate.operation
                || entry.representation != candidate.representation
                || entry.mode != candidate.mode
            {
                return Err(Refusal::Mismatch);
            }
            return Ok(match &entry.status {
                Status::Active => TaskAdmission::InFlight,
                Status::Published { task, binding } => TaskAdmission::Existing {
                    task_id: task.clone(),
                    binding: binding.clone(),
                },
                Status::Completed { .. } => TaskAdmission::Unavailable,
            });
        }
        // A stored row whose key could not be read may be this request's
        // original: no new task until that row is repaired or removed (MIK-8052).
        if state.sealed > 0 {
            return Ok(TaskAdmission::Unavailable);
        }
        now.checked_add(RETENTION_SECS)
            .ok_or(Refusal::ExpiryOverflow)?;
        if state.entries.len() >= SLOT_LIMIT {
            state.reclaim(now);
        }
        if state.entries.len() >= SLOT_LIMIT {
            return Err(Refusal::Capacity);
        }
        let generation = state.generation.checked_add(1).ok_or(Refusal::Capacity)?;
        state.generation = generation;
        candidate.generation = generation;
        let binding = TaskBinding {
            identity: identity.clone(),
            principal_digest,
            operation: candidate.operation.clone(),
            representation: candidate.representation.clone(),
            metadata_bytes: candidate.metadata_bytes,
        };
        state.metadata_bytes += candidate.metadata_bytes;
        state.entries.insert(identity.clone(), candidate);
        Ok(TaskAdmission::Owned(TaskLease {
            service: Arc::clone(self),
            identity,
            generation,
            binding,
            handed_over: false,
        }))
    }

    /// Restore one stored task binding at startup, BEFORE serving. Rebuilds a
    /// COMPLETE entry and accounts its bytes exactly as `admit` does, so a
    /// post-restart retry is not a false `Mismatch` and a later release cannot
    /// underflow the counter.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Single-record variant superseded by the plural `import_tasks`, \
                      which builds its own two-phase transaction and is the path \
                      `TaskService::open` takes (src/gateway/task_service/service.rs:90). \
                      Retained only for the per-record admission tests."
        )
    )]
    pub(crate) fn import_task(
        self: &Arc<Self>,
        restored: &RestoredBinding,
        task_id: &str,
    ) -> Result<(), Refusal> {
        if task_id.is_empty() {
            return Err(Refusal::InvalidIdentity);
        }
        let binding = TaskBinding::from_persisted(restored)?;
        let mut state = self.state.lock();
        if state.entries.contains_key(binding.identity()) {
            return Err(Refusal::Mismatch);
        }
        let generation = state.generation.checked_add(1).ok_or(Refusal::Capacity)?;
        state.generation = generation;
        state.metadata_bytes += binding.metadata_bytes;
        let entry = published_entry(&binding, generation, task_id);
        state.entries.insert(binding.identity, entry);
        Ok(())
    }

    /// Restore stored task bindings at startup as one admission transaction.
    /// A refused batch must leave no new reservations; unrelated entries stay.
    ///
    /// Every record is validated, and every number the commit needs is proved,
    /// BEFORE anything is written: a loop that inserted as it went would already
    /// own the earlier keys of a batch its later record refuses.
    pub(crate) fn import_tasks(
        &self,
        restored: &[(RestoredBinding, String)],
    ) -> Result<(), Refusal> {
        if restored.is_empty() {
            return Ok(());
        }
        let mut prepared = Vec::with_capacity(restored.len());
        for (record, task_id) in restored {
            // A binding whose handle is unusable restores an unreachable task.
            if task_id.is_empty() {
                return Err(Refusal::InvalidIdentity);
            }
            prepared.push((TaskBinding::from_persisted(record)?, task_id.clone()));
        }
        {
            // Two records naming one identity, or one task handle, describe a
            // store no admission could have written. Neither pair is collapsed:
            // deduplicating them would import a corrupt record instead of
            // refusing it, even when the two records are identical.
            let mut identities = HashSet::with_capacity(prepared.len());
            let mut handles = HashSet::with_capacity(prepared.len());
            for (binding, task_id) in &prepared {
                if !identities.insert(binding.identity()) || !handles.insert(task_id.as_str()) {
                    return Err(Refusal::Mismatch);
                }
            }
        }
        let generations = u64::try_from(prepared.len()).map_err(|_| Refusal::Capacity)?;

        let mut state = self.state.lock();
        // An identity already held is never overwritten: the entry that is there
        // owns its task, and this record would strand one of the two.
        if prepared
            .iter()
            .any(|(binding, _)| state.entries.contains_key(binding.identity()))
        {
            return Err(Refusal::Mismatch);
        }
        // A handle a held identity already published is never rebound: the
        // in-batch set cannot see that pair, so held state answers for it. One
        // ephemeral set of the published handles, read and dropped under this
        // same guard, before any record is written.
        {
            let published: HashSet<&str> = state
                .entries
                .values()
                .filter_map(|entry| match &entry.status {
                    Status::Published { task, .. } => Some(task.as_str()),
                    _ => None,
                })
                .collect();
            if prepared
                .iter()
                .any(|(_, task_id)| published.contains(task_id.as_str()))
            {
                return Err(Refusal::Mismatch);
            }
        }
        if state
            .entries
            .len()
            .checked_add(prepared.len())
            .is_none_or(|held| held > SLOT_LIMIT)
        {
            return Err(Refusal::Capacity);
        }
        let mut metadata_bytes = state.metadata_bytes;
        for (binding, _) in &prepared {
            metadata_bytes = metadata_bytes
                .checked_add(binding.metadata_bytes)
                .ok_or(Refusal::Capacity)?;
        }
        // The last thing checked and the last thing written. Numbering the whole
        // batch has to be possible before any of it is numbered, or a refused
        // batch would have spent the generations it could not use.
        let last_generation = state
            .generation
            .checked_add(generations)
            .ok_or(Refusal::Capacity)?;

        let mut generation = state.generation;
        for (binding, task_id) in prepared {
            generation += 1;
            let entry = published_entry(&binding, generation, &task_id);
            state.entries.insert(binding.identity, entry);
        }
        state.generation = last_generation;
        state.metadata_bytes = metadata_bytes;
        Ok(())
    }

    /// Sole principal hasher. Empty identity is refused; oversize is refused
    /// before hashing. Bound is the existing `METADATA_LIMIT`.
    pub(crate) fn owner(principal: &str) -> Result<TaskOwner, Refusal> {
        if principal.is_empty() {
            return Err(Refusal::InvalidIdentity);
        }
        // Bytes, exactly as `prepare` bounds a principal: a character count would
        // both refuse and accept the wrong multibyte identities.
        if principal.len() > METADATA_LIMIT {
            return Err(Refusal::MetadataTooLarge);
        }
        // The one digest `admit_task` persists, under the one domain tag. No
        // second hasher exists for a caller to disagree with.
        Ok(TaskOwner {
            digest: canonical_json_sha256(&json!([PRINCIPAL_TAG, principal])),
        })
    }

    /// Open an expiry transaction on this identity. Blocking, and the guard
    /// must not cross an `await`.
    pub(crate) fn expiry_guard<'a>(self: &'a Arc<Self>, identity: &str) -> TaskExpiryGuard<'a> {
        TaskExpiryGuard {
            state: self.state.lock(),
            identity: identity.to_owned(),
        }
    }

    /// Whether this exact request is ALREADY admitted — being created right
    /// now, or published.
    ///
    /// Read-only in the strongest sense available here: it takes the same lock
    /// every admission takes, reads one entry, and writes nothing — no slot, no
    /// lease, no generation, no reclaim. So a caller may ask "has this already
    /// been admitted" without that question becoming an admission, which is the
    /// difference between answering a repeat with the handle it already owns and
    /// quietly reserving the key for a call that is about to be refused.
    ///
    /// `Active` counts, and that is the whole correction: between the record
    /// becoming readable and the dedupe entry being published there is a real
    /// window in which the first caller's task exists and this index does not
    /// yet name it. Answering `false` there tells a retrying caller that its own
    /// accepted call never happened. It deliberately answers only yes/no: the
    /// handle itself comes back from `admit_task`, which is the authority that
    /// mints nothing for an `Active` key and returns the original task for a
    /// published one.
    ///
    /// Exact-bound, and deliberately narrower than `admit_task`'s own match: a
    /// differing operation, representation or mode answers `false` rather than
    /// `Mismatch`, because this is not the authority on refusal — `admit_task`
    /// is, and it will say so in its own words when the caller reaches it. What
    /// this must never do is answer `true` for a request that would not have
    /// been admitted onto that same task.
    pub(crate) fn already_admitted(&self, request: Request<'_>) -> bool {
        if request.mode != Mode::Task {
            return false;
        }
        let Ok((identity, candidate)) = request.prepare() else {
            return false;
        };
        let state = self.state.lock();
        let Some(entry) = state.entries.get(&identity) else {
            return false;
        };
        if entry.operation != candidate.operation
            || entry.representation != candidate.representation
            || entry.mode != candidate.mode
        {
            return false;
        }
        match &entry.status {
            // Neither is ever `expired` (see `Entry::expired`): an active key is
            // owned by a live lease and a published one's lifetime belongs to
            // the store, so there is no deadline to re-decide here.
            Status::Active | Status::Published { .. } => true,
            // Unreachable for `Mode::Task` — a task lease is either handed to a
            // publication or dropped into `abandon`, and only the sync `Lease`
            // reaches `finish` — so it is answered conservatively rather than
            // assumed away.
            Status::Completed { .. } => false,
        }
    }

    pub(super) fn publish_task(
        &self,
        identity: &str,
        generation: u64,
        task_id: &str,
        binding: TaskBinding,
    ) {
        let mut state = self.state.lock();
        if let Some(entry) = state.entries.get_mut(identity)
            && entry.generation == generation
            && matches!(entry.status, Status::Active)
        {
            entry.status = Status::Published {
                task: task_id.to_owned(),
                binding,
            };
        }
    }
}

/// One restored entry, COMPLETE: a published task accounts for its bytes exactly
/// as the live admission that wrote it did, so a later release cannot underflow
/// the counter. Shared by the single and batch import so the two cannot drift.
pub(super) fn published_entry(binding: &TaskBinding, generation: u64, task_id: &str) -> Entry {
    Entry {
        operation: binding.operation.clone(),
        representation: binding.representation.clone(),
        mode: Mode::Task,
        metadata_bytes: binding.metadata_bytes,
        generation,
        status: Status::Published {
            task: task_id.to_owned(),
            binding: binding.clone(),
        },
    }
}
