// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared execution ownership. Transport activation is a separate increment.
//!
//! One short mutex transaction owns all map and retained-byte transitions. Active
//! leases never expire: a timeout cannot prove that a side effect has stopped.
//! Task mode currently supports reservation/conflict/abort only; durable Task
//! publication and settlement belong to the following lifecycle increment.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::hashing::{canonical_json, canonical_json_sha256};

pub(crate) const SLOT_LIMIT: usize = 10_000;
pub(crate) const METADATA_LIMIT: usize = 4_096;
pub(crate) const RESULT_LIMIT: usize = 512 * 1_024;
pub(crate) const TOTAL_RESULT_LIMIT: usize = 128 * 1_024 * 1_024;
pub(crate) const RETENTION_SECS: u64 = 24 * 60 * 60;

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Sync,
    Task,
}

pub(crate) struct Request<'a> {
    pub principal: &'a str,
    pub key: &'a str,
    pub operation: &'a Value,
    pub representation: &'a Value,
    pub mode: Mode,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    InvalidIdentity,
    MetadataTooLarge,
    Capacity,
    ExpiryOverflow,
    Mismatch,
}

#[derive(Debug)]
pub(crate) enum Admission {
    Owned(Lease),
    InFlight,
    Replay(Arc<[u8]>),
    Unavailable,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Settlement {
    Retained,
    Unavailable,
}

#[derive(Debug, Default, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct Snapshot {
    pub entries: usize,
    pub metadata_bytes: usize,
    pub result_bytes: usize,
}

pub(crate) struct ExecutionAdmission {
    state: Mutex<State>,
    /// Fired immediately before `admit_task` takes `state`, so a test can tell
    /// "blocked on the lock" from "the thread never arrived". Test-only.
    #[cfg(test)]
    lock_witness: Mutex<Option<LockWitness>>,
    clock: Clock,
}

#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    metadata_bytes: usize,
    result_bytes: usize,
    generation: u64,
}

struct Entry {
    operation: String,
    representation: String,
    mode: Mode,
    metadata_bytes: usize,
    generation: u64,
    status: Status,
}

enum Status {
    Active,
    /// A durable task owns this key. Its lifetime belongs to the store's
    /// expiry, never to generic reclaim: `Entry::expired` stays false for it.
    Published {
        task: String,
        binding: TaskBinding,
    },
    Completed {
        bytes: Option<Arc<[u8]>>,
        // None is fail-closed process-lifetime retention after clock overflow.
        // Metadata always reserves the maximum u64 width, including this case.
        expires: Option<u64>,
    },
}

impl Entry {
    fn expired(&self, now: u64) -> bool {
        matches!(&self.status, Status::Completed { expires: Some(at), .. } if *at <= now)
    }

    fn result_bytes(&self) -> usize {
        match &self.status {
            Status::Completed {
                bytes: Some(bytes), ..
            } => bytes.len(),
            _ => 0,
        }
    }
}

impl State {
    fn remove(&mut self, key: &str) {
        if let Some(entry) = self.entries.remove(key) {
            self.metadata_bytes -= entry.metadata_bytes;
            self.result_bytes -= entry.result_bytes();
        }
    }

    fn reclaim(&mut self, now: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| {
            if entry.expired(now) {
                self.metadata_bytes -= entry.metadata_bytes;
                self.result_bytes -= entry.result_bytes();
                false
            } else {
                true
            }
        });
        before - self.entries.len()
    }
}

impl Request<'_> {
    fn prepare(self) -> Result<(String, Entry), Refusal> {
        if self.principal.is_empty() || self.key.is_empty() {
            return Err(Refusal::InvalidIdentity);
        }
        // UTF-8 input bytes are a lower bound on their JSON encoding. Reject
        // huge strings before allocating a second copy for the accounting tuple.
        if self.principal.len().saturating_add(self.key.len()) > METADATA_LIMIT {
            return Err(Refusal::MetadataTooLarge);
        }
        // Lowercase SHA-256 hex always encodes to exactly 64 JSON bytes. Check
        // the envelope before spending work canonicalizing rejected operations.
        let fingerprint_width = "0".repeat(64);
        let mode = match self.mode {
            Mode::Sync => "sync",
            Mode::Task => "task",
        };
        // Reserve the largest future state, expiry width and permitted task ID.
        // NUL costs six JSON bytes per input byte: no valid 36-byte UTF-8 ID can
        // encode larger. Nothing attacker-controlled is normalized or trimmed.
        let metadata_bytes = canonical_json(&json!([
            1,
            self.principal,
            self.key,
            fingerprint_width,
            fingerprint_width,
            mode,
            u64::MAX,
            "completed_unavailable",
            "\0".repeat(36)
        ]))
        .len();
        if metadata_bytes > METADATA_LIMIT {
            return Err(Refusal::MetadataTooLarge);
        }
        let operation = canonical_json_sha256(self.operation);
        let representation = canonical_json_sha256(self.representation);
        let identity = canonical_json_sha256(&json!([
            "mcp-gateway.execution-admission.v1",
            self.principal,
            self.key
        ]));
        Ok((
            identity,
            Entry {
                operation,
                representation,
                mode: self.mode,
                metadata_bytes,
                generation: 0,
                status: Status::Active,
            },
        ))
    }
}

impl ExecutionAdmission {
    pub(crate) fn new(clock: Clock) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            #[cfg(test)]
            lock_witness: Mutex::new(None),
            clock,
        })
    }

    /// Call only after current authorization, with a stable verified principal
    /// and sanitized operation/representation descriptors. No backend work occurs
    /// here. A Task lease is only a reservation, never a durable acknowledgement.
    pub(crate) fn admit(self: &Arc<Self>, request: Request<'_>) -> Result<Admission, Refusal> {
        let (identity, mut candidate) = request.prepare()?;
        let now = (self.clock)();
        let mut state = self.state.lock();
        if state
            .entries
            .get(&identity)
            .is_some_and(|entry| entry.expired(now))
        {
            state.remove(&identity);
        }
        // Existing ownership precedes capacity and expiry checks for NEW work.
        if let Some(entry) = state.entries.get(&identity) {
            if entry.operation != candidate.operation
                || entry.representation != candidate.representation
                || entry.mode != candidate.mode
            {
                return Err(Refusal::Mismatch);
            }
            return Ok(match &entry.status {
                // A Sync caller can never be handed a task handle. The mode
                // check above already refuses a Task request here; this arm
                // refuses the Sync one.
                Status::Published { .. } => return Err(Refusal::Mismatch),
                Status::Active => Admission::InFlight,
                Status::Completed {
                    bytes: Some(bytes), ..
                } => Admission::Replay(Arc::clone(bytes)),
                Status::Completed { bytes: None, .. } => Admission::Unavailable,
            });
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
        state.metadata_bytes += candidate.metadata_bytes;
        state.entries.insert(identity.clone(), candidate);
        Ok(Admission::Owned(Lease {
            service: Arc::clone(self),
            identity,
            generation,
            dispatched: false,
            settled: false,
        }))
    }

    pub(crate) fn reclaim_completed(&self) -> usize {
        let now = (self.clock)();
        self.state.lock().reclaim(now)
    }

    fn finish(&self, identity: &str, generation: u64, bytes: Option<Arc<[u8]>>) -> Settlement {
        let expires = (self.clock)().checked_add(RETENTION_SECS);
        let mut state = self.state.lock();
        if !state.entries.get(identity).is_some_and(|entry| {
            entry.generation == generation && matches!(entry.status, Status::Active)
        }) {
            return Settlement::Unavailable;
        }
        let retained = bytes.filter(|bytes| {
            expires.is_some()
                && bytes.len() <= RESULT_LIMIT
                && state
                    .result_bytes
                    .checked_add(bytes.len())
                    .is_some_and(|total| total <= TOTAL_RESULT_LIMIT)
        });
        let outcome = if retained.is_some() {
            Settlement::Retained
        } else {
            Settlement::Unavailable
        };
        // Slot and metadata were reserved before dispatch. An over-budget or
        // uncertain result needs no extra reservation and can never redispatch.
        state.result_bytes += retained.as_ref().map_or(0, |bytes| bytes.len());
        state
            .entries
            .get_mut(identity)
            .expect("owner checked under this guard")
            .status = Status::Completed {
            bytes: retained,
            expires,
        };
        outcome
    }

    fn abandon(&self, identity: &str, generation: u64) {
        let mut state = self.state.lock();
        if state.entries.get(identity).is_some_and(|entry| {
            entry.generation == generation && matches!(entry.status, Status::Active)
        }) {
            state.remove(identity);
        }
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Snapshot {
        let state = self.state.lock();
        Snapshot {
            entries: state.entries.len(),
            metadata_bytes: state.metadata_bytes,
            result_bytes: state.result_bytes,
        }
    }
}

/// One non-cloneable owner. Dropping it before dispatch releases the slot;
/// dropping after dispatch records uncertainty instead of repeating an effect.
pub(crate) struct Lease {
    service: Arc<ExecutionAdmission>,
    identity: String,
    generation: u64,
    dispatched: bool,
    settled: bool,
}

impl fmt::Debug for Lease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lease")
            .field("dispatched", &self.dispatched)
            .finish_non_exhaustive()
    }
}

impl Lease {
    /// Mark immediately before the first possible backend side effect.
    pub(crate) fn mark_dispatched(&mut self) {
        self.dispatched = true;
    }

    /// Settle a synchronous operation with its secured result, without delivery
    /// correlation or signing. Replay policy checks and fresh signing are caller
    /// responsibilities. Serialization happens outside the admission mutex.
    pub(crate) fn complete_secured(mut self, result: &Value) -> Settlement {
        let bytes = canonical_json(result).into_bytes();
        let bytes = (bytes.len() <= RESULT_LIMIT).then(|| Arc::from(bytes));
        let outcome = self.service.finish(&self.identity, self.generation, bytes);
        self.settled = true;
        outcome
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if !self.settled {
            if self.dispatched {
                self.service.finish(&self.identity, self.generation, None);
            } else {
                self.service.abandon(&self.identity, self.generation);
            }
        }
    }
}

#[cfg(test)]
#[path = "admission_tests.rs"]
mod tests;

// ---------------------------------------------------------------------------
// S1 — admission-owned task binding, restart import, expiry transaction.
// Sync-mode paths above are unchanged apart from one refusing match arm.
// ---------------------------------------------------------------------------

/// Domain tag for the persisted principal digest. Separate from the identity
/// tag on purpose: the identity folds in the retry key, so two tasks from one
/// principal would otherwise disagree about who owns them.
const PRINCIPAL_TAG: &str = "mcp-gateway.execution-admission.principal.v1";

/// Everything a durable task record must persist about the admission that
/// authorized it. Opaque: the task service stores and compares these values and
/// never derives them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TaskBinding {
    identity: String,
    principal_digest: String,
    operation: String,
    representation: String,
    metadata_bytes: usize,
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
    digest: String,
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
    service: Arc<ExecutionAdmission>,
    identity: String,
    generation: u64,
    binding: TaskBinding,
    handed_over: bool,
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
    service: Arc<ExecutionAdmission>,
    identity: String,
    generation: u64,
    binding: TaskBinding,
    resolved: bool,
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
    state: parking_lot::MutexGuard<'a, State>,
    identity: String,
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
    fn fire_lock_witness(&self) {
        let witness = self.lock_witness.lock().clone();
        if let Some(witness) = witness {
            witness();
        }
    }

    #[cfg(not(test))]
    fn fire_lock_witness(&self) {}

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
        self.fire_lock_witness();
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
        restored: Vec<(RestoredBinding, String)>,
    ) -> Result<(), Refusal> {
        if restored.is_empty() {
            return Ok(());
        }
        let mut prepared = Vec::with_capacity(restored.len());
        for (record, task_id) in &restored {
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
    pub(crate) fn owner(&self, principal: &str) -> Result<TaskOwner, Refusal> {
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

    fn publish_task(&self, identity: &str, generation: u64, task_id: &str, binding: TaskBinding) {
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
fn published_entry(binding: &TaskBinding, generation: u64, task_id: &str) -> Entry {
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

#[cfg(test)]
#[path = "task_admission_tests.rs"]
mod task_tests;

#[cfg(test)]
#[path = "task_qualification_tests.rs"]
mod task_qualification_tests;

#[cfg(test)]
#[path = "task_service_import_tests.rs"]
mod task_service_import_tests;
