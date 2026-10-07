// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared execution ownership. Transport activation is a separate increment.
//!
//! One short mutex transaction owns all map and retained-byte transitions. Active
//! leases never expire: a timeout cannot prove that a side effect has stopped.
//! Task mode currently supports reservation/conflict/abort only; durable Task
//! publication and settlement belong to the following lifecycle increment.

use std::collections::HashMap;
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

// MIK-7991 r4: the invoke-path idempotency entry completes before this one and
// must never outlive it, so a keyed re-issue is always answered here first and
// that path's replay arm stays unreached. Both clocks start at completion and
// both stores are process memory; a longer inner TTL would open the window.
const _: () = assert!(super::COMPLETED_TTL.as_secs() <= RETENTION_SECS);

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
        self.admit_round(request, "")
    }

    /// Partition a continuation by its trusted round discriminator, without
    /// changing the caller's key or the identity of fresh requests. A separate
    /// typed hash domain prevents a caller-supplied key from impersonating a
    /// round. Operation and representation checks still apply within the round.
    pub(crate) fn admit_round(
        self: &Arc<Self>,
        request: Request<'_>,
        round: &str,
    ) -> Result<Admission, Refusal> {
        if round.len() > METADATA_LIMIT {
            return Err(Refusal::MetadataTooLarge);
        }
        let (identity, mut candidate) = request.prepare()?;
        let identity = if round.is_empty() {
            identity
        } else {
            canonical_json_sha256(&json!([
                "mcp-gateway.execution-admission.round.v1",
                identity,
                round
            ]))
        };
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

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Superseded, not deferred: production already reclaims inline \
                      under slot pressure (`state.reclaim(now)` at admission.rs:279 \
                      and :711), so no caller needs this wrapper. It is retained \
                      because the admission tests have no other way to trigger and \
                      observe `State::reclaim`, which production does run. Delete it \
                      with those tests if that accounting moves elsewhere."
        )
    )]
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
    pub(crate) dispatched: bool,
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

#[path = "admission_tasks.rs"]
mod tasks;
#[cfg(test)]
pub(crate) use tasks::LockWitness;
// Every task type keeps the crate path it had before the move, used or not.
#[allow(unused_imports)]
pub(crate) use tasks::{
    RestoredBinding, TaskAdmission, TaskBinding, TaskExpiryGuard, TaskLease, TaskOwner,
    TaskPublication,
};

#[cfg(test)]
#[path = "task_admission_tests.rs"]
mod task_tests;

#[cfg(test)]
#[path = "task_qualification_tests.rs"]
mod task_qualification_tests;

#[cfg(test)]
#[path = "task_service_import_tests.rs"]
mod task_service_import_tests;
