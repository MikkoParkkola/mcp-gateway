// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The input round's durable writes (MIK-7311.LIFECYCLE.1): open a round with
//! its continuation, accept answers, and select rounds past their TTL.
//!
//! Every write here runs under the store's ordering lock on a blocking thread,
//! like every other mutation, and is refused before anything is written.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use tokio::sync::OwnedSemaphorePermit;

use super::{Shared, StoreError, TaskStore, owned, record_name, serialize};
use crate::gateway::task_service::record::{
    CommittedTask, INPUT_ROUND_VERSION, InputRound, Record,
};
use crate::protocol::mrtr::InputRequired;
use crate::protocol::tasks::{Task, TaskStatus, TaskTransition};

/// What one accepted `ProvideInput` write did.
pub(crate) enum ProvideOutcome {
    /// A valid subset: accepted and persisted; the round stays open.
    Partial(CommittedTask),
    /// The set is complete and the row is now `working`. Carries what the
    /// resume sends, and the worker permit taken inside the same write.
    Resumed {
        task: CommittedTask,
        round: InputRound,
        slot: OwnedSemaphorePermit,
    },
    /// The set would be complete but no worker is free. Nothing written.
    PoolFull,
    /// The round is closed: its continuation deadline or the task's TTL has
    /// passed. Nothing written.
    Closed(RoundClosed),
}

/// Why an open round no longer takes answers (#2429).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RoundClosed {
    /// The stored continuation's deadline, in unix seconds, has passed.
    Continuation(u64),
    /// The task's own TTL has elapsed.
    Ttl,
}

impl RoundClosed {
    /// The sentence a refused update and the cancelled task both carry.
    pub(crate) fn reason(self) -> String {
        match self {
            Self::Continuation(deadline) => {
                let at = i64::try_from(deadline)
                    .ok()
                    .and_then(|secs| DateTime::<Utc>::from_timestamp(secs, 0))
                    .map_or_else(|| deadline.to_string(), |at| at.to_rfc3339());
                format!("the input round closed at its continuation deadline ({at})")
            }
            Self::Ttl => "the input round closed when the task's TTL elapsed".to_owned(),
        }
    }
}

/// Test-only seams on the store: the commit hook, and a frozen clock for the
/// deadline decisions. Production has none of these fields.
#[cfg(test)]
#[derive(Default)]
pub(super) struct TestSeams {
    hook: std::sync::Mutex<Option<super::CommitHook>>,
    clock: std::sync::Mutex<Option<DateTime<Utc>>>,
    clock_after_resume: std::sync::Mutex<Option<DateTime<Utc>>>,
    /// Answer writes that have entered the store, before its ordering lock.
    arrived: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl TestSeams {
    pub(super) fn set_hook(&self, hook: Option<super::CommitHook>) {
        *self
            .hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    pub(super) fn hook(&self) -> Option<super::CommitHook> {
        self.hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Shared {
    /// The clock every round-deadline decision reads. Wall time in production;
    /// a test may freeze it per store.
    #[cfg_attr(
        not(test),
        expect(clippy::unused_self, reason = "one shape with the cfg(test) clock")
    )]
    pub(super) fn now(&self) -> DateTime<Utc> {
        #[cfg(test)]
        if let Some(frozen) = *self
            .seams
            .clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            return frozen;
        }
        Utc::now()
    }
}

impl TaskStore {
    /// The store's clock (see [`Shared::now`]).
    pub(crate) fn now(&self) -> DateTime<Utc> {
        self.0.now()
    }

    #[cfg(test)]
    pub(crate) fn set_clock_for_test(&self, at: Option<DateTime<Utc>>) {
        *self
            .0
            .seams
            .clock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = at;
    }

    /// Freeze the clock at `at` right after the next completing write commits.
    #[cfg(test)]
    pub(crate) fn set_clock_after_next_resume(&self, at: DateTime<Utc>) {
        *self
            .0
            .seams
            .clock_after_resume
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(at);
    }

    /// How many answer writes have reached the store's ordering lock.
    #[cfg(test)]
    pub(crate) fn arrivals_for_test(&self) -> usize {
        self.0
            .seams
            .arrived
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Hold the ordering lock, as a writer would.
    #[cfg(test)]
    pub(crate) fn hold_order_for_test(&self) -> std::sync::MutexGuard<'_, ()> {
        self.0.order()
    }

    /// The stored round (if open) and the revision of task `id`, whoever owns it.
    #[cfg(test)]
    pub(crate) fn input_round_for_test(&self, id: &str) -> (Option<InputRound>, u64) {
        let state = self.0.state();
        let entry = state.entries.get(id).expect("the task exists");
        (entry.record.input_round.clone(), entry.record.revision)
    }

    /// Settle an open round `cancelled` with `reason` as its status message,
    /// in ONE write: the round is dropped before the record is measured.
    ///
    /// # Errors
    /// `RevisionConflict` when the row moved; `InvalidTransition` when no
    /// round is open.
    pub(crate) async fn close_round(
        &self,
        owner: &str,
        id: &str,
        revision: u64,
        reason: String,
    ) -> Result<CommittedTask, StoreError> {
        let shared = Arc::clone(&self.0);
        let (owner, id) = (owner.to_owned(), id.to_owned());
        tokio::task::spawn_blocking(move || {
            shared.close_round_blocking(&owner, &id, revision, reason)
        })
        .await
        .map_err(|_| StoreError::Storage)?
    }

    /// Commit `input_required` together with the round's continuation.
    ///
    /// # Errors
    /// `InvalidTransition` for a round the model refuses; `Capacity` when the
    /// record with the continuation leaves no room under the byte cap.
    pub(crate) async fn require_input(
        &self,
        owner: &str,
        id: &str,
        revision: u64,
        requested: InputRequired,
        round: InputRound,
        at: DateTime<Utc>,
    ) -> Result<CommittedTask, StoreError> {
        let shared = Arc::clone(&self.0);
        let (owner, id) = (owner.to_owned(), id.to_owned());
        tokio::task::spawn_blocking(move || {
            shared.require_input_blocking(&owner, &id, revision, requested, round, at)
        })
        .await
        .map_err(|_| StoreError::Storage)?
    }

    /// Accept answers for an open round, all or nothing.
    ///
    /// # Errors
    /// `InvalidTransition` when no round is open or any key is not
    /// outstanding; `Capacity` when the answers would exceed the byte cap.
    pub(crate) async fn provide_input(
        &self,
        owner: &str,
        id: &str,
        answers: Map<String, Value>,
        reserve: impl FnOnce() -> Option<OwnedSemaphorePermit> + Send + 'static,
        at: DateTime<Utc>,
    ) -> Result<ProvideOutcome, StoreError> {
        let shared = Arc::clone(&self.0);
        let (owner, id) = (owner.to_owned(), id.to_owned());
        tokio::task::spawn_blocking(move || {
            shared.provide_input_blocking(&owner, &id, answers, reserve, at)
        })
        .await
        .map_err(|_| StoreError::Storage)?
    }

    /// Every open round closed at `now`, by its continuation deadline or its
    /// task's TTL, as `(id, revision, owner digest, why)`. A compact snapshot:
    /// each settlement re-checks the revision under the ordering lock.
    pub(crate) fn expired_input_rounds(
        &self,
        now: DateTime<Utc>,
    ) -> Vec<(String, u64, String, RoundClosed)> {
        // A sweep on a clock before 1970 skips this pass rather than cancel
        // every round it cannot date; the answer path still refuses them
        // (MIK-8202).
        if now.timestamp() < 0 {
            return Vec::new();
        }
        let state = self.0.state();
        if !state.ready {
            return Vec::new();
        }
        state
            .entries
            .iter()
            .filter_map(|(id, entry)| {
                let closed = closed_at(&entry.task, &entry.record, now)?;
                Some((
                    id.clone(),
                    entry.record.revision,
                    entry.record.admission.principal_digest.clone(),
                    closed,
                ))
            })
            .collect()
    }
}

impl Shared {
    /// The owner-scoped row, cloned under the ordering lock the caller holds.
    fn read_owned(&self, owner: &str, id: &str) -> Result<(Task, Record), StoreError> {
        let state = self.state();
        if !state.ready {
            return Err(StoreError::Unavailable);
        }
        let entry = owned(&state, owner, id)?;
        Ok((entry.task.clone(), entry.record.clone()))
    }

    fn fits_cap(&self, record: &Record) -> Result<Vec<u8>, StoreError> {
        let bytes = serialize(record)?;
        if bytes.len() > self.limits.record_bytes {
            return Err(StoreError::Capacity);
        }
        Ok(bytes)
    }

    fn require_input_blocking(
        &self,
        owner: &str,
        id: &str,
        revision: u64,
        requested: InputRequired,
        round: InputRound,
        at: DateTime<Utc>,
    ) -> Result<CommittedTask, StoreError> {
        let _order = self.order();
        let (mut task, mut record) = self.read_owned(owner, id)?;
        if record.revision != revision {
            return Err(StoreError::RevisionConflict);
        }
        task.transition(TaskTransition::RequireInput(requested), at)
            .map_err(|_| StoreError::InvalidTransition)?;
        record.revision = record.revision.checked_add(1).ok_or(StoreError::Capacity)?;
        record.model = task.snapshot();
        record.version = record.version.max(INPUT_ROUND_VERSION);
        record.input_round = Some(round);
        // A round that leaves no room for even its shortest answer could never
        // be completed: refused now, while it can still settle. Measured as
        // `provide_input` writes that answer, through the same transition, so
        // the probe and the real write never disagree at the cap (MIK-7661).
        let shortest = task
            .input_requests()
            .and_then(|requests| requests.keys().min_by_key(|key| key.len()))
            .cloned()
            .unwrap_or_default();
        let (mut answered, mut probe) = (task.clone(), record.clone());
        let mut minimal = Map::new();
        minimal.insert(shortest, json!({}));
        let change = answered
            .transition(TaskTransition::ProvideInput(Value::Object(minimal)), at)
            .map_err(|_| StoreError::InvalidTransition)?;
        probe.revision = probe.revision.checked_add(1).ok_or(StoreError::Capacity)?;
        probe.model = answered.snapshot();
        if let Some(open) = probe.input_round.as_mut() {
            open.accepted_inputs.extend(change.accepted_inputs);
        }
        self.fits_cap(&probe)?;
        // The round's keys stay on the model, which the bounded failure keeps:
        // a round that leaves it no room is refused while the task can still
        // settle (MIK-7651).
        if super::targets::fallback_bytes(&task, &record, at)? > self.limits.record_bytes {
            return Err(StoreError::Capacity);
        }
        let bytes = self.fits_cap(&record)?;
        self.commit(&record_name(task.id()), &bytes)?;
        Ok(self.publish(task, record))
    }

    fn close_round_blocking(
        &self,
        owner: &str,
        id: &str,
        revision: u64,
        reason: String,
    ) -> Result<CommittedTask, StoreError> {
        let _order = self.order();
        let (mut task, mut record) = self.read_owned(owner, id)?;
        if record.revision != revision {
            return Err(StoreError::RevisionConflict);
        }
        // Terminal is absorbing: a row another writer settled is not closed twice.
        if matches!(
            task.status(),
            TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Cancelled
        ) {
            return Err(StoreError::InvalidTransition);
        }
        let at = self.now();
        for event in [
            TaskTransition::StatusMessage(Some(reason)),
            TaskTransition::Cancel,
        ] {
            task.transition(event, at)
                .map_err(|_| StoreError::InvalidTransition)?;
        }
        record.revision = record.revision.checked_add(1).ok_or(StoreError::Capacity)?;
        // Drops the round before the record is measured.
        record.set_model(&task);
        let bytes = self.fits_cap(&record)?;
        self.commit(&record_name(task.id()), &bytes)?;
        Ok(self.publish(task, record))
    }

    /// Apply the one-shot clock a test armed for the moment a resume commits.
    #[cfg(test)]
    fn after_resume_commit(&self) {
        let lock = |slot: &std::sync::Mutex<Option<DateTime<Utc>>>| {
            slot.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
        };
        if let Some(at) = lock(&self.seams.clock_after_resume) {
            *self
                .seams
                .clock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(at);
        }
    }

    fn provide_input_blocking(
        &self,
        owner: &str,
        id: &str,
        answers: Map<String, Value>,
        reserve: impl FnOnce() -> Option<OwnedSemaphorePermit>,
        at: DateTime<Utc>,
    ) -> Result<ProvideOutcome, StoreError> {
        #[cfg(test)]
        self.seams
            .arrived
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _order = self.order();
        let (mut task, mut record) = self.read_owned(owner, id)?;
        // Read after the lock, never before: an update queued while the round
        // was open must not be let through once it has closed.
        if let Some(closed) = closed_at(&task, &record, self.now()) {
            return Ok(ProvideOutcome::Closed(closed));
        }
        let outstanding = task.input_requests().ok_or(StoreError::InvalidTransition)?;
        // The model ignores a key that is not outstanding; here it refuses the
        // whole update before any key is accepted.
        if answers.is_empty() || answers.keys().any(|key| !outstanding.contains_key(key)) {
            return Err(StoreError::InvalidTransition);
        }
        let completing = answers.len() == outstanding.len();
        let mut round = record
            .input_round
            .take()
            .ok_or(StoreError::InvalidTransition)?;
        let change = task
            .transition(TaskTransition::ProvideInput(Value::Object(answers)), at)
            .map_err(|_| StoreError::InvalidTransition)?;
        round.accepted_inputs.extend(change.accepted_inputs);
        record.revision = record.revision.checked_add(1).ok_or(StoreError::Capacity)?;
        record.model = task.snapshot();
        // Measured with the answers held, completing or not: the cap bounds
        // what an update may make the gateway keep.
        record.input_round = Some(round);
        let bytes = self.fits_cap(&record)?;
        if !completing {
            self.commit(&record_name(task.id()), &bytes)?;
            return Ok(ProvideOutcome::Partial(self.publish(task, record)));
        }
        // The permit is taken inside this write and before the CAS to
        // `working`: no free worker means nothing is written.
        let Some(slot) = reserve() else {
            return Ok(ProvideOutcome::PoolFull);
        };
        let round = record
            .input_round
            .take()
            .ok_or(StoreError::InvalidTransition)?;
        let bytes = serialize(&record)?;
        self.commit(&record_name(task.id()), &bytes)?;
        #[cfg(test)]
        self.after_resume_commit();
        Ok(ProvideOutcome::Resumed {
            task: self.publish(task, record),
            round,
            slot,
        })
    }
}

/// Whether an open round no longer takes answers at `now`, and why. The
/// continuation deadline is named first: it is the one the client can act on.
fn closed_at(task: &Task, record: &Record, now: DateTime<Utc>) -> Option<RoundClosed> {
    if task.status() != TaskStatus::InputRequired {
        return None;
    }
    let deadline = record
        .input_round
        .as_ref()
        .and_then(|round| round.continuation_deadline);
    // A time before 1970 is a clock that cannot be read: every deadline
    // counts as passed, never as still ahead (MIK-8202).
    let passed = |deadline: u64| {
        u64::try_from(now.timestamp())
            .ok()
            .is_none_or(|now| now >= deadline)
    };
    // The task's lifetime too: a 1969 `now` would read a finite TTL as never
    // reached, so it counts as elapsed (MIK-8202).
    let before_epoch = now.timestamp() < 0;
    match deadline {
        Some(deadline) if passed(deadline) => Some(RoundClosed::Continuation(deadline)),
        _ if before_epoch || task.retention_elapsed(now) => Some(RoundClosed::Ttl),
        _ => None,
    }
}

#[cfg(test)]
#[path = "store_input_tests.rs"]
mod tests;
