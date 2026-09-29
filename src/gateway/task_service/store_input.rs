// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The input round's durable writes (MIK-7311.LIFECYCLE.1): open a round with
//! its continuation, accept answers, and select rounds past their TTL.
//!
//! Every write here runs under the store's ordering lock on a blocking thread,
//! like every other mutation, and is refused before anything is written.
#![allow(
    dead_code,
    reason = "stubs for the failing tests; used by the input-round change"
)]

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
}

impl TaskStore {
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

    /// Every open round past the TTL its record was created with, as
    /// `(id, revision, owner digest)`. A compact snapshot: each settlement
    /// re-checks the revision under the ordering lock.
    pub(crate) fn expired_input_rounds(&self, now: DateTime<Utc>) -> Vec<(String, u64, String)> {
        let state = self.0.state();
        if !state.ready {
            return Vec::new();
        }
        state
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.task.status() == TaskStatus::InputRequired
                    && entry.task.retention_elapsed(now)
            })
            .map(|(id, entry)| {
                (
                    id.clone(),
                    entry.record.revision,
                    entry.record.admission.principal_digest.clone(),
                )
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
        // be completed: refused now, while it can still settle.
        let shortest = task
            .input_requests()
            .and_then(|requests| requests.keys().min_by_key(|key| key.len()))
            .cloned()
            .unwrap_or_default();
        let mut probe = record.clone();
        if let Some(open) = probe.input_round.as_mut() {
            open.accepted_inputs.insert(shortest, json!({}));
        }
        self.fits_cap(&probe)?;
        let bytes = self.fits_cap(&record)?;
        self.commit(&record_name(task.id()), &bytes)?;
        Ok(self.publish(task, record))
    }

    fn provide_input_blocking(
        &self,
        owner: &str,
        id: &str,
        answers: Map<String, Value>,
        reserve: impl FnOnce() -> Option<OwnedSemaphorePermit>,
        at: DateTime<Utc>,
    ) -> Result<ProvideOutcome, StoreError> {
        let _order = self.order();
        let (mut task, mut record) = self.read_owned(owner, id)?;
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
        Ok(ProvideOutcome::Resumed {
            task: self.publish(task, record),
            round,
            slot,
        })
    }
}
