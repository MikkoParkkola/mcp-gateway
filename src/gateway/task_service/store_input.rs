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

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use tokio::sync::OwnedSemaphorePermit;

use super::{StoreError, TaskStore};
use crate::gateway::task_service::record::{CommittedTask, InputRound};
use crate::protocol::mrtr::InputRequired;

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
        _owner: &str,
        _id: &str,
        _revision: u64,
        _requested: InputRequired,
        _round: InputRound,
        _at: DateTime<Utc>,
    ) -> Result<CommittedTask, StoreError> {
        Err(StoreError::InvalidTransition)
    }

    /// Accept answers for an open round, all or nothing.
    ///
    /// # Errors
    /// `InvalidTransition` when no round is open or any key is not
    /// outstanding; `Capacity` when the answers would exceed the byte cap.
    pub(crate) async fn provide_input(
        &self,
        _owner: &str,
        _id: &str,
        _answers: Map<String, Value>,
        _reserve: impl FnOnce() -> Option<OwnedSemaphorePermit> + Send + 'static,
        _at: DateTime<Utc>,
    ) -> Result<ProvideOutcome, StoreError> {
        Err(StoreError::InvalidTransition)
    }

    /// Every open round past the TTL its record was created with, as
    /// `(id, revision, owner digest)`.
    pub(crate) fn expired_input_rounds(&self, _now: DateTime<Utc>) -> Vec<(String, u64, String)> {
        Vec::new()
    }
}
