// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The task store's restart floor adapter (owner TaskStore): it pauses the
//! store's gate, waits for admitted work to finish, re-saves every record
//! without closing the store, and certifies the image a restart trusts.
//! RED STUB: answers Ok and does nothing.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the restart coordinator (slice 9b) constructs and drives it"
    )
)]

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::{StoreError, TaskStore};
use crate::gateway::restart_floor::{FloorAdapter, FloorFault, FloorOwner};

/// Why a re-save ended without certifying.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Resave {
    Store(StoreError),
    /// A later attempt, a resume or a stop replaced this one.
    Superseded,
}

/// The task store's floor adapter. Holds every re-save it spawned, so late
/// work outlives a dropped checkpoint future and `settled` can see it.
pub(crate) struct TaskFloor {
    store: TaskStore,
    stop_budget: Duration,
    attempt: u64,
    current: Arc<AtomicU64>,
    late: Vec<JoinHandle<Result<(), Resave>>>,
}

impl TaskFloor {
    /// An adapter over `store`. An internal submitter still parked
    /// `stop_budget` past an attempt's deadline proceeds (the backstop).
    pub(crate) fn new(store: &TaskStore, stop_budget: Duration) -> Self {
        Self {
            store: store.clone(),
            stop_budget,
            attempt: 0,
            current: Arc::new(AtomicU64::new(0)),
            late: Vec::new(),
        }
    }
}

impl FloorAdapter for TaskFloor {
    fn owner(&self) -> FloorOwner {
        FloorOwner::TaskStore
    }

    fn pause(&mut self, _deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        Box::pin(async { Ok(()) })
    }

    fn checkpoint(&mut self, _deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        Box::pin(async { Ok(()) })
    }

    fn resume(&mut self) {}

    fn release_for_stop(&mut self) {}

    fn commit(&mut self) {}

    fn settled(&self) -> bool {
        true
    }
}
