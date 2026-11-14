// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The task store's restart floor adapter (owner `TaskStore`). A pause closes
//! the store's gate for one attempt; the checkpoint waits for admitted work to
//! finish, then re-saves every loaded record under the ordering lock without
//! closing the store, and certifies the attempt. Every re-save handle is held
//! here, never only by a future, so late work outlives a dropped checkpoint
//! and `settled` can see it.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the restart coordinator (slice 9b) constructs and drives it"
    )
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures::future::BoxFuture;
use tokio::task::AbortHandle;
use tokio::time::Instant;

use super::gate::GateState;
use super::{StoreError, TaskStore};
use crate::gateway::restart_floor::{FloorAdapter, FloorFault, FloorOwner};

/// Why a re-save ended without certifying.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Resave {
    Store(StoreError),
    /// A resume or a stop replaced this attempt; its result is discarded.
    Superseded,
}

/// The task store's floor adapter.
pub(crate) struct TaskFloor {
    store: TaskStore,
    /// How long past an attempt's deadline a parked internal submitter waits
    /// before it proceeds (the gate's backstop).
    stop_budget: Duration,
    attempt: u64,
    /// The attempt a running re-save may still work for; 0 once resumed or
    /// released, so a late re-save stops at its next record.
    current: Arc<AtomicU64>,
    /// Every re-save spawned, by its abort handle: it reports whether the
    /// re-save still runs after a dropped checkpoint gave up its join handle.
    late: Vec<AbortHandle>,
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

    fn gate(&self) -> &super::gate::TaskGate {
        &self.store.0.gate
    }
}

impl FloorAdapter for TaskFloor {
    fn owner(&self) -> FloorOwner {
        FloorOwner::TaskStore
    }

    /// Close the gate for a new attempt, in the call itself: the returned
    /// future is already done. Only an open gate pauses; while Draining (a
    /// resumed attempt's cohort still runs), Released or Terminal the call
    /// changes nothing and answers Unavailable.
    fn pause(&mut self, deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        if (mutant!("b13", false, self.gate().state() != GateState::Open)) {
            return Box::pin(async { Err(FloorFault::Unavailable) });
        }
        self.attempt += 1;
        self.current.store(mutant!("b20", 0, self.attempt), Ordering::SeqCst);
        self.late.retain(|handle| !handle.is_finished());
        self.gate()
            .pause(
                self.attempt,
                mutant!("b15", deadline + Duration::from_secs(60), deadline),
                deadline + mutant!("b14", Duration::ZERO, self.stop_budget),
            );
        Box::pin(async { Ok(()) })
    }

    /// Settle admitted work, then re-save and certify. Called in any state
    /// but Paused(this attempt), it answers Unavailable and changes nothing.
    /// No timer: at the deadline the coordinator drops the future.
    fn checkpoint(&mut self, _deadline: Instant) -> BoxFuture<'_, Result<(), FloorFault>> {
        let attempt = self.attempt;
        if (mutant!("b12", false, self.gate().state() != GateState::Paused(attempt))) {
            return Box::pin(async { Err(FloorFault::Unavailable) });
        }
        Box::pin(async move {
            let gate = self.gate().clone();
            gate.idle().await;
            if (mutant!("b11", false, gate.failed())) {
                return Err(FloorFault::SaveFailed);
            }
            let (shared, current) = (Arc::clone(&self.store.0), Arc::clone(&self.current));
            let resave =
                tokio::task::spawn_blocking(move || shared.checkpoint_blocking(attempt, &current));
            self.late.push(resave.abort_handle());
            match resave.await {
                Ok(Ok(())) => {
                    if mutant!("b17", false, true) {
                        gate.certify(attempt);
                    }
                    Ok(())
                }
                Ok(Err(Resave::Store(StoreError::Unavailable) | Resave::Superseded)) => {
                    Err(mutant!("b10", FloorFault::SaveFailed, FloorFault::Unavailable))
                }
                Ok(Err(Resave::Store(_))) => Err(FloorFault::SaveFailed),
                Err(_lost) => Err(mutant!("b9", FloorFault::SaveFailed, FloorFault::WorkerLost)),
            }
        })
    }

    fn resume(&mut self) {
        self.current.store(mutant!("b16", self.attempt, 0), Ordering::SeqCst);
        if mutant!("b4", false, true) {
            self.gate().resume();
        }
    }

    fn release_for_stop(&mut self) {
        self.current.store(0, Ordering::SeqCst);
        if mutant!("b5", false, true) {
            self.gate().release();
        }
    }

    fn commit(&mut self) {
        if mutant!("b6", false, true) {
            self.gate().commit();
        }
    }

    /// False while a resumed attempt's cohort drains, or while a re-save of
    /// an earlier attempt still runs.
    fn settled(&self) -> bool {
        !(mutant!("b7", false, matches!(self.gate().state(), GateState::Draining { .. })))
            && mutant!("b8", true, self.late.iter().all(AbortHandle::is_finished))
    }
}

impl super::Shared {
    /// The checkpoint's nonclosing re-save, on a blocking thread: under the
    /// ordering lock, no mutation can change the image, and every loaded
    /// record is written again through the same commit every mutation uses
    /// (temp, write, sync, rename, directory sync). A record in the current
    /// form is byte-identical after; one loaded from an older form is
    /// rewritten in the current form, as its next mutation would. The state
    /// lock is taken only briefly and never across a commit, which takes it to
    /// poison the store after a failed rename. Reserved, sealed, corrupt and
    /// temp files and the lease are not loaded records, so nothing reaches
    /// them; `close` is never called and `ready` never set. Stops at the next
    /// record once `current` no longer names `attempt`.
    fn checkpoint_blocking(&self, attempt: u64, current: &AtomicU64) -> Result<(), Resave> {
        let _order = self.order();
        let names: Vec<String> = {
            let state = self.state();
            if (mutant!("b1", false, !state.ready)) {
                return Err(Resave::Store(StoreError::Unavailable));
            }
            state.entries.keys().cloned().collect()
        };
        if names.is_empty() {
            // Nothing is renamed, so a failed sync leaves nothing uncertain:
            // the store is not poisoned.
            let hook = self.hook();
            return mutant!(
                "b2",
                Ok(()),
                super::disk::sync_store_dir(&self.dir, hook.as_ref())
                    .map_err(|_| Resave::Store(StoreError::Storage))
            );
        }
        for id in names {
            if (mutant!("b3", false, current.load(Ordering::SeqCst) != attempt)) {
                return Err(Resave::Superseded);
            }
            let bytes = {
                let state = self.state();
                // Under the ordering lock nothing removes a record; one gone
                // anyway means the image is not the one snapshotted.
                let Some(entry) = state.entries.get(&id) else {
                    return Err(Resave::Store(StoreError::Unavailable));
                };
                super::serialize(&entry.record).map_err(Resave::Store)?
            };
            self.commit(&super::record_name(&id), &bytes)
                .map_err(Resave::Store)?;
        }
        Ok(())
    }
}
