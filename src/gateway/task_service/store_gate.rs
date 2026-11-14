// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The task store's gate: every mutation asks it for admission immediately
//! before its blocking work is spawned, and the restart checkpoint closes it,
//! waits for the admitted work to finish, and opens it again.
//!
//! One watch value holds the state and the count of admitted work, so checking
//! the state and counting an admission are one step: no checkpoint can see
//! nothing in flight between a submitter's check and its count. The watch sits
//! outside the store's `order` and `state` locks and is never held across an
//! await or I/O, so the adapter's synchronous calls never wait behind a write.
//!
//! RED-FIRST SKELETON: every method below admits, counts and changes nothing,
//! so each row in `store_gate_tests.rs` fails at its own assertion until the
//! behaviour lands. Design: restart slice 5, mik-9444/design.md (r3 final).
#![allow(dead_code, reason = "red-phase: remove when the implementation uses it")]

use std::sync::Arc;

use tokio::sync::watch;
use tokio::time::Instant;

/// Who asks the gate: the caller decides, because one store method can serve
/// two classes (a route cancel and a worker settle share `settle_bounded_by`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// A client request: task admission, input, the route cancel.
    External,
    /// Work completing an admitted task: worker settles, dispatch marks, rounds.
    Internal,
    /// The periodic expiry sweep.
    Sweep,
}

/// The gate's state word. `Paused` and `Certified` carry the attempt number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GateState {
    Open,
    Paused(u64),
    Certified(u64),
    /// After a resume: submitters parked before it are admitted first; `left`
    /// counts the ones whose blocking work has not finished yet.
    Draining { left: usize },
    Terminal,
    Released,
}

/// Why the gate turned a submitter away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The gateway is restarting: a new external submission after commit, or one
    /// still parked past its deadline.
    Restarting,
    /// A sweep while the store is paused or draining; the next tick covers it.
    Skipped,
}

#[derive(Debug, Default)]
struct Gate {
    state: Option<GateState>,
    in_flight: usize,
    failed: bool,
    parked: usize,
    epoch: u64,
    deadline: Option<Instant>,
}

/// One per store, shared by every entry point and the checkpoint adapter.
/// Cloning shares the same gate.
#[derive(Clone, Debug)]
pub(crate) struct TaskGate {
    tx: Arc<watch::Sender<Gate>>,
    /// Kept for the store's lifetime, so no update depends on a submitter
    /// holding a receiver.
    _rx: watch::Receiver<Gate>,
    #[cfg(test)]
    seams: seams::GateSeams,
}

/// An admission, counted in flight until dropped. It is moved into the
/// blocking closure, so the count follows the work, not the caller.
#[derive(Debug)]
pub(crate) struct Admitted {
    _gate: TaskGate,
}

impl Admitted {
    /// Note the closure's outcome before the admission drops: a storage failure
    /// during an attempt fails that attempt's checkpoint. Stub: notes nothing.
    pub(crate) fn record<T>(&self, _result: &Result<T, super::StoreError>) {}
}

impl TaskGate {
    pub(crate) fn new() -> Self {
        let (tx, rx) = watch::channel(Gate::default());
        Self {
            tx: Arc::new(tx),
            _rx: rx,
            #[cfg(test)]
            seams: seams::GateSeams::default(),
        }
    }

    /// Ask for admission for one mutation of class `kind`. Stub: always admits.
    pub(crate) async fn admit(&self, _kind: Kind) -> Result<Admitted, Refused> {
        Ok(Admitted { _gate: self.clone() })
    }

    /// Close the gate for `attempt`, whose checkpoint ends at `deadline`; an
    /// internal submitter still parked at `backstop` proceeds. Stub.
    pub(crate) fn pause(&self, _attempt: u64, _deadline: Instant, _backstop: Instant) {}

    /// The attempt's checkpoint succeeded. Stub.
    pub(crate) fn certify(&self, _attempt: u64) {}

    /// Cancel recovery: drain parked submitters first, then open. Stub.
    pub(crate) fn resume(&self) {}

    /// A stop signal won: admit everything, replay nothing. Stub.
    pub(crate) fn release(&self) {}

    /// The commit edge: refuse new external submissions. Stub.
    pub(crate) fn commit(&self) {}

    /// The current state. Stub: always open.
    pub(crate) fn state(&self) -> GateState {
        self.tx.borrow().state.unwrap_or(GateState::Open)
    }

    /// Admitted work not yet finished. Stub: always zero.
    pub(crate) fn in_flight(&self) -> usize {
        self.tx.borrow().in_flight
    }

    /// Submitters parked now (live tickets). Stub: always zero.
    pub(crate) fn parked(&self) -> usize {
        self.tx.borrow().parked
    }

    /// Whether an admitted closure failed with a storage error since the last
    /// pause. Stub: never.
    pub(crate) fn failed(&self) -> bool {
        self.tx.borrow().failed
    }

    /// Resolves once no admitted work is in flight. Stub: at once.
    pub(crate) async fn idle(&self) {}

    /// Whether a sweep tick may start. Stub: always.
    pub(crate) fn sweeps_allowed(&self) -> bool {
        true
    }

    /// Test-only: the barriers a row holds to interleave a race.
    #[cfg(test)]
    pub(crate) fn seams(&self) -> &seams::GateSeams {
        &self.seams
    }
}

/// Test seams: barriers inside `admit`, so a row fixes the order of a race
/// without sleeping.
#[cfg(test)]
pub(crate) mod seams {
    use std::sync::{Arc, Mutex};

    use tokio::sync::Semaphore;

    /// A rendezvous: the gate signals `reached` and waits for `release`.
    #[derive(Debug, Default)]
    pub(crate) struct Hold {
        reached: Semaphore,
        release: Semaphore,
    }

    impl Hold {
        /// The gate's side: announce arrival, then wait to be let go.
        pub(crate) async fn pass(&self) {
            self.reached.add_permits(1);
            if let Ok(permit) = self.release.acquire().await {
                permit.forget();
            }
        }

        /// The row's side: wait until the gate has arrived.
        pub(crate) async fn reached(&self) {
            if let Ok(permit) = self.reached.acquire().await {
                permit.forget();
            }
        }

        /// The row's side: let the gate go on.
        pub(crate) fn release(&self) {
            self.release.add_permits(1);
        }
    }

    /// Which barriers are armed. Cloning shares them.
    #[derive(Clone, Debug, Default)]
    pub(crate) struct GateSeams {
        /// Inside `admit`, right after the decision.
        pub(crate) at_decision: Arc<Mutex<Option<Arc<Hold>>>>,
        /// Inside `admit`, after a Park decision and before the wait.
        pub(crate) before_wait: Arc<Mutex<Option<Arc<Hold>>>>,
    }

    impl GateSeams {
        /// Arm a barrier and hand the row its side.
        pub(crate) fn arm(slot: &Mutex<Option<Arc<Hold>>>) -> Arc<Hold> {
            let hold = Arc::new(Hold::default());
            *slot.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&hold));
            hold
        }
    }
}
