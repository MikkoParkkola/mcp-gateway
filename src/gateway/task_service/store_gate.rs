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
//! A submitter the gate parks holds a ticket. Resume admits every ticket that
//! exists at that moment before anything newer (task writes are
//! revision-checked, so order decides which of two writes on one revision
//! wins), and the gate opens only when that cohort's work has finished. An
//! external parker refuses itself one second past its attempt's deadline,
//! after the coordinator's own exit at the deadline has had its chance; an
//! internal one waits for the coordinator's exit, with a backstop past the
//! stop budget at which it proceeds rather than lose a task's final write.

#![cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the restart checkpoint adapter, the caller of the state changes, lands in the next change"
    )
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

/// Who asks the gate: the caller decides, because one store method can serve
/// two classes (a route cancel and a worker settle share `settle_bounded_as`).
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum GateState {
    #[default]
    Open,
    Paused(u64),
    Certified(u64),
    /// After a resume: submitters parked before it are admitted first; `left`
    /// counts the ones whose blocking work has not finished yet.
    Draining {
        left: usize,
    },
    Terminal,
    Released,
}

/// Why the gate turned a submitter away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// The gateway is restarting: a new external submission after commit, or one
    /// still parked past its deadline.
    Restarting,
    /// A sweep while the store is paused, draining or terminal; the next tick
    /// covers it.
    Skipped,
}

/// The margin past an attempt's deadline at which an external parker refuses
/// itself: the coordinator's own exit at the deadline always runs first.
const EXTERNAL_GRACE: Duration = Duration::from_secs(1);

#[derive(Debug, Default)]
struct Gate {
    state: GateState,
    in_flight: usize,
    /// An admitted write failed with a storage error during this attempt.
    failed: bool,
    /// Live tickets.
    parked: usize,
    /// Bumped by every resume and every commit: a ticket born before the
    /// latest one was parked before it.
    epoch: u64,
    /// The epoch the current drain started at.
    drain_epoch: u64,
    attempt: u64,
    deadline: Option<Instant>,
    backstop: Option<Instant>,
}

/// What a parked submitter carries, stamped at its first park.
#[derive(Clone, Copy, Debug)]
struct Stamp {
    born: u64,
    attempt: u64,
    deadline: Option<Instant>,
    backstop: Option<Instant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decision {
    /// Admit; `cohort` when the admission is one of a drain's cohort.
    Admit {
        cohort: bool,
    },
    Park,
    Refuse(Refused),
}

/// The gate's one decision. `stamp` is the submitter's ticket, if it parked
/// before; `expired` is true once that ticket's own bound has passed.
fn decide(g: &Gate, kind: Kind, stamp: Option<&Stamp>, expired: bool) -> Decision {
    let born_before = |epoch: u64| stamp.is_some_and(|s| s.born < epoch);
    match (g.state, kind) {
        (GateState::Open | GateState::Released, _) => Decision::Admit { cohort: false },
        (_, Kind::Sweep) => Decision::Refuse(Refused::Skipped),
        (GateState::Paused(attempt) | GateState::Certified(attempt), _) => {
            let own = stamp.is_some_and(|s| s.attempt == attempt);
            match (expired && own, kind) {
                (true, Kind::External) => Decision::Refuse(Refused::Restarting),
                (true, _) => Decision::Admit { cohort: false },
                (false, _) => Decision::Park,
            }
        }
        (GateState::Draining { .. }, _) if born_before(g.drain_epoch) => {
            Decision::Admit { cohort: true }
        }
        (GateState::Draining { .. }, _) => Decision::Park,
        (GateState::Terminal, Kind::External) if born_before(g.epoch) => {
            Decision::Admit { cohort: false }
        }
        (GateState::Terminal, Kind::External) => Decision::Refuse(Refused::Restarting),
        (GateState::Terminal, _) => Decision::Admit { cohort: false },
    }
}

/// One per store, shared by every entry point and the checkpoint adapter.
/// Cloning shares the same gate.
#[derive(Clone, Debug)]
pub(crate) struct TaskGate {
    tx: Arc<watch::Sender<Gate>>,
    /// Kept for the store's lifetime, so no update depends on a submitter
    /// holding a receiver.
    rx: watch::Receiver<Gate>,
    #[cfg(test)]
    seams: seams::GateSeams,
}

/// An admission, counted in flight until dropped. It is moved into the
/// blocking closure, so the count follows the work, not the caller.
#[derive(Debug)]
pub(crate) struct Admitted {
    gate: TaskGate,
    /// The drain epoch this admission belongs to as a cohort member.
    cohort: Option<u64>,
    recorded: AtomicBool,
}

impl Admitted {
    /// Note the closure's outcome before the admission drops: a storage failure
    /// during an attempt fails that attempt's checkpoint.
    pub(crate) fn record(&self, storage_failed: bool) {
        self.recorded.store(true, Ordering::Relaxed);
        if storage_failed {
            self.gate.tx.send_if_modified(|g| mark_failed(g));
        }
    }
}

/// A storage failure counts against the attempt only while one is open.
fn mark_failed(g: &mut Gate) -> bool {
    let open_attempt = matches!(g.state, GateState::Paused(_) | GateState::Certified(_));
    if open_attempt && !g.failed {
        g.failed = true;
    }
    open_attempt
}

/// One cohort member done: the drain it belongs to loses one, and opens the
/// gate when it reaches zero. A member of an earlier drain changes nothing.
fn cohort_done(g: &mut Gate, epoch: u64) -> bool {
    match g.state {
        GateState::Draining { left } if g.drain_epoch == epoch => {
            let left = left.saturating_sub(1);
            g.state = if left == 0 {
                GateState::Open
            } else {
                GateState::Draining { left }
            };
            true
        }
        _ => false,
    }
}

impl Drop for Admitted {
    fn drop(&mut self) {
        let unreported = !self.recorded.load(Ordering::Relaxed);
        let cohort = self.cohort;
        self.gate.tx.send_modify(|g| {
            g.in_flight = g.in_flight.saturating_sub(1);
            if unreported {
                // The work ended without an outcome (it panicked).
                mark_failed(g);
            }
            if let Some(epoch) = cohort {
                cohort_done(g, epoch);
            }
        });
    }
}

/// A parked submitter's place: counted in `parked` while it lives. If it ends
/// without being admitted while its drain runs, the drain loses a member.
struct Ticket {
    gate: TaskGate,
    stamp: Stamp,
    admitted: bool,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        let (born, admitted) = (self.stamp.born, self.admitted);
        self.gate.tx.send_modify(|g| {
            g.parked = g.parked.saturating_sub(1);
            if !admitted && born < g.drain_epoch {
                cohort_done(g, g.drain_epoch);
            }
        });
    }
}

/// How long a parked submitter waits before it decides again on its own:
/// none while draining; an external one until one second past its attempt's
/// deadline; an internal one until its backstop.
fn bound(state: GateState, kind: Kind, stamp: &Stamp) -> Option<Instant> {
    match (state, kind) {
        (GateState::Paused(_) | GateState::Certified(_), Kind::External) => {
            stamp.deadline.map(|d| d + EXTERNAL_GRACE)
        }
        (GateState::Paused(_) | GateState::Certified(_), _) => stamp.backstop,
        _ => None,
    }
}

impl TaskGate {
    pub(crate) fn new() -> Self {
        let (tx, rx) = watch::channel(Gate::default());
        Self {
            tx: Arc::new(tx),
            rx,
            #[cfg(test)]
            seams: seams::GateSeams::default(),
        }
    }

    /// Ask for admission for one mutation of class `kind`: admitted at once,
    /// parked until the gate's answer changes, or refused.
    pub(crate) async fn admit(&self, kind: Kind) -> Result<Admitted, Refused> {
        #[cfg(test)]
        self.seams.record(kind);
        let mut rx = self.rx.clone();
        let mut ticket: Option<Ticket> = None;
        let mut expired = false;
        loop {
            let stamp = ticket.as_ref().map(|t| t.stamp);
            let (mut decision, mut fresh, mut drain) = (Decision::Park, None, 0);
            self.tx.send_if_modified(|g| {
                decision = decide(g, kind, stamp.as_ref(), expired);
                drain = g.drain_epoch;
                match decision {
                    Decision::Admit { .. } => {
                        g.in_flight += 1;
                        true
                    }
                    Decision::Park if stamp.is_none() => {
                        g.parked += 1;
                        fresh = Some(Stamp {
                            born: g.epoch,
                            attempt: g.attempt,
                            deadline: g.deadline,
                            backstop: g.backstop,
                        });
                        true
                    }
                    Decision::Park | Decision::Refuse(_) => false,
                }
            });
            #[cfg(test)]
            seams::GateSeams::pass(&self.seams.at_decision).await;
            match decision {
                Decision::Admit { cohort } => {
                    if expired && kind != Kind::External {
                        tracing::error!(
                            attempt = stamp.map(|s| s.attempt),
                            "a task-store write proceeded at the restart backstop, outside its attempt's certified image"
                        );
                    }
                    if let Some(ticket) = ticket.as_mut() {
                        ticket.admitted = true;
                    }
                    return Ok(Admitted {
                        gate: self.clone(),
                        cohort: cohort.then_some(drain),
                        recorded: AtomicBool::new(false),
                    });
                }
                Decision::Refuse(refused) => return Err(refused),
                Decision::Park => {}
            }
            if let Some(stamp) = fresh {
                ticket = Some(Ticket {
                    gate: self.clone(),
                    stamp,
                    admitted: false,
                });
            }
            let Some(ticket) = ticket.as_mut() else {
                // Unreachable: a Park decision always leaves a ticket.
                continue;
            };
            let state = self.restamp(&mut ticket.stamp);
            expired = false;
            #[cfg(test)]
            seams::GateSeams::pass(&self.seams.before_wait).await;
            let stamp = ticket.stamp;
            let woken = |g: &Gate| decide(g, kind, Some(&stamp), false) != Decision::Park;
            match bound(state, kind, &stamp) {
                Some(until) => {
                    expired = tokio::time::timeout_at(until, rx.wait_for(woken))
                        .await
                        .is_err();
                }
                None => {
                    let _ = rx.wait_for(woken).await;
                }
            }
        }
    }

    /// Give a ticket parked in an earlier attempt this attempt's bounds; the
    /// current state either way.
    fn restamp(&self, stamp: &mut Stamp) -> GateState {
        let g = self.tx.borrow();
        if let GateState::Paused(attempt) | GateState::Certified(attempt) = g.state
            && attempt != stamp.attempt
        {
            stamp.attempt = attempt;
            stamp.deadline = g.deadline;
            stamp.backstop = g.backstop;
        }
        g.state
    }

    /// Close the gate for `attempt`, whose checkpoint ends at `deadline`; an
    /// internal submitter still parked at `backstop` proceeds. Only an open
    /// gate pauses (one pause per attempt; a final state stays final).
    pub(crate) fn pause(&self, attempt: u64, deadline: Instant, backstop: Instant) {
        self.tx.send_if_modified(|g| {
            if g.state != GateState::Open {
                return false;
            }
            g.state = GateState::Paused(attempt);
            g.attempt = attempt;
            g.deadline = Some(deadline);
            g.backstop = Some(backstop);
            g.failed = false;
            true
        });
    }

    /// The attempt's checkpoint succeeded.
    pub(crate) fn certify(&self, attempt: u64) {
        self.tx.send_if_modified(|g| {
            let paused = g.state == GateState::Paused(attempt);
            if paused {
                g.state = GateState::Certified(attempt);
            }
            paused
        });
    }

    /// Cancel recovery: every submitter parked now is admitted ahead of
    /// anything newer, and the gate opens once their work has finished.
    pub(crate) fn resume(&self) {
        self.tx.send_if_modified(|g| {
            if !matches!(g.state, GateState::Paused(_) | GateState::Certified(_)) {
                return false;
            }
            g.epoch += 1;
            g.drain_epoch = g.epoch;
            g.state = match g.parked {
                0 => GateState::Open,
                left => GateState::Draining { left },
            };
            true
        });
    }

    /// A stop signal won: admit everything, parked work included; no order.
    pub(crate) fn release(&self) {
        self.tx.send_if_modified(|g| {
            let live = g.state != GateState::Terminal && g.state != GateState::Released;
            if live {
                g.state = GateState::Released;
            }
            live
        });
    }

    /// The commit edge: work parked before it and internal work go on; a new
    /// external submission is refused.
    pub(crate) fn commit(&self) {
        self.tx.send_if_modified(|g| {
            let certified = matches!(g.state, GateState::Certified(_));
            if certified {
                g.state = GateState::Terminal;
                g.epoch += 1;
            }
            certified
        });
    }

    /// The current state.
    pub(crate) fn state(&self) -> GateState {
        self.tx.borrow().state
    }

    /// Admitted work not yet finished.
    pub(crate) fn in_flight(&self) -> usize {
        self.tx.borrow().in_flight
    }

    /// Submitters parked now (live tickets).
    pub(crate) fn parked(&self) -> usize {
        self.tx.borrow().parked
    }

    /// Whether an admitted write failed with a storage error since the pause.
    pub(crate) fn failed(&self) -> bool {
        self.tx.borrow().failed
    }

    /// Resolves once no admitted work is in flight.
    pub(crate) async fn idle(&self) {
        let mut rx = self.rx.clone();
        let _ = rx.wait_for(|g| g.in_flight == 0).await;
    }

    /// Whether a sweep tick may start.
    pub(crate) fn sweeps_allowed(&self) -> bool {
        matches!(self.state(), GateState::Open | GateState::Released)
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
    #[derive(Debug)]
    pub(crate) struct Hold {
        reached: Semaphore,
        release: Semaphore,
    }

    impl Default for Hold {
        fn default() -> Self {
            Self {
                reached: Semaphore::new(0),
                release: Semaphore::new(0),
            }
        }
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
        /// Every class `admit` was asked for, in order (a row reads and clears it).
        pub(crate) admits: Arc<Mutex<Vec<super::Kind>>>,
    }

    impl GateSeams {
        /// `admit` logs each class it is asked for.
        pub(crate) fn record(&self, kind: super::Kind) {
            self.admits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(kind);
        }

        /// `admit` passes an armed barrier, or nothing.
        pub(crate) async fn pass(slot: &Mutex<Option<Arc<Hold>>>) {
            let hold = slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(hold) = hold {
                hold.pass().await;
            }
        }

        /// The classes asked for since the last call, oldest first.
        pub(crate) fn take_admits(&self) -> Vec<super::Kind> {
            std::mem::take(
                &mut *self
                    .admits
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            )
        }

        /// Arm a barrier and hand the row its side.
        pub(crate) fn arm(slot: &Mutex<Option<Arc<Hold>>>) -> Arc<Hold> {
            let hold = Arc::new(Hold::default());
            *slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::clone(&hold));
            hold
        }
    }
}

/// Why a gated blocking job never ran, or never reported back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Gated {
    Refused(Refused),
    /// The blocking task was lost: it panicked, or the runtime is going away.
    Lost,
}

impl From<Gated> for super::StoreError {
    fn from(gated: Gated) -> Self {
        match gated {
            Gated::Refused(Refused::Restarting) => Self::Restarting,
            Gated::Refused(Refused::Skipped) => Self::Skipped,
            Gated::Lost => Self::Storage,
        }
    }
}

/// Whether a gated job's output is a storage failure the checkpoint must see.
pub(crate) trait Outcome {
    fn storage_failed(&self) -> bool;
}

impl<T> Outcome for Result<T, super::StoreError> {
    fn storage_failed(&self) -> bool {
        matches!(self, Err(super::StoreError::Storage))
    }
}

impl<T> Outcome for Vec<T> {
    fn storage_failed(&self) -> bool {
        false
    }
}

impl super::TaskStore {
    /// Whether an expiry sweep tick may start now.
    pub(crate) fn sweeps_allowed(&self) -> bool {
        self.0.gate.sweeps_allowed()
    }

    /// Admit one mutation of class `kind`, then run `work` on the blocking pool
    /// with the admission moved into it: the work stays counted until it ends,
    /// even if this future is dropped, and its failure is noted before the
    /// count drops. The only place the store spawns blocking work for a
    /// mutation.
    pub(super) async fn admitted<R: Outcome + Send + 'static>(
        &self,
        kind: Kind,
        work: impl FnOnce() -> R + Send + 'static,
    ) -> Result<R, Gated> {
        let admission = self.0.gate.admit(kind).await.map_err(Gated::Refused)?;
        tokio::task::spawn_blocking(move || {
            let output = work();
            admission.record(output.storage_failed());
            drop(admission);
            output
        })
        .await
        .map_err(|_| Gated::Lost)
    }
}
