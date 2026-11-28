// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The checkpoint's lock and task plumbing: deadline-bounded waits that stay
//! pending instead of faulting, the config-lock acquisition on an
//! attempt-tagged blocking task with its guard handed over under the gate
//! mutex, the read-only check task, and the guards a certified adapter holds.

use std::future::{Future, pending};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{OwnedMutexGuard, oneshot};
use tokio::time::{Instant, timeout_at};

use super::certify::{self, CheckInput};
use super::gate::{ConfigGate, GateState};
use super::{Certification, FloorFault};
use crate::config_persistence::lock::{Locked, NotLocked, lock_config_blocking_deferred};

/// Awaits `fut` until `deadline`; past it the future stays pending forever
/// (the coordinator's timeout ends it), never a fault for elapsed time.
pub(super) async fn until<T>(deadline: Instant, fut: impl Future<Output = T>) -> T {
    match timeout_at(deadline, fut).await {
        Ok(value) => value,
        Err(_) => pending().await,
    }
}

/// An adapter-owned blocking task, tagged with its attempt. It reads as
/// finished once its closure ends, including by panic.
#[derive(Debug)]
pub(super) struct Task {
    done: Arc<AtomicBool>,
}

/// Held by the task's closure; marks the task finished when dropped.
pub(super) struct DoneGuard(Arc<AtomicBool>);

impl Drop for DoneGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl Task {
    fn start() -> (Self, DoneGuard) {
        let done = Arc::new(AtomicBool::new(false));
        (
            Self {
                done: Arc::clone(&done),
            },
            DoneGuard(done),
        )
    }

    pub(super) fn finished(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }
}

/// What the lock task sends back: the guard, or why there is none.
type LockReply = Result<Locked, NotLocked>;

/// Starts the config-lock acquisition for `attempt` on a blocking task.
pub(super) fn spawn_lock(
    gate: &ConfigGate,
    path: PathBuf,
    attempt: u64,
    deadline: Instant,
    #[cfg(test)] seams: super::seams::FloorSeams,
) -> (Task, oneshot::Receiver<LockReply>) {
    let (tx, rx) = oneshot::channel();
    let (task, done) = Task::start();
    let gate = gate.clone();
    tokio::task::spawn_blocking(move || {
        let _done = done;
        #[cfg(test)]
        let reply = acquire_seamed(&path, attempt, deadline, &seams);
        #[cfg(not(test))]
        let reply = lock_config_blocking_deferred(&path, deadline.into_std(), |_| {});
        hand_off(
            &gate,
            attempt,
            reply,
            tx,
            #[cfg(test)]
            &seams,
        );
        // Still inside the task, `_done` alive: a row can hold `settled` false
        // here, after the guard was handed or dropped.
        #[cfg(test)]
        if let Some(hook) = seams.after_hand_off.as_ref() {
            hook(attempt);
        }
    });
    (task, rx)
}

/// The acquisition under test: the hook may declare the deadline passed.
#[cfg(test)]
fn acquire_seamed(
    path: &std::path::Path,
    attempt: u64,
    deadline: Instant,
    seams: &super::seams::FloorSeams,
) -> LockReply {
    use super::seams::{AttemptEntry, AttemptEvent, LockVerdict};
    let verdict = seams.lock_hook.as_ref().map(|hook| hook(attempt));
    let reply = if verdict == Some(LockVerdict::Busy) {
        Err(NotLocked::Busy)
    } else {
        lock_config_blocking_deferred(path, deadline.into_std(), |_| {})
    };
    let event = match &reply {
        Ok(_) => AttemptEvent::LockAcquired,
        Err(_) => AttemptEvent::LockBusy,
    };
    seams.attempts.push(AttemptEntry { attempt, event });
    reply
}

/// Sends the guard to the checkpoint future only while `attempt` is current,
/// checked under the gate mutex, so a resume or a newer pause can never find
/// a guard parked on a finished attempt. Anything else is dropped here.
fn hand_off(
    gate: &ConfigGate,
    attempt: u64,
    reply: LockReply,
    tx: oneshot::Sender<LockReply>,
    #[cfg(test)] seams: &super::seams::FloorSeams,
) {
    let locked = match reply {
        Ok(locked) => locked,
        Err(refused) => {
            let _ = tx.send(Err(refused));
            return;
        }
    };
    let rejected = {
        let inner = gate.inner.lock();
        if inner.state == GateState::Paused(attempt) {
            tx.send(Ok(locked)).err()
        } else {
            Some(Ok(locked))
        }
    };
    if let Some(back) = rejected {
        drop(back);
        #[cfg(test)]
        seams.slots.push(super::seams::SlotEntry {
            attempt,
            outcome: super::seams::SlotOutcome::DroppedSuperseded,
        });
    }
}

/// The guard from the lock task: Busy at the deadline stays pending, a lock
/// that cannot be taken is a fault, a lost task is `WorkerLost`.
pub(super) async fn take_lock(
    rx: oneshot::Receiver<LockReply>,
    deadline: Instant,
) -> Result<Locked, FloorFault> {
    match until(deadline, rx).await {
        Ok(Ok(locked)) => Ok(locked),
        Ok(Err(NotLocked::Busy)) => pending().await,
        Ok(Err(_)) => Err(FloorFault::SaveFailed),
        Err(_) => Err(FloorFault::WorkerLost),
    }
}

/// Runs the read-only checks on a blocking task; the result comes back
/// through the channel, a panic as a closed channel.
pub(super) fn spawn_check(
    input: CheckInput,
    #[cfg(test)] attempts: super::seams::SeamLog<super::seams::AttemptEntry>,
) -> (Task, oneshot::Receiver<Result<Certification, FloorFault>>) {
    let (tx, rx) = oneshot::channel();
    let (task, done) = Task::start();
    tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        let attempt = input.attempt;
        let result = certify::check(&input);
        // Finished before it is logged: a row that sees the log sees settled.
        drop(done);
        #[cfg(test)]
        attempts.push(super::seams::AttemptEntry {
            attempt,
            event: super::seams::AttemptEvent::CheckDone(result.is_ok()),
        });
        let _ = tx.send(result);
    });
    (task, rx)
}

/// The certification result, bounded by the deadline like every wait.
pub(super) async fn take_check(
    rx: oneshot::Receiver<Result<Certification, FloorFault>>,
    deadline: Instant,
) -> Result<Certification, FloorFault> {
    until(deadline, rx)
        .await
        .map_err(|_| FloorFault::WorkerLost)?
}

/// The two guards of a certified adapter, owned until a recovery call.
#[derive(Default)]
pub(super) struct Held {
    reload: Option<OwnedMutexGuard<()>>,
    config: Option<Locked>,
}

impl Held {
    pub(super) fn new(reload: OwnedMutexGuard<()>, config: Locked) -> Self {
        Self {
            reload: Some(reload),
            config: Some(config),
        }
    }

    /// `resume` and `release_for_stop`: both locks free at once.
    pub(super) fn release_all(&mut self) {
        self.reload = None;
        self.config = None;
    }

    /// Commit: the shutdown drain takes the reload lock; the config lock stays
    /// until the adapter is dropped so no writer lands before the next boot.
    pub(super) fn release_reload(&mut self) {
        self.reload = None;
    }
}
