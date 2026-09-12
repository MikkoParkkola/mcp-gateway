// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Guarded consent commit: compare the captured expectation and replace the
//! grant under ONE authority-lock acquisition.
//!
//! `RuntimeNotImplemented` is never a domain answer. It survives for the one
//! target where the durable writers do not exist at all.
//!
//! WHY THIS EXISTS AS A PRIMITIVE. `commit_grant` is unconditional and `lookup`
//! releases the authority lock before it returns, so a consent journey built
//! from the pair compares a state it has already stopped holding. A grant or a
//! revoke landing in that window is silently overwritten. No amount of care in
//! the service closes it: the window is created by the two-call shape, so the
//! two calls have to become one.
//!
//! CONTRACT FOR THE RUNTIME: acquire the authority lock ONCE — through
//! `PersonalAccountStore::lock_authority`, the store's only acquisition point —
//! and do both the comparison and the durable publication under it. A mismatch
//! returns `Fenced` having written nothing.
//!
//! The contract is not taken on trust. `witness` below logs every acquisition
//! attempt, acquisition and release AT THE LOCK ITSELF, so a call that takes it
//! twice is visible as two sessions whatever the implementation claims about
//! itself, and a caller cannot manufacture a session it did not take.

use super::service::ConsentExpectation;
use super::{AccountError, AccountKey, GrantRecord, PersonalAccountStore};

/// Outcome of a guarded commit. A fenced expectation is an ordinary refusal:
/// the journey lost a race it was meant to lose, and nothing was written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuardedCommit {
    Committed,
    Fenced,
}

/// Guarded-commit refusals. The scaffold is deliberately its own variant so a
/// store failure can never be read as "not implemented", or the reverse.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum GuardedCommitError {
    #[error("guarded consent commit is not implemented")]
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "per-user OAuth scaffolding, deferred to post-4.0.0 backlog MIK-6744/6745/6746"
        )
    )]
    RuntimeNotImplemented,
    #[error(transparent)]
    Store(#[from] AccountError),
}

impl PersonalAccountStore {
    /// Commit `record` only if `expected` is still the authoritative state.
    ///
    /// The comparison and the publication run under ONE acquisition of the
    /// authority lock, which is the entire point: between two of them, a
    /// competing grant or revoke lands and is lost.
    // MIK-6744.STORE.1: guarded-commit is built and unit-tested but has no
    // caller outside its own #[cfg(test)] tree until the consent-commit
    // journey wires it in. `expect` (not `allow`) so this self-deletes the
    // moment production wiring adds a real caller; `cfg_attr(not(test), ..)`
    // keeps the expectation out of the `lib test` compile unit, where the
    // test-tree caller already makes the lint fire (dead_code would not fire
    // there, so a bare `expect` would itself become an `unfulfilled_lint_expectations`
    // error under `--all-targets`).
    #[cfg_attr(not(test), expect(dead_code, reason = "MIK-6744.STORE.1"))]
    pub(crate) fn commit_grant_if_unchanged(
        &self,
        account: &AccountKey,
        expected: &ConsentExpectation,
        record: &GrantRecord,
    ) -> Result<GuardedCommit, GuardedCommitError> {
        #[cfg(not(unix))]
        {
            // No durable writers exist on this target, so there is no guarded
            // commit to perform — and none to pretend to.
            let _ = (account, expected, record);
            Err(GuardedCommitError::RuntimeNotImplemented)
        }
        #[cfg(unix)]
        {
            let digest = account.digest()?;
            let mut authority = self.lock_authority();
            let current = {
                let held = authority.as_ref().ok_or(AccountError::StorageUnavailable)?;
                super::storage::lookup(&self.config, held, &digest, account)?
            };
            if ConsentExpectation::captured(&current) != *expected {
                // Nothing written, nothing removed: the journey lost a race it
                // was meant to lose, and the winner keeps the account.
                return Ok(GuardedCommit::Fenced);
            }
            // Still holding the same guard the comparison ran under.
            super::storage::commit::commit_grant(&self.config, &mut authority, account, record)?;
            Ok(GuardedCommit::Committed)
        }
    }
}

/// Test-only observation of the REAL authority lock.
///
/// The earlier draft of this module asked the implementation to report which
/// acquisition its comparison and its commit ran under. That is an honour
/// system: an implementation could read outside the lock and then report
/// tidily. So nothing is reported by the implementation any more. The store has
/// exactly one acquisition point — `PersonalAccountStore::lock_authority` — and
/// the three phases below are logged there:
///
/// * `Attempt`  — a thread has entered the acquisition point and is about to block
/// * `Acquire`  — it now holds the guard
/// * `Release`  — the guard has been dropped
///
/// Two consequences, and they are the whole proof:
///
/// 1. A call that acquires twice logs two sessions. Lookup-then-commit cannot
///    hide that, because it cannot read or write the authority without the lock.
/// 2. `park_after_acquire` parks INSIDE the acquisition, holding the guard. A
///    competing writer released against a parked call therefore blocks on a
///    real mutex, and the log shows its `Attempt` before the parked session's
///    `Release` and its `Acquire` after — exclusion demonstrated by causal
///    order, never inferred from a timeout or from which record won.
///
/// Events are filtered by store identity, so the many other tests that touch
/// their own stores in parallel cannot contaminate a recording.
#[cfg(test)]
pub(crate) mod witness {
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
    use std::time::{Duration, Instant};

    use super::PersonalAccountStore;

    /// Bounds a failure only: an acquisition or an attempt that never arrives
    /// must end the test instead of hanging the suite.
    const DEADLOCK: Duration = Duration::from_secs(5);

    /// One phase of one authority-lock session, logged where the lock is taken.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(crate) enum Phase {
        Attempt,
        Acquire,
        Release,
    }

    static SERIAL: Mutex<()> = Mutex::new(());
    static STATE: Mutex<Option<State>> = Mutex::new(None);
    static CHANGED: Condvar = Condvar::new();

    struct State {
        store: usize,
        next_id: u64,
        log: Vec<(Phase, u64)>,
        entered: Option<Sender<()>>,
        release: Option<Receiver<()>>,
    }

    fn state() -> MutexGuard<'static, Option<State>> {
        // A panicking test must not wedge every later one; the data behind the
        // lock is a log and two channel ends, so a poisoned view is still sound.
        STATE.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The identity a recording filters on. A store outlives its own recording,
    /// so this address cannot be reused by another store while it is watched.
    pub(crate) fn identify(store: &PersonalAccountStore) -> usize {
        std::ptr::from_ref(store) as usize
    }

    /// One authority-lock session. Handed out at the attempt, so the session
    /// exists before the lock is held and its blocking is observable.
    pub(crate) struct Ticket {
        id: u64,
        watched: bool,
    }

    impl Ticket {
        pub(crate) fn acquired(&self) {
            self.log(Phase::Acquire);
        }

        pub(crate) fn released(&self) {
            self.log(Phase::Release);
        }

        fn log(&self, phase: Phase) {
            if !self.watched {
                return;
            }
            {
                let mut slot = state();
                if let Some(state) = slot.as_mut() {
                    state.log.push((phase, self.id));
                }
            }
            CHANGED.notify_all();
        }
    }

    /// Store: called on entering the acquisition point, before blocking.
    pub(crate) fn attempting(store: usize) -> Ticket {
        let ticket = {
            let mut slot = state();
            match slot.as_mut() {
                Some(state) if state.store == store => {
                    state.next_id += 1;
                    let id = state.next_id;
                    state.log.push((Phase::Attempt, id));
                    Ticket { id, watched: true }
                }
                _ => Ticket {
                    id: 0,
                    watched: false,
                },
            }
        };
        if ticket.watched {
            CHANGED.notify_all();
        }
        ticket
    }

    /// Store: called with the guard HELD, so an armed test parks the lock
    /// itself rather than asking the implementation to pause politely.
    /// Transparent unless a test armed it, and it fires once.
    pub(crate) fn park_after_acquire(store: usize) {
        // Take the channel ends out from under the state lock and release it
        // before blocking, or a parked store would deadlock every observer.
        let armed = {
            let mut slot = state();
            match slot.as_mut() {
                Some(state) if state.store == store => {
                    state.entered.take().zip(state.release.take())
                }
                _ => None,
            }
        };
        if let Some((entered, release)) = armed {
            let _ = entered.send(());
            let _ = release.recv_timeout(DEADLOCK);
        }
    }

    /// Watch one store. Also serialises the tests that observe, so two of them
    /// cannot install recordings over each other.
    pub(crate) fn watch(store: &PersonalAccountStore) -> Recording {
        watch_id(identify(store))
    }

    pub(crate) fn watch_id(store: usize) -> Recording {
        let serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        *state() = Some(State {
            store,
            next_id: 0,
            log: Vec::new(),
            entered: None,
            release: None,
        });
        Recording { _serial: serial }
    }

    /// A live recording. Dropping it disarms, so one case cannot leak into the
    /// next.
    pub(crate) struct Recording {
        _serial: MutexGuard<'static, ()>,
    }

    impl Recording {
        /// A position in the log, so a case can bracket exactly one call.
        pub(crate) fn mark(&self) -> usize {
            state().as_ref().map_or(0, |state| state.log.len())
        }

        pub(crate) fn since(&self, mark: usize) -> Vec<(Phase, u64)> {
            state()
                .as_ref()
                .map(|state| state.log[mark.min(state.log.len())..].to_vec())
                .unwrap_or_default()
        }

        /// Arm the in-lock park for the next acquisition of the watched store.
        pub(crate) fn arm_park(&self) -> Park {
            let (entered_tx, entered_rx) = channel();
            let (release_tx, release_rx) = channel();
            if let Some(state) = state().as_mut() {
                state.entered = Some(entered_tx);
                state.release = Some(release_rx);
            }
            Park {
                entered: entered_rx,
                release: release_tx,
            }
        }

        /// Block until a thread ENTERS the acquisition point after `mark`, and
        /// answer with its session id.
        ///
        /// This is what makes a competitor's blocking observable: it returns on
        /// the competitor's own logged arrival, not on a sleep and not on a
        /// guess about the scheduler.
        #[track_caller]
        pub(crate) fn wait_for_attempt_since(&self, mark: usize) -> u64 {
            let deadline = Instant::now() + DEADLOCK;
            let mut slot = state();
            loop {
                if let Some(id) = slot.as_ref().and_then(|state| {
                    state.log[mark.min(state.log.len())..]
                        .iter()
                        .find(|(phase, _)| *phase == Phase::Attempt)
                        .map(|(_, id)| *id)
                }) {
                    return id;
                }
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .expect("an authority-lock attempt was made within the deadlock bound");
                let (next, waited) = CHANGED
                    .wait_timeout(slot, remaining)
                    .unwrap_or_else(PoisonError::into_inner);
                assert!(
                    !waited.timed_out(),
                    "no thread reached the authority acquisition point within the deadlock bound"
                );
                slot = next;
            }
        }
    }

    impl Drop for Recording {
        fn drop(&mut self) {
            *state() = None;
        }
    }

    /// The armed in-lock park, held by the observing thread.
    pub(crate) struct Park {
        entered: Receiver<()>,
        release: Sender<()>,
    }

    impl Park {
        /// Block until a thread is parked INSIDE the acquisition, holding the
        /// guard. A call that never acquires proves nothing and must say so.
        #[track_caller]
        pub(crate) fn wait_entered(&self) {
            self.entered
                .recv_timeout(DEADLOCK)
                .expect("a call reached the authority lock and parked while holding it");
        }

        pub(crate) fn release(self) {
            let _ = self.release.send(());
        }
    }
}

#[cfg(test)]
mod witness_tests {
    use super::witness::{self, Phase};

    const STORE: usize = 0x5100;
    const OTHER_STORE: usize = 0x5200;

    #[test]
    fn one_acquisition_logs_attempt_acquire_release_under_one_session() {
        let recording = witness::watch_id(STORE);
        let mark = recording.mark();
        let ticket = witness::attempting(STORE);
        ticket.acquired();
        witness::park_after_acquire(STORE);
        ticket.released();

        let events = recording.since(mark);
        let id = events[0].1;
        assert_eq!(
            events,
            vec![
                (Phase::Attempt, id),
                (Phase::Acquire, id),
                (Phase::Release, id)
            ]
        );
    }

    #[test]
    fn the_split_pattern_logs_two_sessions() {
        // The falsifier: this is the shape a lookup-then-commit implementation
        // produces at the lock, and no assertion that accepts it is a proof.
        let recording = witness::watch_id(STORE);
        let mark = recording.mark();
        let read = witness::attempting(STORE);
        read.acquired();
        read.released();
        let write = witness::attempting(STORE);
        write.acquired();
        write.released();

        let events = recording.since(mark);
        assert_eq!(events.len(), 6);
        assert_ne!(
            events[0].1, events[3].1,
            "a released and re-taken lock is two sessions, not one"
        );
    }

    #[test]
    fn another_store_is_not_observed() {
        // Every other test in this crate touches its own store in parallel.
        let recording = witness::watch_id(STORE);
        let mark = recording.mark();
        let elsewhere = witness::attempting(OTHER_STORE);
        elsewhere.acquired();
        elsewhere.released();
        assert!(recording.since(mark).is_empty());
    }

    #[test]
    fn the_armed_park_holds_the_acquirer_until_released() {
        let recording = witness::watch_id(STORE);
        let park = recording.arm_park();
        let mark = recording.mark();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let acquirer = std::thread::spawn(move || {
            let ticket = witness::attempting(STORE);
            ticket.acquired();
            witness::park_after_acquire(STORE);
            ticket.released();
            done_tx.send(()).expect("park observer still listening");
        });

        park.wait_entered();
        assert!(
            done_rx.try_recv().is_err(),
            "the park must not let the acquirer past before it is released"
        );
        assert_eq!(
            recording.since(mark).len(),
            2,
            "parked while holding: attempt and acquire logged, release not yet"
        );
        park.release();
        done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("released acquirer completes");
        acquirer.join().expect("park thread");
        assert_eq!(recording.since(mark).len(), 3);
    }

    #[test]
    fn a_waiting_observer_returns_on_a_later_attempt() {
        let recording = witness::watch_id(STORE);
        let first = witness::attempting(STORE);
        first.acquired();
        let mark = recording.mark();
        let second = std::thread::spawn(|| {
            let ticket = witness::attempting(STORE);
            ticket.acquired();
            ticket.released();
        });

        let id = recording.wait_for_attempt_since(mark);
        assert_ne!(id, 0, "the observer answers with the arriving session");
        second.join().expect("second thread");
        first.released();
    }

    #[test]
    fn a_fresh_recording_starts_empty_so_one_case_cannot_leak_into_the_next() {
        let first = witness::watch_id(STORE);
        let ticket = witness::attempting(STORE);
        ticket.acquired();
        assert_eq!(first.since(0).len(), 2);
        drop(first);

        // Held again, so this observes the reinstalled state rather than
        // whatever a concurrently running case happens to have armed.
        let next = witness::watch_id(STORE);
        assert!(next.since(0).is_empty());
    }
}
