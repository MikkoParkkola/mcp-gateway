// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Whether a slot waits on a person to sign in, and how many times it has
//! been told to. The flag and its generation sit behind one lock, so a clear
//! that was decided for one wait can never erase a newer one.

use parking_lot::Mutex;

/// A slot's wait on a sign-in. Starts clear, at generation zero.
#[derive(Debug, Default)]
pub(crate) struct AuthWait {
    /// `(waiting, generation)`; the generation is bumped by every [`Self::set`].
    state: Mutex<(bool, u64)>,
    /// Test-only: a pause inside [`Self::clear_if`]'s critical section.
    #[cfg(all(test, feature = "webui"))]
    pub(crate) pause: crate::test_pause::Slot,
}

impl AuthWait {
    /// Whether the slot waits on a sign-in now.
    pub(crate) fn get(&self) -> bool {
        self.state.lock().0
    }

    /// The generation of the latest wait.
    #[cfg_attr(
        not(feature = "webui"),
        allow(
            dead_code,
            reason = "the web UI flow reads it to clear only the wait it saw"
        )
    )]
    pub(crate) fn generation(&self) -> u64 {
        self.state.lock().1
    }

    /// Record a wait: set the flag and bump the generation.
    pub(crate) fn set(&self) {
        let mut state = self.state.lock();
        state.0 = true;
        state.1 += 1;
    }

    /// Clear the flag: someone was served, so nobody is waiting.
    pub(crate) fn clear(&self) {
        self.state.lock().0 = false;
    }

    /// Clear the flag only if no wait was recorded since generation `seen`.
    /// The compare and the clear happen under one lock.
    #[cfg_attr(
        not(feature = "webui"),
        allow(dead_code, reason = "only the web UI flow confirms a sign-in")
    )]
    pub(crate) fn clear_if(&self, seen: u64) {
        let mut state = self.state.lock();
        if state.1 != seen {
            return;
        }
        #[cfg(all(test, feature = "webui"))]
        self.pause.pause_blocking();
        state.0 = false;
    }

    /// Test-only: put the flag at `waiting` the way a wait or a success would.
    #[cfg(all(test, feature = "webui"))]
    pub(crate) fn set_for_test(&self, waiting: bool) {
        if waiting {
            self.set();
        } else {
            self.clear();
        }
    }
}
