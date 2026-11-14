// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gate the health floor adapter closes during a restart checkpoint
//! (restart slice 6b). The periodic saver checks it under SAVES and the
//! sampler under the history lock, so a closure that read "open" cannot act
//! after the checkpoint's cut. It lives outside both locks: every call that
//! changes it is one atomic store or swap, so the adapter's sync calls never
//! wait.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering::SeqCst};

/// The gate's state. Released and Terminal are final.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GateState {
    /// Saves and samples run as normal.
    Open,
    /// A restart attempt holds the gate: closures skip and mark themselves.
    Paused,
    /// The restart committed: closures skip without marking.
    Terminal,
    /// A stop signal won: closures run as normal until their schedulers end.
    Released,
}

/// Which periodic closure is asking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Closure {
    Save,
    Sample,
}

/// A closure's answer from the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admit {
    Run,
    Skip,
}

/// See the module doc. Every access is SeqCst: the mark-then-read in
/// `admit` and the store-then-swap in the adapter's resume must not both miss.
#[derive(Debug)]
pub(crate) struct HealthGate {
    state: AtomicU8,
    save_skipped: AtomicBool,
    sample_skipped: AtomicBool,
}

impl Default for HealthGate {
    fn default() -> Self {
        Self {
            state: AtomicU8::new(GateState::Open as u8),
            save_skipped: AtomicBool::new(false),
            sample_skipped: AtomicBool::new(false),
        }
    }
}

impl HealthGate {
    // red-phase: stub, the state never changes.
    pub(crate) fn state(&self) -> GateState {
        let _ = self.state.load(SeqCst);
        GateState::Open
    }

    // red-phase: stub, a no-op.
    pub(crate) fn store(&self, state: GateState) {
        let _ = state;
    }

    /// Admission for `which`, called by the closure under the lock that
    /// guards what it touches; `at_mark` is the test seam between the mark
    /// and the second read.
    // red-phase: stub, always runs.
    pub(crate) fn admit(&self, which: Closure, at_mark: impl FnOnce()) -> Admit {
        let _ = (which, at_mark);
        Admit::Run
    }

    /// Take `which`'s mark (true -> false); true means the caller owns the
    /// single coalesced run.
    // red-phase: stub, nothing is ever marked.
    pub(crate) fn claim(&self, which: Closure) -> bool {
        let _ = which;
        false
    }

    /// Whether `which` is marked (a test probe).
    #[cfg(test)]
    pub(crate) fn marked(&self, which: Closure) -> bool {
        match which {
            Closure::Save => self.save_skipped.load(SeqCst),
            Closure::Sample => self.sample_skipped.load(SeqCst),
        }
    }
}
