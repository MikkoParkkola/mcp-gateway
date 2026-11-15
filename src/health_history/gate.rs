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
    Open = 0,
    /// A restart attempt holds the gate: closures skip and mark themselves.
    Paused = 1,
    /// The restart committed: closures skip without marking.
    Terminal = 2,
    /// A stop signal won: closures run as normal until their schedulers end.
    Released = 3,
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

/// See the module doc. Every access is `SeqCst`: the mark-then-read in
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

impl GateState {
    fn from_u8(raw: u8) -> Self {
        match raw {
            0 => Self::Open,
            1 => Self::Paused,
            2 => Self::Terminal,
            _ => Self::Released,
        }
    }
}

impl HealthGate {
    pub(crate) fn state(&self) -> GateState {
        GateState::from_u8(self.state.load(SeqCst))
    }

    pub(crate) fn store(&self, state: GateState) {
        self.state.store(state as u8, SeqCst);
    }

    fn flag(&self, which: Closure) -> &AtomicBool {
        match which {
            Closure::Save => &self.save_skipped,
            Closure::Sample => &self.sample_skipped,
        }
    }

    /// Admission for `which`, called by the closure under the lock that
    /// guards what it touches; `at_mark` is the test seam between the mark
    /// and the second read. Paused: mark, read again; if the gate opened
    /// meanwhile, run only by claiming the mark back (else the replay that
    /// claimed it runs it). Terminal skips unmarked: nothing is replayed after
    /// a commit.
    pub(crate) fn admit(&self, which: Closure, at_mark: impl FnOnce()) -> Admit {
        match self.state() {
            GateState::Open | GateState::Released => Admit::Run,
            GateState::Terminal => Admit::Skip,
            GateState::Paused => {
                self.flag(which).store(true, SeqCst);
                at_mark();
                match self.state() {
                    GateState::Paused | GateState::Terminal => Admit::Skip,
                    GateState::Open | GateState::Released => {
                        if self.claim(which) {
                            Admit::Run
                        } else {
                            Admit::Skip
                        }
                    }
                }
            }
        }
    }

    /// Take `which`'s mark (true -> false); true means the caller owns the
    /// single coalesced run.
    pub(crate) fn claim(&self, which: Closure) -> bool {
        self.flag(which).swap(false, SeqCst)
    }

    /// Whether `which` is marked (a test probe).
    #[cfg(test)]
    pub(crate) fn marked(&self, which: Closure) -> bool {
        self.flag(which).load(SeqCst)
    }
}
