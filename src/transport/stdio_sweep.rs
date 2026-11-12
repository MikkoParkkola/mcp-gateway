// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The descendant sweep: before a backend's own group kill, every process still
//! descended from it (each backend leads its own process group, so a group kill
//! never reaches a gateway-child's own backends) is frozen, verified and killed.
//!
//! The platform sits behind [`ProcessTable`] (Linux `/proc` and pidfd, macOS
//! libproc), so the sweep's order of signals, its deadline slices and its
//! residual accounting are tested against an in-memory table.

use std::collections::BTreeMap;
use std::time::Duration;

/// A process as the sweep knows it: the pid and the start time that tell it apart
/// from a later process that reuses the pid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct Identity {
    pub(super) pid: u32,
    pub(super) start: u64,
}

/// What a process is doing, as far as the sweep can tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProcState {
    Running,
    Stopped,
    Zombie,
    Gone,
}

/// The signals the sweep sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Sig {
    Stop,
    Cont,
    Kill,
}

/// How the table reaches a process: a handle that names exactly it (a pidfd), or
/// its bare pid after an identity re-read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Handle {
    Held,
    ByPid,
}

/// Why a signal was not delivered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SignalError {
    /// The pid now belongs to a different process (or none): nothing was sent.
    Mismatch,
    Denied,
    Failed,
}

/// The process table the sweep reads and signals through.
pub(super) trait ProcessTable {
    /// Every live process with its parent pid.
    fn read(&mut self) -> Vec<(Identity, u32)>;
    fn state(&mut self, id: Identity) -> ProcState;
    /// Signal `id` only if it is still that process.
    fn signal(&mut self, id: Identity, sig: Sig) -> Result<Handle, SignalError>;
    /// A monotonic clock.
    fn now(&mut self) -> Duration;
}

/// The bounds one sweep runs under.
#[derive(Clone, Copy, Debug)]
pub(super) struct SweepConfig {
    /// The share of the stop deadline for freezing and re-walking.
    pub(super) freeze_slice: Duration,
    /// The share for the terminal kills that follow.
    pub(super) kill_slice: Duration,
    /// The most members one sweep holds.
    pub(super) cap: usize,
}

/// What a sweep did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct SweepReport {
    pub(super) killed: Vec<Identity>,
    pub(super) continued: Vec<Identity>,
    /// Members not confirmed gone, and members dropped past the cap.
    pub(super) residual: Vec<Identity>,
    pub(super) passes: u32,
}

/// The process-wide budget of held handles (pidfds) that every sweep draws on.
pub(super) struct PidfdBudget {
    limit: usize,
    used: std::sync::atomic::AtomicUsize,
}

/// One held-handle slot; dropping it gives the slot back.
pub(super) struct Permit<'a>(&'a PidfdBudget);

impl PidfdBudget {
    /// The budget for a process whose soft file-descriptor limit is `nofile` and
    /// which keeps `reserve` descriptors for its own sockets: never above 4096,
    /// never below 64.
    pub(super) fn limit_for(_nofile: usize, _reserve: usize) -> usize {
        0
    }

    pub(super) fn new(limit: usize) -> Self {
        Self {
            limit,
            used: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// A slot, or `None` when every slot is in use.
    pub(super) fn take(&self) -> Option<Permit<'_>> {
        let _ = (self.limit, &self.used);
        None
    }

    pub(super) fn in_use(&self) -> usize {
        self.used.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let _ = self.0;
    }
}

/// One backend's sweep.
pub(super) struct Sweep {
    root: Identity,
    cfg: SweepConfig,
    members: BTreeMap<Identity, u32>,
}

impl Sweep {
    pub(super) fn new(root: Identity, cfg: SweepConfig) -> Self {
        Self {
            root,
            cfg,
            members: BTreeMap::new(),
        }
    }

    /// Record the descendants now, before the first signal of the stop.
    pub(super) fn snapshot(&mut self, _table: &mut dyn ProcessTable) {}

    /// Freeze, verify and kill the members and the root; nothing is left stopped.
    pub(super) fn run(&mut self, _table: &mut dyn ProcessTable) -> SweepReport {
        let _held = (&self.root, &self.cfg, &self.members);
        SweepReport::default()
    }
}

#[cfg(test)]
#[path = "stdio_sweep_tests.rs"]
mod tests;
