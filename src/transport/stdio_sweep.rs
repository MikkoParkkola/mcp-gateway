// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The descendant sweep: before a backend's own group kill, every process still
//! descended from it (each backend leads its own process group, so a group kill
//! never reaches a gateway-child's own backends) is frozen, verified and killed.
//!
//! The platform sits behind [`ProcessTable`] (Linux `/proc` and pidfd, macOS
//! libproc), so the sweep's order of signals, its deadline slices and its
//! residual accounting are tested against an in-memory table.

use std::collections::{BTreeMap, BTreeSet};
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
    /// Signal `id` only if it is still that process. `held` says the sweep holds
    /// a budget slot for a handle (a pidfd) on this process; a table without
    /// handles, or a sweep without a slot, reaches it by bare pid.
    fn signal(&mut self, id: Identity, sig: Sig, held: bool) -> Result<Handle, SignalError>;
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
    pub(super) fn limit_for(nofile: usize, reserve: usize) -> usize {
        nofile.saturating_sub(reserve).clamp(64, 4096)
    }

    pub(super) fn new(limit: usize) -> Self {
        Self {
            limit,
            used: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// A slot, or `None` when every slot is in use.
    pub(super) fn take(&self) -> Option<Permit<'_>> {
        use std::sync::atomic::Ordering;
        self.used
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                (used < self.limit).then_some(used + 1)
            })
            .ok()
            .map(|_| Permit(self))
    }

    pub(super) fn in_use(&self) -> usize {
        self.used.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.0
            .used
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// One backend's sweep.
pub(super) struct Sweep {
    root: Identity,
    cfg: SweepConfig,
    /// Every descendant seen so far, with its parent pid (pruned when it dies).
    members: BTreeMap<Identity, u32>,
    /// Descendants past the cap, never touched, reported at the end.
    dropped: BTreeSet<Identity>,
}

/// What the sweep stopped, and whether the stop was its own.
struct Frozen {
    id: Identity,
    held: bool,
    /// The sweep moved it from running to stopped (so it may continue it).
    ours: bool,
}

impl Sweep {
    pub(super) fn new(root: Identity, cfg: SweepConfig) -> Self {
        Self {
            root,
            cfg,
            members: BTreeMap::new(),
            dropped: BTreeSet::new(),
        }
    }

    /// Record the descendants now, before the first signal of the stop.
    pub(super) fn snapshot(&mut self, table: &mut dyn ProcessTable) {
        let rows = table.read();
        self.collect(&rows);
    }

    /// Add every live descendant of the root and of every member, drop the dead,
    /// and hold the cap (lowest pids kept).
    fn collect(&mut self, rows: &[(Identity, u32)]) -> usize {
        let live: BTreeSet<Identity> = rows.iter().map(|(who, _)| *who).collect();
        self.members.retain(|who, _| live.contains(who));
        self.dropped.retain(|who| live.contains(who));
        let mut parents: BTreeSet<u32> = self.members.keys().map(|who| who.pid).collect();
        parents.insert(self.root.pid);
        let mut added = 0;
        loop {
            let found: Vec<(Identity, u32)> = rows
                .iter()
                .filter(|(who, ppid)| {
                    parents.contains(ppid)
                        && who.pid != self.root.pid
                        && !self.members.contains_key(who)
                        && !self.dropped.contains(who)
                })
                .copied()
                .collect();
            if found.is_empty() {
                break;
            }
            for (who, ppid) in found {
                parents.insert(who.pid);
                if self.members.len() < self.cfg.cap {
                    self.members.insert(who, ppid);
                    added += 1;
                } else {
                    self.dropped.insert(who);
                }
            }
        }
        added
    }

    /// Freeze, verify and kill the members and the root; nothing is left stopped.
    pub(super) fn run(
        &mut self,
        table: &mut dyn ProcessTable,
        budget: &PidfdBudget,
    ) -> SweepReport {
        let mut report = SweepReport::default();
        let freeze_end = table.now() + self.cfg.freeze_slice;
        let rows = table.read();
        self.collect(&rows);
        let root_live = rows.iter().any(|(who, _)| *who == self.root);
        let mut frozen: Vec<Frozen> = Vec::new();
        let mut permits: Vec<Permit<'_>> = Vec::new();
        // Freeze: the root first, then the members, re-walking from the frozen
        // set until a pass adds nothing or the freeze slice ends.
        let mut pending: Vec<Identity> = Vec::new();
        if root_live {
            pending.push(self.root);
        }
        pending.extend(self.members.keys().copied());
        loop {
            report.passes += 1;
            for who in std::mem::take(&mut pending) {
                if table.now() >= freeze_end || frozen.iter().any(|f| f.id == who) {
                    continue;
                }
                let ours = table.state(who) == ProcState::Running;
                let permit = budget.take();
                let held = permit.is_some();
                if table.signal(who, Sig::Stop, held).is_ok() {
                    frozen.push(Frozen {
                        id: who,
                        held,
                        ours,
                    });
                    permits.extend(permit);
                }
            }
            for entry in &frozen {
                while table.now() < freeze_end && table.state(entry.id) == ProcState::Running {}
            }
            if table.now() >= freeze_end {
                break;
            }
            let rows = table.read();
            if self.collect(&rows) == 0 {
                break;
            }
            pending = self
                .members
                .keys()
                .copied()
                .filter(|who| !frozen.iter().any(|f| f.id == *who))
                .collect();
        }
        // Terminal phase: every member and the root get their kill whatever the
        // freeze slice did; a process the sweep stopped and could not kill is
        // continued so it is never left stopped.
        let mut targets: Vec<Identity> = self.members.keys().copied().collect();
        if root_live {
            targets.push(self.root);
        }
        for who in targets {
            let entry = frozen.iter().find(|f| f.id == who);
            let held = entry.is_some_and(|f| f.held);
            match table.signal(who, Sig::Kill, held) {
                Ok(_) => report.killed.push(who),
                Err(_) => {
                    if entry.is_some_and(|f| f.ours) {
                        let _ = table.signal(who, Sig::Cont, held);
                        report.continued.push(who);
                    }
                    if table.state(who) != ProcState::Gone {
                        report.residual.push(who);
                    }
                }
            }
        }
        report.residual.extend(self.dropped.iter().copied());
        drop(permits);
        report
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "stdio_sweep_linux.rs"]
mod linux;

#[cfg(test)]
#[path = "stdio_sweep_tests.rs"]
mod tests;
