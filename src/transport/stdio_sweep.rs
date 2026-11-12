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
    /// The table could not read it (an error, not an exit): never taken for gone.
    Unknown,
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
    /// A by-pid Kill was refused because the process is not known to be stopped.
    NotStopped,
}

/// The gate every by-pid path (no pidfd) applies before it signals, after the
/// identity re-read: a Kill goes only to a process that is stopped or already a
/// zombie, since a stopped process cannot exit and free its pid on its own. A
/// signal through a pidfd needs no such gate.
pub(super) fn by_pid_gate(sig: Sig, state: ProcState) -> Result<(), SignalError> {
    match (sig, state) {
        (Sig::Kill, ProcState::Stopped | ProcState::Zombie) | (Sig::Stop | Sig::Cont, _) => Ok(()),
        (Sig::Kill, _) => Err(SignalError::NotStopped),
    }
}

/// One reading of the process table.
pub(super) struct Listing {
    /// Every process the table could read, with its parent pid.
    pub(super) rows: Vec<(Identity, u32)>,
    /// False when the listing or any entry failed to read for a reason other
    /// than the process being gone: absence from `rows` then proves nothing.
    pub(super) complete: bool,
    /// Pids that exist but could not be read (not ours, or an error): a member
    /// among them is not pruned for being absent from `rows`.
    pub(super) unreadable: Vec<u32>,
}

/// What a rescue did for a member whose pid no longer names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Rescue {
    /// A stopped process, born after the member, was resumed.
    Resumed,
    /// Nothing at that pid needed resuming (it is gone, or running).
    NothingToDo,
    /// A stopped reuser was found and could not be resumed, or the pid could
    /// not be read: it may be left stopped.
    Failed,
}

/// Whether `found`, the process now at a member's pid, is a stopped reuser the
/// sweep's stray SIGSTOP may have hit: the member was alive when the sweep read
/// it, so any other process at its pid was created after that read; one that is
/// stopped within the sweep's window can only have been stopped by us.
pub(super) fn is_stray_stop(member: Identity, found: Identity, state: ProcState) -> bool {
    found.pid == member.pid && found.start > member.start && state == ProcState::Stopped
}

/// Resume the stranger a stray by-pid stop may have landed on, and count what
/// came of it.
fn rescue_stray(table: &mut dyn ProcessTable, member: Identity, report: &mut SweepReport) {
    match table.rescue(member) {
        Rescue::Resumed => report.rescued += 1,
        Rescue::NothingToDo => {}
        Rescue::Failed => {
            report.stop_mismatch += 1;
            report.residual.push(member);
        }
    }
}

/// The process table the sweep reads and signals through.
pub(super) trait ProcessTable {
    fn read(&mut self) -> Listing;
    fn state(&mut self, id: Identity) -> ProcState;
    /// Signal `id` only if it is still that process. `held` says the sweep holds
    /// a budget slot for a handle (a pidfd) on this process; a table without
    /// handles, or a sweep without a slot, reaches it by bare pid.
    fn signal(&mut self, id: Identity, sig: Sig, held: bool) -> Result<Handle, SignalError>;
    /// A monotonic clock.
    fn now(&mut self) -> Duration;
    /// Give back any handle held for `id` (a signal to it failed, so the sweep
    /// does not keep its budget slot).
    fn release(&mut self, _id: Identity) {}
    /// Yield between two polls of a state, so waiting for a freeze to land does
    /// not spin a core.
    fn idle(&mut self) {}
    /// A by-pid signal to `member` found its pid taken by another process: if
    /// that one is stopped (the sweep's SIGSTOP landed on it), resume it. Only a
    /// process created after the member qualifies (see [`is_stray_stop`]).
    fn rescue(&mut self, _member: Identity) -> Rescue {
        Rescue::NothingToDo
    }
}

/// The bounds one sweep runs under.
#[derive(Clone, Copy, Debug)]
pub(super) struct SweepConfig {
    /// The share of the stop deadline for freezing and re-walking. The terminal
    /// kills that follow are non-blocking sends and are never cut: a cut would
    /// leave stopped processes behind.
    pub(super) freeze_slice: Duration,
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
    /// Residual members whose state the table could not read.
    pub(super) unknown: usize,
    /// Members a by-pid Kill was refused for, as not known to be stopped.
    pub(super) unconfirmed: usize,
    /// Members the sweep stopped, could not kill, and could not continue.
    pub(super) stuck_stopped: usize,
    /// Reusers a stray by-pid SIGSTOP landed on, resumed.
    pub(super) rescued: usize,
    /// Reusers a stray by-pid SIGSTOP may have left stopped (rescue failed).
    pub(super) stop_mismatch: usize,
    /// Table readings that were incomplete (a failed listing or entry).
    pub(super) incomplete_reads: u32,
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
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |used| {
                (used < self.limit).then_some(used + 1)
            })
            .ok()
            .map(|_| Permit(self))
    }

    #[cfg(test)]
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
    /// Incomplete table readings so far.
    incomplete_reads: u32,
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
            incomplete_reads: 0,
        }
    }

    /// Record the descendants now, before the first signal of the stop.
    pub(super) fn snapshot(&mut self, table: &mut dyn ProcessTable) {
        let listing = table.read();
        self.collect(&listing);
    }

    /// Add every live descendant of the root and of every member, drop the dead,
    /// and hold the cap (lowest pids kept).
    fn collect(&mut self, listing: &Listing) -> usize {
        let rows = &listing.rows;
        if listing.complete {
            let live: BTreeSet<Identity> = rows.iter().map(|(who, _)| *who).collect();
            let keep = |who: &Identity| live.contains(who) || listing.unreadable.contains(&who.pid);
            self.members.retain(|who, _| keep(who));
            self.dropped.retain(|who| keep(who));
        } else {
            // A member missing from a listing that failed may well be alive.
            self.incomplete_reads += 1;
        }
        let mut parents: BTreeSet<u32> = self.members.keys().map(|who| who.pid).collect();
        parents.insert(self.root.pid);
        let mut added = 0;
        loop {
            let mut found: Vec<(Identity, u32)> = rows
                .iter()
                .filter(|(who, ppid)| {
                    parents.contains(ppid)
                        && who.pid != self.root.pid
                        && !self.members.contains_key(who)
                        && !self.dropped.contains(who)
                })
                .copied()
                .collect();
            // The cap keeps the lowest pids, whatever order the table lists.
            found.sort_by_key(|(who, _)| who.pid);
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
        let listing = table.read();
        self.collect(&listing);
        let root_live = !listing.complete || listing.rows.iter().any(|(who, _)| *who == self.root);
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
                // Only a process seen already stopped (a debugger's stop) or already
                // a zombie is not the sweep's to continue: an unreadable state is
                // not proof that the stop was someone else's.
                let ours = matches!(table.state(who), ProcState::Running | ProcState::Unknown);
                let permit = budget.take();
                match table.signal(who, Sig::Stop, permit.is_some()) {
                    Ok(handle) => {
                        let held = handle == Handle::Held;
                        frozen.push(Frozen {
                            id: who,
                            held,
                            ours,
                        });
                        permits.extend(permit.filter(|_| held));
                    }
                    Err(_) => table.release(who),
                }
            }
            // Confirmed, not assumed: only stopped, zombie or gone count.
            for entry in &frozen {
                while table.now() < freeze_end
                    && matches!(
                        table.state(entry.id),
                        ProcState::Running | ProcState::Unknown
                    )
                {
                    table.idle();
                }
            }
            if table.now() >= freeze_end {
                break;
            }
            let listing = table.read();
            let added = self.collect(&listing);
            // Stable only on a COMPLETE listing that adds nothing: after a failed
            // reading, keep walking until the slice ends.
            if listing.complete && added == 0 {
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
            let mut held = entry.is_some_and(|f| f.held);
            if entry.is_none()
                && let Some(permit) = budget.take()
            {
                // Never frozen (the slice ended, or its stop failed): only a
                // handle that names the exact process may kill it unstopped.
                permits.push(permit);
                held = true;
            }
            match table.signal(who, Sig::Kill, held) {
                Ok(_) => {
                    report.killed.push(who);
                    continue;
                }
                Err(SignalError::NotStopped) => report.unconfirmed += 1,
                // By pid, the member's pid names another process now: the stop
                // may have landed on it. Resume it if it is a stopped reuser;
                // the old identity has nothing left to continue or kill.
                Err(SignalError::Mismatch) if entry.is_some() && !held => {
                    rescue_stray(table, who, &mut report);
                    continue;
                }
                Err(_) => {}
            }
            if entry.is_some_and(|f| f.ours) {
                if table.signal(who, Sig::Cont, held).is_ok() {
                    report.continued.push(who);
                } else {
                    report.stuck_stopped += 1;
                }
            }
            match table.state(who) {
                ProcState::Gone => {}
                ProcState::Unknown => {
                    report.unknown += 1;
                    report.residual.push(who);
                }
                _ => report.residual.push(who),
            }
        }
        // A member frozen by pid whose identity left the set before the kill (the
        // re-walk found its pid held by someone else): its stop may have landed
        // on that stranger, and there is nothing left to kill under the old name.
        let targeted: BTreeSet<Identity> = self.members.keys().copied().collect();
        for entry in &frozen {
            if !entry.held && entry.id != self.root && !targeted.contains(&entry.id) {
                rescue_stray(table, entry.id, &mut report);
            }
        }
        report.residual.extend(self.dropped.iter().copied());
        report.incomplete_reads = self.incomplete_reads;
        drop(permits);
        report
    }
}

#[cfg(target_os = "linux")]
#[path = "stdio_sweep_linux.rs"]
mod linux;
#[cfg(target_os = "linux")]
pub(super) use linux::LinuxTable;
#[cfg(any(target_os = "macos", test))]
#[path = "stdio_sweep_macos.rs"]
mod macos;
#[cfg(target_os = "macos")]
pub(super) use macos::MacTable;

/// The table of the host the gateway runs on.
#[cfg(target_os = "linux")]
pub(super) type PlatformTable = LinuxTable;
#[cfg(target_os = "macos")]
pub(super) type PlatformTable = MacTable;

/// The share of a backend's kill reserve the sweep may spend freezing and
/// re-walking: twice the Linux freeze measured at the 4000-member cap (326 ms,
/// real children and pidfds), so a table at its cap is frozen before the kills
/// begin and no unfrozen member can still fork while they go out.
const FREEZE_SLICE: Duration = Duration::from_millis(700);
/// The room the terminal kills are guaranteed after the freeze, checked at
/// compile time against the reaper's kill reserve: five times the Linux kill
/// phase measured at the cap (141 ms), as the margin for macOS, whose cost per
/// member (a libproc read, then stop, verify and kill) is not measured. The
/// kills themselves are never cut, since a cut would leave stopped processes.
pub(super) const TERMINAL_ROOM: Duration = Duration::from_millis(750);
const _: () = assert!(
    FREEZE_SLICE.as_millis() + TERMINAL_ROOM.as_millis()
        <= super::reaper::KILL_RESERVE.as_millis() / 2,
    "the sweep may take at most half of the reaper's kill reserve"
);
/// Descriptors the gateway keeps for its own sockets and files.
const FD_RESERVE: usize = 512;

/// The one limit that bounds both the descendants a sweep holds and the
/// pidfds all sweeps hold together: the descriptor limit less a reserve, never
/// above 4096 and never below 64 (the reviewed design's formula).
fn fd_limit() -> usize {
    static LIMIT: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *LIMIT.get_or_init(|| {
        let nofile = rustix::process::getrlimit(rustix::process::Resource::Nofile)
            .current
            .and_then(|limit| usize::try_from(limit).ok())
            .unwrap_or(1024);
        let limit = PidfdBudget::limit_for(nofile, FD_RESERVE);
        if limit < 4096 {
            tracing::info!(limit, nofile, "descendant sweep: limit below its cap");
        }
        limit
    })
}

/// The bounds every backend's sweep runs under.
pub(super) fn config() -> SweepConfig {
    SweepConfig {
        freeze_slice: FREEZE_SLICE,
        cap: fd_limit(),
    }
}

/// The one pidfd budget of this process.
pub(super) fn process_budget() -> &'static PidfdBudget {
    static BUDGET: std::sync::OnceLock<PidfdBudget> = std::sync::OnceLock::new();
    BUDGET.get_or_init(|| PidfdBudget::new(fd_limit()))
}

#[cfg(test)]
#[path = "stdio_sweep_tests.rs"]
mod tests;
