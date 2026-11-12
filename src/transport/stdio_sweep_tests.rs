// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The sweep's order of signals, bounds and accounting, against an in-memory table
//! that models what a real kernel does: a killed process reparents its children to
//! init and then answers nothing, a stopped process cannot fork or exit, a pid can
//! be reused, and a by-pid signal can land on a reused pid if the target was running
//! when its identity was checked.

use super::*;

fn id(pid: u32) -> Identity {
    Identity {
        pid,
        start: u64::from(pid) * 100,
    }
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// What the terminal kills may add to the freeze slice in the fake's clock: they
/// are non-blocking sends, never cut, since cutting them would leave processes
/// stopped.
const TERMINAL: Duration = Duration::from_millis(50);

fn cfg() -> SweepConfig {
    SweepConfig {
        freeze_slice: ms(50),
        cap: 4096,
    }
}

struct Proc {
    id: Identity,
    ppid: u32,
    pgid: u32,
    state: ProcState,
    /// Forks a new child on every table operation while running.
    churns: bool,
    /// Ignores SIGSTOP (stays running).
    ignores_stop: bool,
    /// SIGSTOP lands only after this many more table operations (the process
    /// keeps running meanwhile): the stop is asynchronous.
    stop_lag: u32,
    /// Operations left before a delivered SIGSTOP takes effect.
    stop_in: Option<u32>,
    /// Forks one child at the start of this table operation, if still running.
    fork_at: Option<u32>,
}

struct Fake {
    procs: Vec<Proc>,
    /// Every signal the sweep ATTEMPTED: (pid, start time it named, signal).
    attempts: Vec<(u32, u64, Sig)>,
    /// Every signal delivered: (pid, signal, how it was reached).
    log: Vec<(u32, Sig, Handle)>,
    /// Signals that landed on a process other than the one named.
    wrong: Vec<(u32, Sig)>,
    clock: Duration,
    tick: Duration,
    /// Whether the kernel has handles; a sweep without a slot still goes by pid.
    pidfd: bool,
    next_pid: u32,
    /// Table operations so far.
    ops: u32,
    /// The table applies the by-pid Kill gate, as the real tables do.
    strict_by_pid: bool,
    /// A Cont to this pid fails.
    cont_fails: Option<u32>,
    /// This pid exists but the table cannot read it: absent from the rows,
    /// listed as unreadable, the listing still complete.
    foreign: Option<u32>,
    /// Pids the sweep released a handle for.
    released: Vec<u32>,
    /// A by-pid Stop to this pid lands on a process that took the pid just
    /// before it arrived (the member exited): (pid, start of the reuser).
    reuse_after_stop: Option<(u32, u64)>,
    /// A by-pid Kill to this pid finds a running stranger there instead (the
    /// member exited and its pid was reused): (pid, start of the stranger).
    swap_before_kill: Option<(u32, u64)>,
    /// Every table reading fails: no rows, flagged incomplete.
    blind: bool,
    /// The table cannot read this pid's state (an error, not an exit).
    unreadable: Option<u32>,
    /// A signal that fails: (pid, signal, error).
    fail: Option<(u32, Sig, SignalError)>,
    /// A by-pid target that is running when its identity is checked exits and its
    /// pid is reused before the signal lands: (pid, start of the reusing process).
    reuse_while_running: Option<(u32, u64)>,
}

impl Fake {
    fn new(tree: &[(u32, u32)]) -> Self {
        let procs = tree
            .iter()
            .map(|&(pid, ppid)| Proc {
                id: id(pid),
                ppid,
                pgid: pid,
                state: ProcState::Running,
                churns: false,
                ignores_stop: false,
                stop_lag: 0,
                stop_in: None,
                fork_at: None,
            })
            .collect();
        Self {
            procs,
            attempts: Vec::new(),
            log: Vec::new(),
            wrong: Vec::new(),
            clock: Duration::ZERO,
            tick: ms(1),
            pidfd: true,
            next_pid: 1000,
            ops: 0,
            strict_by_pid: true,
            cont_fails: None,
            foreign: None,
            released: Vec::new(),
            reuse_after_stop: None,
            swap_before_kill: None,
            blind: false,
            unreadable: None,
            fail: None,
            reuse_while_running: None,
        }
    }

    fn proc(&mut self, pid: u32) -> &mut Proc {
        self.procs
            .iter_mut()
            .find(|p| p.id.pid == pid)
            .expect("a known pid")
    }

    fn state_of(&self, pid: u32) -> ProcState {
        self.procs
            .iter()
            .find(|p| p.id.pid == pid)
            .map_or(ProcState::Gone, |p| p.state)
    }

    fn delivered(&self, pid: u32) -> Vec<Sig> {
        self.log
            .iter()
            .filter(|(p, _, _)| *p == pid)
            .map(|(_, sig, _)| *sig)
            .collect()
    }

    fn attempted(&self, pid: u32) -> Vec<Sig> {
        self.attempts
            .iter()
            .filter(|(p, _, _)| *p == pid)
            .map(|(_, _, sig)| *sig)
            .collect()
    }

    /// Nothing is left stopped.
    fn stopped(&self) -> Vec<u32> {
        self.procs
            .iter()
            .filter(|p| p.state == ProcState::Stopped)
            .map(|p| p.id.pid)
            .collect()
    }

    /// Every operation costs time, and a running churner forks during it.
    fn operate(&mut self) {
        self.clock += self.tick;
        self.ops += 1;
        let ops = self.ops;
        let forking: Vec<u32> = self
            .procs
            .iter()
            .filter(|p| p.fork_at == Some(ops) && p.state == ProcState::Running)
            .map(|p| p.id.pid)
            .collect();
        for parent in forking {
            self.next_pid += 1;
            let pgid = self.next_pid;
            self.procs.push(Proc {
                id: id(self.next_pid),
                ppid: parent,
                pgid,
                state: ProcState::Running,
                churns: false,
                ignores_stop: false,
                stop_lag: 0,
                stop_in: None,
                fork_at: None,
            });
        }
        for p in &mut self.procs {
            if let Some(left) = p.stop_in {
                if left <= 1 {
                    p.stop_in = None;
                    if p.state == ProcState::Running {
                        p.state = ProcState::Stopped;
                    }
                } else {
                    p.stop_in = Some(left - 1);
                }
            }
        }
        let spawning: Vec<u32> = self
            .procs
            .iter()
            .filter(|p| p.churns && p.state == ProcState::Running)
            .map(|p| p.id.pid)
            .collect();
        for parent in spawning {
            self.next_pid += 1;
            let pgid = self.next_pid;
            self.procs.push(Proc {
                id: id(self.next_pid),
                ppid: parent,
                pgid,
                state: ProcState::Running,
                churns: false,
                ignores_stop: false,
                stop_lag: 0,
                stop_in: None,
                fork_at: None,
            });
        }
    }
}

impl ProcessTable for Fake {
    fn read(&mut self) -> Listing {
        self.operate();
        if self.blind {
            return Listing {
                rows: Vec::new(),
                complete: false,
                unreadable: Vec::new(),
            };
        }
        Listing {
            rows: self
                .procs
                .iter()
                .filter(|p| p.state != ProcState::Gone && self.foreign != Some(p.id.pid))
                .map(|p| (p.id, p.ppid))
                .collect(),
            complete: true,
            unreadable: self.foreign.into_iter().collect(),
        }
    }

    fn state(&mut self, who: Identity) -> ProcState {
        self.operate();
        if self.unreadable == Some(who.pid) {
            return ProcState::Unknown;
        }
        self.procs
            .iter()
            .find(|p| p.id == who)
            .map_or(ProcState::Gone, |p| p.state)
    }

    fn signal(&mut self, who: Identity, sig: Sig, held: bool) -> Result<Handle, SignalError> {
        self.operate();
        self.attempts.push((who.pid, who.start, sig));
        let handle = if held && self.pidfd {
            Handle::Held
        } else {
            Handle::ByPid
        };
        if sig == Sig::Cont && self.cont_fails == Some(who.pid) {
            return Err(SignalError::Failed);
        }
        if let Some((pid, failing, error)) = self.fail
            && pid == who.pid
            && failing == sig
        {
            return Err(error);
        }
        let Some(index) = self.procs.iter().position(|p| p.id.pid == who.pid) else {
            return Err(SignalError::Mismatch);
        };
        if self.procs[index].id != who || self.procs[index].state == ProcState::Gone {
            return Err(SignalError::Mismatch);
        }
        if handle == Handle::ByPid && self.strict_by_pid {
            by_pid_gate(sig, self.procs[index].state)?;
        }
        if handle == Handle::ByPid
            && sig == Sig::Stop
            && let Some((pid, start)) = self.reuse_after_stop
            && pid == who.pid
        {
            // The member exited and a new process took its pid just before the
            // stop arrived: the stop lands on the stranger.
            self.procs[index].id = Identity { pid, start };
            self.procs[index].ppid = 1;
            self.procs[index].state = ProcState::Stopped;
            self.wrong.push((pid, sig));
            return Ok(handle);
        }
        if sig == Sig::Kill
            && let Some((pid, start)) = self.swap_before_kill
            && pid == who.pid
        {
            self.procs[index].id = Identity { pid, start };
            self.procs[index].ppid = 1;
            self.procs[index].state = ProcState::Running;
            return Err(SignalError::Mismatch);
        }
        // By pid, a running target can exit and its pid be reused between the
        // identity check and the delivery; a stopped one cannot exit.
        if handle == Handle::ByPid
            && sig == Sig::Kill
            && self.procs[index].state == ProcState::Running
            && let Some((pid, start)) = self.reuse_while_running
            && pid == who.pid
        {
            self.procs[index].id = Identity { pid, start };
            self.procs[index].ppid = 1;
            self.wrong.push((pid, sig));
            return Ok(handle);
        }
        self.log.push((who.pid, sig, handle));
        let target = &mut self.procs[index];
        match sig {
            Sig::Stop if !target.ignores_stop && target.state == ProcState::Running => {
                if target.stop_lag == 0 {
                    target.state = ProcState::Stopped;
                } else {
                    target.stop_in = Some(target.stop_lag);
                }
            }
            Sig::Cont if target.state == ProcState::Stopped => target.state = ProcState::Running,
            Sig::Kill => {
                target.state = ProcState::Gone;
                let dead = who.pid;
                for child in self.procs.iter_mut().filter(|p| p.ppid == dead) {
                    child.ppid = 1;
                }
            }
            _ => {}
        }
        Ok(handle)
    }

    fn now(&mut self) -> Duration {
        self.clock
    }

    fn release(&mut self, id: Identity) {
        self.released.push(id.pid);
    }

    fn rescue(&mut self, member: Identity) -> Rescue {
        let cont_fails = self.cont_fails == Some(member.pid);
        let Some(found) = self.procs.iter_mut().find(|p| p.id.pid == member.pid) else {
            return Rescue::NothingToDo;
        };
        if !is_stray_stop(member, found.id, found.state) {
            return Rescue::NothingToDo;
        }
        if cont_fails {
            return Rescue::Failed;
        }
        found.state = ProcState::Running;
        Rescue::Resumed
    }
}

fn run(fake: &mut Fake, root: u32) -> SweepReport {
    run_with(fake, root, cfg(), &PidfdBudget::new(4096))
}

fn run_with(fake: &mut Fake, root: u32, config: SweepConfig, budget: &PidfdBudget) -> SweepReport {
    let mut sweep = Sweep::new(id(root), config);
    sweep.snapshot(fake);
    sweep.run(fake, budget)
}

/// The root and every descendant are frozen (root first), then killed.
/// Red if the sweep sends no signal.
#[test]
fn the_root_is_frozen_first_and_killed_with_its_members() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 11)]);
    let report = run(&mut fake, 10);
    assert_eq!(
        fake.log
            .iter()
            .find(|(_, sig, _)| *sig == Sig::Stop)
            .map(|e| e.0),
        Some(10),
        "the root is frozen first"
    );
    for pid in [10, 11, 12] {
        let sent = fake.delivered(pid);
        assert_eq!(sent.first(), Some(&Sig::Stop), "pid {pid} frozen first");
        assert_eq!(sent.last(), Some(&Sig::Kill), "pid {pid} killed last");
        assert_eq!(fake.state_of(pid), ProcState::Gone);
    }
    assert!(report.residual.is_empty(), "{report:?}");
}

/// A process outside the tree (a helper that detached before the stop, a daemon
/// reparented to init, a process in a member's group) is never even attempted,
/// while the tree beside it dies.
/// Red if the tree survives, or if anything outside it is signalled.
#[test]
fn a_process_outside_the_tree_is_never_attempted() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (20, 1), (21, 20), (30, 1)]);
    fake.proc(30).pgid = 11; // shares a member's group, no descendant
    run(&mut fake, 10);
    assert_eq!(fake.state_of(11), ProcState::Gone, "the tree dies");
    for pid in [20, 21, 30] {
        assert!(
            fake.attempted(pid).is_empty(),
            "pid {pid}: {:?}",
            fake.attempts
        );
        assert_eq!(fake.state_of(pid), ProcState::Running);
    }
}

/// A recorded pid that now belongs to a different process is never delivered a
/// signal; a sibling beside it is still killed.
/// Red if the sibling survives, or if the reused pid is delivered anything.
#[test]
fn a_reused_pid_is_never_delivered_a_signal() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 10)]);
    let mut sweep = Sweep::new(id(10), cfg());
    sweep.snapshot(&mut fake);
    fake.proc(11).id = Identity {
        pid: 11,
        start: 9_999,
    };
    fake.proc(11).ppid = 1;
    let _ = sweep.run(&mut fake, &PidfdBudget::new(4096));
    assert_eq!(fake.state_of(12), ProcState::Gone, "the sibling is killed");
    assert!(fake.delivered(11).is_empty(), "{:?}", fake.log);
    assert!(fake.wrong.is_empty());
    assert_eq!(fake.state_of(11), ProcState::Running);
}

/// A helper attached at the snapshot that detaches (its parent exits) mid-stop is
/// still a member and is killed.
/// Red if the sweep needs a live parent chain at kill time.
#[test]
fn a_helper_that_detaches_mid_stop_still_dies() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 11)]);
    let mut sweep = Sweep::new(id(10), cfg());
    sweep.snapshot(&mut fake);
    fake.proc(11).state = ProcState::Gone;
    fake.proc(12).ppid = 1;
    let report = sweep.run(&mut fake, &PidfdBudget::new(4096));
    assert_eq!(fake.state_of(12), ProcState::Gone, "{:?}", fake.log);
    assert!(report.killed.contains(&id(12)));
}

/// The backend exited before the sweep (early leader exit); its reparented leaf was
/// in the snapshot and is killed.
/// Red if the sweep does nothing once the root is gone.
#[test]
fn a_leaf_of_a_backend_that_exited_first_is_killed() {
    let mut fake = Fake::new(&[(10, 1), (11, 10)]);
    let mut sweep = Sweep::new(id(10), cfg());
    sweep.snapshot(&mut fake);
    fake.proc(10).state = ProcState::Gone;
    fake.proc(11).ppid = 1;
    let report = sweep.run(&mut fake, &PidfdBudget::new(4096));
    assert_eq!(fake.state_of(11), ProcState::Gone, "{:?}", fake.log);
    assert!(report.killed.contains(&id(11)));
}

/// A leaf that forks on every operation is frozen before the last walk, so every
/// identity a completed pass collected is killed, and the run ends in its slices.
/// Red if a collected identity survives or the run outlasts its slices.
#[test]
fn a_forking_leaf_is_frozen_and_every_collected_identity_dies() {
    let mut fake = Fake::new(&[(10, 1), (11, 10)]);
    fake.proc(11).churns = true;
    let report = run(&mut fake, 10);
    let survivors: Vec<u32> = fake
        .procs
        .iter()
        .filter(|p| p.state != ProcState::Gone)
        .map(|p| p.id.pid)
        .collect();
    assert!(survivors.is_empty(), "survivors: {survivors:?}");
    assert!(
        fake.clock <= cfg().freeze_slice + TERMINAL,
        "ran {:?}",
        fake.clock
    );
    assert!(report.passes >= 1);
}

/// A process that never confirms stopped is still killed within the slices, the
/// frozen set is killed and never continued, and nothing is left stopped.
/// Red if expiry continues the frozen set, leaves anything stopped or overruns.
#[test]
fn slice_expiry_kills_the_frozen_set_and_leaves_nothing_stopped() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 10)]);
    fake.proc(12).ignores_stop = true;
    let mut short = cfg();
    short.freeze_slice = ms(5);
    let report = run_with(&mut fake, 10, short, &PidfdBudget::new(4096));
    assert!(
        fake.stopped().is_empty(),
        "left stopped: {:?}",
        fake.stopped()
    );
    assert!(
        fake.log.iter().all(|(_, sig, _)| *sig != Sig::Cont),
        "{:?}",
        fake.log
    );
    for pid in [10, 11, 12] {
        assert_eq!(fake.state_of(pid), ProcState::Gone, "pid {pid}");
        assert!(report.killed.contains(&id(pid)), "pid {pid}: {report:?}");
    }
    assert!(
        fake.clock <= short.freeze_slice + TERMINAL,
        "ran {:?}",
        fake.clock
    );
}

/// A kill that fails (denied) must not leave the process stopped: the attempts
/// are stop, kill, continue, in that order, and the process is residual.
/// Red if a process whose kill failed stays stopped.
#[test]
fn a_failed_kill_is_followed_by_a_continue_and_a_residual() {
    let mut fake = Fake::new(&[(10, 1), (11, 10)]);
    fake.fail = Some((11, Sig::Kill, SignalError::Denied));
    let report = run(&mut fake, 10);
    assert_eq!(fake.attempted(11), [Sig::Stop, Sig::Kill, Sig::Cont]);
    assert_eq!(fake.state_of(11), ProcState::Running);
    assert_eq!(report.residual, [id(11)]);
    assert_eq!(fake.state_of(10), ProcState::Gone, "the root still dies");
}

/// A continue goes only to a process the sweep itself stopped: one stopped by
/// someone else is left as it was, while the process the sweep stopped is continued.
/// Red if the sweep continues a process it did not stop, or skips its own.
#[test]
fn a_continue_goes_only_to_a_process_the_sweep_stopped() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 10)]);
    fake.proc(11).state = ProcState::Stopped; // stopped by a debugger
    fake.fail = Some((11, Sig::Kill, SignalError::Denied));
    run(&mut fake, 10);
    assert!(
        !fake.attempted(11).contains(&Sig::Cont),
        "{:?}",
        fake.attempts
    );
    assert_eq!(fake.state_of(11), ProcState::Stopped);
    assert_eq!(fake.state_of(12), ProcState::Gone);
}

/// By bare pid a running target can exit and its pid be reused before a signal
/// lands; the sweep stops the target first (a stopped process cannot exit), so no
/// signal ever reaches a reused pid, and every by-pid member is stopped before it
/// is killed.
/// Red if a by-pid member is killed without a stop first, or nothing is killed.
#[test]
fn a_by_pid_member_is_stopped_before_it_is_killed() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 11)]);
    fake.pidfd = false;
    fake.reuse_while_running = Some((11, 777));
    run(&mut fake, 10);
    assert!(
        fake.wrong.is_empty(),
        "landed on a reused pid: {:?}",
        fake.wrong
    );
    for pid in [10, 11, 12] {
        let sent = fake.delivered(pid);
        let kill = sent.iter().position(|s| *s == Sig::Kill).expect("killed");
        assert!(
            sent[..kill].contains(&Sig::Stop),
            "pid {pid} killed without a stop: {sent:?}"
        );
        assert_eq!(fake.state_of(pid), ProcState::Gone);
    }
}

/// The set is capped (lowest pids kept): exact accounting of who dies, who is
/// reported residual, and that a member dropped by the cap is never touched; a
/// member that died before the sweep is never signalled.
/// Red if the cap is ignored, the accounting differs, or a dropped member is stopped.
#[test]
fn the_cap_keeps_the_lowest_pids_and_reports_the_rest() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 10), (13, 10), (14, 10)]);
    let mut small = cfg();
    small.cap = 2;
    let mut sweep = Sweep::new(id(10), small);
    sweep.snapshot(&mut fake);
    fake.proc(14).state = ProcState::Gone;
    let report = sweep.run(&mut fake, &PidfdBudget::new(4096));
    let mut killed = report.killed.clone();
    killed.sort();
    assert_eq!(killed, [id(10), id(11), id(12)], "{report:?}");
    assert_eq!(report.residual, [id(13)], "{report:?}");
    assert!(fake.attempted(13).is_empty() && fake.attempted(14).is_empty());
    assert_eq!(fake.state_of(13), ProcState::Running);
}

/// Handles come from the shared budget: with one slot only one process is reached
/// through a handle, the rest by pid (stopped first), every slot comes back, and
/// everything dies.
/// Red if the budget is ignored, a slot leaks, or the tree survives.
#[test]
fn the_sweep_draws_on_the_shared_budget_and_gives_slots_back() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 10)]);
    let budget = PidfdBudget::new(1);
    run_with(&mut fake, 10, cfg(), &budget);
    let held: std::collections::BTreeSet<u32> = fake
        .log
        .iter()
        .filter(|(_, _, h)| *h == Handle::Held)
        .map(|(p, _, _)| *p)
        .collect();
    assert_eq!(held.len(), 1, "one slot, one handle: {:?}", fake.log);
    assert_eq!(budget.in_use(), 0, "a slot leaked");
    for pid in [10, 11, 12] {
        assert_eq!(fake.state_of(pid), ProcState::Gone, "pid {pid}");
    }
}

/// A large frozen set is killed in full inside the slices.
/// Red if the terminal kills are skipped or overrun the slices.
#[test]
fn a_large_frozen_set_is_killed_inside_the_slices() {
    let mut tree: Vec<(u32, u32)> = vec![(10, 1)];
    tree.extend((11..211).map(|pid| (pid, 10)));
    let mut fake = Fake::new(&tree);
    fake.tick = Duration::from_micros(50);
    run(&mut fake, 10);
    assert!(fake.procs.iter().all(|p| p.state == ProcState::Gone));
    assert!(
        fake.clock <= cfg().freeze_slice + TERMINAL,
        "ran {:?}",
        fake.clock
    );
}

/// On every failure the table can inject, nothing the sweep stopped is left stopped.
/// Red if any failure path leaves a process stopped.
#[test]
fn nothing_is_left_stopped_on_any_failure_path() {
    let failures = [
        (11, Sig::Stop, SignalError::Denied),
        (11, Sig::Kill, SignalError::Denied),
        (11, Sig::Kill, SignalError::Failed),
        (11, Sig::Kill, SignalError::Mismatch),
        (10, Sig::Kill, SignalError::Denied),
    ];
    for failure in failures {
        let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 11)]);
        fake.fail = Some(failure);
        run(&mut fake, 10);
        assert!(
            fake.stopped().is_empty(),
            "{failure:?}: left stopped {:?}",
            fake.stopped()
        );
        assert_eq!(
            fake.state_of(12),
            ProcState::Gone,
            "{failure:?}: the leaf still dies"
        );
    }
}

/// The held-handle budget is shared and gives slots back.
/// Red if the budget hands out nothing or never recovers a slot.
#[test]
fn the_pidfd_budget_is_shared_and_recovers_slots() {
    let budget = PidfdBudget::new(3);
    let a = budget.take().expect("slot 1");
    let _b = budget.take().expect("slot 2");
    let _c = budget.take().expect("slot 3");
    assert_eq!(budget.in_use(), 3);
    assert!(budget.take().is_none(), "no slot past the budget");
    drop(a);
    assert_eq!(budget.in_use(), 2);
    assert!(budget.take().is_some(), "a dropped slot is reusable");
}

/// The budget never starves the gateway's own descriptors and never reaches zero.
/// Red if the limit is zero, unbounded, or ignores the reserve.
#[test]
fn the_pidfd_limit_is_floored_capped_and_leaves_a_reserve() {
    assert_eq!(PidfdBudget::limit_for(0, 128), 64, "floored at 64");
    assert_eq!(
        PidfdBudget::limit_for(100, 128),
        64,
        "reserve over the limit"
    );
    assert_eq!(
        PidfdBudget::limit_for(1_000, 128),
        872,
        "headroom after the reserve"
    );
    assert_eq!(
        PidfdBudget::limit_for(1_000_000, 128),
        4096,
        "capped at 4096"
    );
}

#[path = "stdio_sweep_error_tests.rs"]
mod errors;
