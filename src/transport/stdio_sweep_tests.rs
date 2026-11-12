// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The sweep's order of signals, bounds and accounting, against an in-memory table.

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

fn cfg() -> SweepConfig {
    SweepConfig {
        freeze_slice: ms(50),
        kill_slice: ms(50),
        cap: 4096,
    }
}

struct Proc {
    id: Identity,
    ppid: u32,
    state: ProcState,
    /// Forks a new child on every table read while running.
    churns: bool,
    /// Ignores SIGSTOP (stays running).
    ignores_stop: bool,
}

struct Fake {
    procs: Vec<Proc>,
    /// Every signal the sweep sent: (pid, signal, how it was reached).
    log: Vec<(u32, Sig, Handle)>,
    clock: Duration,
    tick: Duration,
    handle: Handle,
    next_pid: u32,
    /// A signal that fails: (pid, signal, error).
    fail: Option<(u32, Sig, SignalError)>,
}

impl Fake {
    fn new(tree: &[(u32, u32)]) -> Self {
        let procs = tree
            .iter()
            .map(|&(pid, ppid)| Proc {
                id: id(pid),
                ppid,
                state: ProcState::Running,
                churns: false,
                ignores_stop: false,
            })
            .collect();
        Self {
            procs,
            log: Vec::new(),
            clock: Duration::ZERO,
            tick: ms(1),
            handle: Handle::Held,
            next_pid: 1000,
            fail: None,
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

    fn signals(&self, pid: u32) -> Vec<Sig> {
        self.log
            .iter()
            .filter(|(p, _, _)| *p == pid)
            .map(|(_, sig, _)| *sig)
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
}

impl ProcessTable for Fake {
    fn read(&mut self) -> Vec<(Identity, u32)> {
        self.clock += self.tick;
        let spawning: Vec<u32> = self
            .procs
            .iter()
            .filter(|p| p.churns && p.state == ProcState::Running)
            .map(|p| p.id.pid)
            .collect();
        for parent in spawning {
            self.next_pid += 1;
            let child = Proc {
                id: id(self.next_pid),
                ppid: parent,
                state: ProcState::Running,
                churns: false,
                ignores_stop: false,
            };
            self.procs.push(child);
        }
        self.procs
            .iter()
            .filter(|p| p.state != ProcState::Gone)
            .map(|p| (p.id, p.ppid))
            .collect()
    }

    fn state(&mut self, who: Identity) -> ProcState {
        self.procs
            .iter()
            .find(|p| p.id == who)
            .map_or(ProcState::Gone, |p| p.state)
    }

    fn signal(&mut self, who: Identity, sig: Sig) -> Result<Handle, SignalError> {
        let handle = self.handle;
        if let Some((pid, failing, error)) = self.fail
            && pid == who.pid
            && failing == sig
        {
            return Err(error);
        }
        let Some(target) = self.procs.iter_mut().find(|p| p.id.pid == who.pid) else {
            return Err(SignalError::Mismatch);
        };
        if target.id != who {
            return Err(SignalError::Mismatch);
        }
        self.log.push((who.pid, sig, handle));
        match sig {
            Sig::Stop if !target.ignores_stop && target.state == ProcState::Running => {
                target.state = ProcState::Stopped;
            }
            Sig::Cont if target.state == ProcState::Stopped => target.state = ProcState::Running,
            Sig::Kill => target.state = ProcState::Gone,
            _ => {}
        }
        Ok(handle)
    }

    fn now(&mut self) -> Duration {
        self.clock
    }
}

fn run(fake: &mut Fake, root: u32) -> SweepReport {
    let mut sweep = Sweep::new(id(root), cfg());
    sweep.snapshot(fake);
    sweep.run(fake)
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
        let sent = fake.signals(pid);
        assert_eq!(sent.first(), Some(&Sig::Stop), "pid {pid} frozen first");
        assert_eq!(sent.last(), Some(&Sig::Kill), "pid {pid} killed last");
        assert_eq!(fake.state_of(pid), ProcState::Gone);
    }
    assert!(report.residual.is_empty(), "{report:?}");
}

/// A process that is no descendant (a detached helper, a daemon reparented to
/// init) is never signalled.
/// Red if the sweep signals a process outside the backend's tree.
#[test]
fn a_process_outside_the_tree_is_never_signalled() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (20, 1), (21, 20)]);
    run(&mut fake, 10);
    assert_eq!(fake.signals(11).last(), Some(&Sig::Kill), "the tree dies");
    assert!(fake.signals(20).is_empty() && fake.signals(21).is_empty());
    assert_eq!(fake.state_of(20), ProcState::Running);
}

/// A recorded pid that now belongs to a different process is skipped, never
/// signalled.
/// Red if a reused pid receives a signal.
#[test]
fn a_reused_pid_is_skipped_and_never_signalled() {
    let mut fake = Fake::new(&[(10, 1), (11, 10)]);
    let mut sweep = Sweep::new(id(10), cfg());
    sweep.snapshot(&mut fake);
    // The snapshot member 11 exits and an unrelated process takes its pid.
    fake.proc(11).id = Identity {
        pid: 11,
        start: 9_999,
    };
    fake.proc(11).ppid = 1;
    let _ = sweep.run(&mut fake);
    assert!(fake.signals(11).is_empty(), "{:?}", fake.log);
    assert_eq!(fake.state_of(11), ProcState::Running);
}

/// A leaf whose parent exited between the snapshot and the sweep is still a
/// member and is killed.
/// Red if the sweep needs a live parent chain at kill time.
#[test]
fn a_leaf_whose_parent_exited_after_the_snapshot_is_still_killed() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 11)]);
    let mut sweep = Sweep::new(id(10), cfg());
    sweep.snapshot(&mut fake);
    fake.proc(11).state = ProcState::Gone;
    fake.proc(12).ppid = 1;
    let report = sweep.run(&mut fake);
    assert_eq!(fake.state_of(12), ProcState::Gone, "{:?}", fake.log);
    assert!(report.killed.contains(&id(12)));
}

/// The backend exited before the sweep (early leader exit); its leaf, reparented,
/// was in the snapshot and is killed.
/// Red if the sweep does nothing once the root is gone.
#[test]
fn a_leaf_of_a_backend_that_exited_first_is_killed() {
    let mut fake = Fake::new(&[(10, 1), (11, 10)]);
    let mut sweep = Sweep::new(id(10), cfg());
    sweep.snapshot(&mut fake);
    fake.proc(10).state = ProcState::Gone;
    fake.proc(11).ppid = 1;
    let _ = sweep.run(&mut fake);
    assert_eq!(fake.state_of(11), ProcState::Gone, "{:?}", fake.log);
}

/// A leaf that forks on every read is frozen before the last walk, so every
/// identity a completed pass collected is killed, and the run ends inside its
/// slices.
/// Red if a collected identity survives or the run outlasts its slices.
#[test]
fn a_forking_leaf_is_frozen_and_every_collected_identity_dies() {
    let mut fake = Fake::new(&[(10, 1), (11, 10)]);
    fake.proc(11).churns = true;
    let report = run(&mut fake, 10);
    assert!(
        fake.procs.iter().all(|p| p.state == ProcState::Gone),
        "survivors: {:?}",
        fake.procs
            .iter()
            .filter(|p| p.state != ProcState::Gone)
            .map(|p| p.id.pid)
            .collect::<Vec<_>>()
    );
    assert!(
        fake.clock <= cfg().freeze_slice + cfg().kill_slice,
        "ran {:?}",
        fake.clock
    );
    assert!(report.passes >= 1);
}

/// A process that never confirms stopped within the slice is still killed, the
/// frozen set is killed (never continued), and the rest is reported as residual.
/// Red if expiry continues the frozen set or leaves anything stopped.
#[test]
fn slice_expiry_kills_the_frozen_set_and_leaves_nothing_stopped() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 10)]);
    fake.proc(12).ignores_stop = true;
    let mut short = cfg();
    short.freeze_slice = ms(5);
    let mut sweep = Sweep::new(id(10), short);
    sweep.snapshot(&mut fake);
    let report = sweep.run(&mut fake);
    assert!(
        fake.stopped().is_empty(),
        "left stopped: {:?}",
        fake.stopped()
    );
    assert!(!fake.signals(11).contains(&Sig::Cont), "{:?}", fake.log);
    assert_eq!(fake.state_of(11), ProcState::Gone);
    assert_eq!(fake.signals(12).last(), Some(&Sig::Kill));
    assert!(report.residual.contains(&id(12)) || report.killed.contains(&id(12)));
}

/// A kill that fails (denied) must not leave the process stopped: it is
/// continued and counted residual.
/// Red if a process whose kill failed stays stopped.
#[test]
fn nothing_is_left_stopped_when_a_kill_fails() {
    let mut fake = Fake::new(&[(10, 1), (11, 10)]);
    fake.fail = Some((11, Sig::Kill, SignalError::Denied));
    let report = run(&mut fake, 10);
    assert!(
        fake.stopped().is_empty(),
        "left stopped: {:?}",
        fake.stopped()
    );
    assert_eq!(fake.state_of(11), ProcState::Running, "{:?}", fake.log);
    assert!(report.residual.contains(&id(11)));
}

/// A process already stopped by someone else is never continued by the sweep.
/// Red if the sweep continues a process it did not stop.
#[test]
fn a_continue_goes_only_to_a_process_the_sweep_stopped() {
    let mut fake = Fake::new(&[(10, 1), (11, 10)]);
    fake.proc(11).state = ProcState::Stopped;
    fake.fail = Some((11, Sig::Kill, SignalError::Denied));
    run(&mut fake, 10);
    assert!(!fake.signals(11).contains(&Sig::Cont), "{:?}", fake.log);
    assert_eq!(fake.state_of(11), ProcState::Stopped);
}

/// Every member reached by bare pid is stopped before it is killed, never
/// verified and killed while running.
/// Red if a by-pid member is killed without a stop first.
#[test]
fn a_by_pid_member_is_stopped_before_it_is_killed() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 11)]);
    fake.handle = Handle::ByPid;
    run(&mut fake, 10);
    for pid in [10, 11, 12] {
        let sent = fake.signals(pid);
        let kill = sent.iter().position(|s| *s == Sig::Kill).expect("killed");
        assert!(
            sent[..kill].contains(&Sig::Stop),
            "pid {pid} killed without a stop: {sent:?}"
        );
    }
}

/// The set is capped; members past the cap are reported residual, and a member
/// that died before the sweep is never signalled.
/// Red if the cap is ignored or a dead member is signalled.
#[test]
fn the_set_is_capped_and_a_dead_member_is_not_signalled() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 10), (13, 10), (14, 10)]);
    let mut small = cfg();
    small.cap = 2;
    let mut sweep = Sweep::new(id(10), small);
    sweep.snapshot(&mut fake);
    fake.proc(14).state = ProcState::Gone;
    let report = sweep.run(&mut fake);
    assert!(fake.signals(14).is_empty(), "{:?}", fake.log);
    assert!(
        report.killed.len() <= 3,
        "root plus at most the cap: {report:?}"
    );
    assert!(!report.residual.is_empty(), "past the cap: {report:?}");
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
