// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the per-tree walk: an in-memory table that reads the way the Linux
//! walk does, from the seeds down by parent link.

use std::time::Duration;

use super::{
    Handle, Identity, Listing, PidfdBudget, ProcState, ProcessTable, Sig, SignalError, Sweep,
    SweepConfig, full_scan_gone,
};

fn id(pid: u32) -> Identity {
    Identity {
        pid,
        start: u64::from(pid) * 10,
    }
}

fn config() -> SweepConfig {
    SweepConfig {
        freeze_slice: Duration::from_millis(700),
        cap: 64,
    }
}

#[derive(Clone, Copy)]
struct Proc {
    id: Identity,
    ppid: u32,
    state: ProcState,
}

/// A running parent may leave out `omit`'s child: the kernel's children file is
/// reliable only for a stopped parent, so any running parent walked makes the
/// reading unsettled.
#[derive(Default)]
struct Walk {
    procs: Vec<Proc>,
    clock: Duration,
    read_cost: Duration,
    omit: Option<(u32, u32)>,
    hide_seed: Option<u32>,
    stop_fails_once: Option<u32>,
    sent: Vec<(u32, Sig)>,
}

impl Walk {
    fn add(&mut self, pid: u32, ppid: u32) {
        self.procs.push(Proc {
            id: id(pid),
            ppid,
            state: ProcState::Running,
        });
    }

    fn live(&mut self, who: Identity) -> Option<&mut Proc> {
        self.procs
            .iter_mut()
            .find(|p| p.id == who && p.state != ProcState::Gone)
    }

    fn got(&self, pid: u32, sig: Sig) -> bool {
        self.sent.contains(&(pid, sig))
    }
}

impl ProcessTable for Walk {
    fn read(&mut self, walk: &[Identity], stat_only: &[Identity], _until: Duration) -> Listing {
        self.clock += self.read_cost;
        let (mut rows, mut gone, mut settled) = (Vec::new(), Vec::new(), true);
        let mut parents = Vec::new();
        for (seed, walked) in walk
            .iter()
            .map(|s| (s, true))
            .chain(stat_only.iter().map(|s| (s, false)))
        {
            match self
                .procs
                .iter()
                .find(|p| p.id.pid == seed.pid && p.state != ProcState::Gone)
            {
                Some(p) if p.id == *seed => {
                    if self.hide_seed != Some(seed.pid) {
                        rows.push((p.id, p.ppid));
                    }
                    if walked {
                        parents.push(p.id.pid);
                    }
                }
                _ => gone.push(*seed),
            }
        }
        while let Some(parent) = parents.pop() {
            let running = self
                .procs
                .iter()
                .any(|p| p.id.pid == parent && p.state == ProcState::Running);
            settled &= !running;
            for child in self
                .procs
                .iter()
                .filter(|p| p.ppid == parent && p.state != ProcState::Gone)
            {
                let left_out = running && self.omit == Some((parent, child.id.pid));
                if !left_out && !rows.iter().any(|(who, _)| *who == child.id) {
                    rows.push((child.id, child.ppid));
                    parents.push(child.id.pid);
                }
            }
        }
        Listing {
            rows,
            complete: true,
            unreadable: Vec::new(),
            gone,
            settled,
        }
    }

    fn state(&mut self, who: Identity) -> ProcState {
        self.live(who).map_or(ProcState::Gone, |p| p.state)
    }

    fn signal(&mut self, who: Identity, sig: Sig, _held: bool) -> Result<Handle, SignalError> {
        self.sent.push((who.pid, sig));
        if sig == Sig::Stop && self.stop_fails_once == Some(who.pid) {
            self.stop_fails_once = None;
            return Err(SignalError::Failed);
        }
        let proc = self.live(who).ok_or(SignalError::Mismatch)?;
        proc.state = match sig {
            Sig::Stop => ProcState::Stopped,
            Sig::Cont => ProcState::Running,
            Sig::Kill => ProcState::Gone,
        };
        Ok(Handle::Held)
    }

    fn now(&mut self) -> Duration {
        self.clock
    }
}

fn sweep(walk: &mut Walk, root: u32) -> super::SweepReport {
    let mut sweep = Sweep::new(id(root), config());
    sweep.snapshot(walk);
    sweep.run(walk, &PidfdBudget::new(64))
}

/// R-freeze-first: every reading costs more than the freeze slice, so a run
/// that reads before its first freeze pass has no time left to stop anything.
/// The root and the snapshot's members are still stopped, then killed, and
/// nothing is left stopped.
#[test]
fn the_snapshot_members_are_frozen_before_any_reading() {
    let mut walk = Walk {
        read_cost: Duration::from_secs(1),
        ..Walk::default()
    };
    walk.add(100, 1);
    walk.add(101, 100);
    walk.add(102, 101);
    sweep(&mut walk, 100);
    for pid in [100, 101, 102] {
        assert!(walk.got(pid, Sig::Stop), "{pid} was never frozen");
        assert!(walk.got(pid, Sig::Kill), "{pid} was never killed");
    }
    assert!(
        walk.procs.iter().all(|p| p.state != ProcState::Stopped),
        "a process was left stopped"
    );
}

/// R-omit: a running parent leaves its child out of the reading. Only a
/// settled reading may end the freeze loop, so once the parent is stopped the
/// child is listed, collected and killed.
#[test]
fn a_child_left_out_while_its_parent_runs_is_still_killed() {
    let mut walk = Walk {
        omit: Some((101, 102)),
        stop_fails_once: Some(101),
        ..Walk::default()
    };
    walk.add(100, 1);
    walk.add(101, 100);
    walk.add(102, 101);
    sweep(&mut walk, 100);
    assert!(
        walk.got(102, Sig::Kill),
        "the left-out child was never killed"
    );
    assert!(
        walk.procs.iter().all(|p| p.state == ProcState::Gone),
        "a process survived the sweep"
    );
}

/// R-gone, in memory: a walk prunes only on a seed's own evidence. A live
/// member missing from a complete walk's rows stays and is killed; one whose
/// pid now names a newer process is in `gone` and is never signalled.
#[test]
fn a_walk_prunes_only_what_it_names_gone() {
    let mut walk = Walk::default();
    walk.add(100, 1);
    walk.add(101, 100);
    walk.add(103, 100);
    let mut sweep = Sweep::new(id(100), config());
    sweep.snapshot(&mut walk);
    walk.hide_seed = Some(101);
    // Reparented away, so only its own seed reading could list it (the
    // parent's walk no longer does).
    if let Some(member) = walk.procs.iter_mut().find(|p| p.id.pid == 101) {
        member.ppid = 1;
    }
    walk.procs.retain(|p| p.id.pid != 103);
    walk.procs.push(Proc {
        id: Identity {
            pid: 103,
            start: 9_999,
        },
        ppid: 1,
        state: ProcState::Running,
    });
    sweep.run(&mut walk, &PidfdBudget::new(64));
    assert!(
        walk.got(101, Sig::Kill),
        "a live member absent from the rows was dropped"
    );
    assert!(
        !walk.sent.iter().any(|(pid, _)| *pid == 103),
        "the process that reused a member's pid was signalled"
    );
}

/// R-full-gone: a full scan's seeds absent from a COMPLETE scan are gone,
/// unless the table could not read them; an incomplete scan names none.
#[test]
fn a_full_scan_names_gone_only_from_a_complete_listing() {
    let seeds = [id(100), id(101), id(102)];
    let listing = |complete: bool, unreadable: Vec<u32>| Listing {
        rows: vec![(id(100), 1)],
        complete,
        unreadable,
        gone: Vec::new(),
        settled: true,
    };
    assert_eq!(
        full_scan_gone(&seeds, &listing(true, vec![102])),
        vec![id(101)],
        "a complete scan names the absent, readable seed"
    );
    assert_eq!(
        full_scan_gone(&seeds, &listing(false, Vec::new())),
        Vec::<Identity>::new(),
        "an incomplete scan names none"
    );
}
