// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the sweep's table errors, the by-pid kill gate, the asynchronous
//! stop and the slice sizes. The fake table and its helpers are the parent
//! module's.

use super::*;

/// A listing that fails is not a listing that says the tree is gone: members
/// recorded before it are still killed, and the failed reading is counted.
/// Red if a failed listing prunes the members, or is not reported.
#[test]
fn a_failed_listing_does_not_hide_members_from_the_kill() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 11)]);
    let mut sweep = Sweep::new(id(10), cfg());
    sweep.snapshot(&mut fake);
    fake.blind = true;
    let report = sweep.run(&mut fake, &PidfdBudget::new(4096));
    fake.blind = false;
    for pid in [10, 11, 12] {
        assert_eq!(
            fake.state_of(pid),
            ProcState::Gone,
            "pid {pid}: {:?}",
            fake.log
        );
    }
    assert!(report.killed.contains(&id(12)), "{report:?}");
    assert!(report.incomplete_reads >= 1, "{report:?}");
    assert!(fake.stopped().is_empty());
}

/// A member whose kill failed and whose state cannot be read is not taken for
/// gone: it is a residual counted as unreadable, though its kill was attempted.
/// Red if an unreadable state counts as gone (no residual), or goes uncounted.
#[test]
fn an_unreadable_member_is_a_residual_counted_as_unknown() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 11)]);
    fake.unreadable = Some(12);
    fake.fail = Some((12, Sig::Kill, SignalError::Failed));
    let report = run(&mut fake, 10);
    assert!(
        fake.attempted(12).contains(&Sig::Kill),
        "the kill was attempted"
    );
    assert_eq!(report.unknown, 1, "{report:?}");
    assert!(report.residual.contains(&id(12)), "{report:?}");
    assert!(
        !report.residual.contains(&id(11)),
        "a readable member is confirmed"
    );
    // Its pre-stop state was unreadable, so the sweep cannot prove the stop was
    // its own and does not continue it: it is reported, not resumed blind.
    assert_eq!(fake.stopped(), vec![12]);
}

/// A complete listing still prunes: the dead are not signalled.
/// Red if completeness is ignored and nothing is ever pruned.
#[test]
fn a_complete_listing_still_prunes_the_dead() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 11)]);
    let mut sweep = Sweep::new(id(10), cfg());
    sweep.snapshot(&mut fake);
    fake.proc(12).state = ProcState::Gone;
    let report = sweep.run(&mut fake, &PidfdBudget::new(4096));
    assert!(fake.attempted(12).is_empty(), "{:?}", fake.attempts);
    assert_eq!(report.incomplete_reads, 0);
}

/// The gate itself: a by-pid Kill goes only to a stopped or zombie process.
/// Red if a Kill is let through to a running (or unreadable) process.
#[test]
fn the_by_pid_gate_lets_a_kill_reach_only_a_stopped_or_zombie_process() {
    for (state, kill_ok) in [
        (ProcState::Stopped, true),
        (ProcState::Zombie, true),
        (ProcState::Running, false),
        (ProcState::Gone, false),
        (ProcState::Unknown, false),
    ] {
        assert_eq!(by_pid_gate(Sig::Kill, state).is_ok(), kill_ok, "{state:?}");
        assert_eq!(
            by_pid_gate(Sig::Kill, state),
            if kill_ok {
                Ok(())
            } else {
                Err(SignalError::NotStopped)
            },
            "{state:?}"
        );
        assert!(by_pid_gate(Sig::Stop, state).is_ok(), "stop never gated");
        assert!(by_pid_gate(Sig::Cont, state).is_ok(), "cont never gated");
    }
}

/// By pid, a member that is still running when its kill comes (its stop did not
/// land) is refused, never killed blind: it is a residual counted as
/// unconfirmed, and no signal lands on a reused pid. The rest of the tree dies.
/// Red if the gate is missing from the table (the kill lands on the reuser).
#[test]
fn a_by_pid_kill_of_a_running_member_is_refused_and_reported() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 11)]);
    fake.pidfd = false;
    fake.strict_by_pid = true;
    fake.proc(12).ignores_stop = true;
    fake.reuse_while_running = Some((12, 999));
    let report = run(&mut fake, 10);
    assert_eq!(
        fake.state_of(12),
        ProcState::Running,
        "refused, not killed blind"
    );
    assert!(
        fake.wrong.is_empty(),
        "no signal on a reused pid: {:?}",
        fake.wrong
    );
    assert_eq!(report.unconfirmed, 1, "{report:?}");
    assert!(report.residual.contains(&id(12)), "{report:?}");
    for pid in [10, 11] {
        assert_eq!(fake.state_of(pid), ProcState::Gone, "pid {pid}");
    }
}

/// The slices come from the measurement at the cap, not from a round number:
/// freeze at least twice the Linux freeze at 4000 members (326 ms), terminal room
/// at least five times the Linux kill phase there (141 ms), together at most
/// half of the reaper's kill reserve.
/// Red if either slice is cut below its derivation or the pair outgrows the reserve.
#[test]
fn the_slices_are_sized_from_the_measured_cap() {
    assert!(
        FREEZE_SLICE >= Duration::from_millis(2 * 326),
        "{FREEZE_SLICE:?}"
    );
    assert!(
        TERMINAL_ROOM >= Duration::from_millis(5 * 141),
        "{TERMINAL_ROOM:?}"
    );
    assert!(
        FREEZE_SLICE + TERMINAL_ROOM <= crate::transport::stdio::reaper::KILL_RESERVE / 2,
        "{FREEZE_SLICE:?} + {TERMINAL_ROOM:?}"
    );
    assert_eq!(config().freeze_slice, FREEZE_SLICE);
}

/// A stop is asynchronous: a member that is still running while its SIGSTOP is in
/// flight can fork. The sweep confirms every frozen identity stopped before it
/// re-walks, so a child forked in that gap is collected and killed too.
/// Red if the sweep re-walks before the freeze is confirmed: the walk finds
/// nothing new, the kills begin, and the late child is never in the set.
#[test]
fn a_member_that_forks_while_its_stop_is_in_flight_is_still_swept() {
    let mut fake = Fake::new(&[(10, 1), (11, 10)]);
    fake.proc(11).stop_lag = 20;
    fake.proc(11).fork_at = Some(8);
    let report = run(&mut fake, 10);
    assert_eq!(fake.procs.len(), 3, "premise: the member forked mid-stop");
    let survivors: Vec<u32> = fake
        .procs
        .iter()
        .filter(|p| p.state != ProcState::Gone)
        .map(|p| p.id.pid)
        .collect();
    assert!(survivors.is_empty(), "survivors: {survivors:?} {report:?}");
    assert!(fake.stopped().is_empty());
}
