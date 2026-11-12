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
    // Its pre-stop state was unreadable, which is not proof that a stop was
    // someone else's: never left stopped, so it is continued.
    assert!(fake.stopped().is_empty(), "{:?}", fake.stopped());
    assert!(report.continued.contains(&id(12)), "{report:?}");
    // And its freeze was never confirmed: the poll ran to the end of the slice.
    assert!(fake.clock >= cfg().freeze_slice, "ran {:?}", fake.clock);
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
    // And the sweep acted: the live members and the root were killed.
    for pid in [10, 11] {
        assert!(report.killed.contains(&id(pid)), "pid {pid}: {report:?}");
    }
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

/// A member the sweep never froze (its slice ended first) is killed through a
/// pidfd, which names the exact process, since a bare-pid Kill to a running
/// process is refused. Red if the terminal phase sends such a member a bare-pid
/// Kill: the table refuses it and the member escapes alive.
#[test]
fn a_member_unfrozen_at_slice_expiry_is_killed_through_a_pidfd() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 10), (13, 10)]);
    let mut short = cfg();
    short.freeze_slice = ms(2);
    let report = run_with(&mut fake, 10, short, &PidfdBudget::new(4096));
    for pid in [10, 11, 12, 13] {
        assert_eq!(
            fake.state_of(pid),
            ProcState::Gone,
            "pid {pid}: {:?}",
            fake.log
        );
    }
    assert_eq!(report.unconfirmed, 0, "{report:?}");
    assert!(fake.stopped().is_empty());
}

/// With no pidfd slot left, an unfrozen member's Kill goes by pid and the table
/// refuses it: reported as unconfirmed, never killed blind.
/// Red if the gate is bypassed when no slot is available.
#[test]
fn an_unfrozen_member_with_no_pidfd_slot_is_unconfirmed_not_killed_blind() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 10), (13, 10)]);
    fake.pidfd = false;
    fake.reuse_while_running = Some((13, 999));
    let mut short = cfg();
    short.freeze_slice = ms(2);
    let report = run_with(&mut fake, 10, short, &PidfdBudget::new(0));
    assert!(
        fake.wrong.is_empty(),
        "a signal reached a reused pid: {:?}",
        fake.wrong
    );
    assert!(report.unconfirmed >= 1, "{report:?}");
    assert!(!report.residual.is_empty(), "{report:?}");
}

/// After a reading that failed the walk is not called stable: it keeps walking
/// until the slice ends. Red if a failed reading that adds nothing ends the walk.
#[test]
fn a_failed_rewalk_keeps_walking_until_the_slice_ends() {
    let mut fake = Fake::new(&[(10, 1), (11, 10)]);
    let mut sweep = Sweep::new(id(10), cfg());
    sweep.snapshot(&mut fake);
    fake.blind = true;
    let report = sweep.run(&mut fake, &PidfdBudget::new(4096));
    assert!(report.passes > 2, "{report:?}");
    assert!(fake.clock >= cfg().freeze_slice, "ran {:?}", fake.clock);
    assert_eq!(fake.state_of(11), ProcState::Gone);
}

/// A kill that fails and a continue that fails leave a stopped process: it is
/// counted as stuck, not reported as continued.
/// Red if a failed continue is recorded as continued.
#[test]
fn a_failed_continue_is_counted_stuck_not_continued() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 10)]);
    fake.fail = Some((12, Sig::Kill, SignalError::Failed));
    fake.cont_fails = Some(12);
    let report = run(&mut fake, 10);
    assert_eq!(report.stuck_stopped, 1, "{report:?}");
    assert!(!report.continued.contains(&id(12)), "{report:?}");
    assert!(report.residual.contains(&id(12)), "{report:?}");
}

/// A member the table cannot read (listed as unreadable, the listing complete)
/// is not pruned for being absent from the rows: it is still killed.
/// Red if unreadable pids are treated as dead.
#[test]
fn a_member_the_table_cannot_read_is_not_pruned() {
    let mut fake = Fake::new(&[(10, 1), (11, 10), (12, 11)]);
    let mut sweep = Sweep::new(id(10), cfg());
    sweep.snapshot(&mut fake);
    fake.foreign = Some(12);
    let report = sweep.run(&mut fake, &PidfdBudget::new(4096));
    assert!(
        fake.attempted(12).contains(&Sig::Kill),
        "{:?}",
        fake.attempts
    );
    assert!(report.killed.contains(&id(12)), "{report:?}");
}

/// A stop that fails gives its handle back, so the shared budget does not count
/// a descriptor the sweep does not keep. Red if the handle is not released.
#[test]
fn a_failed_stop_releases_its_handle() {
    let mut fake = Fake::new(&[(10, 1), (11, 10)]);
    fake.fail = Some((11, Sig::Stop, SignalError::Denied));
    let budget = PidfdBudget::new(4096);
    run_with(&mut fake, 10, cfg(), &budget);
    assert!(fake.released.contains(&11), "{:?}", fake.released);
    assert_eq!(budget.in_use(), 0);
}

/// Past the cap the lowest pids are kept, whatever order the table lists them.
/// Red if the cap keeps whichever rows come first.
#[test]
fn the_cap_keeps_the_lowest_pids_when_the_table_lists_them_high_first() {
    let mut fake = Fake::new(&[(10, 1), (14, 10), (13, 10), (12, 10), (11, 10)]);
    let mut small = cfg();
    small.cap = 2;
    let report = run_with(&mut fake, 10, small, &PidfdBudget::new(4096));
    assert!(
        report.killed.contains(&id(11)) && report.killed.contains(&id(12)),
        "{report:?}"
    );
    for pid in [13, 14] {
        assert!(report.residual.contains(&id(pid)), "pid {pid}: {report:?}");
        assert_eq!(fake.state_of(pid), ProcState::Running);
    }
}

fn id_at(pid: u32, start: u64) -> Identity {
    Identity { pid, start }
}

/// By pid, the member exits and a stranger takes its pid just before the sweep's
/// SIGSTOP arrives: the stop lands on the stranger, the later Kill and Cont name
/// the old identity and mismatch. The sweep resumes the stranger.
/// Red if a stray stop is left in place (the stranger stays stopped, unreported).
#[test]
fn a_stranger_hit_by_a_stray_stop_is_resumed() {
    let mut fake = Fake::new(&[(10, 1), (11, 10)]);
    fake.pidfd = false;
    fake.reuse_after_stop = Some((11, 999_999));
    let report = run(&mut fake, 10);
    assert_eq!(
        fake.wrong,
        vec![(11, Sig::Stop)],
        "premise: the stop strayed"
    );
    assert_eq!(report.rescued, 1, "{report:?}");
    assert_eq!(
        fake.state_of(11),
        ProcState::Running,
        "the stranger was resumed"
    );
    assert!(fake.stopped().is_empty(), "{:?}", fake.stopped());
    assert_eq!(report.stop_mismatch, 0, "{report:?}");
}

/// When the resume fails the stranger may be left stopped: counted as a stop
/// mismatch and a residual.
/// Red if a failed rescue is silent.
#[test]
fn a_failed_rescue_is_a_stop_mismatch_residual() {
    let mut fake = Fake::new(&[(10, 1), (11, 10)]);
    fake.pidfd = false;
    fake.reuse_after_stop = Some((11, 999_999));
    fake.cont_fails = Some(11);
    let report = run(&mut fake, 10);
    assert_eq!(report.stop_mismatch, 1, "{report:?}");
    assert_eq!(report.rescued, 0, "{report:?}");
    assert!(report.residual.contains(&id(11)), "{report:?}");
    assert_eq!(fake.stopped(), vec![11], "the stranger is still stopped");
}

/// A member that exited before its kill and whose pid a running stranger now
/// holds is not a stop mismatch: nothing to rescue, nothing reported, and the
/// stranger is untouched.
/// Red if every exit race is counted as a stop mismatch.
#[test]
fn a_member_that_exited_by_itself_is_not_a_stop_mismatch() {
    let mut fake = Fake::new(&[(10, 1), (11, 10)]);
    fake.pidfd = false;
    fake.swap_before_kill = Some((11, 888));
    let report = run(&mut fake, 10);
    assert_eq!(report.stop_mismatch, 0, "{report:?}");
    assert_eq!(report.rescued, 0, "{report:?}");
    assert_eq!(
        fake.state_of(11),
        ProcState::Running,
        "the stranger is untouched"
    );
}

/// Only a stopped process born after the member, at the member's pid, is a
/// stray stop's victim.
/// Red if a running process, an older one or another pid qualifies.
#[test]
fn only_a_stopped_later_process_at_the_pid_is_a_stray_stop() {
    let member = id_at(11, 500);
    assert!(is_stray_stop(member, id_at(11, 501), ProcState::Stopped));
    assert!(!is_stray_stop(member, id_at(11, 501), ProcState::Running));
    assert!(
        !is_stray_stop(member, id_at(11, 500), ProcState::Stopped),
        "the member itself"
    );
    assert!(
        !is_stray_stop(member, id_at(11, 499), ProcState::Stopped),
        "older than the member"
    );
    assert!(
        !is_stray_stop(member, id_at(12, 501), ProcState::Stopped),
        "another pid"
    );
}
