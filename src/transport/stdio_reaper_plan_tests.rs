// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The stdio reaper's graceful-ending plan: every caller's stop budget yields a plan that fits it.

#[cfg(unix)]
use super::super::child_tree::NESTED_TERM_NEED;
use super::{DEFAULT_STOP_BUDGET, Ending, KILL_RESERVE, MIN_PHASE, graceful_ending};
use std::time::Duration;

fn total(ending: Ending) -> Duration {
    ending.waits() + KILL_RESERVE
}

/// One row per caller: a gateway shutdown at the default and at a short
/// `shutdown_timeout`, eviction and restart (`close_stage`), a close with
/// no caller budget, and a budget at the reserve.
#[test]
fn every_callers_plan_fits_its_budget() {
    let callers = [
        (
            "shutdown, default shutdown_timeout",
            Duration::from_secs(30),
        ),
        ("shutdown, short shutdown_timeout", Duration::from_secs(9)),
        ("eviction close_stage", Duration::from_secs(10)),
        ("restart close_stage", Duration::from_secs(10)),
        ("no caller budget", DEFAULT_STOP_BUDGET),
        ("at the reserve", KILL_RESERVE),
    ];
    for (caller, budget) in callers {
        for stdin_closed in [true, false] {
            let ending = graceful_ending(budget, stdin_closed, None);
            assert!(
                ending == Ending::Now || total(ending) <= budget,
                "{caller}: plan {ending:?} exceeds its budget {budget:?}"
            );
        }
    }
}

/// An unhurried stop with 3.65 s of waits (the window of the failed CI run) leaves SIGTERM at
/// least what a nested gateway needs to hurry and kill inside the outer's cut:
/// the inner only learns to hurry at the SIGTERM, so a third of the waits
/// (1.22 s) was under its worst case.
/// Red if the SIGTERM phase is back to a third of the waits.
#[cfg(unix)]
#[test]
fn the_sigterm_phase_covers_a_nested_gateways_hurried_path() {
    let waits = Duration::from_millis(3_650);
    let Ending::Graceful { eof, term } = graceful_ending(KILL_RESERVE + waits, true, None) else {
        panic!("waits above the minimum phase give a graceful ending");
    };
    assert_eq!(
        term, NESTED_TERM_NEED,
        "the SIGTERM phase is the nested need"
    );
    assert_eq!(eof + term, waits, "the split spends exactly the waits");
}

/// The SIGTERM floor takes from the EOF wait, so the minimum total carries a
/// window big enough that the EOF wait is no shorter than it was before the
/// floor: a third-split of the previous 3.4 s window gave 2.27 s. At the
/// minimum's window (4.4 s) EOF is 2.9 s and SIGTERM is the nested need; these
/// are the numbers the upgrade note gives operators, so they are pinned exactly.
/// Red if the floor or a growing reap constant erodes the EOF wait.
#[cfg(unix)]
#[test]
fn the_eof_wait_at_the_minimum_is_no_shorter_than_before_the_floor() {
    let before = Duration::from_millis(3_400) * 2 / 3;
    let waits = Duration::from_millis(4_400);
    let Ending::Graceful { eof, term } = graceful_ending(KILL_RESERVE + waits, true, None) else {
        panic!("waits above the minimum phase give a graceful ending");
    };
    assert!(
        eof >= before,
        "EOF wait {eof:?} is under the old {before:?}"
    );
    assert_eq!(eof, Duration::from_millis(2_900), "EOF wait at the minimum");
    assert_eq!(term, NESTED_TERM_NEED, "SIGTERM wait is the nested need");
}

/// The floor is met whenever the waits can afford it, leaving EOF at least the
/// minimum phase: 2 s of waits give SIGTERM the whole need and EOF the rest.
/// Red if a cap (such as half the waits) cuts the floor short of what the waits afford.
#[cfg(unix)]
#[test]
fn the_floor_is_met_whenever_the_waits_can_afford_it() {
    let waits = Duration::from_secs(2);
    assert_eq!(
        graceful_ending(KILL_RESERVE + waits, true, None),
        Ending::Graceful {
            eof: waits
                .checked_sub(NESTED_TERM_NEED)
                .expect("the waits afford the SIGTERM need"),
            term: NESTED_TERM_NEED,
        }
    );
}

/// Small waits cannot afford the floor: SIGTERM takes all but the minimum
/// phase, so the EOF wait is never starved to nothing.
/// Red if the floor ignores the small budget or eats the last minimum phase.
#[cfg(unix)]
#[test]
fn a_small_wait_keeps_the_minimum_phase_for_eof_even_under_the_floor() {
    let waits = Duration::from_secs(1);
    assert_eq!(
        graceful_ending(KILL_RESERVE + waits, true, None),
        Ending::Graceful {
            eof: MIN_PHASE,
            term: waits
                .checked_sub(MIN_PHASE)
                .expect("the waits afford the minimum phase"),
        }
    );
}

/// Waits big enough that a third already covers the need are untouched.
/// Red if the floor reshapes a long stop.
#[cfg(unix)]
#[test]
fn a_long_wait_keeps_its_third_for_sigterm() {
    let waits = Duration::from_secs(9);
    assert_eq!(
        graceful_ending(KILL_RESERVE + waits, true, None),
        Ending::Graceful {
            eof: waits
                .checked_sub(waits / 3)
                .expect("a third never exceeds the whole"),
            term: waits / 3,
        }
    );
}

#[cfg(unix)]
#[test]
fn the_split_keeps_the_reserve_and_gives_a_third_to_sigterm() {
    // 30 s less the reserve (the 5 s reap deadline and the close's 1 s
    // margin) leaves 24 s: a third of it after SIGTERM.
    let waits = Duration::from_secs(24);
    assert_eq!(
        graceful_ending(Duration::from_secs(30), true, None),
        Ending::Graceful {
            eof: waits
                .checked_sub(waits / 3)
                .expect("a third never exceeds the whole"),
            term: waits / 3,
        }
    );
    // Stdin a writer still holds: no EOF wait, SIGTERM at once.
    assert_eq!(
        graceful_ending(Duration::from_secs(10), false, None),
        Ending::Graceful {
            eof: Duration::ZERO,
            term: Duration::from_secs(4),
        }
    );
}

#[test]
fn a_budget_at_or_under_the_reserve_kills_at_once() {
    assert_eq!(graceful_ending(KILL_RESERVE, true, None), Ending::Now);
    assert_eq!(graceful_ending(Duration::ZERO, true, None), Ending::Now);
    assert_eq!(
        graceful_ending(KILL_RESERVE + MIN_PHASE / 2, true, None),
        Ending::Now,
        "waits under the minimum phase are skipped"
    );
}

/// A close begun after the hurry preserves a useful term phase.
/// Red if setup latency drops SIGTERM, extends the budget, or extends an earlier stop.
#[cfg(unix)]
#[test]
fn a_hurried_close_keeps_term_after_setup_latency() {
    let deadline = super::StopDeadline::default();
    let now = std::time::Instant::now();
    let cut = deadline.hurry(now);
    let budget = cut.duration_since(now + Duration::from_millis(10));
    let ending = graceful_ending(budget, true, Some(&deadline));
    assert_eq!(
        ending,
        Ending::Graceful {
            eof: Duration::from_millis(190),
            term: MIN_PHASE,
        }
    );
    assert!(total(ending) <= budget);
    deadline.move_earlier(now + KILL_RESERVE);
    assert_eq!(deadline.hurry(now), now + KILL_RESERVE);
}

/// A cut records when it was made, as one pair with the deadline: a later
/// deadline moves neither, an earlier one moves both.
#[test]
fn a_cut_records_when_it_was_made_and_a_later_one_moves_nothing() {
    let deadline = super::StopDeadline::default();
    assert_eq!(deadline.get_with_set_at(), None, "unset until a stop");
    let now = std::time::Instant::now();
    deadline.move_earlier(now + Duration::from_secs(60));
    let (at, set) = deadline.get_with_set_at().expect("the cut is set");
    assert_eq!(at, now + Duration::from_secs(60));
    assert!(set >= now, "the set-time is when the move ran");
    deadline.move_earlier(now + Duration::from_secs(90));
    assert_eq!(
        deadline.get_with_set_at(),
        Some((at, set)),
        "a later deadline moves neither the cut nor its set-time"
    );
    deadline.move_earlier(now + Duration::from_secs(30));
    let (earlier, reset) = deadline.get_with_set_at().expect("the cut is set");
    assert_eq!(earlier, now + Duration::from_secs(30));
    assert!(reset >= set, "an earlier cut records its own set-time");
}

/// R4 (HANDOVER.4): a tree handed over at the HTTP backend stage's
/// entry, with the stage's deadline set but not hurried, keeps every
/// millisecond past the one kill reserve for its EOF and SIGTERM waits. Red
/// if the reserve is taken twice (once by the caller, once here): the waits
/// then vanish and the plan is an immediate kill.
#[test]
fn a_backend_stage_budget_keeps_its_eof_and_term_phases() {
    let waits = Duration::from_millis(400);
    let deadline = super::StopDeadline::default();
    deadline.move_earlier(std::time::Instant::now() + KILL_RESERVE + waits);
    let ending = graceful_ending(KILL_RESERVE + waits, true, Some(&deadline));
    assert!(
        matches!(ending, Ending::Graceful { .. }),
        "a backend-stage budget lost its graceful plan: {ending:?}"
    );
    assert_eq!(
        ending.waits(),
        waits,
        "the plan's EOF and SIGTERM waits are not the budget less one kill reserve"
    );
}

/// The whole plan at each edge of the allocator, from the constants alone:
/// below the minimum phase nothing is worth waiting for, so the kill comes at
/// once; up to the nested need plus one minimum phase, SIGTERM takes all but
/// the minimum phase and EOF keeps exactly that; from there SIGTERM holds the
/// nested need until a third of the waits overtakes it. Where both phases are
/// kept, they spend the waits exactly.
/// Red if an edge moves: the nested need cut short by a step, or dropped so a
/// third of the waits decides alone.
#[cfg(unix)]
#[test]
fn the_allocator_plan_across_its_edges() {
    let ms = Duration::from_millis;
    let less = |a: Duration, b: Duration| a.checked_sub(b).expect("an edge below zero");
    let (n, m) = (NESTED_TERM_NEED, MIN_PHASE);
    let graceful = |eof, term| Ending::Graceful { eof, term };
    let edges = [
        ("no waits", Duration::ZERO, Ending::Now),
        ("just under one minimum phase", less(m, ms(1)), Ending::Now),
        ("one minimum phase", m, Ending::Now),
        (
            "SIGTERM's share under a minimum phase",
            m + m / 2,
            graceful(m, Duration::ZERO),
        ),
        ("the nested need alone", n, graceful(m, less(n, m))),
        (
            "one step short of need plus phase",
            less(n + m, ms(1)),
            graceful(m, less(n, ms(1))),
        ),
        ("need plus one minimum phase", n + m, graceful(m, n)),
        (
            "one step past need plus phase",
            n + m + ms(1),
            graceful(m + ms(1), n),
        ),
        ("a third equal to the need", n * 3, graceful(n * 2, n)),
        (
            "a third past the need",
            n * 3 + ms(3),
            graceful(n * 2 + ms(2), n + ms(1)),
        ),
    ];
    for (edge, waits, expected) in edges {
        let plan = graceful_ending(KILL_RESERVE + waits, true, None);
        assert_eq!(plan, expected, "{edge}: waits {waits:?}");
        if let Ending::Graceful { eof, term } = plan
            && eof >= m
            && term >= m
        {
            assert_eq!(
                eof + term,
                waits,
                "{edge}: the kept phases do not spend the waits"
            );
        }
    }
}

/// Test-only: [`super::StopDeadline::move_earlier`] with the set-time given
/// instead of read from the clock, so a row can place the cut's set-time on a
/// chosen side of a planned SIGTERM whatever the host's scheduling. The body is
/// `move_earlier`'s, with `set_at` in place of `Instant::now()`. Unix only, as
/// its callers are (the child-tree rows).
#[cfg(unix)]
impl super::StopDeadline {
    /// Test-only: start the clock set-times are stored against, so an instant
    /// read after this call encodes exactly (an earlier one saturates).
    pub(crate) fn start_epoch() {
        std::sync::LazyLock::force(&super::STOP_EPOCH);
    }

    pub(crate) fn move_earlier_at(&self, deadline: std::time::Instant, set_at: std::time::Instant) {
        let nanos = deadline
            .saturating_duration_since(*super::STOP_EPOCH)
            .as_nanos();
        let nanos = u64::try_from(nanos).unwrap_or(u64::MAX - 1);
        let mut cut = self.cut.lock();
        if nanos < cut.0 {
            let set = set_at
                .saturating_duration_since(*super::STOP_EPOCH)
                .as_nanos();
            *cut = (nanos, u64::try_from(set).unwrap_or(u64::MAX - 1));
        }
    }
}

/// A handover's budget is fixed before its stop snapshot runs (a cut snapshot
/// may read for up to 20 ms), so the snapshot's time comes off before the
/// plan: 3 s past the kill reserve with a 1 s snapshot leaves waits of 2 s,
/// and with no snapshot time the waits stay 3 s. Red if the snapshot's time
/// is not subtracted (waits of 3 s both times).
#[test]
fn a_handover_plans_only_what_its_snapshot_left() {
    let budget = KILL_RESERVE + Duration::from_secs(3);
    let after = super::plan::ending_after_snapshot(budget, Duration::from_secs(1), true, None);
    assert_eq!(
        after.waits(),
        Duration::from_secs(2),
        "the snapshot's second was planned"
    );
    let untouched = super::plan::ending_after_snapshot(budget, Duration::ZERO, true, None);
    assert_eq!(untouched.waits(), Duration::from_secs(3));
}

/// Code review r3 (T2): a stop fixes its budget once, gives the snapshot that
/// budget as its limit, and plans only what the timed snapshot left. A clock
/// that reads 30 ms later after the snapshot, under 3 s past the kill
/// reserve, leaves waits of exactly 2.97 s. Red if the snapshot's time is not
/// taken off (3 s).
#[test]
fn a_stop_plans_its_budget_less_its_timed_snapshot() {
    let budget = KILL_RESERVE + Duration::from_secs(3);
    let t0 = std::time::Instant::now();
    // limit-under-test (injected-clock): the row supplies both clock readings.
    let mut readings = [t0, t0 + Duration::from_millis(30)].into_iter();
    let clock = || readings.next().expect("two clock readings");
    let mut given = None;
    let snapshot = |limit: Duration| given = Some(limit);
    let ending = super::plan::ending_around_snapshot_by(clock, budget, snapshot, || true, None);
    assert_eq!(given, Some(budget), "the snapshot's limit");
    assert_eq!(ending.waits(), Duration::from_millis(2970), "the plan");
}
