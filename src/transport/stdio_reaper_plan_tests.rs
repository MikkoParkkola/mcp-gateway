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
