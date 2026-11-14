// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A delete is reported done only once the entry is seen gone. Credential
//! Manager can briefly keep answering for an entry whose delete succeeded; the
//! confirmation loop and the whole delete sequence are platform-neutral, with
//! the OS delete, the existence ask and the sleep injected, so these rows run
//! everywhere and wait for nothing.

use std::cell::{Cell, RefCell};
use std::time::Duration;

use super::keychain::{
    CONFIRM_ATTEMPTS, CONFIRM_GAP, KeychainError, confirm_absent, delete_confirmed,
};

/// What one confirmation run did: its outcome, the asks it made, and every
/// wait it asked for.
struct Run {
    outcome: Result<(), KeychainError>,
    asks: u32,
    sleeps: Vec<Duration>,
}

/// Runs the confirmation with a question that answers "still there" until its
/// `gone_on`-th ask, and a sleeper that only records.
fn asked(attempts: u32, gone_on: u32) -> Run {
    let asks = Cell::new(0);
    let sleeps = RefCell::new(Vec::new());
    let outcome = confirm_absent(
        attempts,
        CONFIRM_GAP,
        |gap| sleeps.borrow_mut().push(gap),
        || {
            asks.set(asks.get() + 1);
            Ok(asks.get() < gone_on)
        },
    );
    Run {
        outcome,
        asks: asks.get(),
        sleeps: sleeps.into_inner(),
    }
}

#[test]
fn an_entry_gone_at_once_is_confirmed_with_one_ask_and_no_wait() {
    let run = asked(CONFIRM_ATTEMPTS, 1);
    assert_eq!(run.outcome, Ok(()));
    assert_eq!(run.asks, 1);
    assert!(run.sleeps.is_empty(), "no wait before the first ask");
}

#[test]
fn a_stale_answer_is_waited_out_up_to_the_last_ask() {
    let run = asked(CONFIRM_ATTEMPTS, CONFIRM_ATTEMPTS);
    assert_eq!(run.outcome, Ok(()), "the last allowed ask saw it gone");
    assert_eq!(run.asks, CONFIRM_ATTEMPTS);
}

#[test]
fn an_entry_that_never_goes_is_not_a_removal() {
    let run = asked(CONFIRM_ATTEMPTS, CONFIRM_ATTEMPTS + 1);
    match run.outcome {
        Err(KeychainError::Unavailable(why)) => {
            assert!(why.contains("could not confirm removal"), "{why}");
        }
        other => panic!("a still-readable entry must fail the delete, got {other:?}"),
    }
    assert_eq!(
        run.asks, CONFIRM_ATTEMPTS,
        "it asks the whole budget, no more"
    );
}

#[test]
fn a_question_that_fails_on_the_first_ask_is_not_a_removal() {
    let asks = Cell::new(0);
    let outcome = confirm_absent(
        CONFIRM_ATTEMPTS,
        CONFIRM_GAP,
        |_| {},
        || {
            asks.set(asks.get() + 1);
            Err(KeychainError::Locked)
        },
    );
    assert_eq!(outcome, Err(KeychainError::Locked));
    assert_eq!(asks.get(), 1, "a failed ask ends the wait");
}

#[test]
fn a_question_that_fails_after_a_stale_answer_is_not_a_removal() {
    let asks = Cell::new(0);
    let outcome = confirm_absent(
        CONFIRM_ATTEMPTS,
        CONFIRM_GAP,
        |_| {},
        || {
            asks.set(asks.get() + 1);
            if asks.get() == 1 {
                Ok(true)
            } else {
                Err(KeychainError::Locked)
            }
        },
    );
    assert_eq!(outcome, Err(KeychainError::Locked));
    assert_eq!(asks.get(), 2, "the failed second ask ends the wait");
}

#[test]
fn no_asks_allowed_is_no_removal_and_says_nothing_was_checked() {
    let run = asked(0, 1);
    assert_eq!(run.asks, 0);
    match run.outcome {
        Err(KeychainError::Unavailable(why)) => {
            assert!(why.contains("could not confirm removal"), "{why}");
            assert!(why.contains("no check"), "{why}");
            assert!(!why.contains("still readable"), "{why}");
        }
        other => panic!("a budget of none cannot confirm anything, got {other:?}"),
    }
}

#[test]
fn there_is_one_wait_between_asks_and_none_before_the_first_or_after_the_last() {
    let run = asked(CONFIRM_ATTEMPTS, 3);
    assert_eq!(run.outcome, Ok(()));
    assert_eq!(run.sleeps, vec![CONFIRM_GAP, CONFIRM_GAP]);

    let run = asked(CONFIRM_ATTEMPTS, CONFIRM_ATTEMPTS + 1);
    assert!(run.outcome.is_err());
    assert_eq!(
        run.sleeps.len(),
        usize::try_from(CONFIRM_ATTEMPTS - 1).expect("a small count"),
        "waits sit between asks only, so the last ask is not followed by one"
    );
}

#[test]
fn the_production_wait_fits_inside_the_two_second_call_bound() {
    assert_eq!(CONFIRM_GAP, Duration::from_millis(100));
    // The delete runs inside one native call bound of 2 s (ADR-028 rule 7).
    let worst_wait = CONFIRM_GAP * (CONFIRM_ATTEMPTS - 1);
    assert_eq!(worst_wait, Duration::from_millis(700));
    assert!(worst_wait < Duration::from_secs(2));
}

/// Runs the whole delete with the given OS delete and ask, returning the
/// outcome and the asks made.
fn deleted(
    remove: Result<(), KeychainError>,
    mut answers: Vec<Result<bool, KeychainError>>,
) -> (Result<(), KeychainError>, usize) {
    answers.reverse();
    let asks = Cell::new(0);
    let outcome = delete_confirmed(
        CONFIRM_ATTEMPTS,
        CONFIRM_GAP,
        |_| {},
        || remove,
        || {
            asks.set(asks.get() + 1);
            answers.pop().unwrap_or(Ok(true))
        },
    );
    (outcome, asks.get())
}

#[test]
fn a_delete_whose_entry_stays_readable_fails() {
    // Every ask finds the entry (the default answer once the list runs out).
    let (outcome, asks) = deleted(Ok(()), Vec::new());
    match outcome {
        Err(KeychainError::Unavailable(why)) => {
            assert!(why.contains("could not confirm removal"), "{why}");
        }
        other => panic!("a delete that leaves the entry readable must fail, got {other:?}"),
    }
    assert_eq!(
        asks,
        usize::try_from(CONFIRM_ATTEMPTS).expect("a small count")
    );
}

#[test]
fn a_delete_whose_ask_errors_fails() {
    let (outcome, asks) = deleted(Ok(()), vec![Ok(true), Err(KeychainError::Locked)]);
    assert_eq!(outcome, Err(KeychainError::Locked));
    assert_eq!(asks, 2);
}

#[test]
fn a_failed_os_delete_asks_nothing() {
    let failure = KeychainError::Unavailable("Credential Manager: Denied".into());
    let (outcome, asks) = deleted(Err(failure.clone()), vec![Ok(false)]);
    assert_eq!(outcome, Err(failure));
    assert_eq!(asks, 0, "a delete that did not run is not confirmed");
}

#[test]
fn a_delete_whose_entry_goes_away_succeeds_after_a_stale_answer() {
    let (outcome, asks) = deleted(Ok(()), vec![Ok(true), Ok(true), Ok(false)]);
    assert_eq!(outcome, Ok(()));
    assert_eq!(asks, 3);
}
