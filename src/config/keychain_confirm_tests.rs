// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A delete is reported done only once the entry is seen gone. Credential
//! Manager can briefly keep answering for an entry whose delete succeeded; the
//! confirmation loop is platform-neutral so these rows run everywhere.

use std::cell::Cell;
use std::time::{Duration, Instant};

use super::keychain::{CONFIRM_ATTEMPTS, KeychainError, confirm_absent};

/// Runs the confirmation with a question that answers "still there" until its
/// `gone_on`-th ask. Returns the outcome and how many times it was asked.
fn asked(attempts: u32, gap: Duration, gone_on: u32) -> (Result<(), KeychainError>, u32) {
    let asks = Cell::new(0);
    let outcome = confirm_absent(attempts, gap, || {
        asks.set(asks.get() + 1);
        Ok(asks.get() < gone_on)
    });
    (outcome, asks.get())
}

#[test]
fn an_entry_gone_at_once_is_confirmed_with_one_ask() {
    let (outcome, asks) = asked(CONFIRM_ATTEMPTS, Duration::ZERO, 1);
    assert_eq!(outcome, Ok(()));
    assert_eq!(asks, 1);
}

#[test]
fn a_stale_answer_is_waited_out_up_to_the_last_ask() {
    let (outcome, asks) = asked(CONFIRM_ATTEMPTS, Duration::ZERO, CONFIRM_ATTEMPTS);
    assert_eq!(outcome, Ok(()), "the last allowed ask saw it gone");
    assert_eq!(asks, CONFIRM_ATTEMPTS);
}

#[test]
fn an_entry_that_never_goes_is_not_a_removal() {
    let (outcome, asks) = asked(CONFIRM_ATTEMPTS, Duration::ZERO, CONFIRM_ATTEMPTS + 1);
    match outcome {
        Err(KeychainError::Unavailable(why)) => {
            assert!(why.contains("could not confirm removal"), "{why}");
        }
        other => panic!("a still-readable entry must fail the delete, got {other:?}"),
    }
    assert_eq!(asks, CONFIRM_ATTEMPTS, "it asks the whole budget, no more");
}

#[test]
fn a_question_that_fails_is_not_a_removal() {
    let asks = Cell::new(0);
    let outcome = confirm_absent(CONFIRM_ATTEMPTS, Duration::ZERO, || {
        asks.set(asks.get() + 1);
        Err(KeychainError::Locked)
    });
    assert_eq!(outcome, Err(KeychainError::Locked));
    assert_eq!(asks.get(), 1, "an unknown answer ends the wait");
}

#[test]
fn no_asks_allowed_is_no_removal() {
    let (outcome, asks) = asked(0, Duration::ZERO, 1);
    assert!(outcome.is_err(), "a budget of none cannot confirm anything");
    assert_eq!(asks, 0);
}

#[test]
fn the_wait_between_asks_is_taken() {
    let started = Instant::now();
    let (outcome, asks) = asked(CONFIRM_ATTEMPTS, Duration::from_millis(40), 3);
    assert_eq!(outcome, Ok(()));
    assert_eq!(asks, 3);
    assert!(
        started.elapsed() >= Duration::from_millis(80),
        "two waits of 40 ms sit between three asks"
    );
}
