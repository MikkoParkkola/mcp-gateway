// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Transition rows of the D5 ledger (B06 PR-2, option B).

use super::*;

fn subscribed(l: &mut Ledger, uri: &str) {
    l.want(uri).expect("room");
    let call = l.sent(uri, true).expect("key");
    l.answered(&call, Outcome::Done);
}

#[test]
fn a_confirmed_subscribe_then_unsubscribe_frees_the_key() {
    let mut l = Ledger::default();
    subscribed(&mut l, "a");
    assert!(l.due().is_empty(), "held Yes needs nothing");
    l.unwant("a");
    assert_eq!(l.due(), vec![("a".to_owned(), false)]);
    let call = l.sent("a", false).expect("key");
    l.answered(&call, Outcome::Done);
    assert_eq!(l.size().0, 0);
}

#[test]
fn an_uncertain_call_strands_the_key_across_later_answers() {
    let mut l = Ledger::default();
    l.want("a").expect("room");
    let first = l.sent("a", true).expect("key");
    l.answered(&first, Outcome::Uncertain);
    // A retry succeeds, but the first call may still run: never Yes.
    let retry = l.sent("a", true).expect("key");
    l.answered(&retry, Outcome::Done);
    assert_eq!(l.due(), vec![("a".to_owned(), true)], "re-sent each pass");
    l.unwant("a");
    assert!(l.due().is_empty(), "a stranded key is not unsubscribed");
    assert_eq!(l.size(), (1, encoded("a"), 1), "still charged");
}

#[test]
fn a_stranded_key_counts_against_the_cap() {
    let mut l = Ledger::default();
    l.want("a").expect("room");
    let call = l.sent("a", true).expect("key");
    l.answered(&call, Outcome::Uncertain);
    l.unwant("a");
    for i in 1..MAX_URIS {
        l.want(&format!("u{i}")).expect("room below the cap");
    }
    assert_eq!(l.want("one-more"), Err(Full));
}

#[test]
fn the_byte_budget_refuses_while_the_key_count_is_low() {
    let mut l = Ledger::default();
    let long = "x".repeat(MAX_URI_BUDGET_BYTES / 2);
    l.want(&format!("1{long}")).expect("room");
    assert_eq!(l.want(&format!("2{long}")), Err(Full));
    assert_eq!(l.size().0, 1);
}

#[test]
fn a_rejected_first_subscribe_consumes_nothing_after_unwatch() {
    let mut l = Ledger::default();
    l.want("a").expect("room");
    let call = l.sent("a", true).expect("key");
    l.answered(&call, Outcome::Refused);
    l.unwant("a");
    assert_eq!(l.size().0, 0);
}

#[test]
fn an_answer_while_another_call_is_in_flight_stays_maybe() {
    let mut l = Ledger::default();
    subscribed(&mut l, "a");
    l.unwant("a");
    let unsub = l.sent("a", false).expect("key");
    l.want("a").expect("room");
    let resub = l.sent("a", true).expect("key");
    l.answered(&unsub, Outcome::Done);
    assert!(l.due().is_empty(), "the subscribe is still in flight");
    l.answered(&resub, Outcome::Done);
    assert!(l.due().is_empty(), "idle at the answer: Yes");
}

#[test]
fn a_third_unsubscribe_error_warns_once_and_keeps_retrying() {
    let mut l = Ledger::default();
    subscribed(&mut l, "a");
    l.unwant("a");
    let warns: Vec<bool> = (0..4)
        .map(|_| {
            let call = l.sent("a", false).expect("key");
            l.answered(&call, Outcome::Refused)
        })
        .collect();
    assert_eq!(warns, vec![false, false, true, false]);
    assert_eq!(l.due(), vec![("a".to_owned(), false)]);
}

#[test]
fn a_holder_change_strands_what_the_old_holder_may_keep_and_resubscribes() {
    let mut l = Ledger::default();
    subscribed(&mut l, "a");
    l.want("idle").expect("room");
    l.holder_changed();
    assert_eq!(l.size(), (3, encoded("a") * 2 + encoded("idle"), 1));
    let mut due = l.due();
    due.sort();
    assert_eq!(
        due,
        vec![("a".to_owned(), true), ("idle".to_owned(), true)],
        "both wanted URIs are subscribed on the new holder"
    );
}

#[test]
fn an_answer_from_the_old_holder_is_ignored() {
    let mut l = Ledger::default();
    l.want("a").expect("room");
    let call = l.sent("a", true).expect("key");
    l.holder_changed();
    l.answered(&call, Outcome::Done);
    assert_eq!(l.size().2, 1, "the old key stays stranded");
    assert_eq!(l.due(), vec![("a".to_owned(), true)]);
}

#[test]
fn repeated_holder_changes_never_exceed_the_cap() {
    let mut l = Ledger::default();
    for i in 0..MAX_URIS {
        subscribed(&mut l, &format!("u{i}"));
    }
    for _ in 0..3 {
        l.holder_changed();
        assert!(l.size().0 <= MAX_URIS);
    }
    assert_eq!(l.unplaced(), MAX_URIS, "no room for any new-holder key");
}

#[test]
fn a_stop_releases_only_keys_an_answer_can_release() {
    let mut l = Ledger::default();
    subscribed(&mut l, "a");
    l.want("b").expect("room");
    let call = l.sent("b", true).expect("key");
    l.answered(&call, Outcome::Uncertain);
    assert_eq!(l.releasable(), vec!["a".to_owned()]);
    assert!(l.needs_cleanup());
}
