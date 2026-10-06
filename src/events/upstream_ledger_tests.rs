// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Transition rows of the D5 ledger (B06 PR-2, option B).

use super::*;

/// Past every retry wait.
fn later() -> Instant {
    Instant::now() + Duration::from_secs(3600)
}

fn subscribed(l: &mut Ledger, uri: &str) {
    l.want(uri).expect("room");
    let call = l.sent(uri, true).expect("key");
    l.answered(&call, Outcome::Done, Instant::now());
}

#[test]
fn a_confirmed_subscribe_then_unsubscribe_frees_the_key() {
    let mut l = Ledger::default();
    subscribed(&mut l, "a");
    assert!(l.due(later()).is_empty(), "held Yes needs nothing");
    l.unwant("a");
    assert_eq!(l.due(later()), vec![("a".to_owned(), false)]);
    let call = l.sent("a", false).expect("key");
    l.answered(&call, Outcome::Done, Instant::now());
    assert_eq!(l.size().0, 0);
}

#[test]
fn an_uncertain_call_strands_the_key_across_later_answers() {
    let mut l = Ledger::default();
    l.want("a").expect("room");
    let first = l.sent("a", true).expect("key");
    l.answered(&first, Outcome::Uncertain, Instant::now());
    // A retry succeeds, but the first call may still run: never Yes.
    let retry = l.sent("a", true).expect("key");
    l.answered(&retry, Outcome::Done, Instant::now());
    assert_eq!(
        l.due(later()),
        vec![("a".to_owned(), true)],
        "re-sent each pass"
    );
    l.unwant("a");
    assert!(
        l.due(later()).is_empty(),
        "a stranded key is not unsubscribed"
    );
    assert_eq!(l.size(), (1, encoded("a"), 1), "still charged");
}

#[test]
fn a_stranded_key_counts_against_the_cap() {
    let mut l = Ledger::default();
    l.want("a").expect("room");
    let call = l.sent("a", true).expect("key");
    l.answered(&call, Outcome::Uncertain, Instant::now());
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
    l.answered(&call, Outcome::Refused, Instant::now());
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
    l.answered(&unsub, Outcome::Done, Instant::now());
    assert!(
        l.due(later()).is_empty(),
        "the subscribe is still in flight"
    );
    l.answered(&resub, Outcome::Done, Instant::now());
    assert!(l.due(later()).is_empty(), "idle at the answer: Yes");
}

#[test]
fn a_third_unsubscribe_error_warns_once_and_keeps_retrying() {
    let mut l = Ledger::default();
    subscribed(&mut l, "a");
    l.unwant("a");
    let warns: Vec<bool> = (0..4)
        .map(|_| {
            let call = l.sent("a", false).expect("key");
            l.answered(&call, Outcome::Refused, Instant::now())
        })
        .collect();
    assert_eq!(warns, vec![false, false, true, false]);
    assert_eq!(l.due(later()), vec![("a".to_owned(), false)]);
}

#[test]
fn a_holder_change_strands_what_the_old_holder_may_keep_and_resubscribes() {
    let mut l = Ledger::default();
    l.observe(1);
    subscribed(&mut l, "a");
    l.want("idle").expect("room");
    l.observe(1);
    assert_eq!(l.size().2, 0, "the same holder again changes nothing");
    l.observe(2);
    assert_eq!(l.size(), (3, encoded("a") * 2 + encoded("idle"), 1));
    let mut due = l.due(later());
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
    l.observe(1);
    l.want("a").expect("room");
    let call = l.sent("a", true).expect("key");
    l.observe(2);
    l.answered(&call, Outcome::Done, Instant::now());
    assert_eq!(l.size().2, 1, "the old key stays stranded");
    assert_eq!(l.due(later()), vec![("a".to_owned(), true)]);
}

#[test]
fn repeated_holder_changes_never_exceed_the_cap() {
    let mut l = Ledger::default();
    l.observe(0);
    for i in 0..MAX_URIS {
        subscribed(&mut l, &format!("u{i}"));
    }
    for holder in 1..4 {
        l.observe(holder);
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
    l.answered(&call, Outcome::Uncertain, Instant::now());
    assert_eq!(l.releasable(), vec!["a".to_owned()]);
    assert!(l.needs_cleanup());
}

#[test]
fn a_repeated_call_on_one_key_backs_off_and_doubles() {
    let mut l = Ledger::default();
    let t0 = Instant::now();
    l.want("a").expect("room");
    let call = l.sent("a", true).expect("key");
    l.answered(&call, Outcome::Uncertain, t0);
    assert!(l.due(t0).is_empty(), "not again at once");
    assert_eq!(l.due(t0 + RETRY_FIRST).len(), 1);
    let call = l.sent("a", true).expect("key");
    l.answered(&call, Outcome::Done, t0);
    assert!(l.due(t0 + RETRY_FIRST).is_empty(), "the wait doubled");
    assert_eq!(l.due(t0 + RETRY_FIRST * 2).len(), 1);
}

#[test]
fn a_call_that_never_left_changes_nothing() {
    let mut l = Ledger::default();
    l.want("a").expect("room");
    let call = l.sent("a", true).expect("key");
    l.answered(&call, Outcome::NotSent, Instant::now());
    l.unwant("a");
    assert_eq!(l.size().0, 0, "not stranded, not held");
    subscribed(&mut l, "b");
    l.unwant("b");
    let call = l.sent("b", false).expect("key");
    l.answered(&call, Outcome::NotSent, Instant::now());
    assert_eq!(l.releasable(), vec!["b".to_owned()], "still held Yes");
}

/// D5 (r1 CRITICAL): the holder changed while a call was out, so its answer
/// may be another holder's. Whatever came back, the key strands.
#[tokio::test]
async fn a_holder_change_across_a_call_strands_its_key() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let backend = Backend::new(
        "b",
        crate::config::BackendConfig::default(),
        &crate::config::FailsafeConfig::default(),
        Duration::from_secs(1),
    );
    let ledger = Mutex::new(Ledger::default());
    ledger.lock().want("a").expect("room");
    let reads = AtomicU64::new(0);
    let holder = || reads.fetch_add(1, Ordering::SeqCst);
    drive(
        &ledger,
        &backend,
        "a",
        true,
        Duration::from_secs(1),
        &holder,
    )
    .await;
    let l = ledger.lock();
    assert_eq!(l.size().2, 1, "the first holder's key is stranded");
    assert_eq!(l.unplaced(), 0, "the URI has a key on the new holder");
}
