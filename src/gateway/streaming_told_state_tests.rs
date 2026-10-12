// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit rows on the told record's pure rules (MIK-8350).

use super::*;

fn digest(served: &str, shown: &str) -> ViewDigest {
    ViewDigest {
        served: served.to_owned(),
        shown: shown.to_owned(),
    }
}

fn baselined(views: &[(&str, ViewDigest)]) -> ToldState {
    let mut told = ToldState::default();
    let view = views
        .iter()
        .map(|(backend, view)| ((*backend).to_owned(), view.clone()))
        .collect();
    assert!(told.baseline(1, view));
    told
}

#[test]
fn a_state_with_no_baseline_records_the_first_view_and_is_owed_nothing() {
    let mut told = ToldState::default();
    assert_eq!(told.peek(1, "a", &digest("s0", "x")), Peek::Quiet);
    assert_eq!(told.peek(2, "a", &digest("s0", "x")), Peek::Quiet);
    assert_eq!(told.peek(3, "a", &digest("s0", "y")), Peek::Owed);
}

#[test]
fn a_backend_added_after_the_baseline_is_owed_when_it_shows_anything() {
    let mut told = baselined(&[("a", digest("s0", "x"))]);
    assert_eq!(told.peek(2, "new", &digest("s0", "t")), Peek::Owed);
    assert_eq!(told.peek(2, "hidden", &digest("s0", "")), Peek::Quiet);
}

#[test]
fn one_served_digest_serves_every_backend() {
    let mut told = baselined(&[("a", digest("s0", "x")), ("b", digest("s0", "y"))]);
    let moved = digest("s1", "x2");
    assert_eq!(told.peek(2, "a", &moved), Peek::Owed);
    assert!(told.commit(2, "a", &moved));
    // b's own listing did not move, and the served list is now told.
    assert_eq!(told.peek(3, "b", &digest("s1", "y")), Peek::Quiet);
}

#[test]
fn a_write_older_than_the_record_is_refused_whatever_its_kind() {
    let view = digest("s1", "x2");
    let mut told = baselined(&[("a", digest("s0", "x"))]);
    assert!(told.commit(5, "a", &view));
    assert!(!told.commit(3, "a", &digest("s2", "x3")), "older commit");
    assert!(!told.refresh(4, HashMap::from([("a".to_owned(), digest("s0", "x"))])));
    assert!(!told.baseline(2, HashMap::from([("z".to_owned(), digest("s0", "z"))])));
    // The refused writes left the record where the newest one put it.
    assert_eq!(told.peek(6, "a", &view), Peek::Quiet);
}

#[test]
fn a_repeat_of_a_told_digest_is_refused() {
    let view = digest("s1", "x2");
    let mut told = baselined(&[("a", digest("s0", "x"))]);
    assert!(told.commit(2, "a", &view));
    assert!(!told.commit(3, "a", &view), "already told");
}

#[test]
fn a_clear_raises_the_floor_for_every_earlier_read() {
    let mut told = baselined(&[("a", digest("s0", "x"))]);
    told.clear(10);
    assert!(
        !told.commit(9, "a", &digest("s1", "x2")),
        "read for the old caller"
    );
    assert!(
        !told.baseline(9, HashMap::new()),
        "baseline read for the old caller"
    );
    assert!(told.baseline(11, HashMap::from([("a".to_owned(), digest("s5", "n"))])));
    assert_eq!(told.peek(12, "a", &digest("s5", "n")), Peek::Quiet);
}

#[test]
fn a_refresh_holds_the_view() {
    let mut told = baselined(&[("a", digest("s0", "x"))]);
    assert!(told.refresh(2, HashMap::from([("a".to_owned(), digest("s1", "x2"))])));
    assert_eq!(told.peek(3, "a", &digest("s1", "x2")), Peek::Quiet);
    assert_eq!(told.peek(3, "a", &digest("s1", "x3")), Peek::Owed);
}

#[tokio::test]
async fn a_plain_bearer_subject_is_live_with_an_empty_context() {
    let ctx = LiveCtx {
        agent: None,
        caller_identity: &crate::security::caller_identity::CallerIdentityConfig::default(),
        cf_verifier: None,
    };
    assert_eq!(ViewSubject::default().live(&ctx), Ok(()));
}

#[tokio::test]
async fn a_held_assertion_with_no_verifier_is_refused_and_none_held_is_not() {
    let ctx = LiveCtx {
        agent: None,
        caller_identity: &crate::security::caller_identity::CallerIdentityConfig::default(),
        cf_verifier: None,
    };
    assert_eq!(ViewSubject::default().verify_held_cf(&ctx).await, Ok(()));
    let held = ViewSubject {
        cf_assertion: Some(Redacted::new("a.b.c")),
        ..ViewSubject::default()
    };
    assert_eq!(held.verify_held_cf(&ctx).await, Err(DeadReason::Adapter));
}
