// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Parked questions: one-shot, identity-bound, expiring, bounded.

use std::time::{Duration, Instant};

use super::*;

fn parked() -> Parked {
    Parked::new(Duration::from_secs(60))
}

fn park(parked: &Parked, identity: Option<&str>, now: Instant) -> String {
    parked
        .park(
            "task-1".into(),
            Some("ctx-1".into()),
            identity,
            Vec::new(),
            now,
        )
        .unwrap_or_else(|refused| panic!("room to park: {refused:?}"))
}

#[test]
fn a_token_is_redeemed_once_by_its_identity() {
    let (parked, now) = (parked(), Instant::now());
    let token = park(&parked, Some("u1"), now);
    assert!(
        !token.contains("task-1"),
        "the token says nothing about the task"
    );

    let Ok(taken) = parked.take(&token, Some("u1"), now) else {
        panic!("the owner redeems");
    };
    assert_eq!(taken.task_id, "task-1");
    assert_eq!(taken.context_id.as_deref(), Some("ctx-1"));
    assert!(parked.take(&token, Some("u1"), now).is_err(), "one-shot");
}

#[test]
fn another_identity_is_refused_and_does_not_burn_the_token() {
    let (parked, now) = (parked(), Instant::now());
    let token = park(&parked, Some("u1"), now);
    for other in [Some("u2"), None] {
        let Err((refused, expired)) = parked.take(&token, other, now) else {
            panic!("another identity is refused");
        };
        assert_eq!(refused, Refused::NotYours);
        assert!(expired.is_none());
    }
    assert!(
        parked.take(&token, Some("u1"), now).is_ok(),
        "still the owner's"
    );

    let anonymous = park(&parked, None, now);
    assert!(
        parked.take(&anonymous, Some("u1"), now).is_err(),
        "None matches only None"
    );
    assert!(parked.take(&anonymous, None, now).is_ok());
}

#[test]
fn an_expired_token_is_refused_and_handed_back_for_cancel() {
    let (parked, now) = (parked(), Instant::now());
    let token = park(&parked, Some("u1"), now);
    let later = now + Duration::from_secs(61);
    let Err((_, expired)) = parked.take(&token, Some("u1"), later) else {
        panic!("an expired token is refused");
    };
    assert_eq!(expired.expect("handed back").task_id, "task-1");
    assert!(parked.drain_expired(later).is_empty(), "already removed");
}

#[test]
fn the_sweep_takes_only_expired_entries() {
    let (parked, now) = (parked(), Instant::now());
    park(&parked, None, now);
    let fresh = park(&parked, None, now + Duration::from_secs(30));
    let swept = parked.drain_expired(now + Duration::from_secs(61));
    assert_eq!(swept.len(), 1);
    assert!(
        parked
            .take(&fresh, None, now + Duration::from_secs(61))
            .is_ok()
    );
    assert!(parked.close().is_empty());
}

#[test]
fn parking_stops_at_the_cap() {
    let (parked, now) = (parked(), Instant::now());
    for _ in 0..PARKED_CAP {
        park(&parked, None, now);
    }
    assert_eq!(
        parked.park("one-more".into(), None, None, Vec::new(), now),
        Err(ParkRefused::Full)
    );
    assert_eq!(parked.close().len(), PARKED_CAP);
}

#[test]
fn nothing_parks_after_close() {
    let (parked, now) = (parked(), Instant::now());
    park(&parked, None, now);
    assert_eq!(parked.close().len(), 1, "close hands back what was waiting");
    assert_eq!(
        parked.park("late".into(), None, None, Vec::new(), now),
        Err(ParkRefused::Closed),
        "a park racing close is refused, so its caller cancels the task"
    );
}
