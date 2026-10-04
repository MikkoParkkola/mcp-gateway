// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7913: how a crash spends the delivery attempt budget. An attempt is
//! counted when it is claimed, before its POST (`OutboxRecord::attempt`,
//! "attempts started so far"), and a restart does not refund it: load returns
//! an in-flight record to pending with its id and bytes unchanged (design F1,
//! docs/design/2026-10-01-mik-7630-mcp-events.md:787) under a budget of "at
//! most 5 attempts" (same document, :658). A crash after a claim therefore
//! spends that attempt whether or not its POST went out. The clock here is
//! the `now` each call is given, never the wall clock.

use chrono::{DateTime, Utc};

use super::super::super::Store;
use super::super::{Claim, Settle};
use super::{TAIL, open_with, record};
use crate::events::outbox::{OutboxCaps, OutboxRecord};

const CAPS: OutboxCaps = OutboxCaps {
    global: 10,
    per_subscription: 10,
};

/// Claim `a` and return the record the claim made (the one a POST would send).
fn claim(store: &Store, now: DateTime<Utc>) -> OutboxRecord {
    match store.claim("a", now).expect("io") {
        Claim::Ready(claimed) => claimed.record,
        Claim::Skip => panic!("record a is not claimable"),
    }
}

/// The receiver answered 503: back to pending, due at `now`.
fn retried(store: &Store, created: DateTime<Utc>, now: DateTime<Utc>) {
    let retry = Settle::Retry {
        next: now,
        status: "http_5xx",
    };
    store
        .settle("a", created, retry, now, super::ROOMY)
        .expect("io");
}

/// A crash: the store is dropped without settling and opened again.
fn restarted(store: Store, dir: &std::path::Path, now: DateTime<Utc>) -> Store {
    drop(store);
    Store::open(dir, now, TAIL).expect("reopen")
}

/// T32 as its design row places it: a crash between attempts 2 and 3 loses
/// nothing, and the next claim is attempt 3.
#[test]
fn a_crash_between_attempts_resumes_at_the_next_attempt() {
    let dir = tempfile::tempdir().expect("dir");
    let t0 = Utc::now();
    let store = open_with(dir.path(), t0, &["s1"]);
    store.enqueue(record("a", "s1", t0), CAPS).expect("io");
    for n in 1..=2 {
        assert_eq!(claim(&store, t0).attempt, n);
        retried(&store, t0, t0);
    }
    let store = restarted(store, dir.path(), t0);
    assert_eq!(claim(&store, t0).attempt, 3, "the restart lost an attempt");
}

/// A crash after a claim, whether before its POST or while it was on the
/// wire, spends that attempt: the next claim is the one after it, with the
/// same id and bytes, so a resent POST is a duplicate the receiver dedupes.
#[test]
fn a_crash_after_a_claim_spends_that_attempt() {
    let dir = tempfile::tempdir().expect("dir");
    let t0 = Utc::now();
    let store = open_with(dir.path(), t0, &["s1"]);
    store.enqueue(record("a", "s1", t0), CAPS).expect("io");
    for _ in 1..=2 {
        claim(&store, t0);
        retried(&store, t0, t0);
    }
    let third = claim(&store, t0);
    assert_eq!(third.attempt, 3);
    let store = restarted(store, dir.path(), t0);
    let fourth = claim(&store, t0);
    assert_eq!(fourth.attempt, 4, "the claimed attempt was refunded");
    assert_eq!(
        (&fourth.event_id, &fourth.body_b64),
        (&third.event_id, &third.body_b64),
        "the resumed attempt is the same occurrence and bytes"
    );
}
