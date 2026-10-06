// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Replay placement and a re-admitted event id (MIK-7820, MIK-7829).

use super::super::Revived;
use super::*;

const OUTBOX: OutboxCaps = OutboxCaps {
    global: 10,
    per_subscription: 10,
};

/// A refresh of `s1`, which reactivates a suspended row, as a resubscribe does.
fn refresh(store: &Store, now: DateTime<Utc>) {
    store
        .admit(
            sub("s1", now),
            true,
            CAPS,
            chrono::Duration::zero(),
            now,
            TAIL,
        )
        .expect("io")
        .expect("refreshed");
}

/// MIK-7820.FIX.1: the replay carries its dead letter's fan-out stamp, so a
/// crash between placing it and unlinking the dead letter reloads as "not
/// replayed": the outbox copy goes, the dead letter stays.
#[test]
fn a_revived_record_keeps_its_dead_letters_stamp() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    store
        .dead_letter(record("e1", "s1", now), DeadReason::Gone, now, ROOMY)
        .expect("io");
    let saved = store.dead_letter_by_id("e1").expect("dead letter");
    let replay = OutboxRecord {
        created_at: now + chrono::Duration::seconds(5),
        ..record("e1", "s1", now)
    };
    assert_eq!(
        store.revive("e1", now, replay, OUTBOX, || now).expect("io"),
        Revived::Written
    );
    let due = store.due(now, &HashSet::new()).expect("io");
    assert_eq!(due.ready.len(), 1);
    assert_eq!(
        due.ready[0].created_at, now,
        "the replay keeps the occurrence's fan-out stamp"
    );
    // A crash after the replay was placed and before its dead letter left.
    crate::events::records::write_record(&dir.path().join("dead"), "e1.json", &saved)
        .expect("restore the dead letter");
    drop(store);
    let reopened = Store::open(dir.path(), now, TAIL).expect("reopen");
    assert!(
        reopened
            .due(now, &HashSet::new())
            .expect("io")
            .ready
            .is_empty(),
        "recovery drops a replay whose dead letter still stands"
    );
    assert_eq!(
        reopened.dead_summaries().len(),
        1,
        "and keeps the dead letter, to be replayed again"
    );
}

/// MIK-7820.FIX.2: a suspended subscription takes no replay. Its pending
/// records are dropped, not buried, if it expires unrefreshed, so the
/// dead letter must stay.
#[test]
fn a_replay_into_a_suspended_subscription_is_refused() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    store
        .dead_letter(record("e1", "s1", now), DeadReason::Exhausted, now, ROOMY)
        .expect("io");
    store.suspend("s1").expect("io");
    let outcome = store
        .revive("e1", now, record("e1", "s1", now), OUTBOX, || now)
        .expect("io");
    assert_eq!(
        outcome,
        Revived::Suspended,
        "a suspended subscription takes no replay"
    );
    assert_eq!(store.dead_summaries().len(), 1, "the dead letter stays");
    // A refresh reactivates the row: nothing was parked behind it.
    refresh(&store, now);
    assert!(
        store
            .due(now, &HashSet::new())
            .expect("io")
            .ready
            .is_empty(),
        "no replay waits in the outbox"
    );
    assert_eq!(
        store
            .revive("e1", now, record("e1", "s1", now), OUTBOX, || now)
            .expect("io"),
        Revived::Written,
        "the kept dead letter replays once refreshed"
    );
}

/// MIK-7829: an occurrence admitted under an event id the outbox still
/// holds, on the wire or pending, is coalesced into that record: the first
/// body, stamp and attempt count stand. Receivers dedupe on the event id,
/// so a second delivery under it would be discarded anyway.
#[test]
fn a_re_admitted_occurrence_under_a_held_id_is_coalesced() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let later = |secs: i64, body: &str| OutboxRecord {
        body_b64: body.into(),
        created_at: now + chrono::Duration::seconds(secs),
        ..record("e1", "s1", now)
    };
    assert_eq!(
        store.enqueue(record("e1", "s1", now), OUTBOX).expect("io"),
        Enqueued::Written
    );
    let Claim::Ready(_) = store.claim("e1", now).expect("io") else {
        panic!("the first record is claimed");
    };
    assert_eq!(
        store.enqueue(later(1, "b24="), OUTBOX).expect("io"),
        Enqueued::Written,
        "while the first is on the wire"
    );
    let retry = Settle::Retry {
        next: now,
        status: "http_5xx",
    };
    store.settle("e1", now, retry, now, ROOMY).expect("io");
    store.suspend("s1").expect("io");
    assert_eq!(
        store.enqueue(later(2, "c24="), OUTBOX).expect("io"),
        Enqueued::Written,
        "while the first waits behind a suspension"
    );
    refresh(&store, now);
    let due = store.due(now, &HashSet::new()).expect("io");
    assert_eq!(due.ready.len(), 1);
    let held = &due.ready[0];
    assert_eq!(held.body_b64, "e30=", "the first body stands");
    assert_eq!(held.created_at, now, "and its stamp");
    assert_eq!(held.attempt, 1, "and its attempt count");
}
