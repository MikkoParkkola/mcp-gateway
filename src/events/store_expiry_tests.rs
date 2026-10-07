// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8061: an expired subscription buries the records that were replayed
//! or tried, instead of dropping them; an unsubscribe still drops them.

use super::super::Revived;
use super::*;

const OUTBOX: OutboxCaps = OutboxCaps {
    global: 10,
    per_subscription: 10,
};

/// Past the expiry `sub` grants.
fn past_expiry(now: DateTime<Utc>) -> DateTime<Utc> {
    now + chrono::Duration::hours(2)
}

/// The reason of the dead letter for `event`, if there is one.
fn dead_reason(store: &Store, event: &str) -> Option<String> {
    store.dead_letter_by_id(event).map(|dead| dead.reason)
}

/// `REPLAYLOSS.1` (L1): a replay, then a suspension, then the subscription
/// expires unrefreshed. The replayed occurrence is buried, not dropped.
#[test]
fn a_replay_frozen_by_a_suspension_is_buried_at_expiry() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    store
        .dead_letter(record("e1", "s1", now), DeadReason::Exhausted, now, ROOMY)
        .expect("io");
    assert_eq!(
        store
            .revive("e1", now, record("e1", "s1", now), OUTBOX, || now)
            .expect("io"),
        Revived::Written
    );
    store.suspend("s1").expect("io");
    store.due(past_expiry(now), &HashSet::new()).expect("io");
    assert_eq!(
        dead_reason(&store, "e1").as_deref(),
        Some("subscription_expired"),
        "the replayed occurrence is a dead letter again"
    );
}

/// L2: a record that failed a send, frozen by a suspension, is buried when
/// its subscription expires.
#[test]
fn a_tried_record_is_buried_at_expiry() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let tried = OutboxRecord {
        attempt: 1,
        last_status: Some("http_503".into()),
        ..record("e1", "s1", now)
    };
    store.enqueue(tried, OUTBOX).expect("io");
    store.suspend("s1").expect("io");
    store.due(past_expiry(now), &HashSet::new()).expect("io");
    assert_eq!(
        dead_reason(&store, "e1").as_deref(),
        Some("subscription_expired")
    );
}

/// L5: the expiry found when the store opens buries as a live sweep does.
#[test]
fn an_expiry_found_at_open_buries_a_tried_record() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let tried = OutboxRecord {
        attempt: 1,
        ..record("e1", "s1", now)
    };
    store.enqueue(tried, OUTBOX).expect("io");
    drop(store);
    let reopened = Store::open(dir.path(), past_expiry(now), TAIL).expect("reopen");
    assert_eq!(
        dead_reason(&reopened, "e1").as_deref(),
        Some("subscription_expired")
    );
}

/// Pin (L4): an unsubscribe takes its pending records with it, replayed or
/// not, and leaves no dead letter.
#[test]
fn an_unsubscribe_still_drops_a_replayed_record() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    store
        .dead_letter(record("e1", "s1", now), DeadReason::Exhausted, now, ROOMY)
        .expect("io");
    store
        .revive("e1", now, record("e1", "s1", now), OUTBOX, || now)
        .expect("io");
    assert!(store.remove("s1", now, TAIL).expect("io"), "unsubscribed");
    assert_eq!(dead_reason(&store, "e1"), None, "dropped, as before");
}
