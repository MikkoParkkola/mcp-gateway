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
    store
        .due(past_expiry(now), &HashSet::new(), ROOMY)
        .expect("io");
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
    store
        .due(past_expiry(now), &HashSet::new(), ROOMY)
        .expect("io");
    assert_eq!(
        dead_reason(&store, "e1").as_deref(),
        Some("subscription_expired")
    );
}

/// L5: a store opened after the expiry keeps the tried record pending (the
/// open sweep buries nothing); the first `due` buries it.
#[test]
fn an_expiry_found_at_open_is_buried_by_the_first_due() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let tried = OutboxRecord {
        attempt: 1,
        ..record("e1", "s1", now)
    };
    store.enqueue(tried, OUTBOX).expect("io");
    drop(store);
    let later = past_expiry(now);
    let reopened = Store::open(dir.path(), later, TAIL).expect("reopen");
    assert_eq!(dead_reason(&reopened, "e1"), None, "nothing buried at open");
    assert!(reopened.has_due("s1", later), "still pending after open");
    reopened.due(later, &HashSet::new(), ROOMY).expect("io");
    assert_eq!(
        dead_reason(&reopened, "e1").as_deref(),
        Some("subscription_expired")
    );
    assert!(!reopened.has_due("s1", later), "the outbox copy is gone");
}

/// L12 pin (the B08b invariant): a re-subscribe of the same key over an
/// expired row still holding a tried record is refused until its burial
/// finishes, then admitted clean: no inherited secret, grace or record.
#[test]
fn a_resubscribe_over_a_kept_expired_row_waits_for_its_burials() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let tried = OutboxRecord {
        attempt: 1,
        ..record("e1", "s1", now)
    };
    store.enqueue(tried, OUTBOX).expect("io");
    let later = past_expiry(now);
    let renewed = || Subscription {
        secret: "whsec_second".into(),
        granted_at: later,
        expires_at: Some(later + chrono::Duration::hours(1)),
        ..sub("s1", later)
    };
    let early = store
        .admit(
            renewed(),
            true,
            CAPS,
            chrono::Duration::hours(1),
            later,
            TAIL,
        )
        .expect("io");
    assert!(
        early.is_err(),
        "refused while the expired row's burial is unfinished"
    );
    store.due(later, &HashSet::new(), ROOMY).expect("io");
    store
        .admit(
            renewed(),
            true,
            CAPS,
            chrono::Duration::hours(1),
            later,
            TAIL,
        )
        .expect("io")
        .expect("admitted once the burial finished");
    let row = store.get("s1").expect("row");
    assert_eq!(row.secret, "whsec_second");
    assert_eq!(row.previous_secret, None, "no grace from the expired row");
    assert!(!store.has_due("s1", later), "no inherited record");
    assert_eq!(
        dead_reason(&store, "e1").as_deref(),
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

/// L16: the worker buries and removes an expired row before any synchronous
/// sweep. The verification tail starts at the row's expiry, not at the
/// removal or the opt-in: it still holds just under an hour after the
/// expiry, and an hour after the expiry it has run out.
#[test]
fn a_row_removed_by_the_worker_stamps_its_tail_at_expiry() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let tried = OutboxRecord {
        attempt: 1,
        ..record("e1", "s1", now)
    };
    store.enqueue(tried, OUTBOX).expect("io");
    let expiry = now + chrono::Duration::hours(1);
    let removal = expiry + chrono::Duration::minutes(50);
    store.due(removal, &HashSet::new(), ROOMY).expect("io");
    assert!(store.get("s1").is_none(), "the worker removed the row");
    let within = expiry + chrono::Duration::minutes(55);
    assert!(
        store.is_verified("p", "https://h/s1", within, TAIL),
        "the tail began at expiry, not at the opt-in"
    );
    let after = expiry + chrono::Duration::minutes(61);
    assert!(
        !store.is_verified("p", "https://h/s1", after, TAIL),
        "the tail began at expiry and has run out"
    );
}

/// L17: an expiry burial whose dead-letter sync fails keeps the outbox copy.
/// Until that burial completes, a cap eviction leaves its dead letter alone,
/// so no eviction can come before, or replace, the burial.
#[test]
fn an_unfinished_expiry_burial_is_not_evicted() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let tried = OutboxRecord {
        attempt: 1,
        ..record("e1", "s1", now)
    };
    store.enqueue(tried, OUTBOX).expect("io");
    store
        .fail_next_dead_sync
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let later = past_expiry(now);
    store.due(later, &HashSet::new(), ROOMY).expect("io");
    assert!(store.has_due("s1", later), "the outbox copy stays");
    let tight = DeadPolicy {
        max_records: 0,
        ..ROOMY
    };
    let evicted = store.sweep_dead(later, tight).expect("io");
    assert!(
        evicted.iter().all(|e| e.event_id != "e1"),
        "an unfinished burial is not evicted"
    );
    store.due(later, &HashSet::new(), ROOMY).expect("io");
    assert_eq!(
        dead_reason(&store, "e1").as_deref(),
        Some("subscription_expired"),
        "the next tick completes the burial"
    );
}

/// An expiry burial keeps the dead-letter caps as every burial does: at a
/// one-record cap, the same call evicts the older dead letter and names it
/// for its receipt.
#[test]
fn an_expiry_burial_keeps_the_dead_letter_caps() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1", "s2"]);
    store
        .dead_letter(record("old", "s2", now), DeadReason::Exhausted, now, ROOMY)
        .expect("io");
    let tried = OutboxRecord {
        attempt: 1,
        ..record("e1", "s1", now)
    };
    store.enqueue(tried, OUTBOX).expect("io");
    let one = DeadPolicy {
        max_records: 1,
        retention: Duration::from_secs(86_400),
        ..ROOMY
    };
    let due = store
        .due(past_expiry(now), &HashSet::new(), one)
        .expect("io");
    assert_eq!(due.buried.len(), 1, "the tried record is buried");
    let evicted: Vec<&str> = due.evicted.iter().map(|e| e.event_id.as_str()).collect();
    assert_eq!(evicted, ["old"], "the cap evicted the older letter at once");
    assert!(
        store.dead_letter_by_id("old").is_none(),
        "gone from the store"
    );
}

/// L18 (pin): a record whose subscription row is gone (an unsubscribe whose
/// record removal did not happen) is dropped by `due`, never buried.
#[test]
fn a_record_of_a_gone_subscription_is_dropped_not_buried() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let tried = OutboxRecord {
        attempt: 1,
        ..record("e1", "s1", now)
    };
    store.enqueue(tried, OUTBOX).expect("io");
    drop(store);
    for entry in std::fs::read_dir(dir.path().join("subs")).expect("subs") {
        std::fs::remove_file(entry.expect("entry").path()).expect("row gone");
    }
    let reopened = Store::open(dir.path(), now, TAIL).expect("reopen");
    reopened.due(now, &HashSet::new(), ROOMY).expect("io");
    assert!(!reopened.has_due("s1", now), "dropped");
    assert_eq!(dead_reason(&reopened, "e1"), None, "never buried");
}

/// L19 (implementation review CRITICAL): unsubscribing an expired row kept
/// for its burials keeps the tail the expiry began; it never restarts it, so
/// a re-subscribe after the tail runs out is challenged again.
#[test]
fn unsubscribing_a_kept_expired_row_does_not_restart_its_tail() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let tried = OutboxRecord {
        attempt: 1,
        ..record("e1", "s1", now)
    };
    store.enqueue(tried, OUTBOX).expect("io");
    let expiry = now + chrono::Duration::hours(1);
    let late = expiry + chrono::Duration::minutes(30);
    assert!(store.remove("s1", late, TAIL).expect("io"), "unsubscribed");
    let after = expiry + chrono::Duration::minutes(61);
    assert!(
        !store.is_verified("p", "https://h/s1", after, TAIL),
        "the tail began at the expiry, not at the unsubscribe"
    );
}

/// A record written before fan-out stamped its callback host is buried at
/// expiry with its row's host: the receipt names the host after the row is
/// gone.
#[test]
fn an_expiry_burial_carries_its_rows_callback_host() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let tried = OutboxRecord {
        attempt: 1,
        ..record("e1", "s1", now)
    };
    store.enqueue(tried, OUTBOX).expect("io");
    let due = store
        .due(past_expiry(now), &HashSet::new(), ROOMY)
        .expect("io");
    assert!(store.get("s1").is_none(), "the row is gone");
    assert_eq!(due.buried.len(), 1, "buried");
    assert_eq!(due.buried[0].callback_host, "h", "the row's host");
}
