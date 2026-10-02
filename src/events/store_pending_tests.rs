// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::collections::HashSet;
use std::time::Duration;

use chrono::{DateTime, Utc};

use super::super::{Caps, Store, TailPolicy};
use super::{Claim, Settle};
use crate::events::outbox::{
    DeadPolicy, DeadReason, Enqueued, OutboxCaps, OutboxRecord, OutboxState,
};
use crate::events::records::Subscription;

const TAIL: TailPolicy = TailPolicy {
    ttl: Duration::from_secs(3600),
    max: 10,
    max_per_principal: 10,
};
const CAPS: Caps = Caps {
    per_principal: 10,
    global: 10,
};
const ROOMY: DeadPolicy = DeadPolicy {
    retention: Duration::from_secs(3600),
    max_records: 100,
    max_bytes: u64::MAX,
};

fn sub(id: &str, now: DateTime<Utc>) -> Subscription {
    Subscription {
        v: 1,
        id: id.into(),
        principal: "p".into(),
        api_key: None,
        credential_kind: None,
        legacy_api_key_name: None,
        url: format!("https://h/{id}"),
        name: "e".into(),
        arguments: serde_json::json!({}),
        secret: "whsec_x".into(),
        previous_secret: None,
        previous_until: None,
        granted_at: now,
        expires_at: Some(now + chrono::Duration::hours(1)),
        active: true,
        failed_since: None,
        last_delivery_at: None,
        last_error: None,
    }
}

fn record(event: &str, sub: &str, now: DateTime<Utc>) -> OutboxRecord {
    OutboxRecord {
        v: 1,
        event_id: event.into(),
        subscription_id: sub.into(),
        name: "e".into(),
        backend: "b".into(),
        body_b64: "e30=".into(),
        tenants: Vec::new(),
        attempt: 0,
        next_attempt_at: now,
        first_attempt_at: None,
        created_at: now,
        state: OutboxState::Pending,
        last_status: None,
        dead_as: None,
    }
}

fn open_with(dir: &std::path::Path, now: DateTime<Utc>, subs: &[&str]) -> Store {
    let store = Store::open(dir, now, TAIL).expect("open");
    for id in subs {
        store
            .admit(
                sub(id, now),
                true,
                CAPS,
                chrono::Duration::zero(),
                now,
                TAIL,
            )
            .expect("io")
            .expect("admitted");
    }
    store
}

#[test]
fn caps_drop_new_records_and_keep_pending_ones() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1", "s2"]);
    let caps = OutboxCaps {
        global: 3,
        per_subscription: 2,
    };
    let put = |e: &str, s: &str| store.enqueue(record(e, s, now), caps).expect("io");
    assert_eq!(put("a", "s1"), Enqueued::Written);
    assert_eq!(put("b", "s1"), Enqueued::Written);
    assert_eq!(put("c", "s1"), Enqueued::DroppedPerSubscription);
    assert_eq!(put("d", "s2"), Enqueued::Written);
    assert_eq!(put("e", "s2"), Enqueued::DroppedGlobal);
    assert_eq!(put("f", "gone"), Enqueued::NoSubscription);
    let due = store.due(now, &HashSet::new()).expect("io");
    assert_eq!(due.ready.len(), 2, "one per subscription");
}

#[test]
fn claim_settle_and_unsubscribe_cancel() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    store.enqueue(record("a", "s1", now), caps).expect("io");
    let Claim::Ready(claimed) = store.claim("a", now).expect("io") else {
        panic!("claimable");
    };
    assert_eq!(claimed.record.attempt, 1);
    assert!(
        matches!(store.claim("a", now).expect("io"), Claim::Skip),
        "in flight"
    );
    let next = now + chrono::Duration::seconds(5);
    let retry = Settle::Retry {
        next,
        status: "http_5xx",
    };
    store.settle("a", retry, now, ROOMY).expect("io");
    assert_eq!(
        store.get("s1").and_then(|s| s.last_error).as_deref(),
        Some("http_5xx")
    );
    let due = store.due(now, &HashSet::new()).expect("io");
    assert!(due.ready.is_empty() && due.next == Some(next));
    store.remove("s1", now, TAIL).expect("remove");
    assert!(
        store
            .due(next, &HashSet::new())
            .expect("io")
            .ready
            .is_empty()
    );
    assert!(
        std::fs::read_dir(dir.path().join("outbox"))
            .expect("dir")
            .next()
            .is_none()
    );
}

#[test]
fn in_flight_returns_to_pending_on_reopen() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    store.enqueue(record("a", "s1", now), caps).expect("io");
    assert!(matches!(
        store.claim("a", now).expect("io"),
        Claim::Ready(_)
    ));
    drop(store);
    let later = now + chrono::Duration::seconds(1);
    let store = Store::open(dir.path(), later, TAIL).expect("reopen");
    let Claim::Ready(claimed) = store.claim("a", later).expect("io") else {
        panic!("recovered");
    };
    assert_eq!(claimed.record.attempt, 2, "the attempt count survived");
}

#[test]
fn dead_letters_are_capped_oldest_first() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let policy = DeadPolicy {
        max_records: 2,
        ..ROOMY
    };
    for (n, id) in ["a", "b", "c"].iter().enumerate() {
        let at = now + chrono::Duration::seconds(i64::try_from(n).expect("small"));
        let evicted = store
            .dead_letter(record(id, "s1", at), DeadReason::Gone, at, policy)
            .expect("io");
        if n == 2 {
            assert_eq!(evicted.len(), 1);
            assert_eq!(evicted[0].event_id, "a");
        }
    }
    let later = now + chrono::Duration::hours(2);
    let swept = store.sweep_dead(later, policy).expect("io");
    assert_eq!(swept.len(), 2, "retention sweeps the rest");
}

#[test]
fn an_outbox_record_already_dead_is_dropped_on_reopen() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    store.enqueue(record("a", "s1", now), caps).expect("io");
    // A crash between the dead letter and the unlink leaves both on disk.
    store
        .dead_letter(record("a", "s1", now), DeadReason::Gone, now, ROOMY)
        .expect("io");
    drop(store);
    let store = Store::open(dir.path(), now, TAIL).expect("reopen");
    assert!(matches!(store.claim("a", now).expect("io"), Claim::Skip));
    assert!(
        std::fs::read_dir(dir.path().join("outbox"))
            .expect("dir")
            .next()
            .is_none(),
        "the stale outbox file is removed"
    );
}

#[test]
fn a_repeated_enqueue_keeps_the_record_in_flight() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    store.enqueue(record("a", "s1", now), caps).expect("io");
    assert!(matches!(
        store.claim("a", now).expect("io"),
        Claim::Ready(_)
    ));
    assert_eq!(
        store.enqueue(record("a", "s1", now), caps).expect("io"),
        Enqueued::Written
    );
    assert!(
        matches!(store.claim("a", now).expect("io"), Claim::Skip),
        "still in flight, not reset to pending"
    );
}

#[test]
fn records_of_expired_subscriptions_are_cancelled_but_suspended_ones_kept() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["live", "paused"]);
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    store.enqueue(record("a", "live", now), caps).expect("io");
    store.enqueue(record("b", "paused", now), caps).expect("io");
    store.suspend("paused").expect("io");
    assert_eq!(store.due(now, &HashSet::new()).expect("io").ready.len(), 1);
    let on_disk = || {
        std::fs::read_dir(dir.path().join("outbox"))
            .expect("dir")
            .count()
    };
    assert_eq!(on_disk(), 2, "the suspended subscription keeps its record");
    let past_expiry = now + chrono::Duration::hours(2);
    store.due(past_expiry, &HashSet::new()).expect("io");
    assert_eq!(on_disk(), 0, "expired: their records are cancelled");
}

#[test]
fn a_failed_settlement_leaves_the_record_pending() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    store.enqueue(record("a", "s1", now), caps).expect("io");
    assert!(matches!(
        store.claim("a", now).expect("io"),
        Claim::Ready(_)
    ));
    // The dead-letter directory is gone, so burying the record fails.
    std::fs::remove_dir_all(dir.path().join("dead")).expect("rm");
    let dead = Settle::Dead {
        reason: DeadReason::Gone,
        status: Some("http_4xx"),
    };
    assert!(store.settle("a", dead, now, ROOMY).is_err());
    let retry_at = now + super::SETTLE_RETRY;
    assert!(
        store
            .due(now, &HashSet::new())
            .expect("io")
            .ready
            .is_empty()
    );
    let due = store.due(retry_at, &HashSet::new()).expect("io");
    assert_eq!(due.ready.len(), 1, "pending again, not stranded in flight");
    let Claim::Ready(claimed) = store.claim("a", retry_at).expect("io") else {
        panic!("claimable");
    };
    assert_eq!(
        claimed.record.dead_as,
        Some(DeadReason::Gone),
        "buried again, never sent again"
    );
    drop(store);
    let store = Store::open(dir.path(), retry_at, TAIL).expect("reopen");
    let Claim::Ready(claimed) = store.claim("a", retry_at).expect("io") else {
        panic!("recovered");
    };
    assert_eq!(
        claimed.record.dead_as,
        Some(DeadReason::Gone),
        "the claim wrote the verdict to disk"
    );
}
