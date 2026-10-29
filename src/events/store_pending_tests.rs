// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        reason = "test code reads the host clock (MIK-8202 AC.14)"
    )
)]
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
        generation: 0,
        incarnation: 0,
        v: 1,
        id: id.into(),
        principal: "p".into(),
        api_key: None,
        credential_kind: None,
        credential_principal: None,
        read_key: None,
        binding: None,
        legacy_api_key_name: None,
        url: format!("https://h/{id}"),
        name: "e".into(),
        arguments: serde_json::json!({}),
        secret: "whsec_x".into(),
        previous_secret: None,
        previous_until: None,
        granted_at: now,
        expires_at: Some(now + crate::duration_bound::delta!(hours, 1)),
        active: true,
        failed_since: None,
        last_delivery_at: None,
        last_error: None,
        payload_fields: Vec::new(),
        unoffered_since: None,
        held_until: None,
        watch_class: None,
        observed_identity: None,
        obs_basis: None,
    }
}

fn record(event: &str, sub: &str, now: DateTime<Utc>) -> OutboxRecord {
    OutboxRecord {
        v: 1,
        event_id: event.into(),
        subscription_id: sub.into(),
        name: "e".into(),
        backend: "b".into(),
        owner_scoped: false,
        callback_host: String::new(),
        body_b64: "e30=".into(),
        tenants: Vec::new(),
        attribution: None,
        attribution_keys: Vec::new(),
        firewall: None,
        attempt: 0,
        unsent: 0,
        next_attempt_at: now,
        first_attempt_at: None,
        created_at: now,
        state: OutboxState::Pending,
        last_status: None,
        dead_as: None,
        replayed: false,
        observed: None,
    }
}

fn open_with(dir: &std::path::Path, now: DateTime<Utc>, subs: &[&str]) -> Store {
    let store = Store::open(dir, Ok(now), TAIL).expect("open");
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
    let due = store.due(now, &HashSet::new(), ROOMY).expect("io");
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
    let next = now + crate::duration_bound::delta!(seconds, 5);
    let retry = Settle::Retry {
        next,
        status: "http_5xx",
    };
    store.settle("a", now, retry, Ok(now), ROOMY).expect("io");
    assert_eq!(
        store.get("s1").and_then(|s| s.last_error).as_deref(),
        Some("http_5xx")
    );
    let due = store.due(now, &HashSet::new(), ROOMY).expect("io");
    assert!(due.ready.is_empty() && due.next == Some(next));
    store.remove("s1", Ok(now), TAIL).expect("remove");
    assert!(
        store
            .due(next, &HashSet::new(), ROOMY)
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
    let later = now + crate::duration_bound::delta!(seconds, 1);
    let store = Store::open(dir.path(), Ok(later), TAIL).expect("reopen");
    let Claim::Ready(claimed) = store.claim("a", later).expect("io") else {
        panic!("recovered");
    };
    assert_eq!(claimed.record.attempt, 2, "the attempt count survived");
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
    assert_eq!(
        store
            .due(now, &HashSet::new(), ROOMY)
            .expect("io")
            .ready
            .len(),
        1
    );
    let on_disk = || {
        std::fs::read_dir(dir.path().join("outbox"))
            .expect("dir")
            .count()
    };
    assert_eq!(on_disk(), 2, "the suspended subscription keeps its record");
    let past_expiry = now + crate::duration_bound::delta!(hours, 2);
    store.due(past_expiry, &HashSet::new(), ROOMY).expect("io");
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
    assert!(store.settle("a", now, dead, Ok(now), ROOMY).is_err());
    let retry_at = now + super::SETTLE_RETRY;
    assert!(
        store
            .due(now, &HashSet::new(), ROOMY)
            .expect("io")
            .ready
            .is_empty()
    );
    let due = store.due(retry_at, &HashSet::new(), ROOMY).expect("io");
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
    let store = Store::open(dir.path(), Ok(retry_at), TAIL).expect("reopen");
    let Claim::Ready(claimed) = store.claim("a", retry_at).expect("io") else {
        panic!("recovered");
    };
    assert_eq!(
        claimed.record.dead_as,
        Some(DeadReason::Gone),
        "the claim wrote the verdict to disk"
    );
}

#[test]
fn a_resubscribe_after_expiry_inherits_no_pending_record() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    store.enqueue(record("a", "s1", now), caps).expect("io");
    let later = now + crate::duration_bound::delta!(hours, 2);
    store
        .admit(
            sub("s1", later),
            true,
            CAPS,
            chrono::Duration::zero(),
            later,
            TAIL,
        )
        .expect("io")
        .expect("admitted");
    assert!(matches!(store.claim("a", later).expect("io"), Claim::Skip));
    assert_eq!(
        std::fs::read_dir(dir.path().join("outbox"))
            .expect("dir")
            .count(),
        0,
        "the expired subscription's retry went with it"
    );
}

#[test]
fn a_cancelled_claim_has_no_signing_row_even_under_a_reused_id() {
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
    assert!(store.signing_row(&claimed.record).is_some(), "claim alive");
    store.remove("s1", Ok(now), TAIL).expect("io");
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
        .expect("admitted");
    assert!(
        store.signing_row(&claimed.record).is_none(),
        "the cancelled claim is not signed with the new row"
    );
    // Not even once a later occurrence under the same id is in flight.
    let later = now + crate::duration_bound::delta!(minutes, 30);
    store.enqueue(record("a", "s1", later), caps).expect("io");
    let Claim::Ready(newer) = store.claim("a", later).expect("io") else {
        panic!("the later occurrence is claimable");
    };
    assert!(store.signing_row(&newer.record).is_some());
    assert!(
        store.signing_row(&claimed.record).is_none(),
        "the old claim does not borrow the later occurrence's flight"
    );
}

#[test]
fn an_old_answer_does_not_settle_a_later_occurrence() {
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
    // Unsubscribed mid-flight, resubscribed, and the id re-admitted later.
    store.remove("s1", Ok(now), TAIL).expect("io");
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
        .expect("admitted");
    let later = now + crate::duration_bound::delta!(minutes, 30);
    store.enqueue(record("a", "s1", later), caps).expect("io");
    store
        .settle("a", now, Settle::Delivered, Ok(later), ROOMY)
        .expect("io");
    assert!(
        matches!(store.claim("a", later).expect("io"), Claim::Ready(_)),
        "the later occurrence is still pending"
    );
}

#[test]
fn a_revocation_decided_on_an_old_row_spares_a_rebound_one() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let refused = store.get("s1").expect("stored");
    // A refresh re-binds the same id to another credential.
    let mut rebound = sub("s1", now);
    rebound.credential_principal = Some("another".into());
    store
        .admit(rebound, true, CAPS, chrono::Duration::zero(), now, TAIL)
        .expect("io")
        .expect("admitted");
    let same = |row: &Subscription| row.credential_principal == refused.credential_principal;
    assert!(!store.remove_where("s1", Ok(now), TAIL, same).expect("io"));
    assert!(store.get("s1").is_some(), "the rebound row survives");
}

/// An attribution counts only while the `arg_keys` it was taken under are
/// still the policy; after a change the record reads as unattributed.
#[test]
fn attribution_counts_only_under_its_own_keys() {
    let mut r = record("a", "s1", Utc::now());
    r.attribution = Some(crate::security::tenant_reads::ReadAttribution::default());
    r.attribution_keys = vec!["repo".to_owned()];
    assert!(r.attribution_under(&["repo".to_owned()]).is_some());
    assert!(
        r.attribution_under(&["repo".to_owned(), "org".to_owned()])
            .is_none()
    );
    assert!(r.attribution_under(&[]).is_none());
}

/// MIK-7791: a record waits behind the one on the wire, and is due.
#[test]
fn has_due_sees_a_pending_record_behind_one_in_flight() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1", "s2"]);
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    assert!(!store.has_due("s1", now), "nothing queued");
    store.enqueue(record("a", "s1", now), caps).expect("io");
    store.enqueue(record("b", "s1", now), caps).expect("io");
    let mut later = record("c", "s2", now);
    later.next_attempt_at = now + crate::duration_bound::delta!(hours, 1);
    store.enqueue(later, caps).expect("io");
    assert!(matches!(store.claim("a", now), Ok(Claim::Ready(_))));
    assert!(store.has_due("s1", now), "b waits behind a");
    assert!(!store.has_due("s2", now), "c is not due yet");
    assert!(!store.has_due("gone", now));
}

/// MIK-7944 .2: a claim settled `Unsent` keeps its attempt number but is
/// not a send, across a restart too; the next claim numbers on from it.
#[test]
fn an_unsent_claim_keeps_its_number_but_is_not_a_send() {
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
    let unsent = Settle::Unsent {
        next: now,
        status: "audit_unavailable",
    };
    store.settle("a", now, unsent, Ok(now), ROOMY).expect("io");
    // Across a restart: the count is on disk with the record.
    drop(store);
    let store = Store::open(dir.path(), Ok(now), TAIL).expect("reopen");
    let Claim::Ready(claimed) = store.claim("a", now).expect("io") else {
        panic!("claimable again");
    };
    assert_eq!(claimed.record.attempt, 2, "numbers stay unique");
    assert_eq!(
        claimed.record.sends(),
        1,
        "the refused claim was not a send"
    );
}

/// MIK-7944 .2: an `Unsent` settlement the disk refused still counts the
/// claim as unsent, so a store fault on top of an audit outage burns no send.
#[test]
fn an_unsent_settlement_the_disk_refused_is_still_not_a_send() {
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
    // The outbox directory is gone, so writing the settlement fails.
    let outbox = dir.path().join("outbox");
    std::fs::remove_dir_all(&outbox).expect("rm");
    let unsent = Settle::Unsent {
        next: now,
        status: "audit_unavailable",
    };
    assert!(store.settle("a", now, unsent, Ok(now), ROOMY).is_err());
    std::fs::create_dir(&outbox).expect("mkdir");
    let retry_at = now + super::SETTLE_RETRY;
    let Claim::Ready(claimed) = store.claim("a", retry_at).expect("io") else {
        panic!("pending again");
    };
    assert_eq!(claimed.record.attempt, 2, "numbers stay unique");
    assert_eq!(
        claimed.record.sends(),
        1,
        "the refused claim was not a send"
    );
}

/// MIK-7944 .2: a record written before `unsent` existed loads with none.
#[test]
fn a_record_without_unsent_reads_as_none() {
    let mut value = serde_json::to_value(record("a", "s1", Utc::now())).expect("json");
    value.as_object_mut().expect("object").remove("unsent");
    let read: OutboxRecord = serde_json::from_value(value).expect("an older record");
    assert_eq!(read.unsent, 0);
}

#[path = "store_pending_burial_tests.rs"]
mod burial;
#[path = "store_pending_crash_tests.rs"]
mod crash;
#[path = "store_pending_dead_letter_tests.rs"]
mod dead_letter;
#[path = "store_expiry_tests.rs"]
mod expiry;
#[path = "store_revive_tests.rs"]
mod revive;
