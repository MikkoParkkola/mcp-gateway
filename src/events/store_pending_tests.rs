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
    store.settle("a", now, retry, now, ROOMY).expect("io");
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
            .expect("io")
            .evicted;
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
    assert!(store.settle("a", now, dead, now, ROOMY).is_err());
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

#[test]
fn evicting_a_dead_letter_takes_a_leftover_outbox_copy_first() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    // A failed unlink left the outbox file behind; memory already let go.
    crate::events::records::write_record(
        &dir.path().join("outbox"),
        &OutboxRecord::file("a"),
        &record("a", "s1", now),
    )
    .expect("io");
    store
        .dead_letter(record("a", "s1", now), DeadReason::Gone, now, ROOMY)
        .expect("io");
    let later = now + chrono::Duration::hours(2);
    assert_eq!(store.sweep_dead(later, ROOMY).expect("io").len(), 1);
    assert!(
        std::fs::read_dir(dir.path().join("outbox"))
            .expect("dir")
            .next()
            .is_none(),
        "no outbox copy outlives its marker"
    );
}

#[test]
fn a_later_occurrence_under_a_dead_id_is_kept() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    // Dead a day ago; the same upstream id re-admitted after the dedupe window.
    let old = now - chrono::Duration::days(1);
    store
        .dead_letter(record("a", "s1", old), DeadReason::Gone, old, ROOMY)
        .expect("io");
    store.enqueue(record("a", "s1", now), caps).expect("io");
    drop(store);
    let store = Store::open(dir.path(), now, TAIL).expect("reopen");
    assert!(
        matches!(store.claim("a", now).expect("io"), Claim::Ready(_)),
        "the new occurrence survives the reload"
    );
    let later = now + chrono::Duration::hours(2);
    store.sweep_dead(later, ROOMY).expect("io");
    assert!(
        dir.path().join("outbox").join("a.json").exists(),
        "evicting the old dead letter keeps the live record"
    );
}

#[test]
fn a_failed_settlement_ignores_an_older_dead_letter_under_the_same_id() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    let old = now - chrono::Duration::days(1);
    store
        .dead_letter(record("a", "s1", old), DeadReason::Gone, old, ROOMY)
        .expect("io");
    store.enqueue(record("a", "s1", now), caps).expect("io");
    assert!(matches!(
        store.claim("a", now).expect("io"),
        Claim::Ready(_)
    ));
    // The newer occurrence's own dead letter cannot be written.
    std::fs::remove_dir_all(dir.path().join("dead")).expect("rm");
    let dead = Settle::Dead {
        reason: DeadReason::TooLarge,
        status: Some("http_4xx"),
    };
    assert!(store.settle("a", now, dead, now, ROOMY).is_err());
    let due = store
        .due(now + super::SETTLE_RETRY, &HashSet::new())
        .expect("io");
    assert_eq!(
        due.ready.len(),
        1,
        "kept for another settlement, not dropped"
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
    let later = now + chrono::Duration::hours(2);
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
    store.remove("s1", now, TAIL).expect("io");
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
    let later = now + chrono::Duration::minutes(30);
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
    store.remove("s1", now, TAIL).expect("io");
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
    let later = now + chrono::Duration::minutes(30);
    store.enqueue(record("a", "s1", later), caps).expect("io");
    store
        .settle("a", now, Settle::Delivered, later, ROOMY)
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
    assert!(!store.remove_where("s1", now, TAIL, same).expect("io"));
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

#[test]
fn revive_moves_a_dead_letter_back_only_while_it_is_the_one_scanned() {
    use super::Revived;
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let roomy = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    for (event, owner) in [("e1", "s1"), ("e2", "gone"), ("e3", "s1")] {
        store
            .dead_letter(record(event, owner, now), DeadReason::Gone, now, ROOMY)
            .expect("io");
    }
    let fresh = |event: &str, owner: &str| record(event, owner, now);
    let stale = now + chrono::Duration::seconds(1);
    assert_eq!(
        store
            .revive("e1", stale, fresh("e1", "s1"), roomy, || now)
            .expect("io"),
        Revived::Missing,
        "a dead letter buried again since the scan is not revived"
    );
    assert_eq!(
        store
            .revive("e2", now, fresh("e2", "gone"), roomy, || now)
            .expect("io"),
        Revived::NoSubscription
    );
    let later = now + chrono::Duration::hours(2);
    assert_eq!(
        store
            .revive("e1", now, fresh("e1", "s1"), roomy, || later)
            .expect("io"),
        Revived::NoSubscription,
        "an expired subscription takes no replay before its sweep"
    );
    store.enqueue(record("e3", "s1", now), roomy).expect("io");
    assert_eq!(
        store
            .revive("e3", now, fresh("e3", "s1"), roomy, || now)
            .expect("io"),
        Revived::AlreadyPending,
        "a record already pending under the id is not a replay"
    );
    store
        .settle("e3", now, Settle::Delivered, now, ROOMY)
        .expect("io");
    let full = OutboxCaps {
        global: 0,
        per_subscription: 0,
    };
    assert_eq!(
        store
            .revive("e3", now, fresh("e3", "s1"), full, || now)
            .expect("io"),
        Revived::Full
    );
    assert_eq!(
        store.dead_summaries().len(),
        3,
        "every refusal keeps its letter"
    );
    assert_eq!(
        store
            .revive("e1", now, fresh("e1", "s1"), roomy, || now)
            .expect("io"),
        Revived::Written
    );
    let left: Vec<String> = store
        .dead_summaries()
        .into_iter()
        .map(|d| d.event_id)
        .collect();
    assert_eq!(left, ["e2", "e3"], "only the revived letter left dead/");
    assert!(!dir.path().join("dead/e1.json").exists(), "and its file");
    let due = store.due(now, &HashSet::new()).expect("io");
    assert_eq!(due.ready.len(), 1);
    assert_eq!(due.ready[0].event_id, "e1");
    assert_eq!(due.ready[0].attempt, 0);
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
    later.next_attempt_at = now + chrono::Duration::hours(1);
    store.enqueue(later, caps).expect("io");
    assert!(matches!(store.claim("a", now), Ok(Claim::Ready(_))));
    assert!(store.has_due("s1", now), "b waits behind a");
    assert!(!store.has_due("s2", now), "c is not due yet");
    assert!(!store.has_due("gone", now));
}

/// MIK-7944 .2: a claim settled `Unsent` keeps its attempt number but is
/// not a send; the next claim numbers on from it.
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
    store.settle("a", now, unsent, now, ROOMY).expect("io");
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
#[path = "store_revive_tests.rs"]
mod revive;
