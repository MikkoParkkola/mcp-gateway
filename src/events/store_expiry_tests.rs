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
            .revive("e1", now, record("e1", "s1", now), OUTBOX, || Ok(now))
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
        .revive("e1", now, record("e1", "s1", now), OUTBOX, || Ok(now))
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

/// A record written before `replayed` existed may be a replay: it reads as
/// one, so its expiry buries it rather than drops it. A new record always
/// writes the field, so `false` round-trips.
#[test]
fn a_record_from_before_the_replayed_field_is_kept_at_expiry() {
    let now = Utc::now();
    let fresh = serde_json::to_value(record("e1", "s1", now)).expect("json");
    assert_eq!(fresh["replayed"], false, "always written");
    let mut legacy = fresh.clone();
    legacy.as_object_mut().expect("object").remove("replayed");
    let legacy: OutboxRecord = serde_json::from_value(legacy).expect("legacy");
    assert!(
        legacy.replayed,
        "a record from before the field may be a replay"
    );
    let fresh: OutboxRecord = serde_json::from_value(fresh).expect("fresh");
    assert!(!fresh.replayed, "false round-trips");
}

/// More expired records than one batch: the rest are due at once, not after
/// an idle wait.
#[test]
fn expired_records_past_one_batch_are_due_at_once() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let roomy = OutboxCaps {
        global: 200,
        per_subscription: 200,
    };
    for n in 0..65 {
        let tried = OutboxRecord {
            attempt: 1,
            ..record(&format!("e{n}"), "s1", now)
        };
        store.enqueue(tried, roomy).expect("io");
    }
    let later = past_expiry(now);
    let due = store.due(later, &HashSet::new(), ROOMY).expect("io");
    assert_eq!(due.buried.len(), 64, "one batch");
    assert!(
        due.next.is_some_and(|at| at <= later),
        "the rest are due now"
    );
    let due = store.due(later, &HashSet::new(), ROOMY).expect("io");
    assert_eq!(due.buried.len(), 1, "the last one");
    assert_eq!(due.next, None, "nothing left");
}

/// An expiry burial whose dead letter is placed but not synced is receipted
/// once, then: its copy stays for the next tick, which finishes the burial
/// without a second receipt, and a restart before that tick loses none.
#[test]
fn an_unsynced_expiry_burial_is_receipted_once() {
    let ids = |due: super::super::Due| -> Vec<String> {
        due.buried.into_iter().map(|r| r.event_id).collect()
    };
    for restart in [false, true] {
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
        let first = store.due(later, &HashSet::new(), ROOMY).expect("io");
        assert_eq!(
            ids(first),
            ["e1"],
            "receipted when in place (restart {restart})"
        );
        assert!(
            store.has_due("s1", later),
            "the copy stays (restart {restart})"
        );
        let store = if restart {
            drop(store);
            Store::open(dir.path(), later, TAIL).expect("reopen")
        } else {
            store
        };
        let second = store.due(later, &HashSet::new(), ROOMY).expect("io");
        assert!(ids(second).is_empty(), "never twice (restart {restart})");
        assert!(!store.has_due("s1", later), "finished (restart {restart})");
    }
}

/// A backlog past one batch that the disk refuses to settle waits for the
/// next tick: it is not due at once, so the worker never spins on it.
#[cfg(unix)]
#[test]
fn a_backlog_the_disk_refuses_is_not_due_at_once() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let roomy = OutboxCaps {
        global: 200,
        per_subscription: 200,
    };
    for n in 0..65 {
        let tried = OutboxRecord {
            attempt: 1,
            ..record(&format!("e{n}"), "s1", now)
        };
        store.enqueue(tried, roomy).expect("io");
    }
    let outbox = dir.path().join("outbox");
    let mode = |m| std::fs::set_permissions(&outbox, std::fs::Permissions::from_mode(m));
    mode(0o500).expect("read-only");
    let due = store.due(past_expiry(now), &HashSet::new(), ROOMY);
    mode(0o700).expect("writable");
    assert_eq!(due.expect("io").next, None, "no progress: not due at once");
}

/// MIK-8057 with MIK-8061: a held row with no lease of its own ends at its
/// hold's bound. Its tried record is buried as `subscription_expired`, and
/// the opt-in's tail starts at that bound, not at the opt-in.
#[test]
fn a_lapsed_hold_buries_its_records_and_starts_the_tail_at_its_bound() {
    use crate::events::store::{Held, Judged};
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = Store::open(dir.path(), now, TAIL).expect("open");
    let unleased = Subscription {
        expires_at: None,
        ..sub("s1", now)
    };
    store
        .admit(unleased, true, CAPS, chrono::Duration::zero(), now, TAIL)
        .expect("io")
        .expect("admitted");
    let tried = OutboxRecord {
        attempt: 1,
        ..record("e1", "s1", now)
    };
    store.enqueue(tried, OUTBOX).expect("io");
    let held = |_: &Subscription| {
        Some(Judged {
            held: Some(Held {
                reason: "event type no longer offered",
                key: None,
            }),
            ..Judged::default()
        })
    };
    let bound = now + chrono::Duration::hours(1);
    store
        .apply_holds(&held, now, chrono::Duration::hours(1))
        .expect("io");
    let past = bound + chrono::Duration::minutes(10);
    store.due(past, &HashSet::new(), ROOMY).expect("io");
    assert_eq!(
        dead_reason(&store, "e1").as_deref(),
        Some("subscription_expired"),
        "the hold's bound ended the row"
    );
    let within = bound + chrono::Duration::minutes(30);
    assert!(
        store.is_verified("p", "https://h/s1", within, TAIL),
        "the tail started at the hold's bound"
    );
}
