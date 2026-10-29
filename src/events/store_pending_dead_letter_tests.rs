// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The dead-letter rows of the pending-store tests: the cap, eviction,
//! reopen, settlement and revival rules for a record that went dead. Moved
//! from `store_pending_tests.rs` for the file-size ceiling.

use super::*;

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
        let at = now
            + chrono::TimeDelta::try_seconds(i64::try_from(n).expect("small")).expect("in range");
        let evicted = store
            .dead_letter(record(id, "s1", at), DeadReason::Gone, at, policy)
            .expect("io")
            .evicted;
        if n == 2 {
            assert_eq!(evicted.len(), 1);
            assert_eq!(evicted[0].event_id, "a");
        }
    }
    let later = now + crate::duration_bound::delta!(hours, 2);
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
    let store = Store::open(dir.path(), Ok(now), TAIL).expect("reopen");
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
    let later = now + crate::duration_bound::delta!(hours, 2);
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
    let old = now - crate::duration_bound::delta!(days, 1);
    store
        .dead_letter(record("a", "s1", old), DeadReason::Gone, old, ROOMY)
        .expect("io");
    store.enqueue(record("a", "s1", now), caps).expect("io");
    drop(store);
    let store = Store::open(dir.path(), Ok(now), TAIL).expect("reopen");
    assert!(
        matches!(store.claim("a", now).expect("io"), Claim::Ready(_)),
        "the new occurrence survives the reload"
    );
    let later = now + crate::duration_bound::delta!(hours, 2);
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
    let old = now - crate::duration_bound::delta!(days, 1);
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
    assert!(store.settle("a", now, dead, Ok(now), ROOMY).is_err());
    let due = store
        .due(now + super::super::SETTLE_RETRY, &HashSet::new(), ROOMY)
        .expect("io");
    assert_eq!(
        due.ready.len(),
        1,
        "kept for another settlement, not dropped"
    );
}

#[test]
fn revive_moves_a_dead_letter_back_only_while_it_is_the_one_scanned() {
    use super::super::Revived;
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
    let stale = now + crate::duration_bound::delta!(seconds, 1);
    assert_eq!(
        store
            .revive("e1", stale, fresh("e1", "s1"), roomy, || Ok(now))
            .expect("io"),
        Revived::Missing,
        "a dead letter buried again since the scan is not revived"
    );
    assert_eq!(
        store
            .revive("e2", now, fresh("e2", "gone"), roomy, || Ok(now))
            .expect("io"),
        Revived::NoSubscription
    );
    let later = now + crate::duration_bound::delta!(hours, 2);
    assert_eq!(
        store
            .revive("e1", now, fresh("e1", "s1"), roomy, || Ok(later))
            .expect("io"),
        Revived::NoSubscription,
        "an expired subscription takes no replay before its sweep"
    );
    store.enqueue(record("e3", "s1", now), roomy).expect("io");
    assert_eq!(
        store
            .revive("e3", now, fresh("e3", "s1"), roomy, || Ok(now))
            .expect("io"),
        Revived::AlreadyPending,
        "a record already pending under the id is not a replay"
    );
    store
        .settle("e3", now, Settle::Delivered, Ok(now), ROOMY)
        .expect("io");
    let full = OutboxCaps {
        global: 0,
        per_subscription: 0,
    };
    assert_eq!(
        store
            .revive("e3", now, fresh("e3", "s1"), full, || Ok(now))
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
            .revive("e1", now, fresh("e1", "s1"), roomy, || Ok(now))
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
    let due = store.due(now, &HashSet::new(), ROOMY).expect("io");
    assert_eq!(due.ready.len(), 1);
    assert_eq!(due.ready[0].event_id, "e1");
    assert_eq!(due.ready[0].attempt, 0);
}
