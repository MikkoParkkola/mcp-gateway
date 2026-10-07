// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A burial keeps its receipt, and an eviction reports what it removed,
//! when the disk fails part way (MIK-7805).

use super::*;

/// MIK-7805 AC5: a burial that is durable keeps its receipt even when the
/// cleanup after it (the outbox file) cannot complete.
#[test]
fn a_burial_keeps_its_receipt_when_the_cleanup_after_it_fails() {
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
    // The outbox directory is replaced by a file: removing the record's file
    // after the dead letter is written then fails.
    std::fs::remove_dir_all(dir.path().join("outbox")).expect("rm");
    std::fs::write(dir.path().join("outbox"), b"x").expect("block");
    let dead = Settle::Dead {
        reason: DeadReason::Gone,
        status: Some("http_4xx"),
    };
    let settled = store.settle("a", now, dead, now, ROOMY).expect("settled");
    assert!(
        settled.buried,
        "the dead letter was written, so it is reported"
    );
    assert!(store.dead_letter_by_id("a").is_some());
}

/// MIK-7805: a dead letter renamed into place whose directory sync then
/// fails is still a burial. `Store::settle` reports it and drops the outbox
/// record, so the occurrence is never resent.
#[test]
fn a_burial_whose_dead_letter_sync_fails_is_still_reported() {
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
    store
        .fail_next_dead_sync
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let dead = Settle::Dead {
        reason: DeadReason::Gone,
        status: Some("http_4xx"),
    };
    let settled = store.settle("a", now, dead, now, ROOMY).expect("settled");
    assert!(
        settled.buried,
        "the dead letter is in place, so it is reported"
    );
    assert!(store.dead_letter_by_id("a").is_some());
    assert!(
        matches!(store.claim("a", now).expect("io"), Claim::Skip),
        "a buried occurrence is never resent"
    );
}

/// MIK-7805: a fan-out burial whose dead letter is renamed into place but
/// whose directory sync fails is still a burial, so its receipt (and with it
/// the governance record) is not dropped.
#[test]
fn a_fan_out_burial_whose_dead_letter_sync_fails_keeps_its_receipt() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    store
        .fail_next_dead_sync
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let settled = store
        .dead_letter(record("a", "s1", now), DeadReason::Gone, now, ROOMY)
        .expect("the burial is reported, not its sync failure");
    assert!(settled.buried);
    assert!(store.dead_letter_by_id("a").is_some());
}

/// MIK-7805 AC5: evictions that completed before a later one failed still
/// reach the caller, so each keeps its governance record.
#[test]
fn an_eviction_that_fails_part_way_still_reports_the_ones_it_made() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    for (n, id) in ["x", "y"].iter().enumerate() {
        let at = now + chrono::Duration::seconds(i64::try_from(n).expect("small"));
        store
            .dead_letter(record(id, "s1", at), DeadReason::Gone, at, ROOMY)
            .expect("io");
    }
    // "y"'s dead letter cannot be unlinked: a directory stands in its place.
    let y = dir.path().join("dead").join(OutboxRecord::file("y"));
    std::fs::remove_file(&y).expect("rm");
    std::fs::create_dir(&y).expect("block");
    let policy = DeadPolicy {
        max_records: 1,
        ..ROOMY
    };
    let at = now + chrono::Duration::seconds(5);
    let settled = store
        .dead_letter(record("z", "s1", at), DeadReason::Gone, at, policy)
        .expect("the burial stands");
    assert!(settled.buried);
    assert_eq!(
        settled
            .evicted
            .iter()
            .map(|e| e.event_id.as_str())
            .collect::<Vec<_>>(),
        ["x"],
        "x went before y failed"
    );
}
