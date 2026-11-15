// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Ended rows: an ending moves the row out of every
//! live reader into `ended/`, and its one notice maps to the ended row
//! until it settles.

use super::*;
use crate::events::outbox::{EndedRow, EndedStamp};

fn stamp(now: DateTime<Utc>, event_id: &str) -> EndedStamp {
    EndedStamp {
        at: now,
        code: -32012,
        event_id: event_id.into(),
    }
}

/// End live row `id` with notice `event_id`, asserting it ended.
fn end(store: &Store, id: &str, now: DateTime<Utc>, event_id: &str) {
    let ended = store
        .end_where(id, stamp(now, event_id), TAIL, |_| true)
        .expect("io");
    assert!(ended, "premise: row {id} was live and ended");
}

/// The file names in `dir`, sorted.
fn names(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = crate::events::records::committed_records(dir)
        .iter()
        .filter_map(|p| p.file_name()?.to_str().map(str::to_owned))
        .collect();
    names.sort();
    names
}

/// Grant `id` again under a new secret.
fn regrant(store: &Store, id: &str, now: DateTime<Utc>, secret: &str) {
    let mut row = sub(id, now);
    row.secret = secret.into();
    store
        .admit(row, true, CAPS, chrono::Duration::zero(), now, TAIL)
        .expect("io")
        .expect("admitted");
}

fn ready_ids(store: &Store, now: DateTime<Utc>, busy: &[&str]) -> Vec<String> {
    let busy: HashSet<String> = busy.iter().map(|b| (*b).to_owned()).collect();
    let mut ids: Vec<String> = store
        .due(now, &busy, ROOMY)
        .expect("io")
        .ready
        .into_iter()
        .map(|r| r.event_id)
        .collect();
    ids.sort();
    ids
}

/// CARRIER.1 (R18): an ended row is gone from every live reader and from
/// the caps, and lives only as `ended/<id>.<incarnation>.json`.
#[test]
fn an_ended_row_leaves_every_live_reader_and_lives_only_under_ended() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let incarnation = store.get("s1").expect("premise: live").incarnation;
    let one = Caps {
        per_principal: 1,
        global: 1,
    };
    assert!(
        store.would_admit("p", one, now).is_err(),
        "premise: the live row fills a cap of one"
    );
    end(&store, "s1", now, "evt_n1");
    assert!(store.get("s1").is_none(), "no live row by id");
    assert!(store.subscriptions().is_empty(), "not in fan-out's list");
    assert!(store.live_subscription_ids(now).is_empty());
    assert_eq!(
        store.would_admit("p", one, now),
        Ok(()),
        "holds no cap slot"
    );
    let ended = store.ended_rows();
    assert_eq!(ended.len(), 1);
    assert_eq!(
        (
            ended[0].row.id.as_str(),
            ended[0].row.incarnation,
            ended[0].ended.code
        ),
        ("s1", incarnation, -32012)
    );
    assert_eq!(ended[0].ended.event_id, "evt_n1");
    assert!(names(store.subs_dir()).is_empty(), "no live file");
    assert_eq!(
        names(store.ended_dir()),
        vec![format!("s1.{incarnation}.json")]
    );
}

/// `end_where` ends nothing when its predicate refuses the row.
#[test]
fn an_ending_the_predicate_refuses_changes_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let ended = store
        .end_where("s1", stamp(now, "evt_n1"), TAIL, |_| false)
        .expect("io");
    assert!(!ended);
    assert!(store.get("s1").is_some(), "still live");
    assert!(store.ended_rows().is_empty());
    assert!(names(store.ended_dir()).is_empty());
    assert!(ready_ids(&store, now, &[]).is_empty(), "no notice queued");
}

/// CARRIER.1 (R22): a re-grant under the same id while the notice is
/// pending writes its own live file; neither write touches the other's bytes.
#[test]
fn a_regrant_while_ended_writes_its_own_file_and_leaves_the_ended_one_alone() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    end(&store, "s1", now, "evt_n1");
    let ended_file = store.ended_dir().join(&names(store.ended_dir())[0]);
    let ended_bytes = std::fs::read(&ended_file).expect("ended file");
    regrant(&store, "s1", now, "whsec_y");
    assert_eq!(store.get("s1").expect("live again").secret, "whsec_y");
    assert_eq!(names(store.subs_dir()), vec!["s1.json".to_owned()]);
    assert_eq!(
        std::fs::read(&ended_file).expect("ended file"),
        ended_bytes,
        "the re-grant left the ended file as it was"
    );
    assert_eq!(store.ended_rows()[0].row.secret, "whsec_x");
    let live_bytes = std::fs::read(store.subs_dir().join("s1.json")).expect("live file");
    let Claim::Ready(claimed) = store.claim("evt_n1", now).expect("io") else {
        panic!("the notice is claimable");
    };
    store
        .settle(
            "evt_n1",
            claimed.record.created_at,
            Settle::Delivered,
            Ok(now),
            ROOMY,
        )
        .expect("io");
    assert!(
        names(store.ended_dir()).is_empty(),
        "settled: ended file gone"
    );
    assert_eq!(
        std::fs::read(store.subs_dir().join("s1.json")).expect("live file"),
        live_bytes,
        "settling the notice left the live file as it was"
    );
}

/// CARRIER.2 (R17, R23): a pending notice is due with no live row under its
/// id, and apart from a successor's event: each has its own busy slot.
#[test]
fn a_pending_notice_is_due_alone_and_beside_a_successor() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    let incarnation = store.get("s1").expect("live").incarnation;
    end(&store, "s1", now, "evt_n1");
    assert!(store.get("s1").is_none(), "premise: no live row");
    assert_eq!(ready_ids(&store, now, &[]), vec!["evt_n1".to_owned()]);
    regrant(&store, "s1", now, "whsec_y");
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 1,
    };
    assert_eq!(
        store.enqueue(record("e2", "s1", now), caps).expect("io"),
        Enqueued::Written,
        "the notice takes none of the successor's per-subscription room"
    );
    assert_eq!(
        ready_ids(&store, now, &[]),
        vec!["e2".to_owned(), "evt_n1".to_owned()]
    );
    assert_eq!(
        ready_ids(&store, now, &["s1"]),
        vec!["evt_n1".to_owned()],
        "the successor's slot does not hold the notice"
    );
    let notice_key = format!("s1#{incarnation}");
    assert_eq!(
        ready_ids(&store, now, &[notice_key.as_str()]),
        vec!["e2".to_owned()],
        "the notice's slot does not hold the successor"
    );
}

/// CARRIER.2: a notice is claimed and signed with its ended row, not with
/// a successor granted under the same id since.
#[test]
fn a_notice_claims_and_signs_with_its_ended_row() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    end(&store, "s1", now, "evt_n1");
    regrant(&store, "s1", now, "whsec_y");
    let Claim::Ready(claimed) = store.claim("evt_n1", now).expect("io") else {
        panic!("the notice is claimable");
    };
    assert_eq!(claimed.subscription.secret, "whsec_x");
    assert_eq!(
        store
            .signing_row(&claimed.record)
            .expect("claimed: signs")
            .secret,
        "whsec_x"
    );
    let body: serde_json::Value =
        serde_json::from_slice(&claimed.record.body().expect("body")).expect("json");
    assert_eq!(body["name"], "subscription.ended");
    assert_eq!(body["eventId"], "evt_n1");
    assert_eq!(body["data"]["code"], -32012);
    assert_eq!(body["data"]["message"], "Forbidden");
    let mut keys: Vec<&String> = body.as_object().expect("object").keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        ["cursor", "data", "eventId", "name", "timestamp"],
        "no _meta"
    );
}

/// Claim notice `event_id` and settle it `outcome`.
fn claim_and_settle(store: &Store, event_id: &str, now: DateTime<Utc>, outcome: Settle) {
    let Claim::Ready(claimed) = store.claim(event_id, now).expect("io") else {
        panic!("{event_id} is claimable");
    };
    store
        .settle(event_id, claimed.record.created_at, outcome, Ok(now), ROOMY)
        .expect("io");
}

/// CARRIER.2: delivered, the notice takes its ended row and file; the
/// successor's status line is not written.
#[test]
fn a_delivered_notice_takes_its_ended_row_and_leaves_the_successor_alone() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    end(&store, "s1", now, "evt_n1");
    regrant(&store, "s1", now, "whsec_y");
    let before = store.get("s1").expect("successor");
    claim_and_settle(&store, "evt_n1", now, Settle::Delivered);
    assert!(store.ended_rows().is_empty());
    assert!(names(store.ended_dir()).is_empty());
    assert!(ready_ids(&store, now, &[]).is_empty(), "the record is gone");
    let after = store.get("s1").expect("successor");
    assert_eq!(
        (after.last_delivery_at, after.generation),
        (before.last_delivery_at, before.generation),
        "no status line written to the successor"
    );
}

/// CARRIER.2: a retry keeps the ended row; the next attempt signs from it.
#[test]
fn a_retried_notice_keeps_its_ended_row() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    end(&store, "s1", now, "evt_n1");
    let retry = Settle::Retry {
        next: now,
        status: "http_5xx",
    };
    claim_and_settle(&store, "evt_n1", now, retry);
    assert_eq!(store.ended_rows().len(), 1);
    assert_eq!(names(store.ended_dir()).len(), 1);
    assert_eq!(ready_ids(&store, now, &[]), vec!["evt_n1".to_owned()]);
}

/// CARRIER.2 (R10): a dead notice is buried as any record is, takes its
/// ended row, and is never replayed, not even onto a successor's live row.
#[test]
fn a_dead_notice_is_buried_takes_its_ended_row_and_is_not_replayed() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    end(&store, "s1", now, "evt_n1");
    let dead = Settle::Dead {
        reason: DeadReason::Exhausted,
        status: Some("http_5xx"),
    };
    claim_and_settle(&store, "evt_n1", now, dead);
    assert!(store.ended_rows().is_empty());
    assert!(names(store.ended_dir()).is_empty());
    let letter = store.dead_letter_by_id("evt_n1").expect("buried");
    regrant(&store, "s1", now, "whsec_y");
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    let revived = store
        .revive("evt_n1", letter.dead_at, letter.record, caps, || Ok(now))
        .expect("io");
    assert_eq!(revived, crate::events::store::Revived::NoSubscription);
    assert!(
        store.dead_letter_by_id("evt_n1").is_some(),
        "the letter stays"
    );
    assert!(ready_ids(&store, now, &[]).is_empty());
}

/// CARRIER.3 (R14): the owner's unsubscribe cancels the id's pending notices
/// and deletes their ended rows, along with the live row.
#[test]
fn an_owner_unsubscribe_cancels_the_notice_and_its_ended_row() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1", "s2"]);
    end(&store, "s1", now, "evt_n1");
    end(&store, "s2", now, "evt_n2");
    regrant(&store, "s1", now, "whsec_y");
    assert!(store.remove("s1", Ok(now), TAIL).expect("io"));
    assert_eq!(
        ready_ids(&store, now, &[]),
        vec!["evt_n2".to_owned()],
        "only the other id's notice is left"
    );
    let left: Vec<String> = store.ended_rows().into_iter().map(|e| e.row.id).collect();
    assert_eq!(left, vec!["s2".to_owned()]);
    assert_eq!(names(store.ended_dir()).len(), 1);
}

/// An ending keeps the pending notice of the id's earlier ending: one
/// notice per ended incarnation (R12b).
#[test]
fn a_second_ending_keeps_the_first_endings_notice() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    end(&store, "s1", now, "evt_n1");
    regrant(&store, "s1", now, "whsec_y");
    end(&store, "s1", now, "evt_n2");
    assert_eq!(
        ready_ids(&store, now, &[]),
        vec!["evt_n1".to_owned(), "evt_n2".to_owned()]
    );
    let mut secrets: Vec<String> = store
        .ended_rows()
        .into_iter()
        .map(|e| e.row.secret)
        .collect();
    secrets.sort();
    assert_eq!(secrets, vec!["whsec_x".to_owned(), "whsec_y".to_owned()]);
    assert_eq!(names(store.ended_dir()).len(), 2);
}

/// A successor that expires settles its own records; the earlier ending's
/// notice is not an expired row's record and stays due.
#[test]
fn an_expired_successor_leaves_the_notice_due() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    end(&store, "s1", now, "evt_n1");
    regrant(&store, "s1", now, "whsec_y");
    let caps = OutboxCaps {
        global: 10,
        per_subscription: 10,
    };
    store.enqueue(record("e2", "s1", now), caps).expect("io");
    let later = now + crate::duration_bound::delta!(hours, 2);
    assert_eq!(ready_ids(&store, later, &[]), vec!["evt_n1".to_owned()]);
    assert!(
        store.get("s1").is_none(),
        "premise: the successor expired away"
    );
    assert_eq!(store.ended_rows().len(), 1);
}

/// A record written before the field loads as an event (R26).
#[test]
fn a_record_written_before_the_field_loads_as_an_event() {
    let now = Utc::now();
    let mut value = serde_json::to_value(record("e1", "s1", now)).expect("json");
    assert!(
        value.get("ended_incarnation").is_none(),
        "premise: an event writes no field"
    );
    value["v"] = 1.into();
    let loaded: OutboxRecord = serde_json::from_value(value).expect("loads");
    assert!(loaded.is_event());
    assert_eq!(loaded.busy_key(), "s1");
}

/// The ended row's file round-trips as an ended row (the flattened row and
/// its stamp).
#[test]
fn an_ended_row_file_loads_back() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    end(&store, "s1", now, "evt_n1");
    let file = store.ended_dir().join(&names(store.ended_dir())[0]);
    let loaded: EndedRow =
        serde_json::from_slice(&std::fs::read(file).expect("file")).expect("an ended row");
    assert_eq!(
        (loaded.row.id.as_str(), loaded.ended.event_id.as_str()),
        ("s1", "evt_n1")
    );
}

/// CARRIER.3: with no live row left under the id, the owner's unsubscribe
/// still cancels the notice and deletes the ended row.
#[test]
fn an_owner_unsubscribe_with_only_an_ended_row_cancels_its_notice() {
    let dir = tempfile::tempdir().expect("dir");
    let now = Utc::now();
    let store = open_with(dir.path(), now, &["s1"]);
    end(&store, "s1", now, "evt_n1");
    assert!(store.get("s1").is_none(), "premise: no live row");
    assert!(store.remove("s1", Ok(now), TAIL).expect("io"), "found");
    assert!(
        ready_ids(&store, now, &[]).is_empty(),
        "the notice is cancelled"
    );
    assert!(store.ended_rows().is_empty());
    assert!(names(store.ended_dir()).is_empty());
}
