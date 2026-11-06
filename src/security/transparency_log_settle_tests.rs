// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settle: the payload lands unchanged and synced, only in the bound log;
//! a refusal claims nothing.

use std::path::Path;
use std::sync::Arc;

use serde_json::{Map, Value, json};

use super::identity::LogId;
use super::identity_tests::swap_in;
use super::rotation::WriteFault;
use super::rotation_tests::{append, cfg, event, lines, log_path};
use super::segments::sibling;
use super::settle::{FailSettle, Reason, Role, SettledBy, Unsettled};
use super::*;

/// An outcome payload as the journal would freeze it.
fn payload() -> Map<String, Value> {
    let settled_by = SettledBy {
        token: "attempt-1".into(),
        intent_counter: 7,
    };
    let v = json!({
        "intent_counter": 3,
        "result": "written",
        "reason": Reason::Committed,
        "settled_by": settled_by,
    });
    v.as_object().unwrap().clone()
}

/// The log's bytes and its mark's, to prove nothing was appended.
fn on_disk(path: &Path) -> (Vec<u8>, Vec<u8>) {
    let read = |p: &Path| std::fs::read(p).unwrap_or_default();
    (read(path), read(&sibling(path, "hwm")))
}

/// Settle an outcome for `token`, bound to `own`, that must land.
async fn settled(l: &Arc<TransparencyLogger>, own: &LogId, token: &str) {
    let got = l.settle(own, token, Role::Outcome, payload()).await;
    assert!(got.is_ok(), "{token}: {got:?}");
}

fn records_of(path: &Path, token: &str) -> Vec<Value> {
    lines(path)
        .into_iter()
        .filter(|v| v["token"].as_str() == Some(token))
        .collect()
}

#[tokio::test]
async fn settle_appends_the_payload_unchanged_into_the_bound_log() {
    // GIVEN: a live logger with a record
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    append(&l, 0);

    // WHEN: an outcome is settled against the logger's own id
    let got = l.settle(&l.log_id(), "w-1", Role::Outcome, payload()).await;

    // THEN: it is the log's last record on disk, at the counter returned,
    // with the role's event, the token and every payload field as given
    let appended = got.unwrap_or_else(|e| panic!("refused: {e:?}"));
    assert_eq!(appended.id, l.log_id());
    let last = lines(&path).pop().unwrap();
    assert_eq!(last["counter"].as_u64(), Some(appended.counter));
    assert_eq!(event(&last), Some("config_write_outcome"));
    assert_eq!(last["token"], "w-1");
    for (key, value) in payload() {
        assert_eq!(last[&key], value, "{key}");
    }
    assert_eq!(last["reason"], "committed");
    assert_eq!(
        last["settled_by"],
        json!({"token": "attempt-1", "intent_counter": 7})
    );
}

#[tokio::test]
async fn settle_bound_to_another_log_appends_nothing() {
    for presented in [false, true] {
        // GIVEN: a binding that is not the logger's id: another id, or the
        // logger presenting another (the Bind(OtherLog) seam)
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
        // `own` is the id settle sees as the logger's.
        let (mut binding, mut own) = (LogId::mint(), l.log_id());
        if presented {
            (binding, own) = (own, LogId::mint());
            l.present_log_id_for_test(own.clone());
        }
        settled(&l, &own, "w-0").await;
        let before = on_disk(&path);

        // WHEN: it is settled, between two settles bound to the logger's id
        let got = l.settle(&binding, "w-1", Role::Outcome, payload()).await;

        // THEN: OtherLog, and the log and its mark are byte-for-byte as before;
        // the settles around it land
        assert!(matches!(got, Err(Unsettled::OtherLog)), "{got:?}");
        assert!(on_disk(&path) == before, "presented: {presented}");
        settled(&l, &own, "w-2").await;
    }
}

#[tokio::test]
async fn settle_after_its_log_was_replaced_lands_in_neither_log() {
    // GIVEN: a live logger, and another log swapped in under it
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    append(&l, 0);
    let binding = l.log_id();
    let other = tempfile::tempdir().unwrap();
    let theirs = log_path(&other);
    append(
        &TransparencyLogger::open(cfg(&theirs, 12, false)).unwrap(),
        0,
    );
    swap_in(&theirs, &path);
    swap_in(&sibling(&theirs, "hwm"), &sibling(&path, "hwm"));

    // WHEN: it is settled with the binding it held
    let got = l.settle(&binding, "w-1", Role::Outcome, payload()).await;

    // THEN: OtherLog, found after the rebuild adopted the other id, and no
    // record names the token in either log
    assert!(matches!(got, Err(Unsettled::OtherLog)), "{got:?}");
    assert!(records_of(&path, "w-1").is_empty());
    assert!(records_of(&theirs, "w-1").is_empty());
}

#[tokio::test]
async fn a_refused_settle_appends_nothing() {
    for refusal in ["sync", "before", "event", "token"] {
        // GIVEN: a live logger, a failing sync, the BeforeAppend seam, or a
        // payload that names the event or the token itself
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
        settled(&l, &l.log_id(), "w-0").await;
        let mut given = payload();
        match refusal {
            "sync" => l.arm_write_fault(Some(WriteFault::SyncError)),
            "before" => l.arm_settle_fault(FailSettle::BeforeAppend),
            key => drop(given.insert(key.into(), "forged".into())),
        }
        let before = on_disk(&path);

        // WHEN: it is settled
        let got = l.settle(&l.log_id(), "w-1", Role::Outcome, given).await;

        // THEN: Refused, and the log and its mark are as before
        assert!(
            matches!(got, Err(Unsettled::Refused(_))),
            "{refusal}: {got:?}"
        );
        assert!(on_disk(&path) == before, "{refusal}");
        // The refusal was that call's only: the next settle lands.
        settled(&l, &l.log_id(), "w-2").await;
    }
}

#[tokio::test]
async fn a_settle_refused_after_its_append_leaves_the_record_for_dedup() {
    // GIVEN: the AfterAppend seam
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    l.arm_settle_fault(FailSettle::AfterAppend);

    // WHEN: it is settled
    let got = l.settle(&l.log_id(), "w-1", Role::Outcome, payload()).await;

    // THEN: Refused, with the synced record on disk: the replay repeats it
    // and the reader collapses the pair
    assert!(matches!(got, Err(Unsettled::Refused(_))), "{got:?}");
    assert_eq!(records_of(&path, "w-1").len(), 1);
}

#[test]
fn settle_events_name_their_role_and_callers_cannot_write_them() {
    let roles = [
        (Role::Outcome, "config_write_outcome"),
        (Role::Abandoned, "config_write_abandoned"),
        (Role::Deferred, "config_write_deferred"),
        (Role::DeliveryStopped, "config_write_delivery_stopped"),
    ];
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    for (role, name) in roles {
        assert_eq!(role.event(), name);
        // A caller naming the event is refused, and nothing is appended.
        let before = on_disk(&path);
        let mut forged = Map::new();
        forged.insert("event".into(), name.into());
        let refused = l.append_event(forged, &AuditEnvelope::gateway());
        assert!(refused.is_err(), "{name}");
        assert!(on_disk(&path) == before, "{name}");
        // A neighbouring caller event is still accepted.
        let mut plain = Map::new();
        plain.insert("event".into(), "config_write_note".into());
        assert!(l.append_event(plain, &AuditEnvelope::gateway()).is_ok());
    }
}

#[test]
fn reasons_have_one_wire_form_each() {
    let wire = |r: Reason| serde_json::to_value(r).unwrap();
    assert_eq!(wire(Reason::RolledBack), "rolled_back");
    assert_eq!(wire(Reason::OperatorAbandoned), "operator_abandoned");
    assert_eq!(wire(Reason::RenamedNotDurable), "renamed_not_durable");
}
