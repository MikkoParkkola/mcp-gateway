// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settle: the payload lands unchanged and synced, only in the bound log;
//! a refusal claims nothing.

use std::path::Path;

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

fn records_of(path: &Path, token: &str) -> Vec<Value> {
    lines(path)
        .into_iter()
        .filter(|v| v["token"].as_str() == Some(token))
        .collect()
}

#[test]
fn settle_appends_the_payload_unchanged_into_the_bound_log() {
    // GIVEN: a live logger with a record
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&l, 0);

    // WHEN: an outcome is settled against the logger's own id
    let got = l.settle(&l.log_id(), "w-1", Role::Outcome, payload());

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

#[test]
fn settle_bound_to_another_log_appends_nothing() {
    for presented in [false, true] {
        // GIVEN: a binding that is not the logger's id: another id, or the
        // logger presenting another (the Bind(OtherLog) seam)
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
        let mut binding = LogId::mint();
        if presented {
            binding = l.log_id();
            l.present_log_id_for_test(LogId::mint());
        }
        let before = on_disk(&path);

        // WHEN: it is settled
        let got = l.settle(&binding, "w-1", Role::Outcome, payload());

        // THEN: OtherLog, and the log and its mark are byte-for-byte as before
        assert!(matches!(got, Err(Unsettled::OtherLog)), "{got:?}");
        assert!(on_disk(&path) == before, "presented: {presented}");
    }
}

#[test]
fn settle_after_its_log_was_replaced_lands_in_neither_log() {
    // GIVEN: a live logger, and another log swapped in under it
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
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
    let got = l.settle(&binding, "w-1", Role::Outcome, payload());

    // THEN: OtherLog, found after the rebuild adopted the other id, and no
    // record names the token in either log
    assert!(matches!(got, Err(Unsettled::OtherLog)), "{got:?}");
    assert!(records_of(&path, "w-1").is_empty());
    assert!(records_of(&theirs, "w-1").is_empty());
}
