// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Settle: the payload lands unchanged and synced, only in the bound log;
//! a refusal claims nothing. Whether a payload holds paths, values or
//! secrets is its producer's (the journal's) to keep out; settle checks only
//! the fields it and the chain own.

use std::path::Path;
use std::sync::Arc;

use serde_json::{Map, Value, json};

use super::identity::LogId;
use super::identity_tests::swap_in;
use super::rotation_tests::{append, cfg, event, lines, log_path};
use super::segments::sibling;
use super::settle::{FailSettle, InvalidPayload, Reason, Role, SettledBy, Unsettled};
use super::*;

/// An outcome payload as the journal would freeze it.
pub(super) fn payload() -> Map<String, Value> {
    let settled_by = SettledBy {
        token: "attempt-1".into(),
        intent_counter: 7,
    };
    // `kind` carries the settle prefix (delta S2'), as the journal writes it.
    let v = json!({
        "kind": "settle.save",
        "intent_counter": 3,
        "result": "written",
        "reason": Reason::Committed,
        "settled_by": settled_by,
    });
    v.as_object().unwrap().clone()
}

/// The log's bytes and its mark's, to prove nothing was appended. A file
/// that is absent reads as empty; any other read error fails the row.
pub(super) fn on_disk(path: &Path) -> (Vec<u8>, Vec<u8>) {
    let read = |p: &Path| match std::fs::read(p) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => panic!("{}: {e}", p.display()),
    };
    (read(path), read(&sibling(path, "hwm")))
}

/// Every byte of the file behind `file`, read from its start.
fn whole(file: &mut std::fs::File) -> Vec<u8> {
    use std::io::{Read, Seek};
    file.rewind().unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    bytes
}

/// Settle an outcome for `token`, bound to `own`, that must land.
async fn settled(l: &Arc<TransparencyLogger>, own: &LogId, token: &str) {
    let got = l.settle(own, token, Role::Outcome, payload()).await;
    assert!(got.is_ok(), "{token}: {got:?}");
}

pub(super) fn records_of(path: &Path, token: &str) -> Vec<Value> {
    lines(path)
        .into_iter()
        .filter(|v| v["token"].as_str() == Some(token))
        .collect()
}

#[tokio::test]
async fn settle_appends_the_payload_unchanged_into_the_bound_log() {
    // GIVEN: a live logger with a record
    let dir = crate::test_dir_keep::kept_tempdir();
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
        let dir = crate::test_dir_keep::kept_tempdir();
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
        let after = l.settle(&own, "w-2", Role::Outcome, payload()).await;
        assert!(after.is_ok(), "presented: {presented}: {after:?}");
        assert!(records_of(&path, "w-1").is_empty());
        assert_eq!(records_of(&path, "w-2").len(), 1, "presented: {presented}");
    }
}

#[tokio::test]
async fn settle_after_its_log_was_replaced_lands_in_neither_log() {
    // GIVEN: a live logger, and another log swapped in under it
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    append(&l, 0);
    let binding = l.log_id();
    let other = crate::test_dir_keep::kept_tempdir();
    let theirs = log_path(&other);
    append(
        &TransparencyLogger::open(cfg(&theirs, 12, false)).unwrap(),
        0,
    );
    // A read handle on the original active file, which the swap unlinks.
    let mut original = std::fs::File::open(&path).unwrap();
    let original_bytes = whole(&mut original);
    swap_in(&theirs, &path);
    swap_in(&sibling(&theirs, "hwm"), &sibling(&path, "hwm"));

    // WHEN: it is settled with the binding it held
    let got = l.settle(&binding, "w-1", Role::Outcome, payload()).await;

    // THEN: OtherLog, found after the rebuild adopted the other id, and no
    // record names the token in either log
    assert!(matches!(got, Err(Unsettled::OtherLog)), "{got:?}");
    assert!(records_of(&path, "w-1").is_empty());
    assert!(records_of(&theirs, "w-1").is_empty());
    // Nor through the original file's inode: no append went to the old fd.
    assert_eq!(whole(&mut original), original_bytes);
}

#[tokio::test]
async fn a_refused_settle_appends_nothing() {
    for refusal in [
        "before",
        "event",
        "token",
        "counter",
        "outcome",
        "segment_seq",
    ] {
        // GIVEN: a live logger and the BeforeAppend seam, or a payload naming
        // a field settle (event, token), the chain (counter), the envelope
        // (outcome) or a segment (segment_seq) owns
        let dir = crate::test_dir_keep::kept_tempdir();
        let path = log_path(&dir);
        let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
        settled(&l, &l.log_id(), "w-0").await;
        let mut given = payload();
        match refusal {
            "before" => l.arm_settle_fault(FailSettle::BeforeAppend),
            key => drop(given.insert(key.into(), "forged".into())),
        }
        let before = on_disk(&path);

        // WHEN: it is settled
        let got = l.settle(&l.log_id(), "w-1", Role::Outcome, given).await;

        // THEN: Refused before the append, Invalid for a payload (no retry
        // can pass it), and the log and its mark are as before
        let want_invalid = refusal != "before";
        let invalid = matches!(got, Err(Unsettled::Invalid(InvalidPayload::ReservedField)));
        let refused = matches!(got, Err(Unsettled::Refused(_)));
        assert!(
            if want_invalid { invalid } else { refused },
            "{refusal}: {got:?}"
        );
        assert!(on_disk(&path) == before, "{refusal}");
        // The refusal was that call's only: the next settle lands.
        settled(&l, &l.log_id(), "w-2").await;
    }
}

#[tokio::test]
async fn a_settle_failing_after_its_append_is_unconfirmed() {
    // GIVEN: the AfterAppend seam
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    l.arm_settle_fault(FailSettle::AfterAppend);

    // WHEN: it is settled
    let got = l.settle(&l.log_id(), "w-1", Role::Outcome, payload()).await;

    // THEN: Unconfirmed, and the record is on disk
    assert!(matches!(got, Err(Unsettled::Unconfirmed(_))), "{got:?}");
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
    let dir = crate::test_dir_keep::kept_tempdir();
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
fn every_role_names_its_event() {
    // Expected names: II.3's record table (design-9318-B.md:270-275).
    use super::settle::IntentKind;
    let roles = [
        (Role::Intent(IntentKind::Save), "config_save_intent"),
        (Role::Intent(IntentKind::Adopt), "config_adopt_intent"),
        (Role::Intent(IntentKind::Restore), "config_restore_intent"),
        (Role::Intent(IntentKind::Backend), "config_backend_intent"),
        (Role::RecoveryIntent, "config_recovery_intent"),
        (Role::Outcome, "config_write_outcome"),
        (Role::Abandoned, "config_write_abandoned"),
        (Role::Deferred, "config_write_deferred"),
        (Role::DeliveryStopped, "config_write_delivery_stopped"),
    ];
    for (role, name) in roles {
        assert_eq!(role.event(), name, "{role:?}");
    }
}

#[test]
fn every_reason_has_one_wire_form() {
    // Expected spellings: II.3's closed reason list (design-9318-B.md:278-280)
    // and the deferral reasons in the deferred row (:274).
    let reasons = [
        (Reason::Committed, "committed"),
        (Reason::RolledBack, "rolled_back"),
        (Reason::KeptNew, "kept_new"),
        (Reason::NothingPending, "nothing_pending"),
        (Reason::DeletedDuringCompute, "deleted_during_compute"),
        (Reason::ComputeRefused, "compute_refused"),
        (Reason::SecretsRefused, "secrets_refused"),
        (Reason::WriterDied, "writer_died"),
        (Reason::Panicked, "panicked"),
        (Reason::OperatorAbandoned, "operator_abandoned"),
        (Reason::RenamedNotDurable, "renamed_not_durable"),
        (Reason::LeftToRecovery, "left_to_recovery"),
    ];
    for (reason, wire) in reasons {
        assert_eq!(serde_json::to_value(reason).unwrap(), wire, "{reason:?}");
    }
}
