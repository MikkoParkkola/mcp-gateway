// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The log's `log_id`: minted once, reused by every reopen and rotation, kept
//! out of `.hwm`, and absent from no 4.0 segment's open record.

use std::path::Path;

use serde_json::Value;

use super::identity::EV_IDENTIFIED;
use super::rotation_tests::{append, cfg, event, lines, log_path, rotate_n, verify};
use super::segments::{HighWater, encode_hwm, list_segments, read_hwm, sibling, write_hwm};
use super::*;

/// Every record of the log, oldest segment first.
fn all_records(path: &Path) -> Vec<Value> {
    let mut all = Vec::new();
    for seg in list_segments(path).unwrap() {
        all.extend(lines(&seg.path));
    }
    all.extend(lines(path));
    all
}

pub(super) fn identified(path: &Path) -> Vec<Value> {
    let all = all_records(path);
    all.into_iter()
        .filter(|v| event(v) == Some(EV_IDENTIFIED))
        .collect()
}

/// Write `records` (their `entry_hash` dropped) to `file`, re-chained from
/// genesis; returns the last counter and entry hash.
pub(super) fn chain_file(
    file: &Path,
    records: impl IntoIterator<Item = serde_json::Map<String, Value>>,
) -> (u64, String) {
    let c = cfg(file, 12, false);
    let (mut prev, mut counter, mut body) = ("genesis".to_string(), 0_u64, String::new());
    for mut fields in records {
        fields.remove("entry_hash");
        counter += 1;
        let (line, hash) = chain_line(&c, fields, counter, &prev).unwrap();
        body += &(line + "\n");
        prev = hash;
    }
    std::fs::write(file, body).unwrap();
    (counter, prev)
}

/// Rewrite a one-segment log as `records`, re-chained, with `.hwm`
/// re-minted at the new tail in the same fixed layout.
pub(super) fn rechain(
    path: &Path,
    records: impl IntoIterator<Item = serde_json::Map<String, Value>>,
) {
    let (counter, entry_hash) = chain_file(path, records);
    let mark = HighWater {
        counter,
        entry_hash,
        segment_seq: 0,
    };
    // Remove first: an in-place rewrite would keep any longer tail.
    std::fs::remove_file(sibling(path, "hwm")).unwrap();
    write_hwm(path, &encode_hwm(&mark, b"", "test").unwrap(), true).unwrap();
}

/// The records of `file` as a beta log wrote them: no `log_id` on any
/// record, no identified record.
pub(super) fn beta_records(file: &Path) -> Vec<serde_json::Map<String, Value>> {
    lines(file)
        .into_iter()
        .filter(|v| event(v) != Some(EV_IDENTIFIED))
        .map(|v| {
            let mut fields = v.as_object().unwrap().clone();
            fields.remove("log_id");
            fields
        })
        .collect()
}

/// Rewrite a one-segment 4.0 log as a beta one.
pub(super) fn beta_shape(path: &Path) {
    rechain(path, beta_records(path));
}

#[test]
fn a_log_with_the_former_separate_predecessor_record_verifies_unchanged() {
    // GIVEN: a log in the shape the separate predecessor record left: an
    // open record without the evidence field, then that record
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let id = l.log_id();
    append(&l, 0);
    drop(l);
    let mut records: Vec<_> = lines(&path)
        .into_iter()
        .map(|v| v.as_object().unwrap().clone())
        .collect();
    let old = serde_json::json!({
        "event": "audit_log_predecessor_missing",
        "previous_log_id": "an-older-log",
    });
    records.insert(1, old.as_object().unwrap().clone());
    rechain(&path, records);
    assert!(lines(&path)[0].get("predecessor_missing").is_none());

    // WHEN: it is verified, then reopened
    let r = verify(&path, false);
    let again = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();

    // THEN: it verifies with no warning, and keeps its id and one identified
    // record
    assert!(r.ok, "{:?}", r.error_message);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    assert_eq!(again.log_id(), id);
    assert_eq!(identified(&path).len(), 1);
    assert!(verify(&path, false).ok);
}

#[test]
fn log_id_upgrade() {
    // GIVEN: a beta-shaped log that verifies
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let first = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&first, 0);
    drop(first);
    beta_shape(&path);
    let hwm_before = std::fs::read(sibling(&path, "hwm")).unwrap();
    assert!(identified(&path).is_empty(), "the fixture has no identity");
    assert!(verify(&path, false).ok, "a beta log verifies");

    // WHEN: 4.0 opens it, it is reopened, and it rotates
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let id = l.log_id();
    let upgraded = std::fs::read(sibling(&path, "hwm")).unwrap();
    // `.hwm` first, before any record or verify check: same fixed length as
    // the beta layout, and the id nowhere in it.
    assert_eq!(upgraded.len(), hwm_before.len(), "`.hwm` layout unchanged");
    assert!(!String::from_utf8_lossy(&upgraded).contains(id.as_str()));
    drop(l);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 1);

    // THEN: one identified record, one id everywhere, `.hwm` keeps its layout
    let found = identified(&path);
    assert_eq!(found.len(), 1, "minted once: {found:?}");
    assert_eq!(found[0]["log_id"].as_str(), Some(id.as_str()));
    assert_eq!(l.log_id(), id, "the id survives a reopen");
    let opened = lines(&path);
    assert_eq!(event(&opened[0]), Some(rotation::EV_OPENED));
    assert_eq!(opened[0]["log_id"].as_str(), Some(id.as_str()), "rotation");
    let hwm = std::fs::read(sibling(&path, "hwm")).unwrap();
    assert!(!String::from_utf8_lossy(&hwm).contains(id.as_str()));
    assert!(read_hwm(&path, b"", "test").is_some());
    let r = verify(&path, false);
    assert!(r.ok, "{:?}", r.error_message);
}

#[test]
fn a_caller_cannot_append_an_audit_log_identified_record() {
    // GIVEN: a log with its minted id
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let id = l.log_id();
    let before = all_records(&path).len();

    // WHEN: a caller tries to name another id
    let mut forged = serde_json::Map::new();
    forged.insert("event".into(), EV_IDENTIFIED.into());
    forged.insert("log_id".into(), "forged".into());
    let refused = l.append_event(forged, &AuditEnvelope::gateway());

    // THEN: it is refused, nothing is appended, and a reopen keeps the id
    assert!(refused.is_err(), "the event is the logger's alone");
    assert_eq!(all_records(&path).len(), before);
    drop(l);
    let again = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    assert_eq!(again.log_id(), id);
}

/// Replace `dst` with a copy of `src` through a rename, so `dst` is a new
/// file (a new inode) as another writer's swap would leave it.
pub(super) fn swap_in(src: &Path, dst: &Path) {
    let tmp = dst.with_extension("swap");
    std::fs::copy(src, &tmp).unwrap();
    std::fs::rename(&tmp, dst).unwrap();
}

#[test]
fn a_log_replaced_under_a_live_logger_is_adopted_with_its_id() {
    // GIVEN: a live logger on one log, and a second log with its own id
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&l, 0);
    let other = crate::test_dir_keep::kept_tempdir();
    let theirs = log_path(&other);
    let replacement = TransparencyLogger::open(cfg(&theirs, 12, false)).unwrap();
    append(&replacement, 0);
    let their_id = replacement.log_id().as_str().to_string();
    drop(replacement);
    assert_ne!(l.log_id().as_str(), their_id, "two logs, two ids");

    // WHEN: the second log replaces the first underneath it, whole (active
    // file and mark), and the live logger writes and then rotates
    swap_in(&theirs, &path);
    swap_in(&sibling(&theirs, "hwm"), &sibling(&path, "hwm"));
    append(&l, 1);
    rotate_n(&l, &path, 1);

    // THEN: the new segment carries the replacement's id, the logger holds
    // it, and the change was raised as an identity change
    let opened = lines(&path);
    assert_eq!(event(&opened[0]), Some(rotation::EV_OPENED));
    assert_eq!(opened[0]["log_id"].as_str(), Some(their_id.as_str()));
    assert_eq!(l.log_id().as_str(), their_id, "the logger adopted the id");
    let raised = l.subscribers.raised();
    assert!(raised.contains(&"log_id"), "raised: {raised:?}");
    assert!(!raised.contains(&"tail"), "raised: {raised:?}");
}

/// Cut a fresh log back to its genesis open record, as a crash after that
/// record and before the identified record leaves it: `marked` keeps a mark
/// at the open record (the crash after the first mark), else none.
fn unfinish_genesis(path: &Path, marked: bool) {
    let first = lines(path).remove(0);
    std::fs::write(path, first.to_string() + "\n").unwrap();
    std::fs::remove_file(sibling(path, "hwm")).unwrap();
    if marked {
        let mark = HighWater {
            counter: 1,
            entry_hash: first["entry_hash"].as_str().unwrap().to_string(),
            segment_seq: 0,
        };
        write_hwm(path, &encode_hwm(&mark, b"", "test").unwrap(), true).unwrap();
    }
}

#[test]
fn an_unfinished_genesis_gets_its_one_identified_record() {
    for marked in [true, false] {
        // GIVEN: a genesis open record carrying an id, and no identified record
        let dir = crate::test_dir_keep::kept_tempdir();
        let path = log_path(&dir);
        let id = TransparencyLogger::open(cfg(&path, 12, false))
            .unwrap()
            .log_id();
        unfinish_genesis(&path, marked);
        assert!(identified(&path).is_empty(), "the fixture has no id record");
        assert_eq!(lines(&path)[0]["log_id"].as_str(), Some(id.as_str()));

        // WHEN: it is reopened twice
        for _ in 0..2 {
            let again = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
            // THEN: the open record's id, every time
            assert_eq!(again.log_id(), id, "marked: {marked}");
        }

        // THEN: exactly one identified record, naming that id, and verify passes
        let found = identified(&path);
        assert_eq!(found.len(), 1, "marked: {marked}: {found:?}");
        assert_eq!(found[0]["log_id"].as_str(), Some(id.as_str()));
        let r = verify(&path, false);
        assert!(r.ok, "marked: {marked}: {:?}", r.error_message);
    }
}

#[test]
fn a_log_whose_identified_record_expired_gets_no_second_one() {
    // GIVEN: a log rotated until retention expired the segment that held its
    // identified record, so open records carry the id and no record names it
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let id = l.log_id();
    rotate_n(&l, &path, 2);
    drop(l);
    let trimmed = TransparencyLogger::open(cfg(&path, 1, false)).unwrap();
    append(&trimmed, 0);
    drop(trimmed);
    assert!(identified(&path).is_empty(), "retention took the id record");

    // WHEN: it is reopened
    let again = TransparencyLogger::open(cfg(&path, 1, false)).unwrap();

    // THEN: the same id, and still no identified record
    assert_eq!(again.log_id(), id);
    assert!(identified(&path).is_empty(), "no second identified record");
}

#[test]
fn a_log_whose_identified_record_expired_with_no_segment_left_gets_no_second_one() {
    // GIVEN: a log whose identified record expired with its segment, and
    // every sealed segment then gone, as the disk-full path's expiries leave
    // it: nothing sealed, and an active open record carrying the id
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let id = l.log_id();
    rotate_n(&l, &path, 2);
    drop(l);
    let trimmed = TransparencyLogger::open(cfg(&path, 1, false)).unwrap();
    append(&trimmed, 0);
    drop(trimmed);
    for seg in list_segments(&path).unwrap() {
        std::fs::remove_file(&seg.path).unwrap();
    }
    assert!(identified(&path).is_empty(), "the id record expired");
    assert_eq!(lines(&path)[0]["log_id"].as_str(), Some(id.as_str()));

    // WHEN: it is reopened twice
    for _ in 0..2 {
        let again = TransparencyLogger::open(cfg(&path, 1, false)).unwrap();
        assert_eq!(again.log_id(), id);
    }

    // THEN: still no identified record: a rotation's open record is no
    // unfinished genesis
    assert!(identified(&path).is_empty(), "no second identified record");
}

#[test]
fn a_torn_identified_record_is_repaired_exactly_once() {
    // The torn line cut mid-record, and cut by its closing byte only: both
    // fail to parse, so recovery drops them and records the drop on line 2.
    let cuts: [fn(usize) -> usize; 2] = [|n| n / 2, |n| n - 1];
    for keep in cuts {
        // GIVEN: a genesis whose identified record was torn mid-write
        let dir = crate::test_dir_keep::kept_tempdir();
        let path = log_path(&dir);
        let id = TransparencyLogger::open(cfg(&path, 12, false))
            .unwrap()
            .log_id();
        let whole = std::fs::read_to_string(&path).unwrap();
        let identified_line = whole.lines().nth(1).unwrap().to_string();
        unfinish_genesis(&path, true);
        let torn = &identified_line.as_bytes()[..keep(identified_line.len())];
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut f, torn).unwrap();
        drop(f);

        // WHEN: it is recovered twice
        for _ in 0..2 {
            let again = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
            assert_eq!(again.log_id(), id);
        }

        // THEN: exactly one identified record, naming the open record's id
        let found = identified(&path);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0]["log_id"].as_str(), Some(id.as_str()));
    }
}

#[test]
fn the_id_scan_finds_an_identified_record_after_an_oversized_line() {
    // GIVEN: a beta active file whose identified record follows a line over
    // the record cap
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let open = r#"{"event":"audit_segment_opened","segment_seq":0,"counter":1}"#;
    let huge = "x".repeat(rotation::MAX_RECORD_BYTES + 16);
    let named = r#"{"event":"audit_log_identified","log_id":"after-the-big-one"}"#;
    std::fs::write(&path, format!("{open}\n{huge}\n{named}\n")).unwrap();

    // WHEN: the id is resolved
    let found = identity::resolve(&path, &[]).unwrap();

    // THEN: the record past the oversized line is found
    assert_eq!(
        found.map(|id| id.as_str().to_string()).as_deref(),
        Some("after-the-big-one")
    );
}
