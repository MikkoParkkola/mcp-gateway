// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A log whose active file vanished starts again with a new id, and that
//! identity change leaves a trace: the new genesis's open record names what
//! survived of the old log, the logger warns naming both ids, and verify
//! warns.

use serde_json::Value;

use super::rotation_tests::{append, cfg, event, lines, log_path, rewrite_line, rotate_n, verify};
use super::segments::{read_hwm, sibling};
use super::*;
use crate::test_log_capture::capture_warnings;

/// The open-record field naming what survived of a lost predecessor.
const PREDECESSOR: &str = "predecessor_missing";

/// The events of `records` in order, a caller record (no event) as "".
fn events(records: &[Value]) -> Vec<&str> {
    records.iter().map(|v| event(v).unwrap_or("")).collect()
}

#[test]
fn a_log_deleted_under_a_live_logger_names_its_predecessor() {
    for keep_hwm in [false, true] {
        // GIVEN: a live logger on an unrotated log with records
        let dir = crate::test_dir_keep::kept_tempdir();
        let path = log_path(&dir);
        let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
        append(&l, 0);
        let old = l.log_id();
        let mark = read_hwm(&path, b"", "test").unwrap();

        // WHEN: the active file is deleted (the mark kept or not), and it writes
        std::fs::remove_file(&path).unwrap();
        if !keep_hwm {
            std::fs::remove_file(sibling(&path, "hwm")).unwrap();
        }
        let ((), warned) = capture_warnings(|| append(&l, 1));

        // THEN: the new genesis's open record carries the evidence, then the
        // mark-missing record when the mark was kept, then the identified record
        let head = lines(&path);
        let want: &[&str] = if keep_hwm {
            &[
                rotation::EV_OPENED,
                rotation::EV_HWM_MISSING,
                identity::EV_IDENTIFIED,
                "",
            ]
        } else {
            &[rotation::EV_OPENED, identity::EV_IDENTIFIED, ""]
        };
        assert_eq!(events(&head), want, "{head:?}");
        let at = want.len() - 2;
        if keep_hwm {
            assert_eq!(head[0]["counter"].as_u64(), Some(mark.counter + 1));
            assert_eq!(head[0][rotation::HWM_MISSING_AT].as_u64(), Some(1));
        } else {
            assert_eq!(head[0]["counter"].as_u64(), Some(1));
        }
        let marker = &head[0][PREDECESSOR];
        assert_eq!(marker["previous_log_id"].as_str(), Some(old.as_str()));
        if keep_hwm {
            let hw = &marker["previous_high_water"];
            assert_eq!(hw["counter"].as_u64(), Some(mark.counter));
            assert_eq!(hw["entry_hash"].as_str(), Some(mark.entry_hash.as_str()));
        } else {
            assert!(marker.get("previous_high_water").is_none(), "{marker}");
        }

        // THEN: the logger holds the new id, raised as an identity change
        let new = l.log_id();
        assert_ne!(new, old, "keep_hwm: {keep_hwm}");
        assert_eq!(head[0]["log_id"].as_str(), Some(new.as_str()));
        assert_eq!(head[at]["log_id"].as_str(), Some(new.as_str()));
        let raised = l.subscribers.raised();
        assert!(raised.contains(&"log_id"), "{raised:?}");
        assert!(!raised.contains(&"tail"), "{raised:?}");
        assert!(
            warned.contains(&format!("previous_log_id={old}")),
            "{warned}"
        );
        assert!(warned.contains(&format!(" log_id={new}")), "{warned}");

        // THEN: verify reports the evidence by the old id; with the mark kept
        // it also fails, naming the deletion, before it authenticates the open
        // record, so the warning says the evidence is unverified
        let r = verify(&path, false);
        let named: Vec<&String> = r
            .warnings
            .iter()
            .filter(|w| w.contains(old.as_str()))
            .collect();
        assert_eq!(named.len(), 1, "{:?}", r.warnings);
        assert_eq!(named[0].contains("unverified"), keep_hwm, "{named:?}");
        if keep_hwm {
            let msg = r.error_message.unwrap_or_default();
            assert!(msg.contains("the active segment was deleted"), "{msg}");
        } else {
            assert!(r.ok, "{:?}", r.error_message);
        }
    }
}

#[test]
fn a_cold_fresh_log_and_its_reopen_record_no_predecessor() {
    // GIVEN: a fresh log, written and reopened
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let first = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&first, 0);
    drop(first);
    let again = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&again, 1);

    // THEN: no open record carries the field, and verify warns of none
    assert!(lines(&path).iter().all(|v| v.get(PREDECESSOR).is_none()));
    let r = verify(&path, false);
    assert!(r.ok, "{:?}", r.error_message);
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
}

#[test]
fn a_caller_cannot_append_an_open_record_naming_a_predecessor() {
    // GIVEN: a log
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let before = lines(&path).len();

    // WHEN: a caller writes an open record carrying the field
    let mut forged = serde_json::Map::new();
    forged.insert("event".into(), rotation::EV_OPENED.into());
    forged.insert(
        PREDECESSOR.into(),
        serde_json::json!({ "previous_log_id": "forged" }),
    );
    let refused = l.append_event(forged, &AuditEnvelope::gateway());

    // THEN: refused, nothing appended
    assert!(refused.is_err(), "open records are the logger's alone");
    assert_eq!(lines(&path).len(), before);
}

#[test]
fn a_caller_cannot_append_the_retired_predecessor_event() {
    // GIVEN: a log
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let before = lines(&path).len();

    // WHEN: a caller names the retired event
    let mut forged = serde_json::Map::new();
    forged.insert("event".into(), "audit_log_predecessor_missing".into());
    forged.insert("previous_log_id".into(), "forged".into());
    let refused = l.append_event(forged, &AuditEnvelope::gateway());

    // THEN: refused, nothing appended
    assert!(refused.is_err(), "the retired name stays the logger's");
    assert_eq!(lines(&path).len(), before);
}

#[test]
fn a_continuing_log_whose_active_file_vanished_names_no_predecessor() {
    for live in [false, true] {
        // GIVEN: a rotated log, its id on the sealed segment's open record
        let dir = crate::test_dir_keep::kept_tempdir();
        let path = log_path(&dir);
        let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
        let id = l.log_id();
        rotate_n(&l, &path, 1);
        append(&l, 0);

        // WHEN: its active file is deleted, then the live logger writes, or
        // a new logger opens it
        std::fs::remove_file(&path).unwrap();
        let after = if live {
            append(&l, 1);
            l.log_id()
        } else {
            drop(l);
            TransparencyLogger::open(cfg(&path, 12, false))
                .unwrap()
                .log_id()
        };

        // THEN: the same id, and the new open record names no predecessor
        assert_eq!(after, id, "live: {live}");
        let head = lines(&path);
        assert_eq!(event(&head[0]), Some(rotation::EV_OPENED), "{head:?}");
        assert!(
            head[0].get(PREDECESSOR).is_none(),
            "live: {live}: {}",
            head[0]
        );
    }
}

/// A log whose live logger saw its active file and mark deleted: its new
/// genesis open record names the old id only. Returns the log and that id.
fn replaced_genesis(dir: &tempfile::TempDir) -> (std::path::PathBuf, String) {
    let path = log_path(dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&l, 0);
    let old = l.log_id().as_str().to_string();
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_file(sibling(&path, "hwm")).unwrap();
    append(&l, 1);
    (path, old)
}

/// The warning a verified record naming `named` reads as.
fn verified_warning(path: &std::path::Path, named: &str) -> String {
    format!(
        "{} starts a new log after its predecessor went missing: {named}",
        path.display()
    )
}

/// Write `records` to `path` as they are: no re-chaining, so an edited
/// record keeps its stored `entry_hash` string.
fn write_lines(path: &std::path::Path, records: &[Value]) {
    let body = records
        .iter()
        .fold(String::new(), |acc, v| acc + &v.to_string() + "\n");
    std::fs::write(path, body).unwrap();
}

#[test]
fn the_predecessor_warning_shows_the_checked_record_not_a_swapped_one() {
    // GIVEN: the checked genesis open record, and the file's first line then
    // swapped for one naming another id under the same entry_hash string
    let dir = crate::test_dir_keep::kept_tempdir();
    let (path, old) = replaced_genesis(&dir);
    let mut all = lines(&path);
    let checked = all[0].clone();
    all[0][PREDECESSOR]["previous_log_id"] = "edited".into();
    write_lines(&path, &all);

    // WHEN: the warning is built for the checked record
    let warned = identity::predecessor_warning(&path, Some(&checked)).unwrap();

    // THEN: it names the checked evidence, verified, never the swapped one
    let want = verified_warning(&path, &format!("previous log_id {old}"));
    assert_eq!(warned.as_deref(), Some(want.as_str()));
}

#[test]
fn an_edited_predecessor_field_fails_the_chain_and_reads_unverified() {
    // GIVEN: a genesis open record whose evidence was edited, its entry_hash
    // string kept
    let dir = crate::test_dir_keep::kept_tempdir();
    let (path, _) = replaced_genesis(&dir);
    let mut all = lines(&path);
    all[0][PREDECESSOR]["previous_log_id"] = "edited".into();
    write_lines(&path, &all);

    // WHEN: it is verified
    let r = verify(&path, false);

    // THEN: the chain fails at that record, and the warning is unverified
    assert!(!r.ok, "an edited record cannot verify");
    let msg = r.error_message.unwrap_or_default();
    assert!(msg.contains("entry_hash mismatch"), "{msg}");
    let named: Vec<&String> = r.warnings.iter().filter(|w| w.contains("edited")).collect();
    assert_eq!(named.len(), 1, "{:?}", r.warnings);
    assert!(named[0].contains("unverified"), "{named:?}");
}

#[test]
fn a_clean_replacing_genesis_warns_verified_with_its_own_evidence() {
    // GIVEN: an untouched replacing genesis
    let dir = crate::test_dir_keep::kept_tempdir();
    let (path, old) = replaced_genesis(&dir);

    // WHEN: it is verified
    let r = verify(&path, false);

    // THEN: it passes, with exactly the checked record's evidence, verified
    assert!(r.ok, "{:?}", r.error_message);
    let want = verified_warning(&path, &format!("previous log_id {old}"));
    assert_eq!(r.warnings, [want]);
}

#[test]
fn an_evidence_object_with_no_parts_reads_as_no_evidence_fields() {
    // GIVEN: a genesis open record whose evidence object names nothing
    let dir = crate::test_dir_keep::kept_tempdir();
    let (path, _) = replaced_genesis(&dir);
    rewrite_line(&path, 0, |v| v[PREDECESSOR] = serde_json::json!({}));
    let checked = lines(&path).remove(0);

    // WHEN: the warning is built for it
    let warned = identity::predecessor_warning(&path, Some(&checked)).unwrap();

    // THEN: it says so, with no dangling separator
    let want = verified_warning(&path, "no evidence fields");
    assert_eq!(warned.as_deref(), Some(want.as_str()));
}

#[test]
fn a_first_line_swapped_after_the_chain_check_warns_with_the_checked_record() {
    // GIVEN: an untouched replacing genesis, and its first line swapped for
    // one naming another id (entry_hash string kept) once the chain check
    // has run and before the warning is built
    let dir = crate::test_dir_keep::kept_tempdir();
    let (path, old) = replaced_genesis(&dir);
    let swapped = path.clone();
    verify::AFTER_STREAM.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            let mut all = lines(&swapped);
            all[0][PREDECESSOR]["previous_log_id"] = "edited".into();
            write_lines(&swapped, &all);
        }));
    });

    // WHEN: it is verified
    let r = verify(&path, false);

    // THEN: the hook ran, and the warning shows the checked record, verified
    assert_eq!(lines(&path)[0][PREDECESSOR]["previous_log_id"], "edited");
    assert!(r.ok, "{:?}", r.error_message);
    let want = verified_warning(&path, &format!("previous log_id {old}"));
    assert_eq!(r.warnings, [want]);
}
