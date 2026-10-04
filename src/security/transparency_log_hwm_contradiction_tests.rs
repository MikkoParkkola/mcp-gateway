// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7884: a restart must not advance `.hwm` over a tail that contradicts
//! the mark (a replaced record at its counter, a restored older file, a record
//! gone from the log). Split from `transparency_log_hwm_missing_tests.rs`.

use super::hwm_missing_tests::{MARK, marks, never_rotates};
use super::rotation_tests::{append, cfg, event, lines, log_path, rewrite_line, rotate_n, verify};
use super::*;

/// MIK-7884 AC1: the record at `.hwm`'s counter is replaced by another that
/// chains (an unsigned log, re-hashed), then the gateway restarts and appends.
/// The restart must record the mismatch; before the fix the append advanced
/// `.hwm` over the replacement and Live verify passed.
#[test]
fn a_replaced_tail_is_not_laundered_by_a_restart_append() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(never_rotates(&path)).unwrap();
    (0..5).for_each(|i| append(&l, i));
    drop(l);
    let last = lines(&path).len() - 1;
    rewrite_line(&path, last, |v| v["tool"] = "replaced".into());
    let l = TransparencyLogger::open(never_rotates(&path)).unwrap();
    append(&l, 9);
    drop(l);
    assert!(!marks(&path).is_empty(), "the restart wrote no finding");
    let r = verify(&path, false);
    assert!(!r.ok, "a restart append laundered a replaced tail");
    assert!(r.error_message.unwrap().contains(MARK));
}

/// MIK-7884 AC2: an active file restored from an older segment (lower
/// counters, a different segment number than `.hwm` names) is below the mark.
/// Both signing modes: the mark is authenticated, so the tail is the
/// unauthenticated side.
#[test]
fn a_restored_active_from_an_older_segment_is_not_laundered() {
    for signed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let l = TransparencyLogger::open(cfg(&path, 12, signed)).unwrap();
        rotate_n(&l, &path, 1);
        append(&l, 100);
        let older = std::fs::read(&path).unwrap();
        rotate_n(&l, &path, 1);
        append(&l, 101);
        drop(l);
        let before_restore = lines(&path).last().unwrap()["counter"].as_u64().unwrap();
        std::fs::write(&path, older).unwrap();
        let l = TransparencyLogger::open(cfg(&path, 12, signed)).unwrap();
        append(&l, 102);
        drop(l);
        assert!(!marks(&path).is_empty(), "no finding (signed: {signed})");
        // The later sealed sibling stays, so verify rejects the restored file
        // on its own account too; the finding is the marker, and the counters
        // the restart wrote sit above the mark, never reusing a lost one.
        let r = verify(&path, signed);
        assert!(!r.ok, "a restored older active passed (signed: {signed})");
        let mark_counter = marks(&path)[0];
        assert!(
            mark_counter > before_restore,
            "the finding reused a counter at or below the mark (signed: {signed})"
        );
    }
}

/// MIK-7884 (seat review): a torn suffix after a replaced record at the mark.
/// The repair record puts the tail one ahead of the mark, so the plain
/// counter/hash comparison no longer sees the replacement; the record at the
/// mark's counter is compared as well.
#[test]
fn a_replaced_record_at_the_mark_is_found_when_a_torn_suffix_was_repaired() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(never_rotates(&path)).unwrap();
    (0..5).for_each(|i| append(&l, i));
    drop(l);
    let last = lines(&path).len() - 1;
    rewrite_line(&path, last, |v| v["tool"] = "replaced".into());
    let mut torn = std::fs::read(&path).unwrap();
    torn.extend_from_slice(b"{\"counter\":99,\"ev");
    std::fs::write(&path, torn).unwrap();
    let l = TransparencyLogger::open(never_rotates(&path)).unwrap();
    append(&l, 9);
    drop(l);
    assert!(!marks(&path).is_empty(), "the replacement went unrecorded");
    assert!(!verify(&path, false).ok);
}

/// MIK-7884: a mark that lags its tail (a crash between record and mark) is
/// honest while the record at the mark is intact, and a finding when the
/// record there is not what the mark recorded. Signed and unsigned.
#[test]
fn a_tail_ahead_of_the_mark_is_checked_against_the_record_at_the_mark() {
    use super::rotation_tests::SECRET;
    use super::segments::{HighWater, encode_hwm, read_hwm, write_hwm};
    for signed in [false, true] {
        for tamper in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = log_path(&dir);
            let secret = if signed { SECRET.as_bytes() } else { b"" };
            let l = TransparencyLogger::open(cfg(&path, 12, signed)).unwrap();
            (0..5).for_each(|i| append(&l, i));
            drop(l);
            let record = lines(&path)[3].clone();
            let mark = HighWater {
                counter: record["counter"].as_u64().unwrap(),
                entry_hash: if tamper {
                    "not-the-record-hash".into()
                } else {
                    record["entry_hash"].as_str().unwrap().into()
                },
                segment_seq: 0,
            };
            write_hwm(&path, &encode_hwm(&mark, secret, "test").unwrap(), true).unwrap();
            assert!(read_hwm(&path, secret, "test").is_some(), "mark readable");
            let l = TransparencyLogger::open(cfg(&path, 12, signed)).unwrap();
            append(&l, 9);
            drop(l);
            assert_eq!(
                !marks(&path).is_empty(),
                tamper,
                "signed {signed}, tampered {tamper}"
            );
        }
    }
}

/// MIK-7884: the mark can name a sealed segment (its record is the seal) while
/// the active file already holds the next open record; that record is checked
/// there too.
#[test]
fn a_mark_naming_a_sealed_segment_is_checked_against_its_seal() {
    use super::segments::{HighWater, encode_hwm, sealed_path, write_hwm};
    for tamper in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
        rotate_n(&l, &path, 1);
        drop(l);
        let seal = lines(&sealed_path(&path, 0)).pop().unwrap();
        assert_eq!(event(&seal), Some("audit_segment_sealed"));
        let mark = HighWater {
            counter: seal["counter"].as_u64().unwrap(),
            entry_hash: if tamper {
                "not-the-seal-hash".into()
            } else {
                seal["entry_hash"].as_str().unwrap().into()
            },
            segment_seq: 0,
        };
        write_hwm(&path, &encode_hwm(&mark, b"", "test").unwrap(), true).unwrap();
        let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
        append(&l, 9);
        drop(l);
        assert_eq!(!marks(&path).is_empty(), tamper, "tampered {tamper}");
    }
}

/// MIK-7884: a mark whose record is no longer in the log at all (cut out,
/// the tail left ahead of it) is a finding, not a restart.
#[test]
fn a_mark_whose_record_is_gone_from_the_log_is_a_finding() {
    use super::segments::{HighWater, encode_hwm, write_hwm};
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    (0..5).for_each(|i| append(&l, i));
    drop(l);
    let mut all = lines(&path);
    let gone = all.remove(3);
    let body = all
        .iter()
        .fold(String::new(), |acc, v| acc + &v.to_string() + "\n");
    std::fs::write(&path, body).unwrap();
    let mark = HighWater {
        counter: gone["counter"].as_u64().unwrap(),
        entry_hash: gone["entry_hash"].as_str().unwrap().into(),
        segment_seq: 0,
    };
    write_hwm(&path, &encode_hwm(&mark, b"", "test").unwrap(), true).unwrap();
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&l, 9);
    drop(l);
    assert!(!marks(&path).is_empty(), "a cut-out record went unrecorded");
}

/// MIK-7884 (seat review): the repair record of a torn suffix on a restored
/// older file takes a counter above the mark, never one already committed.
#[test]
fn a_repair_record_on_a_restored_older_file_reuses_no_committed_counter() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(never_rotates(&path)).unwrap();
    (0..3).for_each(|i| append(&l, i));
    let older = std::fs::read(&path).unwrap();
    (3..9).for_each(|i| append(&l, i));
    drop(l);
    let committed = lines(&path).last().unwrap()["counter"].as_u64().unwrap();
    let mut torn = older;
    torn.extend_from_slice(b"{\"counter\":4,\"ev");
    std::fs::write(&path, torn).unwrap();
    drop(TransparencyLogger::open(never_rotates(&path)).unwrap());
    let repair = lines(&path)
        .into_iter()
        .find(|v| event(v) == Some("audit_segment_torn_tail_dropped"))
        .expect("a repair record");
    assert!(
        repair["counter"].as_u64().unwrap() > committed,
        "the repair record reused a committed counter: {repair}"
    );
}

/// MIK-7884: the predicate's truth table, so each comparison is pinned alone
/// (the seal-finishing and after-seal recovery paths share it).
#[test]
fn a_tail_contradicts_the_mark_when_behind_it_or_replaced_at_it() {
    use super::hwm_scan::contradicts;
    use super::segments::HighWater;
    let mark = HighWater {
        counter: 10,
        entry_hash: "h10".into(),
        segment_seq: 3,
    };
    assert!(!contradicts(None, 1, "x"), "no mark, nothing to contradict");
    assert!(
        !contradicts(Some(&mark), 10, "h10"),
        "the mark's own record"
    );
    assert!(!contradicts(Some(&mark), 11, "any"), "ahead of the mark");
    assert!(contradicts(Some(&mark), 9, "h9"), "behind the mark");
    assert!(
        contradicts(Some(&mark), 10, "other"),
        "replaced at the mark"
    );
}

/// MIK-7884: a tail that matches the mark (same counter, same hash) is the
/// honest case and records nothing, in either signing mode.
#[test]
fn an_honest_restart_records_no_finding() {
    for signed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let l = TransparencyLogger::open(cfg(&path, 12, signed)).unwrap();
        rotate_n(&l, &path, 2);
        append(&l, 7);
        drop(l);
        let l = TransparencyLogger::open(cfg(&path, 12, signed)).unwrap();
        append(&l, 8);
        drop(l);
        assert!(marks(&path).is_empty(), "false finding (signed: {signed})");
        assert!(verify(&path, signed).ok, "signed: {signed}");
    }
}
