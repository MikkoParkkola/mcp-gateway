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
            if !tamper {
                assert!(
                    verify(&path, signed).ok,
                    "honest lagging mark, signed {signed}"
                );
            }
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
        if !tamper {
            assert!(verify(&path, false).ok, "honest sealed mark");
        }
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

/// Bot-review ledger L1359: that repair record sits above the mark, so a
/// finding read at its own counter starts the loss there. The first counter
/// actually dropped is the line after the restored tail, and the finding the
/// restart carries forward must start at it.
#[test]
fn a_torn_repair_above_the_mark_records_the_first_dropped_counter() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(never_rotates(&path)).unwrap();
    (0..3).for_each(|i| append(&l, i));
    let older = std::fs::read(&path).unwrap();
    let first_dropped = lines(&path).last().unwrap()["counter"].as_u64().unwrap() + 1;
    (3..9).for_each(|i| append(&l, i));
    drop(l);
    let mut torn = older;
    torn.extend_from_slice(b"{\"counter\":4,\"ev");
    std::fs::write(&path, torn).unwrap();
    drop(TransparencyLogger::open(never_rotates(&path)).unwrap());
    let found = super::hwm_scan::hwm_missing_in(&path, &never_rotates(&path)).unwrap();
    assert_eq!(found, Some(first_dropped), "{:?}", lines(&path));
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

/// #2831 bot review: the active file rebuilt as sealed segment 0 followed by
/// the genuine records of segment 1 ends on the mark's own record, so counter
/// and hash agree with `.hwm`, yet it opens segment 0 while the mark names 1.
/// The restart must record that, and the next rotation must not seal it over
/// the genuine segment 0. Signed and unsigned: copied lines keep their sigs.
#[test]
fn a_tail_at_the_mark_restored_under_an_older_segment_is_a_finding() {
    use super::segments::sealed_path;
    for signed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let l = TransparencyLogger::open(cfg(&path, 12, signed)).unwrap();
        rotate_n(&l, &path, 1);
        (0..3).for_each(|i| append(&l, i));
        drop(l);
        let genuine_0 = std::fs::read(sealed_path(&path, 0)).unwrap();
        let mut rebuilt = genuine_0.clone();
        rebuilt.extend(std::fs::read(&path).unwrap());
        std::fs::write(&path, rebuilt).unwrap();
        let l = TransparencyLogger::open(cfg(&path, 12, signed)).unwrap();
        assert!(!marks(&path).is_empty(), "no finding (signed: {signed})");
        // Past a whole segment: rotate_n would count segments, and an
        // overwrite leaves the count unchanged.
        (0..50).for_each(|i| append(&l, i));
        drop(l);
        assert!(
            sealed_path(&path, 1).exists(),
            "no rotation happened, so nothing was tested (signed: {signed})"
        );
        assert_eq!(
            std::fs::read(sealed_path(&path, 0)).unwrap(),
            genuine_0,
            "a rotation overwrote sealed segment 0 (signed: {signed})"
        );
        assert!(!marks(&path).is_empty(), "finding lost (signed: {signed})");
    }
}

/// MIK-7949: an active file ending in a copied seal of an already sealed
/// segment is not a crash to finish. Before the fix the restart renamed it
/// over the genuine segment, here a one-line file replacing all of segment 1.
#[test]
fn a_copied_seal_of_a_sealed_segment_does_not_replace_it() {
    use super::segments::sealed_path;
    for signed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let l = TransparencyLogger::open(cfg(&path, 12, signed)).unwrap();
        rotate_n(&l, &path, 2);
        append(&l, 7);
        drop(l);
        let genuine_1 = std::fs::read(sealed_path(&path, 1)).unwrap();
        let seal = lines(&sealed_path(&path, 1)).pop().unwrap();
        assert_eq!(event(&seal), Some("audit_segment_sealed"));
        std::fs::write(&path, format!("{seal}\n")).unwrap();
        let l = TransparencyLogger::open(cfg(&path, 12, signed)).unwrap();
        assert_eq!(
            std::fs::read(sealed_path(&path, 1)).unwrap(),
            genuine_1,
            "the restart replaced sealed segment 1 (signed: {signed})"
        );
        assert!(!marks(&path).is_empty(), "no finding (signed: {signed})");
        (0..50).for_each(|i| append(&l, i));
        drop(l);
        assert!(
            sealed_path(&path, 2).exists(),
            "no rotation (signed: {signed})"
        );
        assert_eq!(
            std::fs::read(sealed_path(&path, 1)).unwrap(),
            genuine_1,
            "a rotation replaced sealed segment 1 (signed: {signed})"
        );
        assert!(!marks(&path).is_empty(), "finding lost (signed: {signed})");
    }
}

/// MIK-7949 (review): a sealed segment renamed to the last number makes the
/// next number wrap (debug panic, release 0) or saturate onto that name, so a
/// seal would replace a segment. The restart must refuse instead, active file
/// present or not, and leave every segment as it was.
#[test]
fn a_sealed_segment_at_the_last_number_is_refused_not_overwritten() {
    use super::segments::sealed_path;
    for keep_active in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
        rotate_n(&l, &path, 1);
        append(&l, 7);
        drop(l);
        let last = sealed_path(&path, u64::MAX);
        std::fs::rename(sealed_path(&path, 0), &last).unwrap();
        let genuine = std::fs::read(&last).unwrap();
        if !keep_active {
            std::fs::remove_file(&path).unwrap();
        }
        let opened = std::panic::catch_unwind(|| TransparencyLogger::open(cfg(&path, 12, false)));
        assert!(
            matches!(&opened, Ok(Err(e)) if e.kind() == std::io::ErrorKind::InvalidData),
            "restart did not refuse (active kept: {keep_active})"
        );
        assert_eq!(
            std::fs::read(&last).unwrap(),
            genuine,
            "active kept: {keep_active}"
        );
    }
}

/// Write `records` back as the active file, one JSON line each, as found.
fn write_lines(path: &std::path::Path, records: &[serde_json::Value]) {
    let mut text = String::new();
    for record in records {
        text.push_str(&record.to_string());
        text.push('\n');
    }
    std::fs::write(path, text).unwrap();
}

/// Restart a log whose mark lags its tail by one record, after `edit` has
/// changed the active file, and report whether the restart recorded a finding.
fn lagging_mark_restart_finds(
    signed: bool,
    edit: impl FnOnce(&mut Vec<serde_json::Value>),
) -> bool {
    mark_restart_finds(signed, Some(3), edit)
}

/// Restart a log of an opened record and five appends whose mark names
/// record `at` (`None`: the newest), after `edit` has changed the active file,
/// and report whether the restart recorded a finding.
fn mark_restart_finds(
    signed: bool,
    at: Option<usize>,
    edit: impl FnOnce(&mut Vec<serde_json::Value>),
) -> bool {
    use super::rotation_tests::SECRET;
    use super::segments::{HighWater, encode_hwm, write_hwm};
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let secret = if signed { SECRET.as_bytes() } else { b"" };
    let l = TransparencyLogger::open(cfg(&path, 12, signed)).unwrap();
    (0..5).for_each(|i| append(&l, i));
    drop(l);
    let mut records = lines(&path);
    let at = at.unwrap_or(records.len() - 1);
    let mark = HighWater {
        counter: records[at]["counter"].as_u64().unwrap(),
        entry_hash: records[at]["entry_hash"].as_str().unwrap().into(),
        segment_seq: 0,
    };
    write_hwm(&path, &encode_hwm(&mark, secret, "test").unwrap(), true).unwrap();
    edit(&mut records);
    write_lines(&path, &records);
    let l = TransparencyLogger::open(cfg(&path, 12, signed)).unwrap();
    append(&l, 9);
    drop(l);
    !marks(&path).is_empty()
}

/// The record the mark names is judged on its content, not on the hash it
/// carries: an edit that keeps the stored `entry_hash` is a finding, so
/// retention cannot later expire the edited record with nothing recorded.
#[test]
fn a_record_at_the_mark_edited_under_its_stored_hash_is_a_finding() {
    for signed in [false, true] {
        assert!(
            !lagging_mark_restart_finds(signed, |_| {}),
            "control, signed {signed}"
        );
        let found = lagging_mark_restart_finds(signed, |records| {
            records[3]["tampered"] = serde_json::Value::Bool(true);
        });
        assert!(found, "edited record at the mark accepted, signed {signed}");
    }
    // The hash leaves `sig` out, so on a signed log a replaced signature keeps
    // the stored and recomputed hashes; only the signature check sees it.
    let found = lagging_mark_restart_finds(true, |records| {
        records[3]["sig"] = serde_json::Value::String("0".repeat(64));
    });
    assert!(found, "a forged signature at the mark accepted");
}

/// The record at the mark is looked up with the scan's line bound: a line
/// over `MAX_RECORD_BYTES` is a finding, as `hwm_missing_in` counts it, and is
/// never read into memory whole.
#[test]
fn an_oversized_line_beside_the_mark_is_a_finding() {
    let found = lagging_mark_restart_finds(false, |records| {
        let filler = "x".repeat(super::rotation::MAX_RECORD_BYTES + 1);
        records.insert(2, serde_json::Value::String(filler));
    });
    assert!(found, "oversized line read past without a finding");
}

/// The mark can name the newest record itself (a clean shutdown): that record
/// is judged on its content too, or an edit under its stored hash, or a forged
/// signature, would pass a restart and later expire with nothing recorded.
#[test]
fn a_tail_at_the_mark_is_judged_on_its_content() {
    for signed in [false, true] {
        assert!(
            !mark_restart_finds(signed, None, |_| {}),
            "control, signed {signed}"
        );
        let found = mark_restart_finds(signed, None, |records| {
            records.last_mut().unwrap()["tampered"] = serde_json::Value::Bool(true);
        });
        assert!(found, "edited tail at the mark accepted, signed {signed}");
    }
    let found = mark_restart_finds(true, None, |records| {
        records.last_mut().unwrap()["sig"] = serde_json::Value::String("0".repeat(64));
    });
    assert!(found, "a forged signature on the tail at the mark accepted");
}
