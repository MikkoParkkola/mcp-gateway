// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #2294: a restart that finds `.hwm` missing on a log that went through
//! segment handling chains an `audit_segment_hwm_missing` record before it
//! writes a fresh mark, so the restart cannot launder a cut tail. Live verify
//! fails on it, Archive warns, and the finding outlives the segment it was
//! written in.

use std::path::Path;
use std::sync::Arc;

use super::recovery_tests::expired_last_sealed_then_tail_cut;
use super::rotation::WriteFault;
use super::rotation_tests::{
    append, cfg, event, lines, log_path, rewrite_line, rotate_n, strip_genesis_open, verify,
};
use super::segments::{list_segments, sibling};
use super::*;
use crate::security::audit::AuditFailurePolicy;

const MARK: &str = "audit_segment_hwm_missing";

/// A config that never rotates.
fn never_rotates(path: &Path) -> Arc<TransparencyLogConfig> {
    let mut c = (*cfg(path, 12, false)).clone();
    c.rotation.max_segment_bytes = u64::MAX;
    Arc::new(c)
}

/// Counters of every marker record, sealed segments first.
fn marks(path: &Path) -> Vec<u64> {
    let mut files: Vec<_> = list_segments(path)
        .unwrap()
        .into_iter()
        .map(|s| s.path)
        .collect();
    files.push(path.to_path_buf());
    files
        .iter()
        .flat_map(|f| lines(f))
        .filter(|v| event(v) == Some(MARK))
        .map(|v| v["counter"].as_u64().unwrap())
        .collect()
}

fn delete_hwm(path: &Path) {
    std::fs::remove_file(sibling(path, "hwm")).unwrap();
}

fn cut_tail(path: &Path, n: usize) {
    let mut all = lines(path);
    all.truncate(all.len() - n);
    let body = all
        .iter()
        .fold(String::new(), |acc, v| acc + &v.to_string() + "\n");
    std::fs::write(path, body).unwrap();
}

/// A never-rotated new-format log with five appends, `.hwm` deleted and the
/// tail cut by two records.
fn never_rotated_then_tail_cut(path: &Path) {
    let l = TransparencyLogger::open(never_rotates(path)).unwrap();
    (0..5).for_each(|i| append(&l, i));
    drop(l);
    assert!(verify(path, false).ok, "positive control");
    delete_hwm(path);
    cut_tail(path, 2);
}

fn assert_live_fails_on_mark(path: &Path) {
    let r = verify(path, false);
    assert!(!r.ok, "a restart laundered the missing .hwm");
    let msg = r.error_message.unwrap();
    assert!(msg.contains(MARK), "{msg}");
}

#[test]
fn a_restart_marks_a_missing_hwm_on_a_never_rotated_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    never_rotated_then_tail_cut(&path);
    let l = TransparencyLogger::open(never_rotates(&path)).unwrap();
    assert_eq!(marks(&path).len(), 1, "one marker, written at open");
    assert_live_fails_on_mark(&path);
    append(&l, 9);
    drop(l);
    assert_live_fails_on_mark(&path);
}

#[test]
fn a_restart_marks_a_missing_hwm_after_the_last_sealed_expired() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    expired_last_sealed_then_tail_cut(&path);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&l, 9);
    drop(l);
    assert_eq!(marks(&path).len(), 1);
    assert_live_fails_on_mark(&path);
}

#[test]
fn a_restart_marks_a_missing_hwm_with_a_sealed_segment() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 1);
    append(&l, 0);
    drop(l);
    delete_hwm(&path);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&l, 9);
    drop(l);
    assert_eq!(marks(&path).len(), 1);
    assert_live_fails_on_mark(&path);
}

#[test]
fn archive_mode_warns_on_the_mark() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    never_rotated_then_tail_cut(&path);
    drop(TransparencyLogger::open(never_rotates(&path)).unwrap());
    let r = verify_segments(&path, &cfg(&path, 12, false), VerifyMode::Archive).unwrap();
    assert!(r.ok, "{:?}", r.error_message);
    assert!(
        r.warnings.iter().any(|w| w.contains(MARK)),
        "{:?}",
        r.warnings
    );
}

#[test]
fn archive_mode_still_fails_a_broken_chain_beside_the_mark() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    never_rotated_then_tail_cut(&path);
    let l = TransparencyLogger::open(never_rotates(&path)).unwrap();
    append(&l, 9);
    drop(l);
    rewrite_line(&path, 1, |v| v["tool"] = "forged".into());
    let r = verify_segments(&path, &cfg(&path, 12, false), VerifyMode::Archive).unwrap();
    assert!(!r.ok, "a broken chain passed in archive mode");
}

/// A crash between the marker and the fresh `.hwm` leaves the marker as the
/// last record: the next open re-mints the mark without stacking another.
#[test]
fn a_crash_before_the_fresh_hwm_does_not_stack_markers() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    never_rotated_then_tail_cut(&path);
    drop(TransparencyLogger::open(never_rotates(&path)).unwrap());
    let first = marks(&path);
    assert_eq!(first.len(), 1);
    delete_hwm(&path);
    drop(TransparencyLogger::open(never_rotates(&path)).unwrap());
    assert_eq!(marks(&path), first, "a second marker was stacked");
    assert_live_fails_on_mark(&path);
}

/// Retention deletes the segment holding the marker, then each segment whose
/// open record carried it: Live verify still fails.
#[test]
fn the_mark_outlives_retention() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 1, false)).unwrap();
    rotate_n(&l, &path, 1);
    drop(l);
    delete_hwm(&path);
    let l = TransparencyLogger::open(cfg(&path, 1, false)).unwrap();
    assert_eq!(marks(&path).len(), 1);
    // Counted by the newest sealed number: with `retain_segments: 1` the
    // number of sealed files stops growing. Five rotations expire the
    // marker's segment and then the segment holding the carrying record.
    let newest = |p: &Path| list_segments(p).unwrap().last().map_or(0, |s| s.seq + 1);
    let target = newest(&path) + 5;
    let mut i = 0;
    while newest(&path) < target {
        append(&l, i);
        i += 1;
        assert!(i < 5_000, "no rotation happened");
    }
    drop(l);
    assert!(marks(&path).is_empty(), "the marker's segment expired");
    assert_live_fails_on_mark(&path);
}

/// A JSON escape in the marker's event keeps its hash valid; expiry still
/// carries the finding, so no raw-text match can be the carry test.
#[test]
fn an_escaped_marker_still_outlives_retention() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 1, false)).unwrap();
    rotate_n(&l, &path, 1);
    drop(l);
    delete_hwm(&path);
    drop(TransparencyLogger::open(cfg(&path, 1, false)).unwrap());
    let raw = std::fs::read_to_string(&path).unwrap();
    let escaped = raw.replace(
        &format!("\"{MARK}\""),
        "\"\\u0061udit_segment_hwm_missing\"",
    );
    assert_ne!(raw, escaped, "the marker was rewritten");
    std::fs::write(&path, escaped).unwrap();
    assert_live_fails_on_mark(&path);
    let l = TransparencyLogger::open(cfg(&path, 1, false)).unwrap();
    let newest = |p: &Path| list_segments(p).unwrap().last().map_or(0, |s| s.seq + 1);
    let target = newest(&path) + 5;
    let mut i = 0;
    while newest(&path) < target {
        append(&l, i);
        i += 1;
        assert!(i < 5_000, "no rotation happened");
    }
    drop(l);
    assert!(marks(&path).is_empty(), "the marker's segment expired");
    assert_live_fails_on_mark(&path);
}

/// Mark a retain-1 log, append past the marker, apply `edit` to the active
/// file's text, restart, then rotate until the marker's segment is gone.
fn tamper_then_expire(edit: impl FnOnce(String) -> String) {
    tamper_then_expire_as(false, |_, raw| edit(raw));
}

fn tamper_then_expire_as(signed: bool, edit: impl FnOnce(&Path, String) -> String) {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 1, signed)).unwrap();
    rotate_n(&l, &path, 1);
    drop(l);
    delete_hwm(&path);
    let l = TransparencyLogger::open(cfg(&path, 1, signed)).unwrap();
    append(&l, 0);
    drop(l);
    let raw = std::fs::read_to_string(&path).unwrap();
    let edited = edit(&path, raw.clone());
    assert_ne!(raw, edited, "the edit changed the file");
    std::fs::write(&path, edited).unwrap();
    let l = TransparencyLogger::open(cfg(&path, 1, signed)).unwrap();
    let newest = |p: &Path| list_segments(p).unwrap().last().map_or(0, |s| s.seq + 1);
    let target = newest(&path) + 5;
    let mut i = 0;
    while newest(&path) < target {
        append(&l, i);
        i += 1;
        assert!(i < 5_000, "no rotation happened");
    }
    drop(l);
    assert!(marks(&path).is_empty(), "the marker's segment expired");
    let r = verify_segments(&path, &cfg(&path, 1, signed), VerifyMode::Live).unwrap();
    assert!(!r.ok, "a restart laundered the missing .hwm");
    let msg = r.error_message.unwrap();
    assert!(msg.contains(MARK), "{msg}");
}

/// On a signed log, dropping the marker and re-hashing the rest without the
/// secret leaves records whose signatures fail; recovery counts that.
#[test]
fn an_unsigned_rehash_of_a_signed_log_is_not_forgotten_at_restart() {
    tamper_then_expire_as(true, |_, raw| {
        // Counters are renumbered too, so only the signatures can tell.
        let mut prev: Option<(u64, String)> = None;
        let mut out = String::new();
        for line in raw.lines() {
            let mut v: serde_json::Value = serde_json::from_str(line).unwrap();
            if event(&v) == Some(MARK) {
                continue;
            }
            if let Some((c, h)) = &prev {
                v["counter"] = (c + 1).into();
                v["prev_entry_hash"] = h.clone().into();
            }
            if let Some(o) = v.as_object_mut() {
                o.remove("sig");
                o.remove("key_id");
            }
            let hash = recompute_entry_hash(&v).unwrap();
            v["entry_hash"] = hash.clone().into();
            prev = Some((v["counter"].as_u64().unwrap(), hash));
            out += &(v.to_string() + "\n");
        }
        out
    });
}

/// Rotate a retain-1 log `n` times, counted by the newest sealed number.
fn rotate_retained(l: &TransparencyLogger, path: &Path, n: u64) {
    let newest = |p: &Path| list_segments(p).unwrap().last().map_or(0, |s| s.seq + 1);
    let target = newest(path) + n;
    let mut i = 0;
    while newest(path) < target {
        append(l, i);
        i += 1;
        assert!(i < 5_000, "no rotation happened");
    }
}

/// The open record that carries the finding is cut from the active file:
/// the newest sealed segment still holds it, and the headless active is
/// itself a finding.
#[test]
fn a_cut_carrying_open_record_is_not_forgotten_at_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 1, true)).unwrap();
    rotate_n(&l, &path, 1);
    drop(l);
    delete_hwm(&path);
    let l = TransparencyLogger::open(cfg(&path, 1, true)).unwrap();
    rotate_retained(&l, &path, 1);
    append(&l, 0);
    drop(l);
    let first = lines(&path)[0].clone();
    assert!(
        first.get("hwm_missing_at").is_some(),
        "the open record carries it"
    );
    let raw = std::fs::read_to_string(&path).unwrap();
    let rest = raw.split_once('\n').unwrap().1.to_string();
    std::fs::write(&path, rest).unwrap();
    let l = TransparencyLogger::open(cfg(&path, 1, true)).unwrap();
    rotate_retained(&l, &path, 5);
    drop(l);
    assert!(marks(&path).is_empty(), "the marker's segment expired");
    let r = verify_segments(&path, &cfg(&path, 1, true), VerifyMode::Live).unwrap();
    assert!(!r.ok, "a cut open record laundered the finding");
    assert!(r.error_message.unwrap().contains(MARK));
}

/// Rotate until the active file's open record names `n` more segments.
fn rotate_by_open_seq(l: &TransparencyLogger, path: &Path, n: u64) {
    let seq = |p: &Path| lines(p)[0]["segment_seq"].as_u64().unwrap_or(0);
    let target = seq(path) + n;
    let mut i = 0;
    while seq(path) < target {
        append(l, i);
        i += 1;
        assert!(i < 5_000, "no rotation happened");
    }
}

/// With no sealed segment kept (`retain_segments: 0`), the active file's
/// carrying open record is the only copy of the finding: cutting it leaves a
/// headless file, which recovery must count as a finding itself.
#[test]
fn a_cut_open_record_with_no_sealed_copy_is_not_forgotten() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 0, true)).unwrap();
    rotate_by_open_seq(&l, &path, 1);
    drop(l);
    delete_hwm(&path);
    let l = TransparencyLogger::open(cfg(&path, 0, true)).unwrap();
    rotate_by_open_seq(&l, &path, 1);
    append(&l, 0);
    drop(l);
    assert!(
        list_segments(&path).unwrap().is_empty(),
        "no sealed copy kept"
    );
    assert!(
        lines(&path)[0].get("hwm_missing_at").is_some(),
        "the open record carries it"
    );
    let raw = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, raw.split_once('\n').unwrap().1).unwrap();
    let l = TransparencyLogger::open(cfg(&path, 0, true)).unwrap();
    rotate_by_open_seq(&l, &path, 3);
    drop(l);
    let r = verify_segments(&path, &cfg(&path, 0, true), VerifyMode::Live).unwrap();
    assert!(!r.ok, "a headless active laundered the finding");
    assert!(r.error_message.unwrap().contains(MARK));
}

/// A marker the mark already counts, torn at the tail, is a committed record:
/// its drop at restart is recorded again, not replaced by a clean repair.
#[test]
fn a_torn_committed_marker_is_not_forgotten_at_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 1, true)).unwrap();
    rotate_n(&l, &path, 1);
    drop(l);
    delete_hwm(&path);
    drop(TransparencyLogger::open(cfg(&path, 1, true)).unwrap());
    assert_eq!(event(lines(&path).last().unwrap()), Some(MARK));
    let raw = std::fs::read(&path).unwrap();
    std::fs::write(&path, &raw[..raw.len() - 5]).unwrap();
    let l = TransparencyLogger::open(cfg(&path, 1, true)).unwrap();
    rotate_retained(&l, &path, 5);
    drop(l);
    let r = verify_segments(&path, &cfg(&path, 1, true), VerifyMode::Live).unwrap();
    assert!(!r.ok, "a torn repair laundered the finding");
    assert!(r.error_message.unwrap().contains(MARK));
}

/// Whitespace past the scan's line bound keeps the marker's hash valid; a
/// line recovery cannot read counts as a finding, not as none.
#[test]
fn a_padded_marker_is_not_forgotten_at_restart() {
    tamper_then_expire(|raw| {
        let at = raw.find(&format!("\"{MARK}\"")).expect("marker present");
        let mut padded = raw.clone();
        padded.insert_str(at, &" ".repeat(super::rotation::MAX_RECORD_BYTES + 1));
        padded
    });
}

/// An edited marker fails its hash; recovery counts it as a finding.
#[test]
fn an_edited_marker_is_not_forgotten_at_restart() {
    tamper_then_expire(|raw| raw.replace(MARK, "audit_segment_hwm_mizzing"));
}

/// A deleted marker line breaks the link; recovery counts it as a finding.
#[test]
fn a_deleted_marker_is_not_forgotten_at_restart() {
    tamper_then_expire(|raw| {
        raw.lines()
            .filter(|l| !l.contains(MARK))
            .fold(String::new(), |acc, l| acc + l + "\n")
    });
}

/// Disk-full expiry of the segment holding the marker carries the finding.
#[test]
fn the_mark_outlives_disk_full_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    never_rotated_then_tail_cut(&path);
    let l = TransparencyLogger::open(cfg(&path, 12, false))
        .unwrap()
        .with_failure_policy(AuditFailurePolicy::FailClosed);
    rotate_n(&l, &path, 1);
    l.arm_write_fault(Some(WriteFault::FullUntilReserveFreed));
    append(&l, 1);
    l.arm_write_fault(None);
    append(&l, 2);
    drop(l);
    assert!(
        list_segments(&path).unwrap().is_empty(),
        "segment 0 expired"
    );
    assert!(marks(&path).is_empty(), "the marker's segment expired");
    assert_live_fails_on_mark(&path);
}

/// A crash after the first seal but before its rename, with `.hwm` missing:
/// recovery finishes the rotation and still marks the log.
#[test]
fn a_crash_between_seal_and_rename_is_marked() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 1);
    drop(l);
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(super::segments::sealed_path(&path, 0), &path).unwrap();
    assert_eq!(
        event(lines(&path).last().unwrap()),
        Some("audit_segment_sealed")
    );
    delete_hwm(&path);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&l, 9);
    drop(l);
    assert_eq!(marks(&path).len(), 1);
    assert_live_fails_on_mark(&path);
}

/// MIK-7884: the seal-finishing path (a crash after the seal record, before
/// the rename) shares the predicate. Its tail is the seal, so a mark ahead of
/// it, or at its counter with another hash, is a contradiction, not a restart.
#[test]
fn a_finished_seal_that_contradicts_the_mark_is_marked() {
    use super::segments::{HighWater, encode_hwm, write_hwm};
    for replaced_at_seal in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
        rotate_n(&l, &path, 1);
        drop(l);
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(super::segments::sealed_path(&path, 0), &path).unwrap();
        let seal = lines(&path).pop().unwrap();
        assert_eq!(event(&seal), Some("audit_segment_sealed"));
        if replaced_at_seal {
            // The mark sits at the seal's counter, recording another hash.
            let mark = HighWater {
                counter: seal["counter"].as_u64().unwrap(),
                entry_hash: "not-the-seal-hash".into(),
                segment_seq: 0,
            };
            write_hwm(&path, &encode_hwm(&mark, b"", "test").unwrap(), true).unwrap();
        }
        let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
        append(&l, 9);
        drop(l);
        assert!(
            !marks(&path).is_empty(),
            "no finding (replaced at the seal: {replaced_at_seal})"
        );
        // Verify fails too, on the missing counters or the marker: either way
        // the restart did not launder the contradiction.
        assert!(!verify(&path, false).ok, "replaced: {replaced_at_seal}");
    }
}

/// A pre-D6 log (no open record) keeps its re-minted mark and verifies clean.
#[test]
fn a_pre_d6_log_is_not_marked() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(never_rotates(&path)).unwrap();
    (0..3).for_each(|i| append(&l, i));
    drop(l);
    strip_genesis_open(&path);
    delete_hwm(&path);
    let l = TransparencyLogger::open(never_rotates(&path)).unwrap();
    append(&l, 9);
    drop(l);
    assert!(marks(&path).is_empty());
    let r = verify(&path, false);
    assert!(r.ok, "{:?}", r.error_message);
}

/// A crash before the first `.hwm` leaves only the genesis open record: a
/// clean log, not a marked one (#2275).
#[test]
fn a_genesis_only_log_is_not_marked() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    drop(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    let hwm = sibling(&path, "hwm");
    if hwm.exists() {
        delete_hwm(&path);
    }
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&l, 9);
    drop(l);
    assert!(marks(&path).is_empty());
    let r = verify(&path, false);
    assert!(r.ok, "{:?}", r.error_message);
}

/// MIK-7712 (#2340) AC1: the committed marker is cut whole, at a newline, with
/// `.hwm` kept. No line is torn, but the tail now ends below the mark, so the
/// restart records the loss again and the finding outlives retention.
#[test]
fn a_whole_line_cut_of_a_committed_marker_is_not_forgotten() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 1, true)).unwrap();
    rotate_n(&l, &path, 1);
    drop(l);
    delete_hwm(&path);
    drop(TransparencyLogger::open(cfg(&path, 1, true)).unwrap());
    assert_eq!(event(lines(&path).last().unwrap()), Some(MARK));
    cut_tail(&path, 1);
    let l = TransparencyLogger::open(cfg(&path, 1, true)).unwrap();
    rotate_retained(&l, &path, 5);
    drop(l);
    let r = verify_segments(&path, &cfg(&path, 1, true), VerifyMode::Live).unwrap();
    assert!(!r.ok, "a whole-line cut laundered the finding");
    assert!(r.error_message.unwrap().contains(MARK));
}

/// MIK-7712 (#2340) AC2: a crash between the torn-tail record and the marker.
/// The repair record at the committed counter is written, the marker is not,
/// and `.hwm` still names that counter: the state a full restart leaves once
/// its marker line is removed. The repair record itself carries the loss.
#[test]
fn a_crash_before_the_marker_keeps_a_committed_torn_drop() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 1, true)).unwrap();
    rotate_n(&l, &path, 1);
    drop(l);
    delete_hwm(&path);
    drop(TransparencyLogger::open(cfg(&path, 1, true)).unwrap());
    let raw = std::fs::read(&path).unwrap();
    std::fs::write(&path, &raw[..raw.len() - 5]).unwrap();
    drop(TransparencyLogger::open(cfg(&path, 1, true)).unwrap());
    let tail: Vec<_> = lines(&path).iter().rev().take(2).cloned().collect();
    assert_eq!(event(&tail[0]), Some(MARK), "the restart marked the drop");
    assert_eq!(
        event(&tail[1]),
        Some("audit_segment_torn_tail_dropped"),
        "{tail:?}"
    );
    // The crash: the marker never reached the disk.
    cut_tail(&path, 1);
    let l = TransparencyLogger::open(cfg(&path, 1, true)).unwrap();
    rotate_retained(&l, &path, 5);
    drop(l);
    let r = verify_segments(&path, &cfg(&path, 1, true), VerifyMode::Live).unwrap();
    assert!(!r.ok, "an interrupted recovery lost the committed drop");
    assert!(r.error_message.unwrap().contains(MARK));
}

/// MIK-7712 (#2340) AC3: the record at `.hwm`'s counter is replaced by another
/// that chains (an unsigned log, re-hashed). The counter still matches, but
/// the hash the mark recorded does not, and Live verify says so.
#[test]
fn verify_compares_the_hash_at_the_mark() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(never_rotates(&path)).unwrap();
    (0..5).for_each(|i| append(&l, i));
    drop(l);
    assert!(verify(&path, false).ok, "positive control");
    let last = lines(&path).len() - 1;
    rewrite_line(&path, last, |v| v["tool"] = "replaced".into());
    let r = verify(&path, false);
    assert!(!r.ok, "a replaced record at the mark passed");
    let msg = r.error_message.unwrap();
    assert!(
        msg.contains("high-water mark") && msg.contains("hash"),
        "{msg}"
    );
}

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

/// MIK-7712 AC1, review: the active segment holding the committed marker is
/// emptied (or deleted) with `.hwm` kept. The newest surviving record is then
/// the seal, below the mark, so the restart records the loss there too.
#[test]
fn an_emptied_active_below_the_mark_is_not_forgotten() {
    for delete in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(&dir);
        let l = TransparencyLogger::open(cfg(&path, 1, true)).unwrap();
        rotate_n(&l, &path, 1);
        drop(l);
        delete_hwm(&path);
        drop(TransparencyLogger::open(cfg(&path, 1, true)).unwrap());
        assert_eq!(event(lines(&path).last().unwrap()), Some(MARK));
        if delete {
            std::fs::remove_file(&path).unwrap();
        } else {
            std::fs::write(&path, b"").unwrap();
        }
        let l = TransparencyLogger::open(cfg(&path, 1, true)).unwrap();
        rotate_retained(&l, &path, 5);
        drop(l);
        let r = verify_segments(&path, &cfg(&path, 1, true), VerifyMode::Live).unwrap();
        assert!(
            !r.ok,
            "an emptied active laundered the finding (deleted: {delete})"
        );
        assert!(r.error_message.unwrap().contains(MARK), "deleted: {delete}");
    }
}

/// MIK-7712, review: after an emptied active, the restart writes the
/// replacement open record, then the marker. A crash between the two leaves
/// only the open record, which carries the loss itself.
#[test]
fn a_crash_after_the_replacement_open_record_keeps_the_loss() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 1, true)).unwrap();
    rotate_n(&l, &path, 1);
    drop(l);
    delete_hwm(&path);
    drop(TransparencyLogger::open(cfg(&path, 1, true)).unwrap());
    std::fs::write(&path, b"").unwrap();
    drop(TransparencyLogger::open(cfg(&path, 1, true)).unwrap());
    let active = lines(&path);
    assert_eq!(
        event(&active[0]),
        Some("audit_segment_opened"),
        "{active:?}"
    );
    assert_eq!(event(active.last().unwrap()), Some(MARK), "{active:?}");
    // The crash: the marker never reached the disk.
    cut_tail(&path, 1);
    let l = TransparencyLogger::open(cfg(&path, 1, true)).unwrap();
    rotate_retained(&l, &path, 5);
    drop(l);
    let r = verify_segments(&path, &cfg(&path, 1, true), VerifyMode::Live).unwrap();
    assert!(!r.ok, "a crash before the marker lost the finding");
    assert!(r.error_message.unwrap().contains(MARK));
}
