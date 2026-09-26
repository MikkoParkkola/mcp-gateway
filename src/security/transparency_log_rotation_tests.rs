// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D6 rotation tests: trigger, chain continuity, multi-segment verify,
//! retention, seams. Crash-recovery and disk-full rows live in
//! `transparency_log_recovery_tests.rs`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::segments::{list_segments, sealed_path, sibling};
use super::*;
use crate::security::audit_rotation_config::{OnDiskFull, RotationConfig};

pub(super) const SECRET: &str = "a-test-secret-that-is-at-least-32-bytes!!";

/// A 4 KiB-segment config. Built directly, not through
/// `RotationConfig::validate`, whose operator floor is 1 MiB.
pub(super) fn cfg(path: &Path, retain: u32, signed: bool) -> Arc<TransparencyLogConfig> {
    Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "test".into(),
        shared_secret: if signed { SECRET.into() } else { String::new() },
        rotation: RotationConfig {
            max_segment_bytes: 4096,
            max_segment_age_secs: 0,
            retain_segments: retain,
            on_disk_full: OnDiskFull::ExpireOldest,
        },
    })
}

pub(super) fn log_path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("transparency.jsonl")
}

pub(super) fn append(l: &TransparencyLogger, i: usize) {
    l.log_invocation(
        "s",
        "c",
        "srv",
        &format!("tool_{i}"),
        "sha256:aa",
        "sha256:bb",
    )
    .expect("append");
}

/// Append until `n` rotations have happened.
pub(super) fn rotate_n(l: &TransparencyLogger, path: &Path, n: usize) {
    let mut i = 0;
    let start = list_segments(path).unwrap().len();
    while list_segments(path).unwrap().len() < start + n {
        append(l, i);
        i += 1;
        assert!(i < 1_000, "no rotation happened");
    }
}

pub(super) fn lines(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

pub(super) fn event(v: &serde_json::Value) -> Option<&str> {
    v.get("event").and_then(serde_json::Value::as_str)
}

pub(super) fn verify(path: &Path, signed: bool) -> VerifyResult {
    verify_segments(path, &cfg(path, 12, signed), VerifyMode::Live).unwrap()
}

/// Rewrite one line of `file` with `edit`, re-chaining its hash (unsigned).
pub(super) fn rewrite_line(file: &Path, index: usize, edit: impl FnOnce(&mut serde_json::Value)) {
    let mut all = lines(file);
    edit(&mut all[index]);
    let hash = recompute_entry_hash(&all[index]).unwrap();
    all[index]["entry_hash"] = hash.into();
    let body = all
        .iter()
        .fold(String::new(), |acc, v| acc + &v.to_string() + "\n");
    std::fs::write(file, body).unwrap();
}

#[test]
fn rotates_at_max_segment_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 1);
    assert!(sealed_path(&path, 0).exists(), "segment .0 sealed");
    assert!(std::fs::metadata(&path).unwrap().len() < 4096);
}

#[test]
fn chain_continues_across_segments() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 3);
    let mut all = Vec::new();
    for seg in list_segments(&path).unwrap() {
        all.extend(lines(&seg.path));
    }
    all.extend(lines(&path));
    for pair in all.windows(2) {
        assert_eq!(
            pair[1]["counter"].as_u64(),
            pair[0]["counter"].as_u64().map(|c| c + 1)
        );
        assert_eq!(pair[1]["prev_entry_hash"], pair[0]["entry_hash"]);
    }
    let first = &lines(&path)[0];
    assert_eq!(event(first), Some(rotation::EV_OPENED));
    assert_eq!(first["prev_segment_final_hash"], first["prev_entry_hash"]);
}

/// Null control: must stay green on the unmutated build.
#[test]
fn verify_passes_multi_segment_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 3);
    append(&l, 0);
    let r = verify(&path, false);
    assert!(r.ok, "{:?}", r.error_message);
    assert_eq!(r.segments_checked, 4);
}

#[test]
fn verify_fails_on_missing_middle_segment() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 3);
    std::fs::remove_file(sealed_path(&path, 1)).unwrap();
    let r = verify(&path, false);
    assert!(!r.ok);
    assert!(r.error_message.unwrap().contains("segment 1"));
}

#[test]
fn verify_fails_on_hand_deleted_oldest() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 3);
    std::fs::remove_file(sealed_path(&path, 0)).unwrap();
    let r = verify(&path, false);
    assert!(!r.ok);
    assert!(r.error_message.unwrap().contains("no expiry record"));
}

#[test]
fn verify_passes_after_retention_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 2, false)).unwrap();
    rotate_n(&l, &path, 2);
    for _ in 0..3 {
        let newest = list_segments(&path).unwrap().last().unwrap().seq;
        let mut spins = 0;
        while list_segments(&path).unwrap().last().unwrap().seq == newest {
            append(&l, 0);
            spins += 1;
            assert!(spins < 1_000, "no rotation happened");
        }
    }
    let seqs: Vec<u64> = list_segments(&path)
        .unwrap()
        .iter()
        .map(|s| s.seq)
        .collect();
    assert_eq!(seqs, vec![3, 4], "the two newest survive");
    let r = verify(&path, false);
    assert!(r.ok, "{:?}", r.error_message);
    assert_eq!(r.segments_expired, 3);
}

#[test]
fn verify_fails_on_swapped_segment_names() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 3);
    let (a, b, tmp) = (
        sealed_path(&path, 1),
        sealed_path(&path, 2),
        sibling(&path, "x"),
    );
    std::fs::rename(&a, &tmp).unwrap();
    std::fs::rename(&b, &a).unwrap();
    std::fs::rename(&tmp, &b).unwrap();
    let r = verify(&path, false);
    assert!(!r.ok);
    let msg = r.error_message.unwrap();
    // `.1` now holds segment 2: the seq seam, not the prev link, must decide.
    assert!(
        msg.contains("holds segment_seq Some(2)"),
        "the seq seam decides: {msg}"
    );
}

#[test]
fn verify_rejects_wrong_active_segment_seq() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 2);
    drop(l);
    let newest = list_segments(&path).unwrap().last().unwrap().seq;
    rewrite_line(&path, 0, |v| v["segment_seq"] = (newest + 2).into());
    // Only the open record exists in the active file, so no later link breaks.
    let r = verify(&path, false);
    assert!(!r.ok);
    assert!(r.error_message.unwrap().contains("segment_seq"));
}

#[test]
fn list_segments_ignores_non_segment_siblings() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    for suffix in [
        "lock",
        "reserve",
        "hwm",
        "bak",
        "7",
        &"1".repeat(19),
        &"1".repeat(21),
    ] {
        std::fs::write(sibling(&path, suffix), b"x").unwrap();
    }
    std::fs::write(sealed_path(&path, 5), b"x").unwrap();
    let found: Vec<u64> = list_segments(&path)
        .unwrap()
        .iter()
        .map(|s| s.seq)
        .collect();
    assert_eq!(found, vec![5]);
}

#[test]
fn deleted_active_is_a_verify_gap() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 1);
    (0..5).for_each(|i| append(&l, i));
    drop(l);
    std::fs::remove_file(&path).unwrap();
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&l, 99);
    let r = verify(&path, false);
    assert!(!r.ok);
    assert!(
        r.error_message.unwrap().contains("missing"),
        "names the gap"
    );
}

#[test]
fn truncated_active_is_a_verify_gap() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 1);
    (0..5).for_each(|i| append(&l, i));
    drop(l);
    let mut all = lines(&path);
    all.truncate(all.len() - 2);
    std::fs::write(
        &path,
        all.iter()
            .fold(String::new(), |acc, v| acc + &v.to_string() + "\n"),
    )
    .unwrap();
    let r = verify(&path, false);
    assert!(!r.ok);
    assert!(r.error_message.unwrap().contains("at the tail"));
}

#[test]
fn deleted_hwm_fails_verify() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 1);
    std::fs::remove_file(sibling(&path, "hwm")).unwrap();
    assert!(!verify(&path, false).ok);
}

#[test]
fn forged_hwm_fails_signed_verify() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, true)).unwrap();
    rotate_n(&l, &path, 1);
    drop(l);
    // Reopen with room to spare, so the next five stay in this segment.
    let mut big = (*cfg(&path, 12, true)).clone();
    big.rotation.max_segment_bytes = 1024 * 1024;
    let l = TransparencyLogger::open(Arc::new(big)).unwrap();
    (0..5).for_each(|i| append(&l, i));
    drop(l);
    let mut all = lines(&path);
    all.truncate(all.len() - 2);
    std::fs::write(
        &path,
        all.iter()
            .fold(String::new(), |acc, v| acc + &v.to_string() + "\n"),
    )
    .unwrap();
    let tail = all.last().unwrap();
    let forged = segments::HighWater {
        counter: tail["counter"].as_u64().unwrap(),
        entry_hash: tail["entry_hash"].as_str().unwrap().into(),
        segment_seq: 1,
    };
    // Rewritten without the key: an empty MAC.
    segments::write_hwm(
        &path,
        &segments::encode_hwm(&forged, b"", "test").unwrap(),
        true,
    )
    .unwrap();
    assert!(!verify(&path, true).ok);
}

#[test]
fn torn_hwm_counts_as_missing() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 1);
    let hwm = sibling(&path, "hwm");
    let bytes = std::fs::read(&hwm).unwrap();
    std::fs::write(&hwm, &bytes[..bytes.len() / 2]).unwrap();
    assert!(!verify(&path, false).ok);
    let archive = verify_segments(&path, &cfg(&path, 12, false), VerifyMode::Archive).unwrap();
    assert!(archive.ok, "{:?}", archive.error_message);
    assert!(archive.warnings.iter().any(|w| w.contains("archive mode")));
}

#[test]
fn archive_mode_accepts_copy_without_hwm() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 2);
    drop(l);
    let copy = tempfile::tempdir().unwrap();
    let cpath = log_path(&copy);
    std::fs::copy(&path, &cpath).unwrap();
    for seg in list_segments(&path).unwrap() {
        std::fs::copy(&seg.path, sealed_path(&cpath, seg.seq)).unwrap();
    }
    let archive = verify_segments(&cpath, &cfg(&cpath, 12, false), VerifyMode::Archive).unwrap();
    assert!(archive.ok);
    assert!(
        !verify(&cpath, false).ok,
        "live mode still fails without .hwm"
    );
}

#[test]
fn verify_runs_when_active_absent() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 2);
    (0..3).for_each(|i| append(&l, i));
    drop(l);
    std::fs::remove_file(&path).unwrap();
    let r = verify(&path, false);
    assert!(!r.ok);
    assert!(r.segments_checked >= 2, "streamed the sealed segments");
    assert!(r.error_message.unwrap().contains("missing"));
}

#[test]
fn verify_with_live_appender_passes() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    rotate_n(&l, &path, 1);
    // Deterministic: a record lands after the stream ends. Reading `.hwm`
    // first means the stream is only ever ahead of it.
    let writer = Arc::clone(&l);
    verify::AFTER_STREAM.with(|h| *h.borrow_mut() = Some(Box::new(move || append(&writer, 7))));
    let r = verify(&path, false);
    assert!(r.ok, "{:?}", r.error_message);
    // And repeatedly across rotations.
    for _ in 0..3 {
        rotate_n(&l, &path, 1);
        assert!(verify(&path, false).ok);
    }
}

#[test]
fn signed_entry_only_in_sealed_segment_refuses_hash_only_verify() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, true)).unwrap();
    rotate_n(&l, &path, 1);
    drop(l);
    // Strip every sig from the active file: only `.0` holds one.
    let stripped = lines(&path).into_iter().fold(String::new(), |acc, mut v| {
        v.as_object_mut().unwrap().remove("sig");
        acc + &v.to_string() + "\n"
    });
    std::fs::write(&path, stripped).unwrap();
    assert!(log_contains_signed_entry(&path).unwrap());
}

#[test]
fn caller_cannot_append_segment_event() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let mut f = serde_json::Map::new();
    f.insert("event".into(), "audit_segment_expired".into());
    assert!(l.append_event(f, &AuditEnvelope::gateway()).is_err());
    let mut f = serde_json::Map::new();
    f.insert("segment_seq".into(), 3.into());
    assert!(l.append_event(f, &AuditEnvelope::gateway()).is_err());
}

#[test]
fn oversized_record_refused_without_degrading() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false))
        .unwrap()
        .with_failure_policy(crate::security::audit::AuditFailurePolicy::FailClosed);
    let mut f = serde_json::Map::new();
    f.insert("blob".into(), "x".repeat(5 * 1024 * 1024).into());
    assert!(l.append_event(f, &AuditEnvelope::gateway()).is_err());
    assert!(!l.is_degraded());
    append(&l, 1);
}

/// Coordinator ruling: the oversized exemption is a marker type, not an
/// `ErrorKind`, so a corrupt tail (`InvalidData`) on resync still degrades.
#[test]
fn corrupt_tail_on_resync_still_degrades() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false))
        .unwrap()
        .with_failure_policy(crate::security::audit::AuditFailurePolicy::FailClosed);
    append(&l, 1);
    let mut body = std::fs::read_to_string(&path).unwrap();
    body.push_str("{not json}\n");
    std::fs::write(&path, body).unwrap();
    let r = l.append_event_synced(serde_json::Map::new(), &AuditEnvelope::gateway());
    assert!(r.is_err());
    assert!(l.is_degraded());
}
