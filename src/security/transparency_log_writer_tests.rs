// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D6: more than one writer, trigger timing, and verify edge rows.

use std::sync::Arc;
use std::time::Duration;

use super::rotation::{EV_EXPIRED, EV_OPENED};
use super::rotation_tests::{
    SECRET, append, cfg, event, lines, log_path, rewrite_line, rotate_n, verify,
};
use super::segments::{list_segments, sealed_path};
use super::*;

#[test]
fn hot_path_append_follows_foreign_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let a = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let b = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&a, 0);
    b.append_event_synced(serde_json::Map::new(), &AuditEnvelope::gateway())
        .unwrap();
    rotate_n(&b, &path, 1);
    append(&a, 42); // hot path, no resync
    assert_eq!(lines(&path).pop().unwrap()["tool"], "tool_42");
    assert!(verify(&path, false).ok);
}

#[test]
fn second_process_append_follows_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let a = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    let b = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&a, &path, 1);
    let mut f = serde_json::Map::new();
    f.insert("who_wrote".into(), "b".into());
    b.append_event_synced(f, &AuditEnvelope::gateway()).unwrap();
    assert_eq!(lines(&path).pop().unwrap()["who_wrote"], "b");
    // B pushes the active file past the limit; A's next synced append must
    // see the new size and rotate first.
    while std::fs::metadata(&path).unwrap().len() < 4000 {
        b.append_event_synced(serde_json::Map::new(), &AuditEnvelope::gateway())
            .unwrap();
    }
    let sealed_before = list_segments(&path).unwrap().len();
    a.append_event_synced(serde_json::Map::new(), &AuditEnvelope::gateway())
        .unwrap();
    assert!(list_segments(&path).unwrap().len() > sealed_before);
    assert!(verify(&path, false).ok);
}

#[test]
fn synced_append_rotates_without_deadlock() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let (tx, rx) = std::sync::mpsc::channel();
    let p = path.clone();
    std::thread::spawn(move || {
        let l = TransparencyLogger::open(cfg(&p, 12, false)).unwrap();
        while list_segments(&p).unwrap().len() < 3 {
            l.append_event_synced(serde_json::Map::new(), &AuditEnvelope::gateway())
                .unwrap();
        }
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("synced rotation deadlocked on <path>.lock");
    assert!(verify(&path, false).ok);
}

#[test]
fn size_rotation_happens_before_the_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 2);
    for seg in list_segments(&path).unwrap() {
        let seal = lines(&seg.path).pop().unwrap().to_string().len() as u64 + 1;
        assert!(std::fs::metadata(&seg.path).unwrap().len() <= 4096 + seal);
    }
    // The record that triggered the rotation is the first after the open record.
    let active = lines(&path);
    assert_eq!(event(&active[0]), Some(EV_OPENED));
    assert!(active[1].get("tool").is_some());
}

#[test]
fn age_rotation_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let mut c = (*cfg(&path, 12, false)).clone();
    c.rotation.max_segment_bytes = 64 * 1024 * 1024;
    c.rotation.max_segment_age_secs = 60;
    let c = Arc::new(c);
    let l = TransparencyLogger::open(Arc::clone(&c)).unwrap();
    append(&l, 0);
    l.set_clock_offset(61);
    append(&l, 1); // pre-D6 segment 0 counts its age from open: rotates
    assert_eq!(list_segments(&path).unwrap().len(), 1);
    drop(l);
    // Reopen: the age comes from the open record, not the process start.
    let l = TransparencyLogger::open(c).unwrap();
    append(&l, 2);
    assert_eq!(list_segments(&path).unwrap().len(), 1, "not yet 60 s old");
    l.set_clock_offset(61 + 61);
    append(&l, 3);
    assert_eq!(list_segments(&path).unwrap().len(), 2);
}

#[test]
fn session_lookup_spans_segments() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    l.log_invocation("wanted", "c", "srv", "first", "a", "b")
        .unwrap();
    rotate_n(&l, &path, 1);
    l.log_invocation("wanted", "c", "srv", "second", "a", "b")
        .unwrap();
    let got = show_session_entries(&path, "wanted").unwrap();
    let tools: Vec<_> = got.iter().map(|e| e["tool"].as_str().unwrap()).collect();
    assert_eq!(tools, vec!["first", "second"]);
}

#[test]
fn verify_rejects_expiry_counter_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 1, false)).unwrap();
    rotate_n(&l, &path, 1);
    let before = list_segments(&path).unwrap()[0].seq;
    while list_segments(&path).unwrap()[0].seq == before {
        append(&l, 0);
    }
    drop(l);
    // Find the expiry for segment 0 and bump its last_counter.
    let files: Vec<_> = list_segments(&path)
        .unwrap()
        .into_iter()
        .map(|s| s.path)
        .chain([path.clone()])
        .collect();
    let (file, idx) = files
        .iter()
        .find_map(|f| {
            lines(f)
                .iter()
                .position(|v| event(v) == Some(EV_EXPIRED))
                .map(|i| (f.clone(), i))
        })
        .expect("an expiry record");
    rewrite_line(&file, idx, |v| {
        v["last_counter"] = (v["last_counter"].as_u64().unwrap() + 1).into();
    });
    // Re-chain the next line so only the anchor rule can decide.
    if lines(&file).len() > idx + 1 {
        let h = lines(&file)[idx]["entry_hash"].clone();
        rewrite_line(&file, idx + 1, |v| v["prev_entry_hash"] = h);
    }
    let r = verify(&path, false);
    assert!(!r.ok);
    assert!(
        r.error_message
            .unwrap()
            .contains("expiry record does not match")
    );
}

#[test]
fn forged_expiry_fails_signed_verify() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 1, true)).unwrap();
    rotate_n(&l, &path, 1);
    let before = list_segments(&path).unwrap()[0].seq;
    while list_segments(&path).unwrap()[0].seq == before {
        append(&l, 0);
    }
    // The logger's own expiry record is signed.
    let own = lines(&path)
        .into_iter()
        .chain(
            list_segments(&path)
                .unwrap()
                .iter()
                .flat_map(|s| lines(&s.path)),
        )
        .find(|v| event(v) == Some(EV_EXPIRED))
        .expect("expiry");
    assert!(own.get("sig").is_some(), "expiry records are HMAC-signed");
    drop(l);
    // An attacker deletes the oldest survivor and appends an unsigned expiry.
    let oldest = list_segments(&path).unwrap()[0].clone();
    std::fs::remove_file(&oldest.path).unwrap();
    let tail = lines(&path).pop().unwrap();
    let mut forged = serde_json::json!({
        "event": EV_EXPIRED, "segment_seq": oldest.seq,
        "counter": tail["counter"].as_u64().unwrap() + 1,
        "prev_entry_hash": tail["entry_hash"],
    });
    forged["entry_hash"] = recompute_entry_hash(&forged).unwrap().into();
    let mut body = std::fs::read_to_string(&path).unwrap();
    body += &forged.to_string();
    body.push('\n');
    std::fs::write(&path, body).unwrap();
    let signed = verify_segments(&path, &cfg(&path, 1, true), VerifyMode::Archive).unwrap();
    assert!(!signed.ok);
    let _ = SECRET;
}

#[test]
fn unrotated_v1_log_verifies_as_segment_zero() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    // A pre-D6 log: written with rotation effectively off, then reopened.
    let mut c = (*cfg(&path, 12, false)).clone();
    c.rotation.max_segment_bytes = u64::MAX;
    let l = TransparencyLogger::open(Arc::new(c)).unwrap();
    (0..20).for_each(|i| append(&l, i));
    drop(l);
    std::fs::remove_file(segments::sibling(&path, "hwm")).unwrap();
    assert!(verify(&path, false).ok, "no sealed segment: no hwm needed");
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 1);
    assert!(sealed_path(&path, 0).exists());
    assert!(verify(&path, false).ok);
}

// ── Final-review fixes (grok r1, kimi r1 on #1060) ───────────────────────────

/// The disk-full path can expire the last sealed segment. The active file
/// then holds segment N with no sibling to count from, and verify must not
/// read that as tampering.
#[test]
fn verify_passes_after_disk_full_drains_every_sealed_segment() {
    use super::rotation::WriteFault;
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false))
        .unwrap()
        .with_failure_policy(crate::security::audit::AuditFailurePolicy::FailClosed);
    rotate_n(&l, &path, 1);
    l.arm_write_fault(Some(WriteFault::FullUntilReserveFreed));
    append(&l, 1);
    l.arm_write_fault(None);
    assert!(l.write_faults_fired() > 0);
    assert!(
        list_segments(&path).unwrap().is_empty(),
        "the last sealed segment expired"
    );
    assert_eq!(lines(&path)[0]["segment_seq"], 1);
    let r = verify(&path, false);
    assert!(r.ok, "{:?}", r.error_message);
    assert_eq!(r.segments_expired, 1);
}

/// Altering a middle segment's seal breaks the next file's link.
#[test]
fn verify_fails_on_altered_middle_seal() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 3);
    drop(l);
    let middle = sealed_path(&path, 1);
    let last = lines(&middle).len() - 1;
    rewrite_line(&middle, last, |v| v["next_segment_seq"] = 2.into());
    rewrite_line(&middle, last, |v| {
        v["timestamp"] = "1970-01-01T00:00:00Z".into();
    });
    assert!(!verify(&path, false).ok);
}

/// Every boundary checks its own named link, not only `prev_entry_hash`: an
/// open record whose `prev_segment_final_hash` names another seal fails even
/// with every hash re-chained.
#[test]
fn verify_checks_prev_segment_final_hash_at_every_seam() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 3);
    drop(l);
    let seg1 = sealed_path(&path, 1);
    rewrite_line(&seg1, 0, |v| {
        v["prev_segment_final_hash"] = format!("sha256:{}", "0".repeat(64)).into();
    });
    // Re-chain everything after it, so only the seam rule can decide.
    let rechain = |file: &std::path::Path, from: usize, mut prev: serde_json::Value| {
        for i in from..lines(file).len() {
            rewrite_line(file, i, |v| v["prev_entry_hash"] = prev.clone());
            prev = lines(file)[i]["entry_hash"].clone();
        }
        prev
    };
    let relink = |file: &std::path::Path, tail: serde_json::Value| {
        rewrite_line(file, 0, |v| {
            v["prev_entry_hash"] = tail.clone();
            v["prev_segment_final_hash"] = tail.clone();
        });
        let head = lines(file)[0]["entry_hash"].clone();
        rechain(file, 1, head)
    };
    let head = lines(&seg1)[0]["entry_hash"].clone();
    let tail = rechain(&seg1, 1, head);
    let tail = relink(&sealed_path(&path, 2), tail);
    relink(&path, tail);
    std::fs::remove_file(segments::sibling(&path, "hwm")).unwrap();
    let r = verify_segments(&path, &cfg(&path, 12, false), VerifyMode::Archive).unwrap();
    assert!(!r.ok);
    assert!(r.error_message.unwrap().contains("prev_segment_final_hash"));
}

/// A log opened over its retention limit is trimmed on its first append.
#[test]
fn retention_runs_at_the_start_of_an_append() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 4);
    drop(l);
    let l = TransparencyLogger::open(cfg(&path, 1, false)).unwrap();
    l.log_invocation("s", "c", "srv", "tiny", "a", "b").unwrap();
    assert_eq!(
        list_segments(&path).unwrap().len(),
        1,
        "trimmed before any rotation"
    );
    assert!(verify(&path, false).ok);
}

#[test]
fn oversized_hwm_hash_is_a_named_error() {
    let mark = segments::HighWater {
        counter: 1,
        entry_hash: "x".repeat(400),
        segment_seq: 0,
    };
    let err = segments::encode_hwm(&mark, b"", "test").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("high-water mark"), "{err}");
}

/// Rotate once after each of the next `left` verify passes.
fn arm(l: Arc<TransparencyLogger>, path: std::path::PathBuf, left: u32) {
    verify::AFTER_STREAM.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            rotate_n(&l, &path, 1);
            if left > 1 {
                arm(l, path, left - 1);
            }
        }));
    });
}

/// A log that rotates under the reader twice in a row is reported as busy,
/// not as tampered.
#[test]
fn verify_reports_a_log_changing_under_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    rotate_n(&l, &path, 1);
    arm(Arc::clone(&l), path.clone(), 2);
    let err = verify_segments(&path, &cfg(&path, 12, false), VerifyMode::Live).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Interrupted);
    assert!(err.to_string().contains("changed during verification"));
}

/// The active file vanishing between the listing and the read (a rename by a
/// live rotation) is a retry, not a failed chain.
#[test]
fn verify_retries_when_a_listed_file_vanishes() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 1);
    drop(l);
    let (p, gone) = (path.clone(), segments::sibling(&path, "moved"));
    // Pass 1 lists the active file, which is then renamed away before the
    // read; pass 2 finds it restored and verifies cleanly.
    verify::LISTED.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            std::fs::rename(&p, &gone).unwrap();
            verify::BEFORE_STREAM.with(|h| {
                *h.borrow_mut() = Some(Box::new(move || std::fs::rename(&gone, &p).unwrap()));
            });
        }));
    });
    let r = verify(&path, false);
    assert!(r.ok, "{:?}", r.error_message);
}
