// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D6 crash recovery, disk-full and cross-writer tests. Every recovery row
//! runs on a thread joined with a 10 s timeout, so a `<path>.lock`
//! re-acquire fails the test instead of hanging CI.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::rotation::{EV_EXPIRED, EV_SEALED, EV_TORN, WriteFault};
use super::rotation_tests::{append, cfg, event, lines, log_path, rotate_n, verify};
use super::segments::{list_segments, sealed_path, sibling};
use super::*;
use crate::security::audit::AuditFailurePolicy;
use crate::security::audit_rotation_config::OnDiskFull;

/// Run `f` on a thread; fail if it does not finish within 10 s.
fn within_10s<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("timed out: a lock was re-acquired under a held guard")
}

fn open(path: &Path, retain: u32) -> TransparencyLogger {
    TransparencyLogger::open(cfg(path, retain, false)).unwrap()
}

/// Write a log with one sealed segment, then return the active file's lines.
fn one_rotation(path: &Path) -> Vec<serde_json::Value> {
    let l = open(path, 12);
    rotate_n(&l, path, 1);
    drop(l);
    lines(path)
}

/// A real crash mid-rotation leaves `.hwm` at the seal: point it there,
/// since the fixtures build the crash state from a completed rotation.
fn hwm_at_seal(path: &Path) -> serde_json::Value {
    let seal = lines(&sealed_path(path, 0)).pop().unwrap();
    let hw = segments::HighWater {
        counter: seal["counter"].as_u64().unwrap(),
        entry_hash: seal["entry_hash"].as_str().unwrap().into(),
        segment_seq: 0,
    };
    segments::write_hwm(path, &segments::encode_hwm(&hw, b"", "test").unwrap(), true).unwrap();
    seal
}

#[test]
fn recovers_crash_after_seal() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    one_rotation(&path);
    // Rebuild the state "seal written, rename not done": move `.0` back.
    std::fs::remove_file(&path).unwrap();
    hwm_at_seal(&path);
    std::fs::rename(sealed_path(&path, 0), &path).unwrap();
    assert_eq!(event(lines(&path).last().unwrap()), Some(EV_SEALED));
    let p = path.clone();
    within_10s(move || {
        let l = open(&p, 12);
        append(&l, 1);
    });
    assert!(sealed_path(&path, 0).exists(), "rotation finished");
    assert!(verify(&path, false).ok);
}

#[test]
fn recovers_crash_after_rename() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    one_rotation(&path);
    std::fs::remove_file(&path).unwrap(); // seal + rename, no active
    // The hwm still names the seal counter, so no gap is reported.
    let seal = hwm_at_seal(&path);
    let p = path.clone();
    within_10s(move || drop(open(&p, 12)));
    assert_eq!(lines(&path)[0]["prev_entry_hash"], seal["entry_hash"]);
    assert!(verify(&path, false).ok);
}

#[test]
fn recovers_crash_after_create_before_open_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    one_rotation(&path);
    std::fs::write(&path, b"").unwrap(); // empty active beside a sealed `.0`
    let seal = hwm_at_seal(&path);
    let p = path.clone();
    within_10s(move || drop(open(&p, 12)));
    let first = &lines(&path)[0];
    assert_ne!(first["prev_entry_hash"], "genesis");
    assert_eq!(first["prev_entry_hash"], seal["entry_hash"]);
    assert!(verify(&path, false).ok);
}

#[test]
fn torn_open_record_is_truncated_and_rewritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let active = one_rotation(&path);
    let open_line = active[0].to_string();
    std::fs::write(&path, &open_line.as_bytes()[..open_line.len() / 2]).unwrap();
    hwm_at_seal(&path);
    let p = path.clone();
    within_10s(move || drop(open(&p, 12)));
    assert!(verify(&path, false).ok);
}

#[test]
fn torn_tail_dropped_is_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = open(&path, 12);
    (0..3).for_each(|i| append(&l, i));
    drop(l);
    let mut body = std::fs::read(&path).unwrap();
    body.extend_from_slice(b"{\"counter\":4,\"half");
    std::fs::write(&path, body).unwrap();
    let p = path.clone();
    within_10s(move || drop(open(&p, 12)));
    assert_eq!(event(lines(&path).last().unwrap()), Some(EV_TORN));
    assert!(verify(&path, false).ok);
}

#[test]
fn newline_less_valid_record_is_kept() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = open(&path, 12);
    (0..3).for_each(|i| append(&l, i));
    drop(l);
    let body = std::fs::read(&path).unwrap();
    std::fs::write(&path, &body[..body.len() - 1]).unwrap();
    let p = path.clone();
    within_10s(move || drop(open(&p, 12)));
    let all = lines(&path);
    assert_eq!(all.len(), 3, "record kept, no torn-tail record");
    assert!(std::fs::read(&path).unwrap().ends_with(b"\n"));
    assert!(verify(&path, false).ok);
}

#[test]
fn recovers_crash_between_expiry_record_and_unlink() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = open(&path, 1);
    rotate_n(&l, &path, 1);
    // Rotate once more: retention records `.0`'s expiry and unlinks it.
    let before = list_segments(&path).unwrap().last().unwrap().seq;
    while list_segments(&path).unwrap().last().unwrap().seq == before {
        append(&l, 0);
    }
    drop(l);
    assert!(lines(&path).iter().any(|v| event(v) == Some(EV_EXPIRED)));
    std::fs::write(sealed_path(&path, 0), b"stale copy\n").unwrap(); // "not yet unlinked"
    let p = path.clone();
    within_10s(move || drop(open(&p, 1)));
    assert!(!sealed_path(&path, 0).exists());
}

#[test]
fn open_refuses_unsealed_newest_segment_without_active() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = open(&path, 12);
    (0..3).for_each(|i| append(&l, i));
    drop(l);
    std::fs::rename(&path, sealed_path(&path, 0)).unwrap(); // no seal line
    let p = path.clone();
    let err = within_10s(move || TransparencyLogger::open(cfg(&p, 12, false)).err());
    assert!(
        err.expect("open must refuse")
            .to_string()
            .contains("segment 0")
    );
    assert!(!path.exists(), "no active file created");
}

/// A fail-closed logger with two sealed segments.
fn two_sealed(path: &Path, on_full: OnDiskFull) -> TransparencyLogger {
    let mut c = (*cfg(path, 12, false)).clone();
    c.rotation.on_disk_full = on_full;
    let l = TransparencyLogger::open(Arc::new(c))
        .unwrap()
        .with_failure_policy(AuditFailurePolicy::FailClosed);
    rotate_n(&l, path, 2);
    l
}

#[test]
fn disk_full_expire_oldest_frees_reserve_then_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = two_sealed(&path, OnDiskFull::ExpireOldest);
    assert!(sibling(&path, "reserve").exists());
    l.arm_write_fault(Some(WriteFault::FullUntilReserveFreed));
    append(&l, 1);
    assert!(l.write_faults_fired() > 0, "the injector fired");
    assert!(!l.is_degraded());
    assert!(!sealed_path(&path, 0).exists(), "oldest segment gone");
    let expiry = lines(&path)
        .into_iter()
        .find(|v| event(v) == Some(EV_EXPIRED))
        .expect("expiry recorded");
    assert_eq!(expiry["reason"], "storage_full");
    assert_eq!(expiry["segment_seq"], 0);
    assert!(sibling(&path, "reserve").exists(), "reserve recreated");
    // No torn line: every line parses (lines() would panic otherwise).
    assert!(std::fs::read(&path).unwrap().ends_with(b"\n"));
    l.arm_write_fault(None);
    assert!(verify(&path, false).ok);
}

#[test]
fn disk_full_refuse_stays_degraded() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = two_sealed(&path, OnDiskFull::Refuse);
    l.arm_write_fault(Some(WriteFault::FullUntilReserveFreed));
    assert!(l.log_invocation("s", "c", "srv", "t", "a", "b").is_err());
    assert!(l.write_faults_fired() > 0);
    assert!(l.is_degraded());
    assert!(sealed_path(&path, 0).exists(), "nothing deleted");
    assert!(
        !sibling(&path, "reserve").exists(),
        "refuse keeps no reserve"
    );
}

#[test]
fn expiry_record_unwritable_deletes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = two_sealed(&path, OnDiskFull::ExpireOldest);
    l.arm_write_fault(Some(WriteFault::FullForever));
    assert!(l.log_invocation("s", "c", "srv", "t", "a", "b").is_err());
    assert!(l.write_faults_fired() > 0);
    assert!(l.is_degraded());
    assert!(sealed_path(&path, 0).exists() && sealed_path(&path, 1).exists());
}

#[test]
fn expiry_fsync_failure_deletes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let mut c = (*cfg(&path, 1, false)).clone();
    c.rotation.on_disk_full = OnDiskFull::ExpireOldest;
    let l = TransparencyLogger::open(Arc::new(c))
        .unwrap()
        .with_failure_policy(AuditFailurePolicy::FailClosed);
    rotate_n(&l, &path, 1);
    l.arm_write_fault(Some(WriteFault::ExpirySyncFails));
    // The next rotation makes retention expire `.0`; its fsync fails.
    let mut failed = false;
    for i in 0..10_000 {
        if l.log_invocation("s", "c", "srv", &format!("t{i}"), "a", "b")
            .is_err()
        {
            failed = true;
            break;
        }
    }
    assert!(failed && l.write_faults_fired() > 0);
    assert!(
        sealed_path(&path, 0).exists(),
        "no unlink before a durable record"
    );
    assert!(l.is_degraded());
}

#[test]
fn enospc_after_rename_rebuilds_writer() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = two_sealed(&path, OnDiskFull::ExpireOldest);
    l.arm_write_fault(Some(WriteFault::FullAfterRename));
    rotate_n(&l, &path, 1);
    assert!(l.write_faults_fired() > 0);
    append(&l, 5);
    let last = lines(&path).pop().unwrap();
    assert_eq!(
        last["tool"], "tool_5",
        "the retry landed in the new active file"
    );
    assert!(verify(&path, false).ok);
}

#[test]
fn reserve_is_written_not_sparse() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = open(&path, 12);
    rotate_n(&l, &path, 1);
    let meta = std::fs::metadata(sibling(&path, "reserve")).unwrap();
    assert_eq!(meta.len(), 1024 * 1024);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert!(meta.blocks() * 512 >= meta.len(), "allocated, not a hole");
    }
}

#[test]
fn rotation_leaves_no_degraded_window() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = Arc::new(open(&path, 100).with_failure_policy(AuditFailurePolicy::FailClosed));
    // Deterministic: between rename and the new open record, `Inner` is held.
    let held = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let flag = Arc::clone(&held);
    l.on_rotation_window(Box::new(move |logger| {
        if logger.inner_is_free() {
            flag.store(false, std::sync::atomic::Ordering::Release);
        }
    }));
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let l = Arc::clone(&l);
            std::thread::spawn(move || {
                for i in 0..400 {
                    l.log_invocation("s", "c", "srv", &format!("t{t}-{i}"), "a", "b")
                        .expect("no append error during rotation");
                    assert!(!l.is_degraded());
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert!(
        held.load(std::sync::atomic::Ordering::Acquire),
        "Inner released mid-rotation"
    );
    assert!(list_segments(&path).unwrap().len() >= 50);
    assert!(verify(&path, false).ok);
}
