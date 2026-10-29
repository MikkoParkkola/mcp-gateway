// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Signature rows split from the rotation tests: the signed-entry scan behind
//! `audit verify`'s keyless refusal, and the signatures a keyless verifying
//! pass reports. A child of the rotation tests, so it shares their helpers.

use super::*;

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

/// The live file is sealed while the signed-entry scan reads: its signed
/// records move to the sealed name, and the scan still finds them rather
/// than reading the new, unsigned live file and passing a hash-only verify.
#[test]
fn a_rotation_during_the_signed_entry_scan_still_finds_the_signature() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, true)).unwrap();
    append(&l, 3);
    drop(l);
    assert!(list_segments(&path).unwrap().is_empty(), "one segment");
    let live = path.clone();
    verify::LISTED.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            std::fs::rename(&live, sealed_path(&live, 0)).unwrap();
            let opened = serde_json::json!({"event": "audit_segment_opened", "segment_seq": 1});
            std::fs::write(&live, format!("{opened}\n")).unwrap();
        }));
    });
    assert!(log_contains_signed_entry(&path).unwrap());
}

/// A listed sealed segment goes while the scan reads: the scan lists again
/// and reads what is left, rather than failing `audit verify`.
#[test]
fn a_segment_removed_during_the_signed_entry_scan_is_read_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, true)).unwrap();
    rotate_n(&l, &path, 1);
    drop(l);
    let sealed = sealed_path(&path, list_segments(&path).unwrap()[0].seq);
    verify::LISTED.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || std::fs::remove_file(&sealed).unwrap()));
    });
    assert!(
        log_contains_signed_entry(&path).unwrap(),
        "the live file is signed"
    );
}

/// The log rotates under both passes of the signed-entry scan: a busy log,
/// `Interrupted`, never an answer read from a listing that moved.
#[test]
fn a_signed_entry_scan_rotated_twice_is_interrupted() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&l, 3);
    drop(l);
    let seal = |live: &Path, seq: u64| {
        std::fs::rename(live, sealed_path(live, seq)).unwrap();
        let opened = serde_json::json!({"event": "audit_segment_opened", "segment_seq": seq + 1});
        std::fs::write(live, format!("{opened}\n")).unwrap();
    };
    let live = path.clone();
    verify::LISTED.with(|h| {
        *h.borrow_mut() = Some(Box::new(move || {
            seal(&live, 0);
            verify::LISTED.with(|h| *h.borrow_mut() = Some(Box::new(move || seal(&live, 1))));
        }));
    });
    let err = log_contains_signed_entry(&path).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Interrupted, "{err}");
}

/// Verify without the key, as a copied set: the `.hwm` a signed logger
/// keeps cannot be read without its key, and is not what these rows test.
fn keyless(path: &Path) -> VerifyResult {
    verify_segments(path, &cfg(path, 12, false), VerifyMode::Archive).unwrap()
}

/// The verifying pass reports a signature it read: a signed log checked
/// without the key passes its hash chain and says it saw one.
#[test]
fn a_keyless_pass_reports_the_signatures_it_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, true)).unwrap();
    append(&l, 0);
    drop(l);
    let r = keyless(&path);
    assert!(r.ok, "{:?}", r.error_message);
    assert!(r.signed_entry_seen);

    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&l, 0);
    drop(l);
    assert!(!keyless(&path).signed_entry_seen, "an unsigned log");
}

/// A chain that fails at its first line still reports the signature on
/// that line: a broken chain cannot hide one.
#[test]
fn a_failed_pass_still_reports_a_signature() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, true)).unwrap();
    append(&l, 0);
    drop(l);
    let mut all = lines(&path);
    all[0]["entry_hash"] = "not-the-hash".into();
    let body = all
        .iter()
        .fold(String::new(), |acc, v| acc + &v.to_string() + "\n");
    std::fs::write(&path, body).unwrap();
    let r = keyless(&path);
    assert!(!r.ok);
    assert!(r.signed_entry_seen);
}

/// A `sig` key with no usable value still claims a signature, so it counts.
#[test]
fn an_empty_signature_still_counts_as_signed() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    append(&l, 0);
    drop(l);
    rewrite_line(&path, 1, |v| v["sig"] = serde_json::Value::Null);
    assert!(keyless(&path).signed_entry_seen);
}

/// The only signed entry is the live file's first line, rejected by the
/// seam check before any per-entry check runs: the pass still reports the
/// signature, because it is noted when the line is parsed.
#[test]
fn a_signature_rejected_before_its_checks_is_still_reported() {
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = TransparencyLogger::open(cfg(&path, 12, false)).unwrap();
    rotate_n(&l, &path, 1);
    drop(l);
    let mut all = lines(&path);
    all[0]["sig"] = "unchecked".into();
    all[0]["prev_segment_seq"] = 99.into();
    let body = all
        .iter()
        .fold(String::new(), |acc, v| acc + &v.to_string() + "\n");
    std::fs::write(&path, body).unwrap();

    let r = keyless(&path);

    assert!(!r.ok);
    let msg = r.error_message.clone().unwrap_or_default();
    assert!(
        msg.contains("prev_segment_seq"),
        "rejected by the seam check: {msg}"
    );
    assert!(r.signed_entry_seen);
}
