// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8374: SIEM export and `audit verify` agree on a signed log. With no
//! signing key configured, `audit verify` refuses a log that holds a signed
//! entry (MIK-6700); export used to pass the same log on hash-only, so a
//! re-chained forgery reached the SIEM.

use super::*;
use crate::security::TransparencyLogger;
use crate::security::transparency_log::{TransparencyLogConfig, log_contains_signed_entry};
use std::sync::Arc;

const SECRET: &str = "a-test-secret-that-is-at-least-32-bytes!!";

fn open_log(path: &Path, secret: &str) -> Arc<TransparencyLogger> {
    Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            key_id: "test-key".to_string(),
            shared_secret: secret.to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log"),
    )
}

/// Three invocations written under `secret` ("" for an unsigned log).
fn write_log(path: &Path, secret: &str) {
    let log = open_log(path, secret);
    for i in 0..3 {
        log.log_invocation("s", "c", "srv", "t", &format!("r{i}"), "p")
            .expect("append");
    }
}

/// Remove `sig` and `key_id` from the first `n` entries. Both are outside the
/// entry hash, so the chain stays intact and those entries read as unsigned.
fn strip_leading_signatures(log: &Path, n: usize) {
    let content = std::fs::read_to_string(log).expect("read");
    let mut lines: Vec<serde_json::Value> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect();
    for entry in lines.iter_mut().take(n) {
        let map = entry.as_object_mut().expect("object");
        map.remove("sig");
        map.remove("key_id");
    }
    let mut rewritten = lines
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    rewritten.push('\n');
    std::fs::write(log, rewritten).expect("write");
}

/// An exporter configured with no signing key: `with_signing_secret("")`
/// is how the gateway wires an empty `shared_secret`.
fn keyless_exporter(dir: &Path, log: &Path) -> LogExporter {
    LogExporter::open(
        ExportSource::Invocation,
        log.to_path_buf(),
        dir.join("cursor.json"),
    )
    .expect("open exporter")
    .with_signing_secret("")
}

/// MIK-8374.EXPORTSIG.1/.3: a signed log exported with no key halts, naming
/// the missing key, and forwards nothing. Red on base: every entry forwarded.
#[test]
fn a_signed_log_without_a_key_is_not_exported_hash_only() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("inv.jsonl");
    write_log(&log, SECRET);
    assert!(
        log_contains_signed_entry(&log).expect("scan"),
        "the log is signed"
    );

    let sink = CollectingSink::new();
    let mut exp = keyless_exporter(dir.path(), &log);
    match exp.poll(&sink) {
        Err(ExportError::VerificationFailed(msg)) => {
            assert!(
                msg.contains("no signing key"),
                "not the missing-key refusal: {msg}"
            );
        }
        other => panic!("a signed log passed export hash-only: {other:?}"),
    }
    assert!(sink.delivered().is_empty(), "nothing forwarded");
    assert_eq!(exp.cursor().last_entry_hash, "genesis");
}

/// MIK-8374.EXPORTSIG.2 (green pin): an unsigned log with no key still
/// exports hash-only, unchanged.
#[test]
fn an_unsigned_log_without_a_key_still_exports() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("inv.jsonl");
    write_log(&log, "");
    assert!(!log_contains_signed_entry(&log).expect("scan"));

    let sink = CollectingSink::new();
    let out = keyless_exporter(dir.path(), &log)
        .poll(&sink)
        .expect("exports");
    // The genesis open record, then the three invocations.
    assert_eq!(out.forwarded, 4);
}

/// MIK-8374.EXPORTSIG.4: `audit verify`'s rule and the exporter's agree on a
/// mixed log, an unsigned prefix and then signed entries. `sig` and `key_id`
/// are outside the entry hash, so stripping them leaves the chain intact.
#[test]
fn verify_and_export_agree_on_a_mixed_log() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("inv.jsonl");
    write_log(&log, SECRET);
    strip_leading_signatures(&log, 2);

    assert!(
        log_contains_signed_entry(&log).expect("scan"),
        "verify sees a signed entry"
    );
    let sink = CollectingSink::new();
    assert!(
        matches!(
            keyless_exporter(dir.path(), &log).poll(&sink),
            Err(ExportError::VerificationFailed(m)) if m.contains("no signing key")
        ),
        "export must refuse the log verify refuses, for the missing key"
    );
    assert!(sink.delivered().is_empty());
}

/// Halt, restore the key, resume: the halted poll moved nothing, so the keyed
/// exporter on the same cursor forwards every entry exactly once.
#[test]
fn restoring_the_key_resumes_without_loss_or_duplicates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("inv.jsonl");
    write_log(&log, SECRET);

    let halted = CollectingSink::new();
    assert!(keyless_exporter(dir.path(), &log).poll(&halted).is_err());
    assert!(halted.delivered().is_empty());

    let sink = CollectingSink::new();
    let mut keyed = LogExporter::open(
        ExportSource::Invocation,
        log.clone(),
        dir.path().join("cursor.json"),
    )
    .expect("reopen on the same cursor")
    .with_signing_secret(SECRET);
    assert_eq!(keyed.poll(&sink).expect("exports").forwarded, 4);
    let counters: Vec<u64> = sink.delivered().iter().map(|e| e.counter).collect();
    assert_eq!(counters, [1, 2, 3, 4], "every entry once, in order");
    assert_eq!(
        keyed.poll(&sink).expect("caught up").forwarded,
        0,
        "nothing again"
    );
}

/// A batch that ends inside the unsigned prefix forwards that verified
/// prefix; the poll that reaches the first signed entry halts there.
#[test]
fn a_small_batch_forwards_the_unsigned_prefix_then_halts_at_the_signed_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("inv.jsonl");
    write_log(&log, SECRET);
    strip_leading_signatures(&log, 2);

    let sink = CollectingSink::new();
    let mut exp = keyless_exporter(dir.path(), &log).with_max_batch(2);
    assert_eq!(exp.poll(&sink).expect("the unsigned prefix").forwarded, 2);
    assert!(
        matches!(exp.poll(&sink), Err(ExportError::VerificationFailed(m)) if m.contains("no signing key")),
        "the next poll halts at the first signed entry"
    );
    assert_eq!(sink.delivered().len(), 2, "nothing past the prefix");
}

/// The shared rule is presence of `sig`: a null, empty or garbled value is
/// still a signed entry, so it cannot downgrade a log to hash-only.
#[test]
fn any_sig_field_marks_an_entry_signed() {
    use crate::security::transparency_log::is_signed_entry;
    for sig in [
        serde_json::json!(null),
        serde_json::json!(""),
        serde_json::json!(42),
        serde_json::json!("not-hex"),
    ] {
        assert!(
            is_signed_entry(&serde_json::json!({"counter": 1, "sig": sig})),
            "{sig}"
        );
    }
    assert!(!is_signed_entry(&serde_json::json!({"counter": 1})));
}

/// A null `sig` still marks an entry signed, through the scan `audit verify`
/// uses and through the exporter alike: it cannot open a hash-only path.
#[test]
fn a_null_sig_is_refused_by_verify_and_export_alike() {
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("inv.jsonl");
    write_log(&log, "");
    let content = std::fs::read_to_string(&log).expect("read");
    let mut lines: Vec<serde_json::Value> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect();
    let last = lines.last_mut().expect("an entry");
    last.as_object_mut()
        .expect("object")
        .insert("sig".into(), serde_json::Value::Null);
    let mut rewritten = lines
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    rewritten.push('\n');
    std::fs::write(&log, rewritten).expect("write");

    assert!(
        log_contains_signed_entry(&log).expect("scan"),
        "verify sees it as signed"
    );
    let sink = CollectingSink::new();
    let mut exp = keyless_exporter(dir.path(), &log);
    assert!(
        matches!(exp.poll(&sink), Err(ExportError::VerificationFailed(m)) if m.contains("no signing key")),
        "export refuses it too"
    );
    assert!(sink.delivered().is_empty());
}
