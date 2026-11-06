// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D6: `mcp-gateway audit verify` over a rotated log, as a process. Covers
//! the CLI wiring the library tests cannot: the early exit when the active
//! file is missing, the `--archive` flag, and `--anchor` (MIK-7713).

#[path = "common/gateway_bin.rs"]
mod gateway_bin;

use std::path::Path;
use std::sync::Arc;

use mcp_gateway::security::TransparencyLogger;
use mcp_gateway::security::transparency_log::{RotationConfig, TransparencyLogConfig};

/// Sealed segments beside `path`: `<name>.` plus 20 digits.
fn sealed_count(path: &Path) -> usize {
    let name = path.file_name().unwrap().to_string_lossy().into_owned() + ".";
    std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.strip_prefix(&name)
                .is_some_and(|s| s.len() == 20 && s.bytes().all(|b| b.is_ascii_digit()))
        })
        .count()
}

fn write_log(path: &Path) {
    let rotation = RotationConfig {
        max_segment_bytes: 4096,
        ..RotationConfig::default()
    };
    let l = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "cli".into(),
        shared_secret: String::new(),
        rotation,
    }))
    .unwrap();
    let mut i = 0;
    while sealed_count(path) < 3 {
        l.log_invocation("s", "c", "srv", &format!("t{i}"), "a", "b")
            .unwrap();
        i += 1;
        assert!(i < 1_000, "no rotation happened");
    }
}

fn verify(dir: &Path, log: &Path, archive: bool) -> (bool, String) {
    verify_with(dir, log, archive, None)
}

fn verify_with(dir: &Path, log: &Path, archive: bool, anchor: Option<&Path>) -> (bool, String) {
    let config = dir.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, "auth:\n  enabled: false\n")
        .unwrap();
    let mut cmd = gateway_bin::command(dir, gateway_bin::Inherit::Environment);
    cmd.arg("--config")
        .arg(&config)
        .args(["audit", "verify", "--path"])
        .arg(log);
    if archive {
        cmd.arg("--archive");
    }
    if let Some(anchor) = anchor {
        cmd.arg("--anchor").arg(anchor);
    }
    let out = cmd.output().expect("audit verify runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), text)
}

#[test]
fn audit_verify_spans_segments_as_a_process() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("transparency.jsonl");
    write_log(&log);
    let (ok, text) = verify(dir.path(), &log, false);
    assert!(ok, "{text}");
    assert!(text.contains("across 4 segments"), "{text}");
}

#[test]
fn audit_verify_reads_sealed_segments_when_the_active_file_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("transparency.jsonl");
    write_log(&log);
    std::fs::remove_file(&log).unwrap();
    let (ok, text) = verify(dir.path(), &log, false);
    assert!(!ok);
    assert!(!text.contains("not found"), "must verify, not bail: {text}");
    assert!(text.contains("missing"), "reports the gap: {text}");
}

#[test]
fn audit_verify_archive_accepts_a_copy_without_hwm() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("transparency.jsonl");
    write_log(&log);
    std::fs::remove_file(dir.path().join("transparency.jsonl.hwm")).unwrap();
    let (live, text) = verify(dir.path(), &log, false);
    assert!(!live, "live mode needs the high-water mark: {text}");
    let (ok, text) = verify(dir.path(), &log, true);
    assert!(ok, "{text}");
    assert!(text.contains("archive copy"), "names the mode: {text}");
}

/// MIK-7713: `--anchor` as a process, live and archive. A valid anchor
/// passes; a missing or malformed one, or a wiped log, exits 1 naming why.
#[test]
fn audit_verify_checks_the_log_against_an_anchor() {
    for archive in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("transparency.jsonl");
        write_log(&log);
        let anchor = dir.path().join("anchor.hwm");
        std::fs::copy(dir.path().join("transparency.jsonl.hwm"), &anchor).unwrap();
        let (ok, text) = verify_with(dir.path(), &log, archive, Some(&anchor));
        assert!(ok, "{text}");

        let missing = dir.path().join("missing.hwm");
        let (ok, text) = verify_with(dir.path(), &log, archive, Some(&missing));
        assert!(!ok && text.contains("anchor"), "missing anchor: {text}");
        let malformed = dir.path().join("malformed.hwm");
        std::fs::write(&malformed, "not a high-water mark\n").unwrap();
        let (ok, text) = verify_with(dir.path(), &log, archive, Some(&malformed));
        assert!(!ok && text.contains("anchor"), "malformed anchor: {text}");

        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name.starts_with("transparency.jsonl") {
                std::fs::remove_file(path).unwrap();
            }
        }
        let (ok, text) = verify_with(dir.path(), &log, archive, Some(&anchor));
        assert!(
            !ok && text.contains("behind its anchor"),
            "wiped log: {text}"
        );
    }
}

/// An unrotated log with two caller records, its logger dropped.
fn small_log(path: &Path) {
    let l = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "cli".into(),
        shared_secret: String::new(),
        rotation: RotationConfig::default(),
    }))
    .unwrap();
    for i in 0..2 {
        l.log_invocation("s", "c", "srv", &format!("t{i}"), "a", "b")
            .unwrap();
    }
}

/// An unrotated log with records whose active file was deleted with its
/// `.hwm` kept, then reopened: the new genesis names the surviving mark.
fn log_with_deleted_active(path: &Path) {
    small_log(path);
    std::fs::remove_file(path).unwrap();
    small_log(path);
}

#[test]
fn audit_verify_prints_its_warnings_when_the_chain_fails() {
    // GIVEN: a log whose active file was deleted with its mark kept
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("transparency.jsonl");
    log_with_deleted_active(&log);

    // WHEN: it is verified as a process
    let (ok, text) = verify(dir.path(), &log, false);

    // THEN: it fails naming the deletion, and still prints the predecessor
    // warning, unverified
    assert!(!ok, "{text}");
    assert!(text.contains("the active segment was deleted"), "{text}");
    let warned = text
        .lines()
        .find(|l| l.starts_with("warning:") && l.contains("predecessor went missing"));
    assert!(warned.is_some_and(|w| w.contains("unverified")), "{text}");
}

/// Edit record `index` of `path` in place, its stored hashes left as they
/// were, as a hand edit of the file would.
fn edit_record(path: &Path, index: usize, edit: impl FnOnce(&mut serde_json::Value)) {
    let text = std::fs::read_to_string(path).unwrap();
    let mut records: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    edit(&mut records[index]);
    let body: String = records.iter().map(|v| v.to_string() + "\n").collect();
    std::fs::write(path, body).unwrap();
}

/// A carriage return, then an escape sequence that would erase the line.
const HOSTILE: &str = "id\r\u{1b}[2Kforged";

/// No raw control character reached the output: every one was escaped.
fn shown_escaped(text: &str) {
    assert!(!text.contains('\r') && !text.contains('\u{1b}'), "{text:?}");
    assert!(text.contains(r"\u{d}\u{1b}[2Kforged"), "{text}");
}

#[test]
fn audit_verify_escapes_a_predecessor_id_in_its_warning() {
    // GIVEN: a failing log whose predecessor evidence names a hostile id
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("transparency.jsonl");
    log_with_deleted_active(&log);
    edit_record(&log, 0, |v| {
        v["predecessor_missing"]["previous_log_id"] = HOSTILE.into();
    });

    // WHEN: it is verified as a process
    let (ok, text) = verify(dir.path(), &log, false);

    // THEN: the warning shows the id escaped, still labelled unverified
    assert!(!ok, "{text}");
    shown_escaped(&text);
    let warned = text
        .lines()
        .find(|l| l.contains("predecessor went missing"));
    assert!(warned.is_some_and(|w| w.contains("unverified")), "{text}");
}

#[test]
fn audit_verify_escapes_log_text_in_its_failure_line() {
    // GIVEN: a log one of whose records names a hostile previous hash
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("transparency.jsonl");
    small_log(&log);
    edit_record(&log, 1, |v| v["prev_entry_hash"] = HOSTILE.into());

    // WHEN: it is verified as a process
    let (ok, text) = verify(dir.path(), &log, false);

    // THEN: the failure names it, escaped
    assert!(!ok, "{text}");
    shown_escaped(&text);
}
