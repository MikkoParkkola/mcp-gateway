// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D6: `mcp-gateway audit verify` over a rotated log, as a process. Covers
//! the CLI wiring the library tests cannot: the early exit when the active
//! file is missing, and the `--archive` flag.

use std::path::Path;
use std::process::Command;
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
    }
}

fn verify(dir: &Path, log: &Path, archive: bool) -> (bool, String) {
    let config = dir.join("gateway.yaml");
    mcp_gateway::gateway::test_helpers::write_owner_only(&config, "auth:\n  enabled: false\n")
        .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-gateway"));
    cmd.arg("--config")
        .arg(&config)
        .args(["audit", "verify", "--path"])
        .arg(log);
    if archive {
        cmd.arg("--archive");
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
