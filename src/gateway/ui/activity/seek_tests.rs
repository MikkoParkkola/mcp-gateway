// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C1 and C2 of the U2 test plan at the seek level.

use std::path::Path;
use std::sync::Arc;

use serde_json::json;

use super::{Reads, seek};
use crate::security::audit_rotation_config::{OnDiskFull, RotationConfig};
use crate::security::transparency_log::segments::list_segments;
use crate::security::{TransparencyLogConfig, TransparencyLogger};

fn logger(path: &Path) -> TransparencyLogger {
    TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "test".into(),
        shared_secret: String::new(),
        rotation: RotationConfig {
            max_segment_bytes: 4096,
            max_segment_age_secs: 0,
            retain_segments: 1000,
            on_disk_full: OnDiskFull::ExpireOldest,
        },
    }))
    .unwrap()
}

#[test]
fn c1_an_old_record_in_a_sealed_segment_is_found_by_seek() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let l = logger(&path);
    for i in 0..400 {
        l.log_invocation(
            "s",
            "c",
            "srv",
            &format!("tool_{i}"),
            "sha256:aa",
            "sha256:bb",
        )
        .unwrap();
    }
    let segments = list_segments(&path).unwrap().len();
    assert!(segments >= 20, "fixture spans {segments} segments");
    for counter in [2, 57, 300] {
        let mut reads = Reads::default();
        let found = seek(&path, counter, &mut reads).unwrap().expect("kept");
        assert_eq!(found.entry["counter"], counter);
        // One first-line read per segment, then a bisection of one file.
        assert!(reads.0 <= segments + 1 + 40, "{} reads", reads.0);
    }
    let mut reads = Reads::default();
    assert!(seek(&path, 100_000, &mut reads).unwrap().is_none());
}

#[test]
fn c1_bisection_reads_o_log_n_windows_in_a_large_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let pad = "p".repeat(400);
    let body: String = (1..=30_000)
        .map(|c| json!({"counter": c, "pad": pad}).to_string() + "\n")
        .collect();
    std::fs::write(&path, body).unwrap();
    for counter in [1, 15_000, 29_999, 30_000] {
        let mut reads = Reads::default();
        let found = seek(&path, counter, &mut reads).unwrap().expect("kept");
        assert_eq!(found.entry["counter"], counter);
        // ~12 MB: a scan reads ~190 chunks; halving reads two per step.
        assert!(reads.0 <= 60, "counter {counter}: {} reads", reads.0);
    }
}

#[test]
fn c1_a_record_at_the_cap_is_returned_whole() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let mut big = json!({"counter": 5, "pad": ""});
    let base = big.to_string().len();
    big["pad"] = "x".repeat(4 * 1024 * 1024 - base).into();
    let mut body = String::new();
    for c in 1..5 {
        body.push_str(&(json!({"counter": c}).to_string() + "\n"));
    }
    body.push_str(&(big.to_string() + "\n"));
    for c in 6..10 {
        body.push_str(&(json!({"counter": c}).to_string() + "\n"));
    }
    std::fs::write(&path, body).unwrap();
    for counter in [4, 5, 6, 9] {
        let mut reads = Reads::default();
        let found = seek(&path, counter, &mut reads).unwrap().expect("kept");
        assert_eq!(found.entry["counter"], counter);
    }
    let mut reads = Reads::default();
    let found = seek(&path, 5, &mut reads).unwrap().unwrap();
    assert_eq!(found.entry.to_string().len(), 4 * 1024 * 1024);
}

#[test]
fn c2_a_counter_not_in_the_kept_log_is_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let body: String = (10..=20)
        .map(|c| json!({"counter": c}).to_string() + "\n")
        .collect();
    std::fs::write(&path, body).unwrap();
    for counter in [1, 9, 21] {
        let mut reads = Reads::default();
        assert!(
            seek(&path, counter, &mut reads).unwrap().is_none(),
            "{counter}"
        );
    }
}

#[test]
fn c1_bad_lines_never_hide_the_records_after_them() {
    // A torn line after every third counter, and a line over the record cap
    // after counter 25: every counter on both sides is still found.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let mut body = String::new();
    for c in 1..=40 {
        body.push_str(&(json!({"counter": c, "pad": "p".repeat(200)}).to_string() + "\n"));
        // Torn lines dense enough that the bisection lands on them.
        if c % 3 == 0 {
            body.push_str("{\"counter\": torn\n");
        }
        if c == 25 {
            body.push_str(&"x".repeat(5 * 1024 * 1024));
            body.push('\n');
        }
    }
    std::fs::write(&path, body).unwrap();
    for counter in 1..=40 {
        let mut reads = Reads::default();
        let found = seek(&path, counter, &mut reads)
            .unwrap()
            .unwrap_or_else(|| panic!("counter {counter} hidden by a bad line"));
        assert_eq!(found.entry["counter"], counter);
    }
}

#[test]
fn a_file_in_the_rotation_gap_is_found_under_its_sealed_name() {
    use crate::security::transparency_log::segments::sealed_path;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("inv.jsonl");
    std::fs::write(sealed_path(&log, 3), "{\"counter\": 1}\n").unwrap();
    // The active name is gone for an instant; segment 3's bytes are sealed.
    assert!(super::open_segment(&log, 3, || {}).unwrap().is_some());
    assert!(super::open_segment(&log, 4, || {}).unwrap().is_none());
}
