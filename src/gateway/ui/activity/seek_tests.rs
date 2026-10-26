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
        .map(|c| format!("{}\n", json!({"counter": c, "pad": pad})))
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
        body.push_str(&format!("{}\n", json!({"counter": c})));
    }
    body.push_str(&format!("{big}\n"));
    for c in 6..10 {
        body.push_str(&format!("{}\n", json!({"counter": c})));
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
        .map(|c| format!("{}\n", json!({"counter": c})))
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
