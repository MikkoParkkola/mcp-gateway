// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! C2, C3, C5a, C6, C7 and the Developer receipts (L3) of the U2 test plan.

use std::path::Path;
use std::sync::Arc;

use serde_json::{Value, json};

use super::{NOT_RECORDED, RowId, parse_id, receipt};
use crate::gateway::ui::activity::access::Access;
use crate::gateway::ui::activity::reader::{Line, Which};
use crate::gateway::ui::activity::rows::{FINDINGS_NOT_RECORDED, row_id};
use crate::security::audit_rotation_config::{OnDiskFull, RotationConfig};
use crate::security::transparency_log::recompute_entry_hash;
use crate::security::transparency_log::segments::{list_segments, sealed_path};
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

fn lines(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn id_of(log: Which, entry: &Value) -> RowId {
    let line = Line {
        log,
        entry: entry.clone(),
        segment: 0,
    };
    parse_id(&row_id(&line).unwrap()).unwrap()
}

fn is_call(v: &Value) -> bool {
    v.get("request_hash").is_some() && v.get("event").is_none()
}

/// Write `entries` chained from genesis, hashed, unsigned.
fn write_chained(path: &Path, entries: &mut [Value]) {
    let mut prev = "genesis".to_string();
    let mut body = String::new();
    for (i, e) in entries.iter_mut().enumerate() {
        e["counter"] = (i + 1).into();
        e["prev_entry_hash"] = prev.clone().into();
        let hash = recompute_entry_hash(e).unwrap();
        e["entry_hash"] = hash.clone().into();
        body.push_str(&(e.to_string() + "\n"));
        prev = hash;
    }
    std::fs::write(path, body).unwrap();
}

#[test]
fn ids_parse_and_refuse_malformed_ones() {
    assert_eq!(
        parse_id("12-0123456789abcdef"),
        Some(RowId {
            log: Which::Invocation,
            counter: 12,
            hash16: "0123456789abcdef".into()
        })
    );
    assert_eq!(
        parse_id("g3-0123456789abcdef").unwrap().log,
        Which::Governance
    );
    for bad in [
        "12",
        "12-0123",
        "x-0123456789abcdef",
        "12-0123456789ABCDEF",
        "12-0123456789abcdeg",
    ] {
        assert_eq!(parse_id(bad), None, "{bad}");
    }
}

#[test]
fn c3_links_mid_segment_and_across_a_seam_verify() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let l = logger(&path);
    for i in 0..60 {
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
    let sealed = list_segments(&path).unwrap();
    assert!(sealed.len() >= 3);
    // The first call of a sealed segment (after its open record), and one
    // in the middle of it.
    let seg = lines(&sealed_path(&path, sealed[1].seq));
    let calls: Vec<&Value> = seg.iter().filter(|v| is_call(v)).collect();
    for entry in [calls[0], calls[calls.len() / 2]] {
        let body = receipt(&path, &id_of(Which::Invocation, entry), &Access::All, None)
            .unwrap()
            .expect("kept");
        assert_eq!(body["chain"]["link"], "verified", "{entry}");
        assert_eq!(body["signature"], "unsigned");
    }
}

#[test]
fn c3_a_broken_link_reads_broken_and_verify_log_agrees() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let mut entries: Vec<Value> = (0..5)
        .map(|i| json!({"tool": format!("tool_{i}"), "request_hash": "sha256:aa", "outcome": "ok"}))
        .collect();
    write_chained(&path, &mut entries);
    // Re-chain record 4 onto a wrong predecessor, its own hash recomputed.
    let mut all = lines(&path);
    all[3]["prev_entry_hash"] = format!("sha256:{}", "0".repeat(64)).into();
    let hash = recompute_entry_hash(&all[3]).unwrap();
    all[3]["entry_hash"] = hash.into();
    let body: String = all.iter().map(|v| v.to_string() + "\n").collect();
    std::fs::write(&path, body).unwrap();

    let broken = receipt(
        &path,
        &id_of(Which::Invocation, &all[3]),
        &Access::All,
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(broken["chain"]["link"], "broken");
    let fine = receipt(
        &path,
        &id_of(Which::Invocation, &all[2]),
        &Access::All,
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(fine["chain"]["link"], "verified");
    let verdict = crate::security::transparency_log::verify_log(&path).unwrap();
    assert!(!verdict.ok, "verify_log must reject the same tamper");
}

#[test]
fn c3_the_genesis_record_is_first_in_kept_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let mut entries = vec![json!({"tool": "tool_0", "request_hash": "sha256:aa", "outcome": "ok"})];
    write_chained(&path, &mut entries);
    let body = receipt(
        &path,
        &id_of(Which::Invocation, &entries[0]),
        &Access::All,
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(body["chain"]["link"], "first_in_kept_log");
}

#[test]
fn c2_a_wrong_hash_prefix_or_an_id_not_kept_is_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let mut entries: Vec<Value> = (0..3)
        .map(|i| json!({"tool": format!("tool_{i}"), "request_hash": "sha256:aa", "outcome": "ok"}))
        .collect();
    write_chained(&path, &mut entries);
    let mut wrong = id_of(Which::Invocation, &entries[1]);
    wrong.hash16 = "ffffffffffffffff".into();
    assert!(
        receipt(&path, &wrong, &Access::All, None)
            .unwrap()
            .is_none()
    );
    let mut absent = id_of(Which::Invocation, &entries[1]);
    absent.counter = 99;
    assert!(
        receipt(&path, &absent, &Access::All, None)
            .unwrap()
            .is_none()
    );
}

#[test]
fn c5a_c6_a_call_receipt_says_what_is_not_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let mut entries = vec![json!({"tool": "t", "request_hash": "sha256:aa", "outcome": "ok"})];
    write_chained(&path, &mut entries);
    let body = receipt(
        &path,
        &id_of(Which::Invocation, &entries[0]),
        &Access::All,
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(body["reach"], NOT_RECORDED);
    assert_eq!(body["decision"], NOT_RECORDED);
    assert_eq!(body["findings"], FINDINGS_NOT_RECORDED);
    assert!(
        !body.to_string().contains("no longer kept"),
        "no history exists to have expired"
    );
}

#[test]
fn c7_a_governance_receipt_never_serves_reason_or_rollback_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gov.jsonl");
    let mut entries = vec![json!({
        "kind": "control_plane_audit", "event_id": "e1", "action": "mutate_grant",
        "actor_id": "alice", "target_id": "srv",
        "reason": "pasted-secret-7f3a9c", "rollback_summary": "undo-text-4b1e",
        "rollback_step": "step-text-9d2c",
    })];
    write_chained(&path, &mut entries);
    let body = receipt(
        &path,
        &id_of(Which::Governance, &entries[0]),
        &Access::All,
        None,
    )
    .unwrap()
    .unwrap();
    assert_eq!(body["reason"], json!({"recorded": true, "length": 20}));
    assert_eq!(
        body["rollback_summary"],
        json!({"recorded": true, "length": 14})
    );
    let text = body.to_string();
    for planted in ["pasted-secret-7f3a9c", "undo-text-4b1e", "step-text-9d2c"] {
        assert!(!text.contains(planted), "{planted} served");
    }
}

#[test]
fn l3_a_developer_reads_its_own_receipts_only() {
    let dir = tempfile::tempdir().unwrap();
    let inv = dir.path().join("inv.jsonl");
    let gov = dir.path().join("gov.jsonl");
    let who = |issuer: &str, subject: &str, principal: &str| json!({"account": "a", "authority": issuer, "subject": subject, "principal": principal});
    let mut calls = vec![
        json!({"tool": "mine", "request_hash": "x", "outcome": "ok", "who": who("https://x", "s", "p1")}),
        json!({"tool": "theirs", "request_hash": "x", "outcome": "ok", "who": who("https://y", "s", "p2")}),
        json!({"tool": "mine-later", "request_hash": "x", "outcome": "ok", "who": who("https://x", "s", "p3")}),
    ];
    write_chained(&inv, &mut calls);
    let mut config = vec![json!({"kind": "control_plane_audit", "actor_id": "oidc:x:s"})];
    write_chained(&gov, &mut config);
    let dev = Access::Own {
        issuer: "https://x".into(),
        subject: "s".into(),
    };
    let read =
        |log: &Path, which, entry: &Value| receipt(log, &id_of(which, entry), &dev, None).unwrap();
    assert_eq!(
        read(&inv, Which::Invocation, &calls[0]).unwrap()["tool"],
        "mine"
    );
    assert_eq!(
        read(&inv, Which::Invocation, &calls[2]).unwrap()["tool"],
        "mine-later",
        "after a token refresh: a new principal, the same issuer and subject"
    );
    assert!(read(&inv, Which::Invocation, &calls[1]).is_none());
    assert!(read(&gov, Which::Governance, &config[0]).is_none());
}

#[test]
fn an_edited_predecessor_or_a_gap_in_the_middle_reads_broken() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let mut entries: Vec<Value> = (0..4)
        .map(|i| json!({"tool": format!("tool_{i}"), "request_hash": "sha256:aa", "outcome": "ok"}))
        .collect();
    write_chained(&path, &mut entries);
    let link = |e: &Value| {
        receipt(&path, &id_of(Which::Invocation, e), &Access::All, None)
            .unwrap()
            .unwrap()["chain"]["link"]
            .clone()
    };
    // Record 2 edited, its stored hash kept: record 3's link is broken.
    let mut all = lines(&path);
    all[1]["tool"] = "edited".into();
    std::fs::write(
        &path,
        all.iter().map(|v| v.to_string() + "\n").collect::<String>(),
    )
    .unwrap();
    assert_eq!(link(&entries[2]), "broken");
    // Record 2 removed: record 3 is not the oldest kept, so a gap, not a start.
    let kept: String = [&entries[0], &entries[2], &entries[3]]
        .iter()
        .map(|v| v.to_string() + "\n")
        .collect();
    std::fs::write(&path, kept).unwrap();
    assert_eq!(link(&entries[2]), "broken");
    assert_eq!(link(&entries[3]), "verified");
    // Retention cut the log at record 3: now it is the start of the kept log.
    let cut: String = [&entries[2], &entries[3]]
        .iter()
        .map(|v| v.to_string() + "\n")
        .collect();
    std::fs::write(&path, cut).unwrap();
    assert_eq!(link(&entries[2]), "first_in_kept_log");
}
