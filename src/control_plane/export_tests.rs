// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for the SIEM exporter (moved out for the file-size ceiling).

use super::*;
use crate::security::TransparencyLogger;
use crate::security::transparency_log::TransparencyLogConfig;
use crate::security::transparency_log::recompute_entry_hash;
use std::sync::Arc;

fn logger(path: &Path) -> Arc<TransparencyLogger> {
    let cfg = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "test".to_string(),
        ..TransparencyLogConfig::default()
    });
    Arc::new(TransparencyLogger::open(cfg).expect("open log"))
}

fn gov_event(l: &TransparencyLogger, id: &str) {
    let mut m = serde_json::Map::new();
    m.insert("kind".into(), "control_plane_audit".into());
    m.insert("event_id".into(), id.into());
    l.append_event(m, &crate::security::audit::AuditEnvelope::gateway())
        .expect("append governance event");
}

/// Sink that always rejects (simulates SIEM outage / backpressure).
struct FailingSink;
impl ExportSink for FailingSink {
    fn deliver(&self, _e: &[ExportEntry]) -> Result<(), ExportError> {
        Err(ExportError::SinkRejected("down".to_string()))
    }
}

fn exporter(dir: &Path, src: ExportSource, log: &Path) -> LogExporter {
    LogExporter::open(src, log.to_path_buf(), dir.join("cursor.json")).unwrap()
}

// MIK-6689.SIEM.1 — new entries from both logs forward in chain order,
// labeled by source, carrying entry_hash/prev/checkpoint.
#[test]
fn forwards_both_sources_in_chain_order() {
    let dir = tempfile::tempdir().unwrap();
    let inv_path = dir.path().join("inv.jsonl");
    let gov_path = dir.path().join("gov.jsonl");
    let inv = logger(&inv_path);
    let gov = logger(&gov_path);
    inv.log_invocation("s1", "c", "srv", "t", "req:1", "resp:1")
        .unwrap();
    inv.log_invocation("s1", "c", "srv", "t", "req:2", "resp:2")
        .unwrap();
    gov_event(&gov, "g1");

    let inv_sink = CollectingSink::new();
    let mut inv_exp = exporter(&dir.path().join("inv"), ExportSource::Invocation, &inv_path);
    std::fs::create_dir_all(dir.path().join("inv")).unwrap();
    let out = inv_exp.poll(&inv_sink).unwrap();
    assert_eq!(out.forwarded, 2);
    let d = inv_sink.delivered();
    assert_eq!(d.iter().map(|e| e.counter).collect::<Vec<_>>(), [1, 2]);
    assert!(d.iter().all(|e| e.source == ExportSource::Invocation));
    assert!(d[0].entry_hash.starts_with("sha256:"));
    assert_eq!(d[1].prev_entry_hash, d[0].entry_hash);

    let gov_sink = CollectingSink::new();
    std::fs::create_dir_all(dir.path().join("gov")).unwrap();
    let mut gov_exp = exporter(&dir.path().join("gov"), ExportSource::Governance, &gov_path);
    assert_eq!(gov_exp.poll(&gov_sink).unwrap().forwarded, 1);
    assert_eq!(gov_sink.delivered()[0].source, ExportSource::Governance);
}

// MIK-6689.SIEM.2 — cursor advances only after ack; a failed send is re-sent.
#[test]
fn cursor_advances_only_after_ack_and_resends() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("inv.jsonl");
    let l = logger(&log);
    l.log_invocation("s", "c", "srv", "t", "r", "p").unwrap();

    let mut exp = exporter(dir.path(), ExportSource::Invocation, &log);
    // Sink is down: nothing forwarded, cursor stays at genesis/offset 0.
    assert!(matches!(
        exp.poll(&FailingSink),
        Err(ExportError::SinkRejected(_))
    ));
    assert_eq!(exp.cursor().last_entry_hash, "genesis");

    // Sink recovers: the same entry is re-sent (at-least-once) and acked.
    let sink = CollectingSink::new();
    assert_eq!(exp.poll(&sink).unwrap().forwarded, 1);
    assert_eq!(sink.delivered().len(), 1);
    assert!(exp.cursor().last_entry_hash.starts_with("sha256:"));

    // A fresh exporter reloads the persisted cursor and does NOT re-send.
    let mut exp2 = exporter(dir.path(), ExportSource::Invocation, &log);
    let sink2 = CollectingSink::new();
    assert_eq!(exp2.poll(&sink2).unwrap().forwarded, 0);
}

// MIK-6689.SIEM.3 — bounded per poll: max_batch caps memory, lag is reported.
#[test]
fn bounded_batch_reports_lag() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("inv.jsonl");
    let l = logger(&log);
    for i in 0..5 {
        l.log_invocation("s", "c", "srv", "t", &format!("r{i}"), &format!("p{i}"))
            .unwrap();
    }
    let sink = CollectingSink::new();
    let mut exp = exporter(dir.path(), ExportSource::Invocation, &log).with_max_batch(2);
    let out = exp.poll(&sink).unwrap();
    assert_eq!(out.forwarded, 2);
    assert!(out.lag_entries >= 1, "lag must be reported for the backlog");
    // Drain the rest across polls.
    assert_eq!(exp.poll(&sink).unwrap().forwarded, 2);
    assert_eq!(exp.poll(&sink).unwrap().forwarded, 1);
    assert_eq!(sink.delivered().len(), 5);
}

// MIK-6689.SIEM.4 — a tampered entry halts export; nothing is forwarded.
#[test]
fn tampered_entry_halts_and_alerts() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("inv.jsonl");
    let l = logger(&log);
    l.log_invocation("s", "c", "srv", "t", "r", "p").unwrap();
    drop(l);
    // Tamper: change a hashed field without re-chaining.
    let content = std::fs::read_to_string(&log).unwrap();
    let tampered = content.replace("\"caller\":\"c\"", "\"caller\":\"attacker\"");
    assert_ne!(tampered, content);
    std::fs::write(&log, tampered).unwrap();

    let sink = CollectingSink::new();
    let mut exp = exporter(dir.path(), ExportSource::Invocation, &log);
    assert!(matches!(
        exp.poll(&sink),
        Err(ExportError::VerificationFailed(_))
    ));
    assert!(sink.delivered().is_empty(), "no entry forwarded on halt");
    assert_eq!(exp.cursor().last_entry_hash, "genesis");
}

// MIK-6689.SIEM.5 — rotation/truncation re-anchors and resumes.
#[test]
fn rotation_reanchors_and_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("inv.jsonl");
    let l = logger(&log);
    l.log_invocation("s", "c", "srv", "t", "r1", "p1").unwrap();
    drop(l);

    let sink = CollectingSink::new();
    let mut exp = exporter(dir.path(), ExportSource::Invocation, &log);
    assert_eq!(exp.poll(&sink).unwrap().forwarded, 1);
    assert!(exp.cursor().last_entry_hash.starts_with("sha256:"));

    // Rotate: the old file is replaced by a fresh, shorter chain.
    std::fs::remove_file(&log).unwrap();
    let l2 = logger(&log);
    l2.log_invocation("s", "c", "srv", "t", "r-new", "p-new")
        .unwrap();
    drop(l2);

    // D6: the recreated file opens with a record continuing the counter
    // (verify reports the deleted records as a gap); export resumes there.
    let out = exp.poll(&sink).unwrap();
    assert!(out.reanchored, "shrunk file must re-anchor");
    assert_eq!(out.forwarded, 2, "the open record, then the new entry");
    assert_eq!(sink.delivered().len(), 3);
}

// MIK-6700 HMAC.3 — the exporter authenticates each entry's sig when a
// secret is configured, catching a re-chained forgery with a stale sig.
fn signed_logger(path: &Path, secret: &str) -> Arc<TransparencyLogger> {
    let cfg = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "test-key".to_string(),
        shared_secret: secret.to_string(),
        ..TransparencyLogConfig::default()
    });
    Arc::new(TransparencyLogger::open(cfg).expect("open signed log"))
}

#[test]
fn exporter_with_secret_rejects_stale_sig_forgery() {
    const SECRET: &str = "a-test-secret-that-is-at-least-32-bytes!!";
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("gov.jsonl");
    let log = signed_logger(&log_path, SECRET);
    gov_event(&log, "e1");
    gov_event(&log, "e2");
    drop(log);

    // Forge the last entry: recompute entry_hash, leave the sig stale.
    let content = std::fs::read_to_string(&log_path).unwrap();
    let mut entries: Vec<serde_json::Value> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let last = entries.last_mut().unwrap();
    last["event_id"] = serde_json::Value::String("forged".to_string());
    let new_hash = recompute_entry_hash(last).unwrap();
    last["entry_hash"] = serde_json::Value::String(new_hash);
    let rewritten = entries
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&log_path, format!("{rewritten}\n")).unwrap();

    // Without a secret the exporter forwards (hash chain is intact).
    let mut plain = LogExporter::open(
        ExportSource::Governance,
        log_path.clone(),
        dir.path().join("cursor-plain.json"),
    )
    .unwrap();
    assert!(plain.poll(&CollectingSink::new()).is_ok());

    // With the secret it halts on the stale-sig entry (own cursor, so it
    // rescans from genesis rather than resuming past the forged entry).
    let mut signed = LogExporter::open(
        ExportSource::Governance,
        log_path.clone(),
        dir.path().join("cursor-signed.json"),
    )
    .unwrap()
    .with_signing_secret(SECRET);
    let err = signed.poll(&CollectingSink::new()).unwrap_err();
    assert!(
        matches!(err, ExportError::VerificationFailed(_)),
        "expected VerificationFailed, got {err:?}"
    );
}

#[test]
fn exporter_with_secret_forwards_intact_signed_log() {
    const SECRET: &str = "a-test-secret-that-is-at-least-32-bytes!!";
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("gov.jsonl");
    let log = signed_logger(&log_path, SECRET);
    gov_event(&log, "e1");
    gov_event(&log, "e2");
    drop(log);

    let sink = CollectingSink::new();
    let mut exp =
        exporter(dir.path(), ExportSource::Governance, &log_path).with_signing_secret(SECRET);
    let out = exp.poll(&sink).unwrap();
    assert_eq!(out.forwarded, 2);
    assert_eq!(sink.delivered().len(), 2);
}

// MIK-6703 SIEM.RUN.1 — the core NDJSON file sink appends one JSON line per
// forwarded entry, and forwarding advances the cursor (at-least-once ack).
#[test]
fn file_sink_writes_ndjson_and_forwards() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("gov.jsonl");
    let log = logger(&log_path);
    gov_event(&log, "e1");
    gov_event(&log, "e2");
    drop(log);

    let sink_path = dir.path().join("siem.ndjson");
    let sink = FileExportSink::open(sink_path.clone()).unwrap();
    let mut exp = exporter(dir.path(), ExportSource::Governance, &log_path);
    let out = exp.poll(&sink).unwrap();
    assert_eq!(out.forwarded, 2);

    let contents = std::fs::read_to_string(&sink_path).unwrap();
    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 2, "one NDJSON line per forwarded entry");
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["source"], "governance");
        assert!(v["entry_hash"].is_string());
    }

    // Cursor advanced: a second poll with no new entries forwards nothing.
    let out2 = exp.poll(&sink).unwrap();
    assert_eq!(out2.forwarded, 0);
}

// SIEM.RUN.2 — ExportConfig is opt-in (disabled by default) so the task is
// never spawned unless an operator configures it.
#[test]
fn export_config_is_opt_in() {
    assert!(!ExportConfig::default().enabled);
}

// MIK-6703 review #1 — fail-closed latch: once the sink is unhealthy (a
// partial write it could not roll back), every subsequent deliver refuses,
// so the cursor can never advance over a torn stream.
#[test]
fn unhealthy_sink_refuses_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let sink = FileExportSink::open(dir.path().join("siem.ndjson")).unwrap();
    // Healthy: an empty deliver succeeds.
    assert!(sink.deliver(&[]).is_ok());
    // Latch unhealthy (simulating an unrecoverable partial write).
    sink.healthy
        .store(false, std::sync::atomic::Ordering::Release);
    let err = sink.deliver(&[]).unwrap_err();
    assert!(
        matches!(err, ExportError::SinkRejected(_)),
        "an unhealthy sink must refuse (fail-closed), got {err:?}"
    );
}

// MIK-6703 review #2 — first-create durability: delivering to a fresh path
// creates the sink file with the content (the dir-fsync path runs).
#[test]
fn file_sink_first_create_persists() {
    let dir = tempfile::tempdir().unwrap();
    let sink_path = dir.path().join("nested/siem.ndjson");
    let sink = FileExportSink::open(sink_path.clone()).unwrap();
    assert!(!sink_path.exists(), "file not created until first deliver");
    let entry = ExportEntry {
        source: ExportSource::Invocation,
        counter: 1,
        entry_hash: "sha256:aa".to_string(),
        prev_entry_hash: "genesis".to_string(),
        checkpoint: "genesis".to_string(),
        raw: serde_json::json!({ "k": "v" }),
    };
    sink.deliver(std::slice::from_ref(&entry)).unwrap();
    let contents = std::fs::read_to_string(&sink_path).unwrap();
    assert_eq!(contents.lines().filter(|l| !l.is_empty()).count(), 1);
}

// MIK-6703 review — deliver is all-or-nothing + durable: repeated batches
// produce a stream where EVERY line is complete valid JSON (no torn lines),
// and each entry appears exactly once (no duplication across delivers).
#[test]
fn file_sink_stream_stays_valid_across_repeated_delivers() {
    let dir = tempfile::tempdir().unwrap();
    let sink_path = dir.path().join("siem.ndjson");
    let sink = FileExportSink::open(sink_path.clone()).unwrap();
    let entry = |c: u64| ExportEntry {
        source: ExportSource::Governance,
        counter: c,
        entry_hash: format!("sha256:{c:064x}"),
        prev_entry_hash: "sha256:prev".to_string(),
        checkpoint: "genesis".to_string(),
        raw: serde_json::json!({ "counter": c }),
    };
    sink.deliver(&[entry(1), entry(2)]).unwrap();
    sink.deliver(&[entry(3)]).unwrap();
    sink.deliver(&[]).unwrap(); // empty batch: no-op, no torn output

    let contents = std::fs::read_to_string(&sink_path).unwrap();
    let counters: Vec<u64> = contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let v: serde_json::Value =
                serde_json::from_str(l).expect("every sink line must be complete valid JSON");
            v["counter"].as_u64().unwrap()
        })
        .collect();
    assert_eq!(
        counters,
        vec![1, 2, 3],
        "each entry once, in order, no torn lines"
    );
}

// SIEM.RUN.1 — status counters fold poll outcomes: forwarded accumulates,
// max_lag is monotonic, last_lag tracks the latest.
#[test]
fn source_status_records_outcomes() {
    let s = SourceExportStatus::default();
    s.record(&PollOutcome {
        forwarded: 3,
        lag_entries: 5,
        reanchored: false,
    });
    s.record(&PollOutcome {
        forwarded: 2,
        lag_entries: 1,
        reanchored: true,
    });
    let snap = s.snapshot();
    assert_eq!(snap["forwarded_total"], 5);
    assert_eq!(snap["last_lag"], 1);
    assert_eq!(snap["max_lag"], 5, "max_lag is monotonic across polls");
    assert_eq!(snap["reanchor_total"], 1);
}

// ── D6 2.11: the exporter follows the log's own rotation ─────────────────────

fn small_logger(path: &Path, retain: u32, secret: &str) -> Arc<TransparencyLogger> {
    let rotation = crate::security::transparency_log::RotationConfig {
        max_segment_bytes: 4096,
        retain_segments: retain,
        ..crate::security::transparency_log::RotationConfig::default()
    };
    let cfg = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "test-key".to_string(),
        shared_secret: secret.to_string(),
        rotation,
    });
    Arc::new(TransparencyLogger::open(cfg).expect("open log"))
}

fn sealed(path: &Path) -> Vec<u64> {
    crate::security::transparency_log::segments::list_segments(path)
        .unwrap()
        .iter()
        .map(|s| s.seq)
        .collect()
}

/// Append until the newest sealed segment number reaches `seq`.
fn until_sealed(l: &TransparencyLogger, path: &Path, seq: u64) {
    let mut i = 0;
    while sealed(path).last().is_none_or(|s| *s < seq) {
        gov_event(l, &format!("e{i}"));
        i += 1;
    }
}

/// Null control: must stay green on the unmutated build.
#[test]
fn export_follows_rotation_without_loss() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("gov.jsonl");
    let l = small_logger(&log, 12, "");
    (0..3).for_each(|i| gov_event(&l, &format!("a{i}")));
    let sink = CollectingSink::new();
    let mut exp = exporter(dir.path(), ExportSource::Governance, &log).with_max_batch(2);
    exp.poll(&sink).unwrap();
    until_sealed(&l, &log, 1);
    loop {
        let out = exp.poll(&sink).unwrap();
        assert!(!out.reanchored);
        if out.forwarded == 0 {
            break;
        }
    }
    let counters: Vec<u64> = sink.delivered().iter().map(|e| e.counter).collect();
    let want: Vec<u64> = (1..=*counters.last().unwrap()).collect();
    assert_eq!(counters, want, "every record exactly once, in order");
}

#[test]
fn export_reanchors_at_oldest_open_record_after_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("gov.jsonl");
    let l = small_logger(&log, 1, "");
    gov_event(&l, "first");
    let sink = CollectingSink::new();
    let mut exp = exporter(dir.path(), ExportSource::Governance, &log);
    exp.poll(&sink).unwrap();
    assert_eq!(exp.cursor().segment_seq, Some(0));
    until_sealed(&l, &log, 2); // retention 1: `.0` expired
    assert!(!sealed(&log).contains(&0));
    let before = sink.delivered().len();
    let out = exp.poll(&sink).unwrap();
    assert!(out.reanchored);
    let first = &sink.delivered()[before];
    assert_eq!(first.raw["event"], "audit_segment_opened");
    assert_eq!(first.raw["segment_seq"], sealed(&log)[0]);
}

#[test]
fn export_rejects_forged_first_line_after_reanchor() {
    const SECRET: &str = "a-test-secret-that-is-at-least-32-bytes!!";
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("gov.jsonl");
    let l = small_logger(&log, 1, SECRET);
    until_sealed(&l, &log, 2);
    drop(l);
    let oldest = crate::security::transparency_log::segments::sealed_path(&log, sealed(&log)[0]);
    let body = std::fs::read_to_string(&oldest).unwrap();
    let mut rows: Vec<serde_json::Value> = body
        .lines()
        .map(|r| serde_json::from_str(r).unwrap())
        .collect();
    rows[0]["sig"] = "hmac-sha256:00".into();
    let body = rows
        .iter()
        .fold(String::new(), |acc, v| acc + &v.to_string() + "\n");
    std::fs::write(&oldest, body).unwrap();
    let mut exp = exporter(dir.path(), ExportSource::Governance, &log).with_signing_secret(SECRET);
    assert!(matches!(
        exp.poll(&CollectingSink::new()),
        Err(ExportError::VerificationFailed(_))
    ));
}

#[test]
fn export_rejects_non_open_first_line_after_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("gov.jsonl");
    let l = small_logger(&log, 1, "");
    until_sealed(&l, &log, 2);
    drop(l);
    let oldest = crate::security::transparency_log::segments::sealed_path(&log, sealed(&log)[0]);
    let body = std::fs::read_to_string(&oldest).unwrap();
    let mut rows: Vec<serde_json::Value> = body
        .lines()
        .map(|r| serde_json::from_str(r).unwrap())
        .collect();
    // Turn the open record into an ordinary record, hash recomputed.
    rows[0]["event"] = "not_an_open_record".into();
    rows[0]["entry_hash"] = recompute_entry_hash(&rows[0]).unwrap().into();
    let body = rows
        .iter()
        .fold(String::new(), |acc, v| acc + &v.to_string() + "\n");
    std::fs::write(&oldest, body).unwrap();
    let mut exp = exporter(dir.path(), ExportSource::Governance, &log);
    assert!(matches!(
        exp.poll(&CollectingSink::new()),
        Err(ExportError::VerificationFailed(_))
    ));
}

#[test]
fn export_loads_pre_d6_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("gov.jsonl");
    let l = small_logger(&log, 12, "");
    gov_event(&l, "a");
    std::fs::write(
        dir.path().join("cursor.json"),
        r#"{"last_entry_hash":"genesis","last_counter":0}"#,
    )
    .unwrap();
    let mut exp = exporter(dir.path(), ExportSource::Governance, &log);
    assert_eq!(exp.cursor().segment_seq, None);
    assert_eq!(exp.poll(&CollectingSink::new()).unwrap().forwarded, 1);
}

#[test]
fn export_from_genesis_cursor_after_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("gov.jsonl");
    let l = small_logger(&log, 1, "");
    until_sealed(&l, &log, 2);
    let sink = CollectingSink::new();
    let mut exp = exporter(dir.path(), ExportSource::Governance, &log);
    exp.poll(&sink)
        .expect("a fresh exporter starts at the oldest open record");
    let first = &sink.delivered()[0];
    assert_eq!(first.raw["event"], "audit_segment_opened");
    assert_eq!(first.raw["segment_seq"], sealed(&log)[0]);
}
