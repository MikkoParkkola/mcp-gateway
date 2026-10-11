// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8202 part 2 (P2), T5b: the exporter and the verifier read an undated
//! delivery record (`timestamp: null`, `clock: "before_epoch"`) as it is.

use std::sync::Arc;

use super::*;
use crate::security::TransparencyLogger;
use crate::security::audit::AuditEnvelope;
use crate::security::transparency_log::TransparencyLogConfig;

/// T5b (guard): an undated delivery record planted in the log survives
/// export in append order, the hash chain verifies, and its null timestamp
/// stays null. Mutant: a null timestamp read as epoch 0.
#[test]
fn t5b_an_undated_delivery_record_exports_and_verifies_with_its_null_timestamp() {
    // GIVEN: a log whose second entry is an undated delivery record
    let dir = tempfile::tempdir().expect("tempdir");
    let log = dir.path().join("inv.jsonl");
    let logger = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: log.to_string_lossy().into_owned(),
            key_id: "test".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log"),
    );
    logger
        .log_invocation("s", "c", "srv", "t", "req", "resp")
        .expect("dated entry");
    let mut fields = serde_json::Map::new();
    fields.insert("event".into(), "response_delivery_attempt".into());
    fields.insert("timestamp".into(), serde_json::Value::Null);
    fields.insert("clock".into(), "before_epoch".into());
    logger
        .append_event(fields, &AuditEnvelope::gateway())
        .expect("undated entry");
    logger
        .log_invocation("s", "c", "srv", "t", "req2", "resp2")
        .expect("dated entry");
    // WHEN
    let verdict = crate::security::transparency_log::verify_log(&log).expect("verify runs");
    std::fs::create_dir_all(dir.path().join("cur")).expect("cursor dir");
    let mut exporter = LogExporter::open(
        ExportSource::Invocation,
        log.clone(),
        dir.path().join("cur").join("cursor.json"),
    )
    .expect("exporter opens");
    let sink = CollectingSink::new();
    exporter.poll(&sink).expect("export runs");
    // THEN
    assert!(verdict.ok, "{:?}", verdict.error_message);
    let delivered = sink.delivered();
    let counters: Vec<u64> = delivered.iter().map(|e| e.counter).collect();
    assert!(
        counters.windows(2).all(|w| w[0] + 1 == w[1]),
        "{counters:?}"
    );
    let undated = delivered
        .iter()
        .find(|e| e.raw["event"] == "response_delivery_attempt")
        .expect("the undated record is exported");
    assert_eq!(undated.raw.get("timestamp"), Some(&serde_json::Value::Null));
    assert_eq!(undated.raw["clock"], "before_epoch");
}
