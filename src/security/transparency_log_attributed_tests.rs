// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7116.MIN.1: the attributed invocation writer (test plan T23, T24, T11).

use std::sync::Arc;

use serde_json::{Map, Value, json};

use super::attributed::MAX_RECORDED_TENANTS;
use super::*;
use crate::security::audit::{AuditEnvelope, InvocationTarget};

fn open(dir: &tempfile::TempDir) -> (TransparencyLogger, PathBuf) {
    let path = dir.path().join("audit.jsonl");
    let logger = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "min1".to_string(),
        ..TransparencyLogConfig::default()
    }))
    .expect("open log");
    (logger, path)
}

fn write(logger: &TransparencyLogger, extra: Map<String, Value>) -> io::Result<()> {
    logger.log_invocation_attributed(
        CorrelationKey {
            id: "trace-1",
            source: CorrelationSource::TraceId,
        },
        &AuditEnvelope::gateway(),
        InvocationTarget::meta("alpha", "read"),
        "sha256:req",
        Some("sha256:resp"),
        extra,
        None,
    )
}

fn invocations(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e.get("tool").is_some())
        .collect()
}

/// `n` distinct 16-hex tenant hashes, deliberately unsorted.
fn hashes(n: usize) -> Vec<String> {
    (0..n).rev().map(|i| format!("{i:016x}")).collect()
}

fn with_tenants(tenants: &[String]) -> Map<String, Value> {
    let mut extra = Map::new();
    extra.insert("tenants".into(), json!(tenants));
    extra
}

/// T23. Past the cap a record keeps the first `MAX_RECORDED_TENANTS` sorted
/// hashes and names the true count; at the cap there is no marker. Both
/// records verify.
#[test]
fn tenant_list_is_capped_with_an_overflow_marker() {
    let dir = tempfile::tempdir().unwrap();
    let (logger, path) = open(&dir);
    write(&logger, with_tenants(&hashes(MAX_RECORDED_TENANTS + 1))).unwrap();
    write(&logger, with_tenants(&hashes(MAX_RECORDED_TENANTS))).unwrap();

    let records = invocations(&path);
    assert_eq!(records.len(), 2);
    let mut sorted = hashes(MAX_RECORDED_TENANTS + 1);
    sorted.sort();
    sorted.truncate(MAX_RECORDED_TENANTS);
    assert_eq!(records[0]["tenants"], json!(sorted));
    assert_eq!(records[0]["tenants_total"], json!(MAX_RECORDED_TENANTS + 1));
    assert_eq!(
        records[1]["tenants"].as_array().map(Vec::len),
        Some(MAX_RECORDED_TENANTS)
    );
    assert!(records[1].get("tenants_total").is_none());
    assert!(verify_log(&path).unwrap().ok);
}

// The cap bounds what attribution can add to a record, far under the append
// limit (a 16-hex hash is 19 bytes with quotes and comma). Checked at compile
// time.
const _: () = assert!(MAX_RECORDED_TENANTS * 19 < super::rotation::MAX_RECORD_BYTES / 8);

/// T24. `extra` cannot overwrite a domain field, forge a chain field, or
/// supply the overflow count only the writer derives (MIK-7646); nothing is
/// appended.
#[test]
fn extra_fields_cannot_collide_with_record_fields() {
    let dir = tempfile::tempdir().unwrap();
    let (logger, path) = open(&dir);
    for key in [
        "route",
        "caller",
        "request_hash",
        "entry_hash",
        "counter",
        "tenants_total",
    ] {
        let mut extra = Map::new();
        extra.insert(key.into(), json!("forged"));
        assert!(
            write(&logger, extra).is_err(),
            "`{key}` in extra must be refused"
        );
    }
    assert!(invocations(&path).is_empty());
}

/// T11 (writer half). Attribution fields are inside the chain: the record
/// verifies, and editing one character of `tenants` breaks verification.
#[test]
fn attribution_fields_are_inside_the_hash_chain() {
    let dir = tempfile::tempdir().unwrap();
    let (logger, path) = open(&dir);
    let tenant = "0123456789abcdef".to_string();
    write(&logger, with_tenants(std::slice::from_ref(&tenant))).unwrap();
    assert_eq!(invocations(&path)[0]["tenants"], json!([tenant]));
    assert!(verify_log(&path).unwrap().ok);

    let text = std::fs::read_to_string(&path).unwrap();
    let tampered = text.replace("0123456789abcdef", "0123456789abcdee");
    assert_ne!(text, tampered);
    std::fs::write(&path, tampered).unwrap();
    assert!(!verify_log(&path).unwrap().ok);
}

/// MIK-8202 E4: an invocation recorded on a clock before 1970 is kept,
/// undated: `timestamp` is `null` and `clock_invalid` is `true`, never a 1969
/// stamp. On a readable clock the row carries a time and no marker.
#[test]
fn an_invocation_on_an_unreadable_clock_is_recorded_undated() {
    let dir = tempfile::tempdir().expect("dir");
    let (logger, path) = open(&dir);
    write(&logger, Map::new()).expect("dated row");
    {
        let _clock = crate::clock::test_clock::before_epoch();
        write(&logger, Map::new()).expect("undated row kept");
    }
    let rows = invocations(&path);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows[0]["timestamp"].is_string(), "{}", rows[0]);
    assert!(rows[0].get("clock_invalid").is_none(), "{}", rows[0]);
    assert_eq!(rows[1]["timestamp"], Value::Null, "{}", rows[1]);
    assert_eq!(rows[1]["clock_invalid"], true, "{}", rows[1]);
}

fn decided() -> crate::security::decision_record::Decision {
    use crate::security::decision_record::{Decided, Decision, DecisionKind};
    Decision {
        v: 1,
        config_revision: Some("hmac-sha256:00".to_owned()),
        running_revision: None,
        pending_restart: Vec::new(),
        kind: DecisionKind::DefaultAllow,
        rule_id: None,
        grant_id: None,
        request_findings: Some(Vec::new()),
        request_findings_truncated: false,
        declared_effect: None,
        decided: Decided::Fresh,
    }
}

/// MIK-8914.API2A.3: the writer's own decision argument is written under its
/// field, inside the hashed and signed entry, and reads back exactly.
#[test]
fn api2a_3_the_decision_is_written_by_the_writer_and_reads_back() {
    let dir = tempfile::tempdir().unwrap();
    let (logger, path) = open(&dir);
    let decision = decided();
    logger
        .log_invocation_attributed(
            CorrelationKey {
                id: "trace-1",
                source: CorrelationSource::TraceId,
            },
            &AuditEnvelope::gateway(),
            InvocationTarget::meta("alpha", "read"),
            "sha256:req",
            Some("sha256:resp"),
            Map::new(),
            Some(&decision),
        )
        .unwrap();
    write(&logger, Map::new()).unwrap();
    let records = invocations(&path);
    let field = crate::security::decision_record::FIELD;
    let written: crate::security::decision_record::Decision =
        serde_json::from_value(records[0][field].clone()).expect("the decision reads back");
    assert_eq!(written, decision);
    assert!(
        records[1].get(field).is_none(),
        "a record written without one carries no decision"
    );
    assert!(
        verify_log(&path).unwrap().ok,
        "the decision is inside the chain"
    );
}

/// A caller's attribution can never supply or overwrite the decision.
#[test]
fn api2a_3_attribution_naming_the_decision_field_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (logger, path) = open(&dir);
    let mut extra = Map::new();
    extra.insert(
        crate::security::decision_record::FIELD.into(),
        json!({"v": 1, "kind": "default_allow", "decided": "fresh"}),
    );
    assert!(write(&logger, extra).is_err());
    assert!(invocations(&path).is_empty());
}
