// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows T4, T5, T6 and the CSV half of T13: the rule filter through
//! the NDJSON and CSV exports, and the scan cap over a filter nothing meets.

use serde_json::{Value, json};

use super::access::Access;
use super::csv::Truncated;
use super::decision_fixtures::{assert_no_sentinel, call, decision, write_chained};
use super::export::{CAPS, Caps, collect, csv, ndjson_size};
use super::rows::Filter;
use super::{ExportQuery, ListQuery, Logs, export_response};
use crate::security::decision_record::read as evidence;
use crate::trust::provenance_public::ProvenancePublicSigner;

fn named(tool: &str, rule: &str) -> Value {
    call("srv", tool, Some(decision(Some(rule))))
}

/// A log of `entries` (oldest first) and the Logs naming it.
fn logs_of(dir: &tempfile::TempDir, mut entries: Vec<Value>) -> Logs {
    let invocation = dir.path().join("inv.jsonl");
    write_chained(&invocation, &mut entries);
    Logs {
        invocation,
        governance: None,
        secret: None,
    }
}

/// The export of `rule` as `format`, as the route serves it.
async fn export(logs: &Logs, rule: &str, format: Option<&str>) -> String {
    let query = ExportQuery {
        list: ListQuery {
            rule: Some(rule.into()),
            ..ListQuery::default()
        },
        format: format.map(str::to_string),
    };
    let signer = ProvenancePublicSigner::from_seed_for_test([7u8; 32], "rule-export-1");
    let response = export_response(logs, &Access::All, &query, Some(&signer));
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn mixed(dir: &tempfile::TempDir) -> Logs {
    logs_of(
        dir,
        vec![
            call("srv", "t_nodec", None),
            call("srv", "t_norule", Some(decision(None))),
            named("t_r2", "r2"),
            named("t_r1", "r1"),
        ],
    )
}

#[tokio::test]
async fn ndjson_export_rule_filter_and_manifest_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let text = export(&mixed(&dir), "r1", None).await;
    let lines: Vec<Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let (manifest, rows) = lines.split_last().unwrap();
    let tools: Vec<&str> = rows.iter().map(|r| r["tool"].as_str().unwrap()).collect();
    assert_eq!(tools, ["t_r1"]);
    assert_eq!(manifest["filters"]["rule"], "r1");
    assert_eq!(
        rows[0]["decision"],
        json!({
            "v": 2, "kind": "tool_policy", "rule": "r1",
            "grant": evidence::NOT_RECORDED_FOR_CALL, "flags": evidence::FLAGS_NOT_SET,
            "findings": evidence::NO_FINDINGS, "effect": "read_only",
            "decided": evidence::DECIDED_FRESH,
        })
    );
    assert_no_sentinel(&text);
}

#[tokio::test]
async fn csv_export_rule_filter() {
    let dir = tempfile::tempdir().unwrap();
    let text = export(&mixed(&dir), "r1", Some("csv")).await;
    assert!(text.contains("t_r1"));
    for other in ["t_r2", "t_norule", "t_nodec"] {
        assert!(!text.contains(other), "{other}");
    }
    assert!(text.ends_with("#end rows=1 truncated=none\r\n"), "{text}");
    assert_no_sentinel(&text);
}

#[tokio::test]
async fn csv_export_rule_filter_ignores_the_id_in_another_field() {
    let dir = tempfile::tempdir().unwrap();
    let mut e = named("rule-1", "r2");
    e["payload"] = "rule-1".into();
    let text = export(&logs_of(&dir, vec![e]), "rule-1", Some("csv")).await;
    assert!(text.ends_with("#end rows=0 truncated=none\r\n"), "{text}");
}

/// Chained, projectable records padded past `scan`: the oldest is r1, every
/// later one r2.
fn padded(dir: &tempfile::TempDir) -> Logs {
    let pad = "p".repeat(400);
    let mut entries = vec![named("needle", "r1")];
    for i in 0..5_000 {
        let mut e = named(&format!("hay_{i}"), "r2");
        e["pad"] = pad.clone().into();
        entries.push(e);
    }
    logs_of(dir, entries)
}

fn gather(logs: &Logs, rule: &str) -> super::export::Collected {
    let filter = Filter {
        rule: Some(rule.into()),
        ..Filter::default()
    };
    let caps = Caps {
        scan: 1 << 20,
        ..CAPS
    };
    collect(
        &logs.invocation,
        None,
        &filter,
        &Access::All,
        None,
        caps,
        ndjson_size,
    )
    .unwrap()
}

#[test]
fn export_rule_filter_stops_at_scan_cap() {
    let dir = tempfile::tempdir().unwrap();
    let logs = padded(&dir);
    assert!(std::fs::metadata(&logs.invocation).unwrap().len() > 1 << 20);
    let none = gather(&logs, "r1");
    assert!(none.rows.is_empty());
    assert_eq!(none.unreadable, 0);
    assert!(matches!(none.truncated, Truncated::Scan));
    assert!(csv(&none).ends_with("#end rows=0 truncated=scan\r\n"));
    // Positive control: same fixture and caps, a rule the records do carry.
    let some = gather(&logs, "r2");
    assert!(!some.rows.is_empty());
    assert_eq!(some.unreadable, 0);
    assert!(some.rows.iter().all(|r| r["decision"]["rule"] == "r2"));
}

/// The CSV `findings_truncated` cell of one call: `true`, or empty.
fn truncated_cell(extra: &Value) -> String {
    let dir = tempfile::tempdir().unwrap();
    let mut d = decision(Some("r1"));
    d["request_findings"] = json!([super::decision_fixtures::finding(
        "pii",
        "high",
        "arguments.q"
    )]);
    for (k, v) in extra.as_object().unwrap() {
        d[k] = v.clone();
    }
    let logs = logs_of(&dir, vec![call("srv", "t", Some(d))]);
    let c = gather_all(&logs);
    let text = csv(&c);
    let mut lines = text.lines();
    let columns: Vec<&str> = lines.next().unwrap().split(',').collect();
    let at = columns
        .iter()
        .position(|c| *c == "findings_truncated")
        .unwrap();
    assert_eq!(columns[at - 1], "findings");
    // The row carries one JSON array in `findings`, quoted, so read the last cell.
    let row = lines.next().unwrap();
    assert_eq!(at, columns.len() - 1);
    row.rsplit(',').next().unwrap().to_string()
}

fn gather_all(logs: &Logs) -> super::export::Collected {
    collect(
        &logs.invocation,
        None,
        &Filter::default(),
        &Access::All,
        None,
        CAPS,
        ndjson_size,
    )
    .unwrap()
}

#[test]
fn csv_truncation_cell_is_true_or_empty() {
    assert_eq!(
        truncated_cell(&json!({"request_findings_truncated": true})),
        "true"
    );
    assert_eq!(
        truncated_cell(&json!({"request_findings_truncated": false})),
        ""
    );
    assert_eq!(truncated_cell(&json!({})), "");
}
