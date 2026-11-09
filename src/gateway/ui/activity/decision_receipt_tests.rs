// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows T7-T12, T15, T16 and the receipt half of T18: the receipt's
//! decision evidence, read back through the decision reader's lines.

use serde_json::{Value, json};

use super::access::Access;
use super::decision_fixtures::{assert_no_sentinel, call, decision, finding, write_chained};
use super::reader::{Line, Which};
use super::receipt::{parse_id, receipt};
use super::rows::{Check, row_id};
use crate::security::decision_record::read as evidence;

/// The receipt body of one call carrying `decision` (or none).
fn receipt_of(decision: Option<Value>) -> Value {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inv.jsonl");
    let mut entries = vec![call("srv", "t", decision)];
    write_chained(&path, &mut entries);
    let line = Line {
        log: Which::Invocation,
        entry: entries[0].clone(),
        segment: 0,
    };
    let id = parse_id(&row_id(&line).unwrap()).unwrap();
    let body = receipt(&path, &id, &Access::All, &Check::bare(None))
        .unwrap()
        .unwrap();
    assert_no_sentinel(&body.to_string());
    body
}

/// A v2 decision with `patch`'s members set over the fixture's.
fn with(patch: &Value) -> Value {
    let mut d = decision(Some("r1"));
    for (k, v) in patch.as_object().unwrap() {
        d[k] = v.clone();
    }
    d
}

fn keys(v: &Value) -> Vec<&str> {
    v.as_object().unwrap().keys().map(String::as_str).collect()
}

#[test]
fn receipt_v2_record_serves_the_full_decision_projection() {
    let found = finding("pii", "high", "arguments.query");
    let body = receipt_of(Some(with(&json!({
        "grant_id": "grant-1", "request_findings": [found.clone()],
        "config_revision": "cfg-1", "running_revision": "run-1",
    }))));
    assert_eq!(
        body["decision"],
        json!({
            "v": 2, "kind": "tool_policy", "rule": "r1", "grant": "grant-1",
            "flags": evidence::FLAGS_NOT_SET, "findings": [found.clone()],
            "effect": "read_only", "decided": evidence::DECIDED_FRESH,
            "config_revision": "cfg-1", "running_revision": "run-1",
        })
    );
    assert_eq!(body["findings"], json!([found]));
}

#[test]
fn receipt_revisions_absent_are_never_invented() {
    let none = receipt_of(Some(decision(Some("r1"))));
    let d = &none["decision"];
    assert!(d.get("config_revision").is_none() && d.get("running_revision").is_none());
    let one = receipt_of(Some(with(&json!({"config_revision": "cfg-1"}))));
    assert_eq!(one["decision"]["config_revision"], "cfg-1");
    assert!(!keys(&one["decision"]).contains(&"running_revision"));
}

#[test]
fn receipt_decided_reads_each_variant() {
    for (stored, line) in [
        ("fresh", evidence::DECIDED_FRESH),
        ("cache_hit_copied", evidence::DECIDED_CACHE_COPIED),
        (
            "cache_hit_not_redecided",
            evidence::DECIDED_CACHE_NOT_REDECIDED,
        ),
        ("replayed", evidence::DECIDED_REPLAYED),
    ] {
        let body = receipt_of(Some(with(&json!({"decided": stored}))));
        assert_eq!(body["decision"]["decided"], line, "{stored}");
    }
}

#[test]
fn receipt_v1_record_reads_by_version_lines() {
    let v1 = json!({"v": 1, "kind": "tool_policy", "rule_id": "r1", "decided": "fresh"});
    let d = receipt_of(Some(v1))["decision"].clone();
    assert_eq!(d["findings"], evidence::NOT_RECORDED_BY_VERSION);
    assert_eq!(d["effect"], evidence::NOT_RECORDED_BY_VERSION);
    assert_eq!(d["flags"], evidence::FLAGS_NOT_SET);
}

#[test]
fn receipt_v2_empty_findings_reads_none_and_matches_the_row() {
    let body = receipt_of(Some(with(&json!({"request_findings": []}))));
    assert_eq!(body["decision"]["findings"], evidence::NO_FINDINGS);
    assert_eq!(body["findings"], body["decision"]["findings"]);
}

#[test]
fn receipt_undeclared_effect_reads_its_line() {
    let body = receipt_of(Some(with(&json!({"declared_effect": "undeclared"}))));
    assert_eq!(body["decision"]["effect"], evidence::UNDECLARED);
}

#[test]
fn receipt_record_without_decision_reads_none() {
    let body = receipt_of(None);
    assert_eq!(body["decision"], evidence::NOT_RECORDED_BY_VERSION);
}

#[test]
fn receipt_absent_rule_and_grant_read_their_lines() {
    let kind_only = json!({"v": 2, "kind": "tool_policy", "decided": "fresh"});
    let d = receipt_of(Some(kind_only))["decision"].clone();
    assert_eq!(d["rule"], evidence::RULE_NOT_RECORDED);
    assert_eq!(d["grant"], evidence::NOT_RECORDED_FOR_CALL);
}

#[test]
fn truncation_is_marked_both_ways() {
    let found = json!([finding("pii", "high", "arguments.q")]);
    let marked = |extra: Value| {
        let mut d = with(&json!({"request_findings": found}));
        for (k, v) in extra.as_object().unwrap() {
            d[k] = v.clone();
        }
        receipt_of(Some(d))
    };
    let yes = marked(json!({"request_findings_truncated": true}));
    assert_eq!(yes["decision"]["findings_truncated"], true);
    assert_eq!(yes["findings_truncated"], true);
    for body in [
        marked(json!({"request_findings_truncated": false})),
        marked(json!({})),
    ] {
        assert!(body["decision"].get("findings_truncated").is_none());
        assert!(body.get("findings_truncated").is_none());
    }
}
