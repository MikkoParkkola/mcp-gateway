// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Typed regression consumers for the documented Firewall audit schema.
//! The repository has a Firewall writer, not a production audit reader. These
//! test consumers pin compatibility of its existing fields without inventing one.

#[path = "capture.rs"]
mod capture;
pub(super) use capture::capture_warnings;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::security::firewall::FirewallAction;
use crate::security::response_policy::{
    ResponseArtifactKind, ResponseCorrelation, ResponsePolicyTarget,
};

#[derive(Debug, Serialize, Deserialize)]
struct LegacyResponseEvent {
    timestamp: String,
    event: String,
    session_id: String,
    server: String,
    tool: String,
    caller: String,
    args_hash: Option<String>,
    action: String,
    findings_count: usize,
    findings: Vec<Value>,
    anomaly_score: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct V2ResponseEvent {
    #[serde(flatten)]
    legacy: LegacyResponseEvent,
    schema_version: u8,
    artifact_kind: String,
    policy_targets: Vec<AuditTarget>,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditTarget {
    server: String,
    tool: String,
}

pub(crate) fn assert_v2_event(
    event: &Value,
    correlation: &ResponseCorrelation<'_>,
    targets: &[ResponsePolicyTarget],
    artifact: ResponseArtifactKind,
    action: FirewallAction,
) {
    let parsed: V2ResponseEvent =
        serde_json::from_value(event.clone()).expect("complete typed v2 event");
    assert_eq!(parsed.schema_version, 2);
    assert_eq!(
        json!(parsed.artifact_kind),
        serde_json::to_value(artifact).unwrap()
    );
    assert!(!parsed.policy_targets.is_empty());
    let mut expected = targets.to_vec();
    expected.sort();
    expected.dedup();
    let expected: Vec<_> = expected
        .into_iter()
        .map(|target| AuditTarget {
            server: target.server,
            tool: target.tool,
        })
        .collect();
    assert_eq!(parsed.policy_targets, expected);
    assert_eq!(parsed.legacy.event, "response");
    assert_eq!(parsed.legacy.session_id, correlation.session_id);
    assert_eq!(parsed.legacy.caller, correlation.caller);
    assert_eq!(parsed.legacy.server, correlation.external_server);
    assert_eq!(parsed.legacy.tool, correlation.external_tool);
    assert_eq!(
        json!(parsed.legacy.action),
        serde_json::to_value(action).unwrap()
    );
    assert_eq!(parsed.legacy.findings_count, parsed.legacy.findings.len());
    assert!(parsed.legacy.args_hash.is_none());
    assert!(parsed.legacy.anomaly_score.is_none());
    chrono::DateTime::parse_from_rfc3339(&parsed.legacy.timestamp)
        .expect("RFC3339 audit timestamp");
    let mut expected_keys = [
        "timestamp",
        "event",
        "session_id",
        "server",
        "tool",
        "caller",
        "args_hash",
        "action",
        "findings_count",
        "findings",
        "anomaly_score",
        "schema_version",
        "artifact_kind",
        "policy_targets",
    ];
    expected_keys.sort_unstable();
    let mut keys: Vec<_> = event
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, expected_keys);
}

/// Both values pass through the same typed v1 field consumer. The v2 producer
/// event is never modified to manufacture an old event from a malformed one.
pub(super) fn assert_legacy_field_compatibility(untouched_v2: &Value) {
    const V1_FIXTURE: &str = r#"{"timestamp":"2026-04-01T12:00:00Z","event":"response","session_id":"legacy-session","server":"legacy-backend","tool":"echo","caller":"legacy-caller","args_hash":null,"action":"allow","findings_count":0,"findings":[],"anomaly_score":null}"#;
    let fixed_v1: Value = serde_json::from_str(V1_FIXTURE).unwrap();
    let v1: LegacyResponseEvent = serde_json::from_value(fixed_v1.clone()).unwrap();
    assert_eq!(serde_json::to_value(v1).unwrap(), fixed_v1);
    let v2_as_legacy: LegacyResponseEvent = serde_json::from_value(untouched_v2.clone())
        .expect("untouched v2 remains readable with the existing typed v1 fields");
    let projection = serde_json::to_value(v2_as_legacy).unwrap();
    for (key, value) in projection.as_object().unwrap() {
        assert_eq!(
            untouched_v2.get(key),
            Some(value),
            "legacy field {key} changed type/value"
        );
    }
    assert_eq!(projection.as_object().unwrap().len(), 11);
}
