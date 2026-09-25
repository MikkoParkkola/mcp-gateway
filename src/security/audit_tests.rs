// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D1 envelope cells that need no gateway: reserved keys, v1/v2 chains,
//! governance records, the outcome table and the trace id (D1-T9, T10, T11,
//! T14, T19).

use std::path::Path;
use std::sync::Arc;

use serde_json::{Map, Value, json};

use super::AuditOutcome;
use crate::Error;
use crate::security::TransparencyLogger;
use crate::security::transparency_log::{TransparencyLogConfig, recompute_entry_hash, verify_log};

fn logger(path: &Path) -> TransparencyLogger {
    TransparencyLogger::open(Arc::new(TransparencyLogConfig {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        key_id: "d1".to_string(),
        shared_secret: String::new(),
    }))
    .expect("open log")
}

/// The one place these cells call the logger.
fn append(logger: &TransparencyLogger, fields: Map<String, Value>) -> std::io::Result<String> {
    logger.append_event(fields, &super::AuditEnvelope::gateway())
}

fn fields(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

fn entries(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .expect("read log")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("entry is JSON"))
        .collect()
}

/// D1-T9. The envelope keys are reserved like the chain keys.
#[test]
fn caller_cannot_forge_envelope_fields() {
    let dir = tempfile::tempdir().unwrap();
    let log = logger(&dir.path().join("a.jsonl"));
    for key in ["schema_version", "trace_id", "outcome", "error_code", "who"] {
        let result = append(
            &log,
            fields(&[("event", json!("x")), (key, json!("forged"))]),
        );
        assert!(
            result.is_err(),
            "a writer supplied `{key}` and it was accepted"
        );
    }
}

/// D1-T10, positive control. Entries without the envelope (v1) and with it
/// (v2) verify in one file.
#[test]
fn v1_and_v2_entries_verify_in_one_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.jsonl");
    // Written the way a 3.x gateway wrote them: no envelope keys at all,
    // chained by hand with the published hash rule.
    let mut prev = "genesis".to_string();
    let mut lines = String::new();
    for counter in 1..=2u64 {
        let mut entry = json!({
            "counter": counter,
            "prev_entry_hash": prev,
            "caller": "ci",
            "tool": "t",
        });
        let hash = recompute_entry_hash(&entry).expect("hash v1 entry");
        entry["entry_hash"] = json!(hash);
        prev = hash;
        lines.push_str(&entry.to_string());
        lines.push('\n');
    }
    std::fs::write(&path, lines).expect("write v1 entries");
    let v2 = logger(&path);
    append(&v2, fields(&[("event", json!("v2"))])).expect("v2 append");
    let result = verify_log(&path).expect("verify");
    assert!(result.ok, "mixed chain must verify");
    assert_eq!(entries(&path).len(), 3);
}

/// D1-T11. A governance mutation by an OIDC actor carries the envelope, and
/// `who` names the `(issuer, sub)` the actor id encodes.
#[test]
fn governance_event_carries_envelope() {
    use crate::control_plane::{
        ControlPlaneAction, ControlPlaneAuditEvent, ControlPlaneRollbackPlan, ControlPlaneStore,
        FileControlPlaneStore,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let store =
        FileControlPlaneStore::open(dir.path().join("store"), Arc::new(logger(&path))).unwrap();
    let actor = crate::key_server::oidc::VerifiedIdentity {
        subject: "123".to_string(),
        email: "x@corp.com".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://a.example".to_string(),
    }
    .stable_actor_id();
    store
        .append_audit(&ControlPlaneAuditEvent {
            event_id: "e1".to_string(),
            actor_id: actor,
            action: ControlPlaneAction::MutateGrant,
            target_id: "g1".to_string(),
            reason: "ticket-1".to_string(),
            rollback: ControlPlaneRollbackPlan {
                summary: "s".to_string(),
                step: "r".to_string(),
            },
        })
        .expect("append governance event");
    let entry = entries(&path).pop().expect("one entry");
    assert_eq!(entry["schema_version"], json!(2), "{entry}");
    assert_eq!(entry["outcome"], json!("ok"), "{entry}");
    assert_eq!(entry["who"]["subject"], json!("123"), "{entry}");
    assert_eq!(
        entry["who"]["authority"],
        json!("https://a.example"),
        "{entry}"
    );
    assert!(!entry.to_string().contains("x@corp.com"), "{entry}");
}

fn forbidden(code: i32) -> Error {
    Error::Forbidden {
        code,
        status: 403,
        message: "no".to_string(),
    }
}

/// An expected `(outcome, error_code)`; `None` means no record.
type Row = (&'static str, Option<i32>);

/// D1-T14. One row per line of the D1-d.2 table, matched on the variant: the
/// -32001 refusal and `BackendNotFound` share a code and not an outcome.
#[test]
fn outcome_mapping_covers_every_row() {
    let json_err = serde_json::from_str::<Value>("{").unwrap_err();
    let rows: Vec<(crate::Result<Value>, Option<Row>)> = vec![
        (Ok(json!({"isError": false})), Some(("ok", None))),
        (Ok(json!({"content": []})), Some(("ok", None))),
        (Ok(json!({"isError": true})), Some(("tool_error", None))),
        (Err(forbidden(-32003)), Some(("denied", Some(-32003)))),
        (
            Err(Error::json_rpc(-32004, "grant")),
            Some(("denied", Some(-32004))),
        ),
        (
            Err(Error::json_rpc(-32001, "isolation")),
            Some(("denied", Some(-32001))),
        ),
        (
            Err(Error::ResponseFirewallRefused),
            Some(("denied", Some(-32600))),
        ),
        (Err(Error::Json(json_err)), Some(("invalid", Some(-32700)))),
        (
            Err(Error::Protocol("p".into())),
            Some(("invalid", Some(-32600))),
        ),
        (
            Err(Error::BackendNotFound("b".into())),
            Some(("invalid", Some(-32001))),
        ),
        (
            Err(Error::ToolNotFound("t".into())),
            Some(("invalid", Some(-32001))),
        ),
        (
            Err(Error::json_rpc(-32602, "params")),
            Some(("invalid", Some(-32602))),
        ),
        (Err(Error::AuditUnavailable), None),
        (
            Err(Error::Transport("down".into())),
            Some(("error", Some(-32000))),
        ),
        (
            Err(Error::BackendTimeout("slow".into())),
            Some(("error", Some(-32000))),
        ),
        (
            Err(Error::CircuitOpen {
                backend: "b".into(),
                last_failure: None,
            }),
            Some(("error", Some(-32000))),
        ),
        (
            Err(Error::Internal("bug".into())),
            Some(("error", Some(-32603))),
        ),
        (
            Err(Error::json_rpc(-32000, "kill switch")),
            Some(("error", Some(-32000))),
        ),
    ];
    for (result, want) in rows {
        let got = AuditOutcome::from_result(&result).map(|o| (o.label(), o.error_code()));
        assert_eq!(got, want, "row {result:?}");
    }
}

/// D1-T19. A writer with no trace id gets the scope's, or a minted one.
#[tokio::test]
async fn non_invoke_writer_gets_trace_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a.jsonl");
    let log = Arc::new(logger(&path));
    let inner = Arc::clone(&log);
    crate::gateway::trace::with_trace_id("gw-scope-1".to_string(), async move {
        append(&inner, fields(&[("event", json!("in"))])).expect("append in scope");
    })
    .await;
    append(&log, fields(&[("event", json!("out"))])).expect("append outside scope");
    let all = entries(&path);
    assert_eq!(all[0]["trace_id"], json!("gw-scope-1"), "{}", all[0]);
    let minted = all[1]["trace_id"].as_str().unwrap_or_default();
    assert!(minted.starts_with("gw-"), "{}", all[1]);
}
