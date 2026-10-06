// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The meta-route refusal answer with an audit log attached: the refusal is
//! written under the caller's W3C trace id, and a failed write fails closed.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::gateway::router::create_router;
use crate::gateway::router::tests::{scoped_auth_config, test_router_app_state_with_auth};
use crate::security::TransparencyLogger;
use crate::security::audit::AuditFailurePolicy;
use crate::security::transparency_log::TransparencyLogConfig;

const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";

struct Fixture {
    router: axum::Router,
    log: Arc<TransparencyLogger>,
    audit_path: std::path::PathBuf,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

async fn fixture(policy: AuditFailurePolicy) -> Fixture {
    let audit = tempfile::tempdir().unwrap();
    let audit_path = audit.path().join("audit.jsonl");
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: audit_path.to_string_lossy().into_owned(),
            key_id: "refusal".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log")
        .with_failure_policy(policy),
    );
    let (mut state, store) = test_router_app_state_with_auth(&scoped_auth_config(false)).await;
    Arc::get_mut(&mut state)
        .expect("state is unique")
        .transparency_log = Some(Arc::clone(&log));
    Fixture {
        router: create_router(state),
        log,
        audit_path,
        _dirs: (audit, store),
    }
}

/// A `gateway_invoke` aimed at a backend the scoped key cannot reach: refused
/// by the router before the meta layer sees it.
async fn refused_invoke(fx: &Fixture, meta: Option<Value>) -> (StatusCode, Value) {
    let mut arguments = json!({"server": "elsewhere", "tool": "t", "arguments": {}});
    if let Some(meta) = meta {
        arguments["_meta"] = meta;
    }
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", "Bearer scoped-key")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "gateway_invoke", "arguments": arguments}
            })
            .to_string(),
        ))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn a_refusal_is_written_under_the_callers_trace_id() {
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    let traceparent = format!("00-{TRACE_ID}-00f067aa0ba902b7-01");
    let (status, body) = refused_invoke(&fx, Some(json!({"traceparent": traceparent}))).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let written = std::fs::read_to_string(&fx.audit_path).unwrap_or_default();
    assert!(
        written.contains(TRACE_ID),
        "the refusal record does not carry the caller's trace id: {written}"
    );
}

#[tokio::test]
async fn a_failed_refusal_write_answers_503_when_the_log_fails_closed() {
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    fx.log.set_append_failure_for_test(true);
    let (status, body) = refused_invoke(&fx, None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"]["code"], -32005, "{body}");
}

#[tokio::test]
async fn a_failed_refusal_write_keeps_the_refusal_when_the_log_is_best_effort() {
    let fx = fixture(AuditFailurePolicy::BestEffort).await;
    fx.log.set_append_failure_for_test(true);
    let (status, body) = refused_invoke(&fx, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

/// MIK-7640. A modern (2026-07-28) call carries no session, which the route
/// passes as an empty id: with no caller trace id the refusal is keyed on the
/// trace id the gateway minted, never on the empty session.
#[tokio::test]
async fn a_modern_refusal_without_a_trace_is_keyed_on_the_minted_trace_id() {
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    let arguments = json!({"server": "elsewhere", "tool": "t", "arguments": {}});
    let body = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": arguments,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    });
    // Two stateless refusals: each is keyed on its own minted trace id.
    for _ in 0..2 {
        let request = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("authorization", "Bearer scoped-key")
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-protocol-version", "2026-07-28")
            .header("mcp-method", "tools/call")
            .header("mcp-name", "gateway_invoke")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = fx.router.clone().oneshot(request).await.unwrap();
        let _ = axum::body::to_bytes(response.into_body(), usize::MAX).await;
    }
    let written = std::fs::read_to_string(&fx.audit_path).unwrap_or_default();
    let records: Vec<Value> = written
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .filter(|entry: &Value| entry.get("correlation_source").is_some())
        .collect();
    let [first, second] = records.as_slice() else {
        panic!("two refusal records: {written}");
    };
    for record in [first, second] {
        assert_eq!(record["correlation_source"], json!("trace_id"), "{record}");
        assert_ne!(record["session_id"], json!(""), "{record}");
    }
    assert_ne!(first["session_id"], second["session_id"], "{written}");
}

/// MIK-7640 control: a legacy call has a session id, so a refusal with no
/// caller trace id is keyed on the session, as before.
#[tokio::test]
async fn a_legacy_refusal_without_a_trace_is_keyed_on_the_session() {
    let fx = fixture(AuditFailurePolicy::FailClosed).await;
    let (status, body) = refused_invoke(&fx, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let written = std::fs::read_to_string(&fx.audit_path).unwrap_or_default();
    let record: Value = written
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .find(|entry: &Value| entry.get("correlation_source").is_some())
        .unwrap_or_else(|| panic!("a refusal record: {written}"));
    assert_eq!(
        record["correlation_source"],
        json!("session_id"),
        "{record}"
    );
}
