// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8040: under the default posture the direct route `POST /mcp/{name}`
//! refuses what `/mcp` refuses before anything acts on a request, with the
//! same code and status, and reaches no backend.

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::direct_guards_fixture::{Answer, Fx, fixture, fixture_modern_off};
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

const MODERN: &str = "2026-07-28";

/// `params` with the modern `_meta` declaration at `version`, plus `extra`.
fn declared(mut params: Value, version: &str, extra: Value) -> Value {
    let mut meta = extra.as_object().cloned().unwrap_or_default();
    meta.insert(
        "io.modelcontextprotocol/protocolVersion".into(),
        json!(version),
    );
    meta.insert(
        "io.modelcontextprotocol/clientCapabilities".into(),
        json!({}),
    );
    params["_meta"] = Value::Object(meta);
    params
}

fn call() -> Value {
    json!({"name": "read", "arguments": {"cmd": "x"}})
}

/// One raw request to `uri`; `id: None` sends a notification.
async fn raw(
    fx: &Fx,
    uri: &str,
    (method, id, params): (&str, Option<i64>, Value),
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", "Bearer k-std")
        .header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let mut body = json!({"jsonrpc": "2.0", "method": method, "params": params});
    if let Some(id) = id {
        body["id"] = json!(id);
    }
    let request = builder
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn calls(fx: &Fx) -> usize {
    fx.calls.load(std::sync::atomic::Ordering::SeqCst)
}

/// The modern mirror headers for `method`, naming `name` when given.
fn mirrors<'a>(method: &'a str, name: Option<&'a str>) -> Vec<(&'a str, &'a str)> {
    let mut headers = vec![("mcp-protocol-version", MODERN), ("mcp-method", method)];
    headers.extend(name.map(|name| ("mcp-name", name)));
    headers
}

/// A refusal case: label, method, params, headers, code, status.
type Case<'a> = (
    &'a str,
    &'a str,
    Value,
    Vec<(&'a str, &'a str)>,
    i32,
    StatusCode,
);

/// Every class `/mcp` refuses on, with the code and status it answers
/// (`handlers/request_checks.rs`, and the Malformed arm in `handlers.rs`).
fn refusal_cases() -> Vec<Case<'static>> {
    let modern_call = || declared(call(), MODERN, json!({}));
    let ok = || mirrors("tools/call", Some("read"));
    let twice = |name: &'static str, value: &'static str| {
        let mut headers = ok();
        headers.push((name, value));
        headers
    };
    let bad = StatusCode::BAD_REQUEST;
    vec![
        ("malformed", "tools/call", call(), ok(), -32602, bad),
        (
            "unserved header",
            "tools/call",
            call(),
            vec![("mcp-protocol-version", "1999-01-01")],
            -32022,
            bad,
        ),
        (
            "unsupported modern",
            "tools/call",
            declared(call(), "2099-01-01", json!({})),
            vec![],
            -32022,
            bad,
        ),
        (
            "duplicated name",
            "tools/call",
            modern_call(),
            twice("mcp-name", "read"),
            -32020,
            bad,
        ),
        (
            "duplicated method",
            "tools/call",
            modern_call(),
            twice("mcp-method", "tools/call"),
            -32020,
            bad,
        ),
        (
            "duplicated version",
            "tools/call",
            modern_call(),
            twice("mcp-protocol-version", MODERN),
            -32020,
            bad,
        ),
        (
            "name mismatch",
            "tools/call",
            modern_call(),
            mirrors("tools/call", Some("other")),
            -32020,
            bad,
        ),
        (
            "method mismatch",
            "tools/call",
            modern_call(),
            mirrors("tools/list", Some("read")),
            -32020,
            bad,
        ),
        (
            "version mismatch",
            "tools/call",
            modern_call(),
            vec![
                ("mcp-protocol-version", "2025-11-25"),
                ("mcp-method", "tools/call"),
                ("mcp-name", "read"),
            ],
            -32020,
            bad,
        ),
        (
            "missing name header",
            "tools/call",
            modern_call(),
            mirrors("tools/call", None),
            -32020,
            bad,
        ),
        (
            "uri mismatch",
            "resources/read",
            declared(json!({"uri": "res://x"}), MODERN, json!({})),
            mirrors("resources/read", Some("res://y")),
            -32020,
            bad,
        ),
        (
            "undeclared capability",
            "roots/list",
            declared(json!({}), MODERN, json!({})),
            mirrors("roots/list", None),
            -32021,
            bad,
        ),
        (
            "removed method",
            "logging/setLevel",
            declared(json!({"level": "info"}), MODERN, json!({})),
            mirrors("logging/setLevel", None),
            -32601,
            StatusCode::NOT_FOUND,
        ),
    ]
}

/// R1: one case per class; refused before any backend is reached.
#[tokio::test]
async fn a_direct_request_is_refused_as_mcp_refuses_it() {
    for (label, method, params, headers, code, status) in refusal_cases() {
        let fx = fixture(Answer::Ok, |_| {}).await;
        let (got, body) = raw(&fx, "/mcp/alpha", (method, Some(7), params), &headers).await;
        assert_eq!(got, status, "{label}: {body}");
        assert_eq!(body["error"]["code"], code, "{label}: {body}");
        assert_eq!(calls(&fx), 0, "{label}: reached the backend: {body}");
    }
}

/// R1, the rollback gate: with `server.modern_protocol: false` a modern
/// request is refused as `/mcp` refuses it, never relayed.
#[tokio::test]
async fn a_rollback_gated_modern_request_is_refused() {
    let fx = fixture_modern_off(Answer::Ok).await;
    let params = declared(call(), MODERN, json!({}));
    let headers = mirrors("tools/call", Some("read"));
    let (status, body) = raw(&fx, "/mcp/alpha", ("tools/call", Some(7), params), &headers).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32022, "{body}");
    assert_eq!(calls(&fx), 0, "{body}");
}

/// K1 controls: a plain legacy call and a well-formed modern call are both
/// dispatched.
#[tokio::test]
async fn well_formed_requests_are_still_dispatched() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let (status, body) = raw(&fx, "/mcp/alpha", ("tools/call", Some(7), call()), &[]).await;
    assert_eq!(status, StatusCode::OK, "legacy: {body}");
    assert!(body["result"]["content"].is_array(), "legacy: {body}");
    let params = declared(call(), MODERN, json!({}));
    let headers = mirrors("tools/call", Some("read"));
    let (status, body) = raw(&fx, "/mcp/alpha", ("tools/call", Some(8), params), &headers).await;
    assert_eq!(status, StatusCode::OK, "modern: {body}");
    assert!(body["result"]["content"].is_array(), "modern: {body}");
    assert_eq!(calls(&fx), 2);
}

/// O1: validation comes before the backend lookup, so an absent backend
/// and an invalid request answer the request refusal, not a 404.
#[tokio::test]
async fn an_invalid_request_to_an_absent_backend_gets_the_request_refusal() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let params = declared(call(), MODERN, json!({}));
    let headers = mirrors("tools/call", Some("other"));
    let (status, body) = raw(&fx, "/mcp/nope", ("tools/call", Some(7), params), &headers).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32020, "{body}");
}

/// N1: a refused modern notification is never forwarded; the control shows
/// an accepted one is (202).
#[tokio::test]
async fn a_refused_modern_notification_is_not_forwarded() {
    const NOTE: &str = "notifications/cancelled";
    let fx = fixture(Answer::Ok, |_| {}).await;
    let params = || declared(json!({"requestId": 1}), MODERN, json!({}));
    let good = mirrors(NOTE, None);
    let (status, body) = raw(&fx, "/mcp/alpha", (NOTE, None, params()), &good).await;
    assert_eq!(status, StatusCode::ACCEPTED, "control: {body}");
    let bad = mirrors("tools/list", None);
    let (status, body) = raw(&fx, "/mcp/alpha", (NOTE, None, params()), &bad).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

/// I1: an invalid retry under an answered idempotency key is refused, never
/// served the cached success; the control replays it.
#[tokio::test]
async fn an_invalid_keyed_retry_is_refused_not_replayed() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let params = || declared(call(), MODERN, json!({ IDEMPOTENCY_KEY_META: "i1" }));
    let good = mirrors("tools/call", Some("read"));
    let (_, first) = raw(&fx, "/mcp/alpha", ("tools/call", Some(7), params()), &good).await;
    assert!(first["result"]["content"].is_array(), "seed: {first}");
    let (_, again) = raw(&fx, "/mcp/alpha", ("tools/call", Some(8), params()), &good).await;
    assert_eq!(again["result"], first["result"], "control replay: {again}");
    let bad = mirrors("tools/call", Some("other"));
    let (status, body) = raw(&fx, "/mcp/alpha", ("tools/call", Some(9), params()), &bad).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"]["code"], -32020, "{body}");
    assert_eq!(calls(&fx), 1, "{body}");
}
