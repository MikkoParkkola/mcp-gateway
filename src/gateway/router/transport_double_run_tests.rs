// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Falsifier: over HTTP, does a fresh same-key call after an input-required
//! round 1 reach the backend again? A verified modern caller that declared
//! form elicitation, on the meta route (`/mcp`, `gateway_invoke`) and on the
//! direct route (`/mcp/{name}`). Each row prints what the client saw.

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::direct_guards_fixture::{Answer, Fx, fixture};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

fn alice() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://a.example.invalid".to_string(),
    }
}

/// One modern `tools/call` named `name` on `uri` as alice, under `key`.
async fn call(fx: &Fx, uri: &str, name: &str, arguments: Value, key: &str) -> (StatusCode, Value) {
    let params = json!({
        "name": name,
        "arguments": arguments,
        "_meta": {
            IDEMPOTENCY_KEY_META: key,
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
        },
    });
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", "Bearer k-std")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
                .to_string(),
        ))
        .unwrap();
    request.extensions_mut().insert(alice());
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn dispatched(fx: &Fx) -> usize {
    fx.calls.load(std::sync::atomic::Ordering::SeqCst)
}

/// Round 1 then a fresh same-key call on `uri`; the backend count after it.
async fn round_then_retry(uri: &str, name: &str, arguments: Value) -> usize {
    let fx = fixture(Answer::AskOnce, |_| {}).await;
    let (status, first) = call(&fx, uri, name, arguments.clone(), "k-falsify").await;
    println!("{uri} round 1: {status} {first}");
    assert_eq!(
        first["result"]["resultType"], "input_required",
        "premise: round 1 asks: {first}"
    );
    assert_eq!(dispatched(&fx), 1, "premise: one tools/call");
    let (status, again) = call(&fx, uri, name, arguments, "k-falsify").await;
    println!("{uri} fresh same-key call: {status} {again}");
    let count = dispatched(&fx);
    println!("{uri} backend count: {count}");
    count
}

/// F1, pass: count 1 (the outer layer answers the fresh call).
#[tokio::test]
async fn f1_meta_route_fresh_same_key_call_after_a_question() {
    let count = round_then_retry(
        "/mcp",
        "gateway_invoke",
        json!({"server": "alpha", "tool": "read", "arguments": {}}),
    )
    .await;
    assert_eq!(count, 1, "the meta route ran the tool again");
}

/// F2, pass: count 2 (the double run is real on the direct route).
#[tokio::test]
async fn f2_direct_route_fresh_same_key_call_after_a_question() {
    let count = round_then_retry("/mcp/alpha", "read", json!({})).await;
    assert_eq!(count, 2, "the direct route did not run the tool again");
}
