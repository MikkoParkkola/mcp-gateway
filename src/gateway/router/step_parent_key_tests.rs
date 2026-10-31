// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Over HTTP, a step caller under its parent call's outer execution lease: a
//! plan step, a chain step and a Code Mode call whose backend asks for input.
//! A fresh call with the parent's idempotency key must not run the backend
//! again. Each row prints what the client saw.

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

/// One modern `tools/call` of the meta tool `name` on `/mcp` as alice, under
/// `key`, declaring form elicitation.
async fn call(fx: &Fx, name: &str, arguments: Value, key: &str) -> (StatusCode, Value) {
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
        .uri("/mcp")
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

/// The parent call, then a fresh call under the same key: the backend count
/// after the second, and both answers.
async fn parent_then_retry(
    fx: &Fx,
    label: &str,
    name: &str,
    arguments: Value,
) -> (usize, Value, (StatusCode, Value)) {
    let (status, first) = call(fx, name, arguments.clone(), "k-step").await;
    println!("{label} first: {status} {first}");
    assert_eq!(
        dispatched(fx),
        1,
        "{label} premise: the step reached the backend once"
    );
    let (status, again) = call(fx, name, arguments, "k-step").await;
    let count = dispatched(fx);
    println!("{label} fresh same-key call: {status} {again}");
    println!("{label} backend count: {count}");
    (count, first, (status, again))
}

/// A Code Mode parent relays its step's question: input required, with the
/// gateway's continuation.
fn assert_relayed(label: &str, first: &Value) {
    assert_eq!(
        first["result"]["resultType"], "input_required",
        "{label} premise: the question was not relayed: {first}"
    );
    assert!(
        first["result"]["requestState"].is_string(),
        "{label} premise: no continuation: {first}"
    );
}

/// The answer the parent's outer entry gives a fresh same-key call after an
/// input-required answer: unavailable, with HTTP 409.
fn assert_unavailable(label: &str, (status, again): &(StatusCode, Value)) {
    assert_eq!(*status, StatusCode::CONFLICT, "{label}: {again}");
    assert!(
        again
            .to_string()
            .contains("Secured execution result is unavailable"),
        "{label}: {again}"
    );
}

/// A plan of one `alpha/read` step whose backend asks.
#[tokio::test]
async fn a_plan_step_that_asks_does_not_run_again_under_the_parent_key() {
    let fx = fixture(Answer::AskOnce, |meta| {
        let definition = serde_json::from_value(json!({
            "playbook": "1.0", "name": "asks", "description": "one asking step",
            "steps": [{"name": "s0", "tool": "read", "server": "alpha", "arguments": {}}]
        }))
        .expect("the playbook deserialises");
        let mut engine = crate::playbook::PlaybookEngine::new();
        engine.register(definition);
        meta.set_playbook_engine(engine);
    })
    .await;
    let (count, first, (status, again)) = parent_then_retry(
        &fx,
        "plan",
        "gateway_run_playbook",
        json!({"name": "asks", "arguments": {}}),
    )
    .await;
    assert_eq!(count, 1, "the plan step ran again under the parent's key");
    // A run carries no continuation: it completes with the question inside
    // its report, and the parent's entry replays that report.
    assert_eq!(status, StatusCode::OK, "{again}");
    assert!(
        first["result"]["content"].is_array(),
        "premise: a completed report: {first}"
    );
    assert_eq!(
        again["result"]["content"], first["result"]["content"],
        "not the stored report"
    );
}

/// A Code Mode chain of one `alpha:read` step whose backend asks.
#[tokio::test]
async fn a_chain_step_that_asks_does_not_run_again_under_the_parent_key() {
    let fx = fixture(Answer::AskOnce, |_| {}).await;
    let (count, first, again) = parent_then_retry(
        &fx,
        "chain",
        "gateway_execute",
        json!({"chain": [{"tool": "alpha:read", "arguments": {}}]}),
    )
    .await;
    assert_eq!(count, 1, "the chain step ran again under the parent's key");
    assert_relayed("chain", &first);
    assert_unavailable("chain", &again);
}

/// A Code Mode single-tool call of `alpha:read` whose backend asks.
#[tokio::test]
async fn a_code_mode_call_that_asks_does_not_run_again_under_the_parent_key() {
    let fx = fixture(Answer::AskOnce, |_| {}).await;
    let (count, first, again) = parent_then_retry(
        &fx,
        "code mode",
        "gateway_execute",
        json!({"tool": "alpha:read", "arguments": {}}),
    )
    .await;
    assert_eq!(
        count, 1,
        "the Code Mode call ran again under the parent's key"
    );
    assert_relayed("code mode", &first);
    assert_unavailable("code mode", &again);
}
