// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Over HTTP, a same-key call after a backend stopped to ask. A verified
//! modern caller, on the meta route (`/mcp`, `gateway_invoke`) and on the
//! direct route (`/mcp/{name}`). Each row prints what the client saw and
//! counts the backend's `tools/call` sends.

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::direct_guards_fixture::{Answer, Fx, fixture};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

const KEY: &str = "k-question";
const UNAVAILABLE: &str = "Secured execution result is unavailable";

fn alice() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://a.example.invalid".to_string(),
    }
}

fn form() -> Value {
    json!({"elicitation": {"form": {}}})
}

/// One modern `tools/call` named `name` on `uri` as alice under `KEY`,
/// declaring `caps`, with `extra` merged into the params (retry fields).
async fn call(
    fx: &Fx,
    (uri, name): (&str, &str),
    arguments: &Value,
    caps: Value,
    extra: Value,
) -> (StatusCode, Value) {
    let mut params = json!({
        "name": name,
        "arguments": arguments,
        "_meta": {
            IDEMPOTENCY_KEY_META: KEY,
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": caps,
        },
    });
    if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        params.extend(extra.clone());
    }
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

const DIRECT: (&str, &str) = ("/mcp/alpha", "read");

fn no_args() -> Value {
    json!({})
}

/// T4: the meta route, unchanged. A fresh same-key call after a relayed
/// question is answered 409 and does not reach the backend.
#[tokio::test]
async fn t4_meta_fresh_same_key_call_after_a_question_is_refused() {
    let fx = fixture(Answer::AskOnce, |_| {}).await;
    let target = ("/mcp", "gateway_invoke");
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let (status, first) = call(&fx, target, &args, form(), json!({})).await;
    println!("meta round 1: {status} {first}");
    assert_eq!(first["result"]["resultType"], "input_required", "{first}");
    let (status, again) = call(&fx, target, &args, form(), json!({})).await;
    println!("meta fresh same-key call: {status} {again}");
    assert_eq!(dispatched(&fx), 1, "the meta route ran the tool again");
    assert!(again.to_string().contains(UNAVAILABLE), "{again}");
}

/// T2: after the refused fresh call, round 1's continuation runs once and
/// completes; replayed identically under the key it is served its stored
/// completion, not run.
#[tokio::test]
async fn t2_round_1s_continuation_runs_after_a_refused_retry() {
    let fx = fixture(Answer::AskOnce, |_| {}).await;
    let (_, first) = call(&fx, DIRECT, &no_args(), form(), json!({})).await;
    let state = first["result"]["requestState"]
        .as_str()
        .unwrap_or_else(|| panic!("premise: a continuation: {first}"))
        .to_owned();
    let (_, again) = call(&fx, DIRECT, &no_args(), form(), json!({})).await;
    println!("direct fresh same-key call: {again}");
    let resume = json!({
        "requestState": state,
        "inputResponses": {"k1": {"action": "accept", "content": {"account": "work"}}},
    });
    let (status, done) = call(&fx, DIRECT, &no_args(), form(), resume.clone()).await;
    println!("direct continuation: {status} {done}");
    assert!(
        done.get("error").is_none(),
        "the continuation failed: {done}"
    );
    assert_eq!(
        dispatched(&fx),
        2,
        "round 1 + its continuation, nothing else"
    );
    let (status, replay) = call(&fx, DIRECT, &no_args(), form(), resume).await;
    println!("direct keyed replay: {status} {replay}");
    assert!(replay.get("error").is_none(), "{replay}");
    assert_eq!(replay["result"]["content"], done["result"]["content"]);
    assert_eq!(dispatched(&fx), 2, "the replay ran");
}

/// T3 (preservation): a question the client did not declare is refused
/// (-32021); declaring it and retrying under the same key runs.
#[tokio::test]
async fn t3_a_direct_undeclared_refusal_frees_the_key() {
    let fx = fixture(Answer::AskOnce, |_| {}).await;
    let (_, refused) = call(&fx, DIRECT, &no_args(), json!({}), json!({})).await;
    println!("direct undeclared: {refused}");
    assert_eq!(refused["error"]["code"], -32021, "premise: {refused}");
    let (_, retried) = call(&fx, DIRECT, &no_args(), form(), json!({})).await;
    println!("direct declared retry: {retried}");
    assert!(retried.get("error").is_none(), "{retried}");
    assert_eq!(dispatched(&fx), 2, "the declared retry did not run");
}

/// T3b (preservation): a question the gateway cannot hand back as a
/// continuation (a malformed round) frees the key: a same-key retry runs.
#[tokio::test]
async fn t3b_a_question_without_a_continuation_frees_the_key() {
    let fx = fixture(Answer::AskMalformed, |_| {}).await;
    let (_, first) = call(&fx, DIRECT, &no_args(), form(), json!({})).await;
    println!("direct malformed round: {first}");
    assert!(first["result"].get("requestState").is_none(), "{first}");
    let (_, again) = call(&fx, DIRECT, &no_args(), form(), json!({})).await;
    println!("direct retry: {again}");
    assert_eq!(dispatched(&fx), 2, "the retry was refused: {again}");
}
