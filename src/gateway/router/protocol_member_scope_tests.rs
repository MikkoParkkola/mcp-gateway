// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A backend's protocol directives reach the client only where the MCP
//! revision lets a backend send them: `taskId` and `requestState` never on a
//! complete `tools/call`, `cacheScope` and `ttlMs` never on `prompts/get` and
//! never on an `input_required` answer. Run on the direct route, over a gated
//! and a passthrough backend.

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::direct_guards_fixture::{Answer, Fx, fixture};

const BACKENDS: [&str; 2] = ["alpha", "alpha-pt"];

/// One modern (2026-07-28) request to `/mcp/{backend}`: the answer's `result`.
async fn modern(fx: &Fx, backend: &str, method: &str, params: Value) -> Value {
    let answer = modern_answer(fx, backend, method, params).await;
    assert!(
        answer.get("error").is_none(),
        "{backend} {method}: premise: {answer}"
    );
    answer["result"].clone()
}

/// One modern request to `/mcp/{backend}`: the whole JSON-RPC answer.
async fn modern_answer(fx: &Fx, backend: &str, method: &str, mut params: Value) -> Value {
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
    });
    let name = crate::protocol::headers::mcp_name_body_field(method)
        .and_then(|field| params[field].as_str())
        .map(str::to_owned);
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{backend}"))
        .header("authorization", "Bearer k-std")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method);
    if let Some(name) = name {
        request = request.header("mcp-name", name);
    }
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": method, "params": params});
    let request = request
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// A complete `tools/call` answer carrying a task handle and a continuation.
fn complete_call_with_task_directives() -> Value {
    json!({
        "content": [{"type": "text", "text": "ok"}],
        "isError": false,
        "resultType": "complete",
        "taskId": "FORGED-task",
        "requestState": "FORGED-state",
    })
}

/// A `prompts/get` answer carrying cache hints, which only a cacheable result
/// may carry.
fn prompt_with_cache_hints() -> Value {
    json!({
        "messages": [],
        "resultType": "complete",
        "cacheScope": "public",
        "ttlMs": 987_654,
    })
}

/// An interim `resources/read` answer carrying cache hints: an interim answer
/// is not the resource, and nothing may cache it.
fn interim_read_with_cache_hints() -> Value {
    json!({
        "resultType": "input_required",
        "requestState": "state-1",
        "cacheScope": "public",
        "ttlMs": 987_654,
    })
}

#[tokio::test]
async fn a_complete_tool_call_delivers_no_task_or_continuation_directive() {
    for backend in BACKENDS {
        let fx = fixture(Answer::Built(complete_call_with_task_directives), |_| {}).await;
        let params = json!({"name": "read", "arguments": {}});
        let result = modern(&fx, backend, "tools/call", params).await;
        assert!(
            result.get("content").is_some(),
            "{backend}: premise: {result}"
        );
        for member in ["taskId", "requestState"] {
            assert!(
                result.get(member).is_none(),
                "{backend}: a complete tools/call delivered {member}: {result}"
            );
        }
    }
}

#[tokio::test]
async fn a_prompt_delivers_no_cache_hint() {
    for backend in BACKENDS {
        let fx = fixture(Answer::Built(prompt_with_cache_hints), |_| {}).await;
        let result = modern(&fx, backend, "prompts/get", json!({"name": "p"})).await;
        assert!(
            result.get("messages").is_some(),
            "{backend}: premise: {result}"
        );
        for member in ["cacheScope", "ttlMs"] {
            assert!(
                result.get(member).is_none(),
                "{backend}: prompts/get delivered {member}: {result}"
            );
        }
    }
}

#[tokio::test]
async fn an_interim_resource_read_delivers_no_cache_hint() {
    for backend in BACKENDS {
        let fx = fixture(Answer::Built(interim_read_with_cache_hints), |_| {}).await;
        let params = json!({"uri": "file:///notes.txt"});
        let result = modern(&fx, backend, "resources/read", params).await;
        assert_eq!(
            result.get("resultType"),
            Some(&json!("input_required")),
            "{backend}: premise: the interim answer arrived: {result}"
        );
        for member in ["cacheScope", "ttlMs"] {
            assert!(
                result.get(member).is_none(),
                "{backend}: an interim resources/read delivered {member}: {result}"
            );
        }
    }
}

/// An interim `tools/call` answer: its continuation is where it belongs.
fn interim_call() -> Value {
    json!({"resultType": "input_required", "requestState": "state-1", "inputRequests": {}})
}

/// A complete `resources/read` answer with its cache hints.
fn final_read_with_cache_hints() -> Value {
    json!({"contents": [], "resultType": "complete", "cacheScope": "private", "ttlMs": 1_000})
}

/// A task handle, to a send that declared no tasks.
fn undeclared_task_handle() -> Value {
    json!({"resultType": "task", "taskId": "t-1", "ttlMs": 1_000})
}

#[tokio::test]
async fn allowed_placements_arrive() {
    for backend in BACKENDS {
        let fx = fixture(Answer::Built(interim_call), |_| {}).await;
        let params = json!({"name": "read", "arguments": {}});
        let result = modern(&fx, backend, "tools/call", params).await;
        // The gateway seals the backend's state into its own token, so the
        // continuation arrives, not as the backend wrote it.
        assert!(
            result.get("requestState").is_some(),
            "{backend}: an interim tools/call lost its continuation: {result}"
        );
        let fx = fixture(Answer::Built(final_read_with_cache_hints), |_| {}).await;
        let params = json!({"uri": "file:///notes.txt"});
        let result = modern(&fx, backend, "resources/read", params).await;
        for member in ["cacheScope", "ttlMs"] {
            assert!(
                result.get(member).is_some(),
                "{backend}: a complete resources/read lost {member}: {result}"
            );
        }
    }
}

#[tokio::test]
async fn an_undeclared_task_handle_is_refused() {
    for backend in BACKENDS {
        let fx = fixture(Answer::Built(undeclared_task_handle), |_| {}).await;
        let params = json!({"name": "read", "arguments": {}});
        let answer = modern_answer(&fx, backend, "tools/call", params).await;
        assert!(
            answer.get("result").is_none(),
            "{backend}: a task handle with no declaration was delivered: {answer}"
        );
        let error = answer["error"].to_string();
        // The refusal itself, not some other failure on the way.
        assert!(error.contains("task handle"), "{backend}: {error}");
        assert!(error.contains("tools/call"), "{backend}: {error}");
        assert!(!error.contains("t-1"), "{backend}: {error}");
    }
}
