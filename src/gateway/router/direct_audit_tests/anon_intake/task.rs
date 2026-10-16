// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8382 rows D2 and D6: a keyed no-principal task submit and a modern
//! `gateway_set_profile` on `/mcp` are refused at intake.

use super::*;

/// D2 (D8(a)): on this auth-off gateway, an anonymous keyed task submit
/// (a `task` member, the tasks extension declared) is refused -32003 and no
/// task is created. RED: today a task submit skips sync admission, so a
/// pooled-owner task is created.
#[tokio::test]
async fn d2_auth_off_anonymous_keyed_task_is_refused() {
    let fx = fixture(idempotent()).await;
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
    "name": "gateway_invoke",
    "arguments": {"server": "alpha", "tool": "t", "arguments": {"customer_id": "c"}},
    "task": {},
    "_meta": {
        (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): KEY,
        "io.modelcontextprotocol/protocolVersion": crate::protocol::meta::MODERN_VERSIONS[0],
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    }}})
    .to_string();
    let (status, answer) = post_to(&fx, "/mcp", &body, &Caller::Modern).await;
    assert!(
        answer.pointer("/result/taskId").is_none(),
        "d2: a task was created: {answer}"
    );
    assert_eq!(message(&answer), NO_PRINCIPAL, "d2: {answer}");
    assert_eq!(status, StatusCode::BAD_REQUEST, "d2: {answer}");
}

/// D6 (D8(c)): a keyed no-principal modern `gateway_set_profile` is refused
/// at intake (-32003). RED: today its own Protocol refusal answers first
/// (admission's `set_profile` check precedes the principal check).
#[tokio::test]
async fn d6_set_profile_answers_intake_first() {
    let fx = fixture(idempotent()).await;
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
    "name": "gateway_set_profile",
    "arguments": {"profile": "default"},
    "_meta": {
        (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): KEY,
        "io.modelcontextprotocol/protocolVersion": crate::protocol::meta::MODERN_VERSIONS[0],
        "io.modelcontextprotocol/clientCapabilities": {},
    }}})
    .to_string();
    let (status, answer) = post_to(&fx, "/mcp", &body, &Caller::Modern).await;
    assert_eq!(message(&answer), NO_PRINCIPAL, "d6: {answer}");
    assert_eq!(status, StatusCode::BAD_REQUEST, "d6: {answer}");
}
