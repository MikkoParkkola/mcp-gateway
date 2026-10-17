// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8382 rows D2 and D6: a keyed no-principal task submit and a modern
//! `gateway_set_profile` on `/mcp` are refused at intake.

use super::*;

/// An anonymous keyed modern task submit of `server`/`t` (a `task` member,
/// the tasks extension declared), key `key`.
fn task_submit(server: &str, key: &str) -> String {
    json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {
    "name": "gateway_invoke",
    "arguments": {"server": server, "tool": "t", "arguments": {"customer_id": "c"}},
    "task": {},
    "_meta": {
        (crate::protocol::mrtr::IDEMPOTENCY_KEY_META): key,
        "io.modelcontextprotocol/protocolVersion": crate::protocol::meta::MODERN_VERSIONS[0],
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    }}})
    .to_string()
}

/// D2 CONTROL (row re-pinned after the 2026-10-17 ruling B, which supersedes
/// D8(a)): on this auth-off gateway an anonymous keyed task submit keeps
/// pooled anonymous task ownership (MIK-7272.TASK.1.20, design 2026-09-08):
/// the intake leaves it to the task path, which answers with a task handle,
/// not -32003.
#[tokio::test]
async fn d2_auth_off_anonymous_keyed_task_keeps_the_pooled_owner() {
    let fx = fixture(idempotent()).await;
    let (status, answer) = post_to(&fx, "/mcp", &task_submit("alpha", KEY), &Caller::Modern).await;
    assert_eq!(status, StatusCode::OK, "d2: {answer}");
    assert!(
        answer.pointer("/result/taskId").is_some(),
        "d2: no task handle: {answer}"
    );
    assert_ne!(
        refusal(&answer),
        (Some(-32003), NO_PRINCIPAL),
        "d2: refused at intake: {answer}"
    );
}

/// D2b (ruling B's proof row): an auth-off anonymous keyed task submit does
/// no backend work before its task handle. Counting cell: every request to
/// `alpha` is counted and never answered ([`Extra::Hang`]), so a submit that
/// waited on `alpha` before answering would never answer; it must answer
/// with a handle within 10 s. What `alpha` was sent by then is the worker's,
/// started after the handle, and is reported, not asserted. Unreachable
/// (`dead`, a socket bound and never listening) and absent (`nope`) cells:
/// a handle each time, so no backend failure decided the answer.
#[tokio::test]
async fn d2b_auth_off_task_submit_does_no_backend_work_before_its_handle() {
    let hung = fixture(Setup {
        extras: &[Extra::Hang],
        ..idempotent()
    })
    .await;
    let counted = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        post_to(
            &hung,
            "/mcp",
            &task_submit("alpha", "d2b-alpha"),
            &Caller::Modern,
        ),
    )
    .await;
    let (status, answer) = counted.unwrap_or_else(|_| {
        panic!(
            "d2b counting: no answer in 10 s while alpha held every request \
             (tools/list {}, tools/call {}): the submit waited on the backend",
            hung.lists.load(Ordering::SeqCst),
            hung.calls.load(Ordering::SeqCst)
        )
    });
    assert!(
        status == StatusCode::OK && answer.pointer("/result/taskId").is_some(),
        "d2b counting: no task handle: {status} {answer}"
    );
    let fx = fixture(idempotent()).await;
    let _closed = register_dead(&fx);
    let mut wrong = Vec::new();
    for (case, server) in [("unreachable", "dead"), ("absent", "nope")] {
        let key = format!("d2b-{server}");
        let (status, answer) =
            post_to(&fx, "/mcp", &task_submit(server, &key), &Caller::Modern).await;
        if status != StatusCode::OK || answer.pointer("/result/taskId").is_none() {
            wrong.push(format!("d2b {case}: no task handle: {status} {answer}"));
        }
    }
    assert!(wrong.is_empty(), "d2b:\n{}", wrong.join("\n"));
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
    assert_eq!(
        refusal(&answer),
        (Some(-32003), NO_PRINCIPAL),
        "d6: {answer}"
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "d6: {answer}");
}
