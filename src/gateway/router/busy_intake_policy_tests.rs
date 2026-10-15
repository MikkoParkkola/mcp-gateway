// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8428 Case D, not reproduced: the case inferred that an UNKEYED
//! task-augmented `gateway_execute` reaches the intake's busy answer before
//! its policy and is told to retry a refused target. No such call reaches
//! intake: task creation without an idempotency key is refused -32602 first
//! (`router/handlers/tasks.rs`, `server/stdio_tasks.rs`), and a keyed plan meets
//! the policy at admission. The pin keeps it that way. Case C's pin is here
//! too: one request's same-target calls share their policy refusal.

use serde_json::{Value, json};

use super::{BACKEND, Fx, TOOL, committed_tasks, fixture, modern_meta, send};

/// An unkeyed single-tool `gateway_execute` of `read`; `task` makes it
/// task-augmented.
async fn unkeyed_execute(fx: &Fx, task: Option<Value>) -> Value {
    let mut params = json!({"name": "gateway_execute",
        "arguments": {"tool": format!("{BACKEND}:{TOOL}"), "arguments": {"folder": "inbox"}},
        "_meta": modern_meta()});
    if let Some(task) = task {
        params["task"] = task;
    }
    send(fx, "tools/call", "gateway_execute", params).await
}

/// Case D pin: under a busy custody and the kill switch, an unkeyed
/// task-augmented call is refused for its missing key, is never told to
/// retry, and creates no task.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unkeyed_tasked_execute_under_busy_is_refused_and_never_told_to_retry() {
    let fx = fixture().await;
    fx.state.meta_mcp.kill_switch().kill(BACKEND);
    fx.gateway.fail_custody_for_test(true);
    let held = committed_tasks(&fx);
    let tasked = unkeyed_execute(&fx, Some(json!({}))).await;
    assert_eq!(
        tasked.pointer("/error/code"),
        Some(&json!(-32602)),
        "{tasked}"
    );
    assert!(
        tasked.pointer("/error/data/retryable").is_none(),
        "Case D: never told to retry: {tasked}"
    );
    assert_eq!(committed_tasks(&fx), held, "Case D: no task: {tasked}");
}

/// Case C pin: the checks that refuse a call before its resolution (here
/// the kill switch) refuse every call to that target in the request, so a
/// second same-target call is never admitted to take the first's carried
/// error. A chain of two calls to the refused target dispatches neither.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_call_to_a_refused_target_in_one_request_is_not_admitted() {
    let fx = fixture().await;
    fx.state.meta_mcp.kill_switch().kill(BACKEND);
    let step = json!({"tool": format!("{BACKEND}:{TOOL}"), "arguments": {"folder": "inbox"}});
    let chain = send(
        &fx,
        "tools/call",
        "gateway_execute",
        json!({"name": "gateway_execute", "arguments": {"chain": [step.clone(), step]},
            "_meta": modern_meta()}),
    )
    .await;
    // `tool_calls`, not `dispatched`: the latter also counts the caller
    // verdict's `tools/list` catalogue fill, which runs before the policy.
    assert!(
        fx.gateway.tool_calls().is_empty(),
        "Case C: neither call reached the backend: {chain}"
    );
}
