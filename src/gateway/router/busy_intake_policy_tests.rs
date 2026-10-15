// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8428 Case D: an UNKEYED task-augmented `gateway_execute` gets the
//! invocation policy only at dispatch, so a target the policy refuses, under
//! a busy custody, must still answer its refusal at intake (as the same call
//! made synchronously does), never "retry", and create no task.

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

/// The answer without its JSON-RPC `id`.
fn without_id(mut answer: Value) -> Value {
    if let Some(object) = answer.as_object_mut() {
        object.remove("id");
    }
    answer
}

/// SETTLE.9. Primary: the task-augmented call answers byte-equal to the
/// synchronous one (the policy refusal), and the task store gains nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unkeyed_tasked_execute_of_a_killed_target_answers_its_refusal_under_busy() {
    let fx = fixture().await;
    fx.state.meta_mcp.kill_switch().kill(BACKEND);
    fx.gateway.fail_custody_for_test(true);
    let sync = unkeyed_execute(&fx, None).await;
    let held = committed_tasks(&fx);
    let tasked = unkeyed_execute(&fx, Some(json!({}))).await;
    assert_eq!(
        without_id(tasked.clone()),
        without_id(sync.clone()),
        "SETTLE.9: the tasked call answers the synchronous call's refusal"
    );
    assert_eq!(
        committed_tasks(&fx),
        held,
        "SETTLE.9: no task for a refused target: {tasked}"
    );
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
    assert_eq!(fx.gateway.dispatched(), 0, "Case C: {chain}");
}
