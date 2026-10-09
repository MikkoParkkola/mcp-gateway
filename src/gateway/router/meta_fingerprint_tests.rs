// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8192` (MIK-8137 P1 rows FP1-FP4): a keyed meta-tool call's identity is
//! the operation it runs, never the client's per-request `_meta`. A retry that
//! differs only in a fresh `progressToken` or in declared capabilities is the
//! same call; a retry with other arguments, or as a task, is not.

use serde_json::{Value, json};

use super::direct_continuation_tests::dispatched;
use super::direct_guards_fixture::{Answer, Fx, fixture, send_with_headers};

/// A keyed modern `tools/call` of meta-tool `name` on `/mcp`.
async fn keyed_meta(fx: &Fx, name: &str, arguments: Value, meta: Value, extra: Value) -> Value {
    let mut params = json!({"name": name, "arguments": arguments, "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        crate::protocol::mrtr::IDEMPOTENCY_KEY_META: "op-fp",
    }});
    if let (Some(into), Some(meta)) = (params["_meta"].as_object_mut(), meta.as_object()) {
        into.extend(meta.clone());
    }
    if let (Some(into), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        into.extend(extra.clone());
    }
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", name),
    ];
    send_with_headers(fx, "/mcp", "k-std", "tools/call", params, None, &headers)
        .await
        .1
}

fn chain(cmd: &str) -> Value {
    json!({"chain": [{"tool": "alpha:read", "arguments": {"cmd": cmd}}]})
}

fn invoke() -> Value {
    json!({"server": "alpha", "tool": "read", "arguments": {}})
}

/// FP1 (`MIK-8192.1`, RED on base): a keyed `gateway_execute` retried with a
/// fresh `progressToken`, or with other declared capabilities, is the same
/// call: served the stored outcome, not refused 409, and not run again.
/// Mutant: `arguments._meta` folded into the operation fingerprint.
#[tokio::test]
async fn fp1_a_fresh_meta_retry_of_gateway_execute_is_the_same_call() {
    let variants = [
        json!({"progressToken": "p-2"}),
        json!({"io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}}),
    ];
    for changed in variants {
        let fx = fixture(Answer::Ok, |_| {}).await;
        let original = json!({"progressToken": "p-1"});
        let first = keyed_meta(&fx, "gateway_execute", chain("a"), original, json!({})).await;
        assert!(first.get("error").is_none(), "{first}");
        let retried = keyed_meta(
            &fx,
            "gateway_execute",
            chain("a"),
            changed.clone(),
            json!({}),
        )
        .await;
        assert!(
            retried.get("error").is_none(),
            "{changed}: refused as another call: {retried}"
        );
        assert_eq!(
            retried["result"], first["result"],
            "{changed}: the stored outcome"
        );
        assert_eq!(dispatched(&fx), 1, "{changed}: ran again");
    }
}

/// FP2 (`MIK-8192.2`, pin, green on base): the same for `gateway_invoke`.
#[tokio::test]
async fn fp2_a_fresh_meta_retry_of_gateway_invoke_is_the_same_call() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let first = keyed_meta(
        &fx,
        "gateway_invoke",
        invoke(),
        json!({"progressToken": "p-1"}),
        json!({}),
    )
    .await;
    assert!(first.get("error").is_none(), "{first}");
    let retried = keyed_meta(
        &fx,
        "gateway_invoke",
        invoke(),
        json!({"progressToken": "p-2"}),
        json!({}),
    )
    .await;
    assert!(retried.get("error").is_none(), "{retried}");
    assert_eq!(dispatched(&fx), 1, "ran again");
}

/// FP3 (`MIK-8192.3`, guard): other tool arguments under the same key are
/// another call: 409, nothing run.
#[tokio::test]
async fn fp3_other_arguments_under_the_same_key_are_refused() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let _ = keyed_meta(&fx, "gateway_execute", chain("a"), json!({}), json!({})).await;
    let other = keyed_meta(&fx, "gateway_execute", chain("b"), json!({}), json!({})).await;
    assert_eq!(other["error"]["code"], 409, "{other}");
    assert_eq!(dispatched(&fx), 1);
}

/// FP4 (guard, lead): the same tool, arguments and key retried as a task
/// (`params.task`) is another operation: refused, never admitted again and
/// never served the stored synchronous result. Identity carries the admission mode
/// (`idempotency/admission.rs:296-301`).
#[tokio::test]
async fn fp4_a_task_retry_of_a_sync_call_is_refused() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    // Production hands the task runtime the meta surface's admission
    // authority (`server/task_runtime.rs:49`); this row means nothing over a
    // fixture with two.
    let shared = std::ptr::eq(
        std::sync::Arc::as_ptr(fx.state.meta_mcp.execution_admission()),
        fx.state.task_executor.service.admission(),
    );
    assert!(
        shared,
        "the fixture admits sync calls and tasks in two stores"
    );
    let caps = json!({"io.modelcontextprotocol/clientCapabilities": {
        "extensions": {"io.modelcontextprotocol/tasks": {}}
    }});
    let first = keyed_meta(&fx, "gateway_invoke", invoke(), caps.clone(), json!({})).await;
    assert!(first.get("error").is_none(), "{first}");
    let as_task = keyed_meta(&fx, "gateway_invoke", invoke(), caps, json!({"task": {}})).await;
    assert!(as_task.get("result").is_none(), "admitted again: {as_task}");
    assert!(
        as_task.get("error").is_some(),
        "refused as another call: {as_task}"
    );
    assert_eq!(dispatched(&fx), 1);
}

/// FP6 (`MIK-8192` on the task path, gpt i1): a keyed task retried with a
/// fresh `progressToken` is the same task. It is answered with the handle it
/// already owns, not refused as another request. Mutant: task admission
/// fingerprinting the raw `_meta`.
#[tokio::test]
async fn fp6_a_fresh_meta_retry_of_a_task_is_the_same_task() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let meta = |token: &str| {
        json!({
            "progressToken": token,
            "io.modelcontextprotocol/clientCapabilities": {
                "extensions": {"io.modelcontextprotocol/tasks": {}}
            }
        })
    };
    let task = json!({"task": {}});
    let first = keyed_meta(&fx, "gateway_invoke", invoke(), meta("p-1"), task.clone()).await;
    let task_id = first["result"]["taskId"].clone();
    assert!(task_id.is_string(), "a task was created: {first}");
    let retried = keyed_meta(&fx, "gateway_invoke", invoke(), meta("p-2"), task).await;
    assert_eq!(
        retried["result"]["taskId"], task_id,
        "the same task: {retried}"
    );
}
