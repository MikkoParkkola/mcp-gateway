// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.2 busy task repeats on a signed capability account: a
//! repeat refused because custody is busy gives its signing nonce back, as
//! the live busy answer does, so the same signed repeat serves after recovery.

use super::*;

/// A signed, keyed, task-augmented capability `gateway_invoke`.
async fn signed_capability_task(harness: &CapabilityHarness, key: &str, nonce: &str) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": CAPABILITY_SERVER, "tool": CAPABILITY_TOOL,
            "arguments": {}, "nonce": nonce},
        "task": {},
        "_meta": keyed_meta(key),
    }});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(CapabilityAccount::alice());
    body_of(
        harness
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("an answer"),
    )
    .await
}

/// R5n (product seat finding 1; mutant M-refund): a signed keyed task
/// repeat refused because custody is busy answers retryable AND asks for its
/// nonce back, as the live busy answer does. After recovery the same signed
/// repeat, under the same nonce, is not refused as a replay and serves the
/// stored task. Keeping the nonce spent on the busy repeat (M-refund) makes
/// the recovered repeat a replay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn r5n_a_busy_signed_task_repeat_gives_its_nonce_back() {
    let harness = capability_harness(true).await;
    let made = signed_capability_task(&harness, "s2-r5n", "s2-r5n-n0").await;
    let id = task_id(&made, "R5n setup");
    let settled = settled_wire(&harness, &id, "R5n setup").await;
    assert_eq!(
        settled.get("status"),
        Some(&json!("completed")),
        "premise: the signed task completes while healthy: {settled}"
    );

    harness.account.fail_custody_for_test(true);
    let busy = signed_capability_task(&harness, "s2-r5n", "s2-r5n-n1").await;
    assert_retryable(&busy, "R5n busy repeat");

    harness.account.fail_custody_for_test(false);
    let recovered = signed_capability_task(&harness, "s2-r5n", "s2-r5n-n1").await;
    assert!(
        !refused_as_replay(&recovered),
        "R5n: the busy repeat kept its nonce spent: {recovered}"
    );
    assert_eq!(
        recovered.pointer("/result/taskId"),
        Some(&json!(id)),
        "R5n: after recovery the same signed repeat serves the stored task: {recovered}"
    );
}
