// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 slice 3c, S-sealed-stdio: the stdio twin of the R4a row. A signed
//! task submit refused because new keyed tasks are sealed, with nothing acted,
//! gives the nonce back on stdio as on `/mcp`. Oracle as in `signing_joint::
//! refund`: send 2 meets the same refusal (refunded), the seal is lifted, send
//! 3 is served, send 4 is a replay. RED on base: send 2 is a replay.

use std::sync::atomic::Ordering;

use serde_json::{Value, json};

use super::owner2_stdio_tasks::{BACKEND, TOOL, backend, dispatch, fixture_on_with};

const REPLAY: &str = "Nonce replay detected";

/// A signed (argument nonce), keyed, task-augmented `gateway_invoke`.
fn signed_task(id: u64, key: &str, nonce: &str) -> Value {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": {
            "name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {}, "nonce": nonce},
            "task": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {
                    "extensions": {"io.modelcontextprotocol/tasks": {}}
                },
                "io.modelcontextprotocol/clientInfo": {"name": "s3c", "version": "1"},
                "io.mcp-gateway/idempotency-key": key,
            },
        },
    })
}

fn message(body: &Value) -> String {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

#[tokio::test]
async fn s3c_stdio_sealed_refusal_gives_the_nonce_back() {
    let served = backend().await;
    let calls = std::sync::Arc::clone(&served.1);
    let fixture = Box::pin(fixture_on_with(served, None, |config| {
        config.server.modern_protocol = true;
        let signing = &mut config.security.message_signing;
        signing.enabled = true;
        signing.shared_secret = "s3c-stdio-signing-secret-at-least-32-bytes".to_string();
        signing.require_nonce = true;
        signing.replay_window = 300;
        signing.key_id = "s3c-stdio".to_string();
    }))
    .await;
    let prime = dispatch(&fixture, signed_task(1, "s3c-st-prime", "s3c-st-n0")).await;
    assert!(
        prime.pointer("/result/taskId").is_some(),
        "premise: a signed stdio task is created: {prime}"
    );
    let admission = fixture.tasks.service.admission();
    admission.adjust_sealed(0, 1);
    let committed = fixture.tasks.service.store.committed_count_for_test();
    let backend_calls = calls.load(Ordering::SeqCst);

    let first = dispatch(&fixture, signed_task(2, "s3c-st", "s3c-st-n1")).await;
    let second = dispatch(&fixture, signed_task(3, "s3c-st", "s3c-st-n1")).await;
    assert_eq!(
        first.pointer("/error/code"),
        Some(&json!(409)),
        "premise: the sealed refusal: {first}"
    );
    assert!(
        message(&first).contains(crate::idempotency::admission::SEALED_MESSAGE),
        "premise: the sealed refusal's own message: {first}"
    );
    assert!(
        !message(&second).contains(REPLAY),
        "S-sealed-stdio: the refused submit kept its nonce: {second}"
    );
    assert_eq!(
        second.pointer("/error/code"),
        Some(&json!(409)),
        "S-sealed-stdio: send 2 met the same refusal: {second}"
    );
    assert_eq!(
        fixture.tasks.service.store.committed_count_for_test(),
        committed,
        "premise: no refusal committed a task"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        backend_calls,
        "premise: no refusal reached the backend"
    );

    admission.adjust_sealed(1, 0);
    let served = dispatch(&fixture, signed_task(4, "s3c-st", "s3c-st-n1")).await;
    assert!(
        served.pointer("/result/taskId").is_some(),
        "send 3 under the given-back nonce is served: {served}"
    );
    let fourth = dispatch(&fixture, signed_task(5, "s3c-st-2", "s3c-st-n1")).await;
    assert!(
        message(&fourth).contains(REPLAY),
        "S-sealed-stdio: the nonce was given back twice: {fourth}"
    );
}
