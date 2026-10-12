// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392.STORED.1 batch B (test plan s1-t0..t2), on MIK-8356's per-user
//! backend: a stored task read judges the target against alpha's OWN
//! catalogue, and a cold slot is re-established with one resolution, never
//! one per poll. Driven through the public `/mcp` handler as alpha.

use std::sync::atomic::Ordering;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::slot_verdict_http_tests::{CLOSED, Gateway, gateway};
use crate::gateway::meta_mcp::slot_verdict_fixture::{BACKEND, BINDING, CallerSlot, Surfaced, TOOL};
use crate::key_server::oidc::VerifiedIdentity;

const OUTPUT: &str = "\"text\":\"ok\"";

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    })
}

/// POST a modern request as alpha.
async fn send(gw: &Gateway, id: i64, method: &str, name: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(VerifiedIdentity {
        subject: "alpha".to_string(),
        email: "alpha@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://issuer.example.invalid".to_string(),
    });
    let response = gw.router.clone().oneshot(request).await.expect("an answer");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn task_get(gw: &Gateway, id: &str) -> Value {
    send(gw, 9, "tasks/get", id, json!({"taskId": id, "_meta": modern_meta()})).await
}

/// A finished task of alpha's own `read`, its output delivered once.
async fn finished(gw: &Gateway, key: &str) -> String {
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let made = send(
        gw,
        2,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"q": "x"}},
            "task": {}, "_meta": meta}),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let control = loop {
        let got = task_get(gw, &id).await;
        if got.to_string().contains(OUTPUT) || std::time::Instant::now() >= bound {
            break got;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    };
    assert!(
        control.to_string().contains(OUTPUT),
        "control: while alpha's slot offers the tool the output is served: {control}"
    );
    id
}

/// Alpha's own slot relisted without the tool, complete.
fn alpha_lacks(gw: &Gateway) {
    let other: crate::protocol::Tool = serde_json::from_value(json!({
        "name": "other", "description": "Another.", "inputSchema": {"type": "object"}
    }))
    .expect("a tool");
    gw.meta
        .backends
        .get(BACKEND)
        .expect("the backend")
        .store_per_user_tools_for_test(BINDING, vec![other]);
}

fn backend(gw: &Gateway) -> std::sync::Arc<crate::backend::Backend> {
    gw.meta.backends.get(BACKEND).expect("the backend")
}

/// T8: alpha's own warm slot no longer lists the tool (the shared slot still
/// does): -32601. Red on base: the read is judged on policy only.
#[tokio::test]
async fn t8_alpha_s_own_slot_lacking_the_tool_answers_absent() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-t8").await;
    alpha_lacks(&gw);
    let read = task_get(&gw, &id).await;
    assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32601)),
        "T8: alpha's catalogue lacks the tool: {read}"
    );
    assert!(!read.to_string().contains(OUTPUT), "T8: output delivered: {read}");
}

/// T8t: the same, but alpha's slot is a TRUNCATED drain: it proves nothing
/// about the tool, so the output is served. Pinning; M7c turns it red.
#[tokio::test]
async fn t8t_a_truncated_slot_without_the_tool_still_delivers() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-t8t").await;
    alpha_lacks(&gw);
    backend(&gw).mark_per_user_truncated_for_test(BINDING);
    let read = task_get(&gw, &id).await;
    assert!(read.to_string().contains(OUTPUT), "T8t: {read}");
}

/// C1: alpha's slot is evicted after the task. The first read re-establishes
/// it with exactly one resolution and serves; N warm polls after it resolve
/// nothing. Red on base: no cold path, the read is judged on the shared view
/// with 0 resolutions.
#[tokio::test]
async fn c1_a_cold_read_resolves_once_then_warm_polls_resolve_nothing() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-c1").await;
    backend(&gw).age_per_user_slot_for_test(BINDING, 400);
    backend(&gw).evict_idle_per_user_entries(std::time::Duration::from_secs(300));
    assert!(
        !backend(&gw).holds_per_user_slot_for_test(BINDING),
        "premise: alpha's slot was evicted"
    );
    let before = gw.mints.load(Ordering::SeqCst);
    let first = task_get(&gw, &id).await;
    assert!(first.to_string().contains(OUTPUT), "C1: the cold read serves: {first}");
    assert_eq!(
        gw.mints.load(Ordering::SeqCst) - before,
        1,
        "C1: the cold read re-establishes alpha's view with one resolution"
    );
    for _ in 0..5 {
        let _ = task_get(&gw, &id).await;
    }
    assert_eq!(
        gw.mints.load(Ordering::SeqCst) - before,
        1,
        "C1: warm polls after it resolve nothing"
    );
}

/// K1: touch-on-read. Alpha's slot is aged past the idle bound, a warm read
/// comes in, then the reaper runs: the slot survives because the read touched
/// it, and nothing was resolved. Red on base: no touch, the slot is evicted.
#[tokio::test]
async fn k1_a_warm_read_keeps_alpha_s_slot_from_idle_eviction() {
    let gw = gateway(CallerSlot::Valid, CLOSED, Surfaced::Yes).await;
    let id = finished(&gw, "s1-k1").await;
    backend(&gw).age_per_user_slot_for_test(BINDING, 301);
    let before = gw.mints.load(Ordering::SeqCst);
    let read = task_get(&gw, &id).await;
    assert!(read.to_string().contains(OUTPUT), "K1: served: {read}");
    backend(&gw).evict_idle_per_user_entries(std::time::Duration::from_secs(300));
    assert!(
        backend(&gw).holds_per_user_slot_for_test(BINDING),
        "K1: the read touched alpha's slot, so the reaper keeps it"
    );
    assert_eq!(gw.mints.load(Ordering::SeqCst), before, "K1: no resolution");
}
