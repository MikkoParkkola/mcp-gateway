// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 STORED.1 T11 and U2: a stored read of a REST capability that
//! dispatches under a personal account (`auth.account`). A managed account
//! revoked after the task ran answers -32601 (T11); an external account has
//! no mint-free view, so it is unjudged and served on its catalogue (U2, the
//! stated residual). Driven through `/mcp` as alice.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::AuthConfig;
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    CAPABILITY_SERVER, CAPABILITY_TOOL, CapabilityAccount,
};

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    })
}

async fn send(router: &axum::Router, method: &str, name: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": method, "params": params});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request.extensions_mut().insert(CapabilityAccount::alice());
    let response = router.clone().oneshot(request).await.expect("an answer");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn task_get(router: &axum::Router, id: &str) -> Value {
    send(
        router,
        "tasks/get",
        id,
        json!({"taskId": id, "_meta": modern_meta()}),
    )
    .await
}

/// A router over alice's capability account, and a finished task of it
/// whose stored result was delivered once.
async fn finished(account: &CapabilityAccount, key: &str) -> (axum::Router, String, impl Sized) {
    let (state, store) = super::tests::meta_fixture::test_router_app_state_with_meta(
        &AuthConfig::default(),
        None,
        |meta| account.install(meta),
    )
    .await;
    let router = super::create_router(Arc::clone(&state));
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    let made = send(
        &router,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": CAPABILITY_SERVER, "tool": CAPABILITY_TOOL, "arguments": {}},
            "task": {}, "_meta": meta}),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let got = task_get(&router, &id).await;
        if got.pointer("/result/status") == Some(&json!("completed")) {
            assert!(got.get("error").is_none(), "control: delivered: {got}");
            return (router, id, (state, store));
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: completes: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// T11: a capability's managed account revoked after the task ran: -32601.
/// Control (in `finished`): the grant live, the stored result is delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn t11_a_capability_account_revoked_after_the_task_answers_absent() {
    let account = CapabilityAccount::start(false).await;
    let (router, id, _keep) = finished(&account, "s1-t11").await;
    account.revoke().await;
    let read = task_get(&router, &id).await;
    assert_eq!(
        read.pointer("/error/code"),
        Some(&json!(-32601)),
        "T11: {read}"
    );
}

/// U2 (M29): an external account has no mint-free view, so its outcome is
/// Unjudged and the read is judged on the catalogue alone: served (the
/// stated residual), never refused as NoView.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn u2_an_external_account_is_unjudged_and_served() {
    let account = CapabilityAccount::start(true).await;
    let (router, id, _keep) = finished(&account, "s1-u2").await;
    let read = task_get(&router, &id).await;
    assert!(read.get("error").is_none(), "U2: served: {read}");
    assert_eq!(
        read.pointer("/result/status"),
        Some(&json!("completed")),
        "U2: {read}"
    );
}
