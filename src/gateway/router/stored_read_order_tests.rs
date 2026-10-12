// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392.STORED.1 order twins (review): a stored read refuses in the live
//! call's order — visibility for a withheld name, then policy, then accounts.
//! Each row drives a live call and a stored read by the same caller under the
//! same withdrawn access and asserts byte-equal errors (trace ids masked).

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{AuthConfig, SurfacedToolConfig};
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, CAPABILITY_SERVER, CAPABILITY_TOOL, CapabilityAccount, DirectAccountGateway,
};
use crate::key_server::oidc::VerifiedIdentity;

const TOOL: &str = "read";

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    })
}

/// POST as `caller`, whose verified identity rides in as a request extension.
async fn send_as(
    router: &axum::Router,
    caller: &VerifiedIdentity,
    method: &str,
    name: &str,
    params: Value,
) -> Value {
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
    request.extensions_mut().insert(caller.clone());
    let response = router.clone().oneshot(request).await.expect("an answer");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// The error object with every per-call trace id (`gw-` and 36 UUID
/// characters) replaced by one placeholder: two calls never share one (K2).
fn error_masked(body: &Value) -> String {
    const UUID_LEN: usize = 36;
    let text = body.get("error").map(Value::to_string).unwrap_or_default();
    let mut out = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(at) = rest.find("gw-") {
        let after = &rest[at + 3..];
        let is_uuid = after.len() >= UUID_LEN
            && after[..UUID_LEN]
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == '-');
        out.push_str(&rest[..at + 3]);
        if is_uuid {
            out.push_str("<trace>");
            rest = &after[UUID_LEN..];
        } else {
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Order twin: a revoked account plus a withdrawn grant on the same Personal
/// capability target. On the live path policy answers first: route authorize
/// runs the identity-grant rule (`meta_mcp/invoke/chokepoint.rs:255-260`,
/// called from `router/handlers/dispatch_tools_call.rs:186`) before caller
/// verdicts (`dispatch_tools_call.rs:393`), and the dispatch policy
/// (`meta_mcp/invoke.rs:158`) runs before its resolution (`invoke.rs:217`).
/// The stored read runs `authorize_stored` before accounts too, so both answer
/// the grant denial (-32004), never -32601.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn order_revoked_account_with_a_withdrawn_grant_answers_the_grant_denial() {
    let account = CapabilityAccount::start_personal().await;
    let (state, _store) = super::tests::meta_fixture::test_router_app_state_with_meta(
        &AuthConfig::default(),
        None,
        |meta| account.install(meta),
    )
    .await;
    let granted = crate::identity_grants::LocalIdentityGrantStore::from_grants([
        CapabilityAccount::alice_grant(),
    ]);
    state.meta_mcp.set_identity_grants(granted);
    let router = super::create_router(Arc::clone(&state));
    let alice = CapabilityAccount::alice();
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("s1-order-grant");
    let made = send_as(
        &router,
        &alice,
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
        let got = send_as(
            &router,
            &alice,
            "tasks/get",
            &id,
            json!({"taskId": id, "_meta": modern_meta()}),
        )
        .await;
        if got.pointer("/result/status") == Some(&json!("completed")) {
            assert!(got.get("error").is_none(), "control: delivered: {got}");
            break;
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: completes: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    account.revoke().await;
    state
        .meta_mcp
        .set_identity_grants(crate::identity_grants::LocalIdentityGrantStore::new());
    let live = send_as(
        &router,
        &alice,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": CAPABILITY_SERVER, "tool": CAPABILITY_TOOL, "arguments": {}},
            "_meta": modern_meta()}),
    )
    .await;
    assert_eq!(
        live.pointer("/error/code"),
        Some(&json!(-32004)),
        "premise: the live call is grant-denied, not absent: {live}"
    );
    let stored = send_as(
        &router,
        &alice,
        "tasks/get",
        &id,
        json!({"taskId": id, "_meta": modern_meta()}),
    )
    .await;
    assert_eq!(
        error_masked(&stored),
        error_masked(&live),
        "order: the stored read answers what the live call answers"
    );
}

/// Order twin: an unbindable caller (empty subject, as Ub) plus a descriptor
/// block on the same tool. On the live path the descriptor block answers
/// first: a withheld surfaced name resolves to no target
/// (`router/authorization.rs:95-107`), so the call answers -32601
/// (`meta_mcp/call_dispatch.rs:27`) before any account resolution
/// (`meta_mcp/invoke/caller_verdict.rs:208`, `meta_mcp/invoke.rs:249`). The
/// stored read judges visibility before accounts too, so both answer -32601.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn order_unbindable_caller_with_a_withheld_tool_answers_absence() {
    let auth = AuthConfig::default();
    let gateway = DirectAccountGateway::new(auth.clone(), &Binding::Connected);
    let (mut state, _store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = gateway.backends();
    let mut gateway = gateway;
    state_mut.meta_mcp =
        Arc::new(
            gateway
                .take_meta()
                .with_surfaced_tools(vec![SurfacedToolConfig {
                    server: BACKEND.to_string(),
                    tool: TOOL.to_string(),
                }]),
        );
    let router = super::create_router(Arc::clone(&state));
    let nobody = VerifiedIdentity {
        subject: String::new(),
        email: "nobody@example.invalid".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://issuer.example.invalid".to_string(),
    };
    let mut tasked = json!({"name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
        "_meta": modern_meta()});
    tasked["task"] = json!({});
    tasked["_meta"][crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("s1-order-withheld");
    let made = send_as(&router, &nobody, "tools/call", "gateway_invoke", tasked).await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: a task was made: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while state
        .task_executor
        .service
        .store
        .status_for_test(&id)
        .is_some_and(|status| status == crate::protocol::tasks::TaskStatus::Working)
    {
        assert!(
            std::time::Instant::now() < bound,
            "premise: the task settles"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .block_tool_for_test(TOOL);
    let stored = send_as(
        &router,
        &nobody,
        "tasks/get",
        &id,
        json!({"taskId": id, "_meta": modern_meta()}),
    )
    .await;
    let live = send_as(
        &router,
        &nobody,
        "tools/call",
        TOOL,
        json!({"name": TOOL, "arguments": {}, "_meta": modern_meta()}),
    )
    .await;
    assert_eq!(
        live.pointer("/error/code"),
        Some(&json!(-32601)),
        "premise: the live surfaced call answers absent: {live}"
    );
    assert_eq!(
        error_masked(&stored),
        error_masked(&live),
        "order: the stored read answers what the live call answers"
    );
}
