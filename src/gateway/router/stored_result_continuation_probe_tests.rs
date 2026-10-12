// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8392 probe P3 (gpt s2-d1 CRITICAL): a keyed continuation retry that
//! names an UNSURFACED backend tool is admitted on admission's plan branch
//! (no target from `check_target_policy`). After the managed grant is
//! revoked, the same retry must not be served the stored output.
//! RED = the plan branch replays a single call without proof of liveness.
//! GREEN = it does not (a fingerprint conflict or the live refusal).

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{ApiKeyConfig, AuthConfig, api_key_digest_spec};
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway,
};

const KEY: &str = "sole-operator-key";
const TOOL: &str = "read";
const MARKER: &str = "stored-output-probe-8392-p3";

fn sole_operator() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(api_key_digest_spec(KEY.as_bytes())),
            expires_at: None,
            name: "operator".to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
            kind: crate::config::ApiKeyKind::Shared,
        }],
        single_user: true,
        ..AuthConfig::default()
    }
}

async fn send(router: &axum::Router, name: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {KEY}"))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

fn meta(key: Option<&str>) -> Value {
    let mut meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
    });
    if let Some(key) = key {
        meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!(key);
    }
    meta
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p3_unsurfaced_keyed_continuation_retry_after_revocation_serves_no_stored_output() {
    let auth = sole_operator();
    // No surfaced tools: `read` is reachable only through `gateway_invoke`,
    // and a continuation retry naming it is routed to its origin backend.
    let mut gateway = DirectAccountGateway::new(auth.clone(), &Binding::Connected);
    let (mut state, _store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = gateway.backends();
    state_mut.meta_mcp = Arc::new(gateway.take_meta());
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
    }))
    .expect("a tool");
    gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .store_shared_tools_for_test(vec![tool]);
    let router = super::create_router(state);

    gateway.answer_next(json!({
        "resultType": "input_required",
        "inputRequests": {"k1": {"method": "elicitation/create",
            "params": {"message": "Which account?", "requestedSchema": {"type": "object"}}}},
        "requestState": "backend-state-1"
    }));
    gateway.answer_next(json!({"content": [{"type": "text", "text": MARKER}], "isError": false}));

    let asked = send(&router, "gateway_invoke", json!({
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
        "_meta": meta(None),
    }))
    .await;
    let state = asked["result"]["requestState"]
        .as_str()
        .unwrap_or_else(|| panic!("premise: an interim answer with a state: {asked}"))
        .to_owned();
    let retry = json!({
        "name": TOOL,
        "arguments": {"folder": "inbox"},
        "requestState": state,
        "inputResponses": {"k1": {"action": "accept", "content": {"account": "work"}}},
        "_meta": meta(Some("p3-continuation")),
    });
    let first = send(&router, TOOL, retry.clone()).await;
    eprintln!("P3 first retry: {first}");
    assert!(
        first.to_string().contains(MARKER),
        "premise: the keyed continuation retry by bare name dispatched: {first}"
    );
    let sent = gateway.tool_calls().len();
    gateway.revoke_operator_grant_for_probe().await;
    let again = send(&router, TOOL, retry).await;
    eprintln!("P3 repeated retry after revocation: {again}");
    assert!(
        !again.to_string().contains(MARKER),
        "P3: a revoked grant's keyed unsurfaced continuation retry was served the stored output: {again}"
    );
    assert_eq!(gateway.tool_calls().len(), sent, "P3: the retry reached the backend: {again}");
}
