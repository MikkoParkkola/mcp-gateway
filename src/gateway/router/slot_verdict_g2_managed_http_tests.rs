// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8356 test plan r3, C9: HTTP `/mcp` `tools/call` of a surfaced tool on
//! a managed-account backend whose caller slot is cold, where the caller's
//! first `tools/list` gets HTTP 401. The managed-401 recovery runs exactly
//! once, the answer is a failed backend (never the unknown-name -32601), and
//! no `tools/call` is sent.
//!
//! The caller is the sole operator of a `single_user` HTTP deployment (the
//! managed-account fixture behind the real router and auth middleware, as
//! `direct_sole_operator_tests`). The shared slot holds the tool with a valid
//! schema, so the call is not refused before the caller's slot is reached.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use crate::config::{ApiKeyConfig, AuthConfig, SurfacedToolConfig, api_key_digest_spec};
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway,
};
use crate::security::TransparencyLogger;
use crate::security::transparency_log::TransparencyLogConfig;

const OPERATOR_KEY: &str = "sole-operator-key";
const TOOL: &str = "read";

fn sole_operator() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(api_key_digest_spec(OPERATOR_KEY.as_bytes())),
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

struct Fx {
    router: axum::Router,
    gateway: DirectAccountGateway,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

/// The router over the sole operator's managed backend, [`TOOL`] surfaced,
/// the shared slot warm with a valid [`TOOL`] and the operator's slot cold.
async fn fixture() -> Fx {
    let audit = tempfile::tempdir().unwrap();
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: audit
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "8356-c9".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log"),
    );
    let auth = sole_operator();
    let mut gateway = DirectAccountGateway::new(auth.clone(), &Binding::Connected);
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = gateway.backends();
    let mut meta = gateway
        .take_meta()
        .with_surfaced_tools(vec![SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: TOOL.to_string(),
        }]);
    meta.enable_transparency_log(Arc::clone(&log));
    state_mut.meta_mcp = Arc::new(meta);
    state_mut.transparency_log = Some(log);
    let tool: crate::protocol::Tool = serde_json::from_value(json!({
        "name": TOOL, "inputSchema": {"type": "object", "properties": {"folder": {"type": "string"}}}
    }))
    .expect("a tool");
    gateway
        .backends()
        .get(BACKEND)
        .expect("the backend")
        .store_shared_tools_for_test(vec![tool]);
    Fx {
        router: create_router(state),
        gateway,
        _dirs: (audit, store),
    }
}

async fn call(fx: &Fx) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": TOOL, "arguments": {"folder": "inbox"}}});
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {OPERATOR_KEY}"))
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// C9 (absence): the cold caller slot's first `tools/list` gets 401. The
/// managed-401 recovery runs exactly once (custody's forced-refresh count),
/// nothing is dispatched, and the answer is not the unknown-name -32601.
/// The premise call proves the fixture reaches the operator's slot first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c9_per_user_cold_caller_managed_401_recovers() {
    let control = fixture().await;
    let answer = call(&control).await;
    assert_eq!(
        control.gateway.tool_calls().len(),
        1,
        "premise: the sole operator's cold-slot call did not dispatch: {answer}"
    );

    let fx = fixture().await;
    fx.gateway.answer_lists_with(&[401]);
    let (refreshes, sent) = (fx.gateway.refreshes(), fx.gateway.tool_calls().len());
    let answer = call(&fx).await;
    assert_eq!(
        fx.gateway.refreshes(),
        refreshes + 1,
        "C9: the managed-401 recovery did not run exactly once: {answer}"
    );
    assert_eq!(
        fx.gateway.tool_calls().len(),
        sent,
        "C9: dispatched after a refused fill: {answer}"
    );
    assert_ne!(
        answer.pointer("/error/code"),
        Some(&json!(-32601)),
        "C9: a failed fill answered as an unknown name: {answer}"
    );
}
