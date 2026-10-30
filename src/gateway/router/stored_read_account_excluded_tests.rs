// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8387 PR-B S7a-acct (lead, 2026-10-17): the account half of S7a. A
//! stored read by a caller whose key excludes the task's managed-account
//! target must not resolve that account. Two scoped keys carry one verified
//! identity, which holds the account's live grant
//! ([`Binding::ConnectedFor`]); custody resolutions are counted at the
//! fixture's custody.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::config::{ApiKeyConfig, AuthConfig, SurfacedToolConfig, api_key_digest_spec};
use crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::{
    BACKEND, Binding, DirectAccountGateway,
};

const INCLUDED: &str = "s7a-acct-included-key";
const EXCLUDED: &str = "s7a-acct-excluded-key";
const ELSEWHERE: &str = "elsewhere_hub";
const SUBJECT: &str = "s7a-acct-subject";
const TOOL: &str = "read";
const MARKER: &str = "stored-output-8387-s7a-acct";

fn key(secret: &str, name: &str, backend: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(api_key_digest_spec(secret.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec![backend.to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

fn auth() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![
            key(INCLUDED, "included", BACKEND),
            key(EXCLUDED, "excluded", ELSEWHERE),
        ],
        ..AuthConfig::default()
    }
}

struct Fx {
    router: axum::Router,
    gateway: DirectAccountGateway,
    _store: crate::gateway::router::tests::FixtureDir,
}

async fn fixture() -> Fx {
    let auth = auth();
    let mut gateway = DirectAccountGateway::new(auth.clone(), &Binding::ConnectedFor(SUBJECT));
    let (mut state, store) = super::tests::test_router_app_state_with_auth(&auth).await;
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    state_mut.backends = gateway.backends();
    let meta = gateway
        .take_meta()
        .with_surfaced_tools(vec![SurfacedToolConfig {
            server: BACKEND.to_string(),
            tool: TOOL.to_string(),
        }]);
    state_mut.meta_mcp = Arc::new(meta);
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
        router: super::create_router(Arc::clone(&state)),
        gateway,
        _store: store,
    }
}

fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}}
        },
    })
}

async fn send(fx: &Fx, secret: &str, method: &str, name: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 5, "method": method, "params": params});
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {secret}"))
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", method)
        .header("mcp-name", name)
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    request
        .extensions_mut()
        .insert(DirectAccountGateway::verified(SUBJECT));
    let response = fx.router.clone().oneshot(request).await.expect("an answer");
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "{method}: not JSON ({e}): {}",
            String::from_utf8_lossy(&bytes)
        )
    })
}

async fn task_get(fx: &Fx, secret: &str, id: &str) -> Value {
    send(
        fx,
        secret,
        "tasks/get",
        id,
        json!({"taskId": id, "_meta": modern_meta()}),
    )
    .await
}

/// S7a-acct, a guard: the excluded key's stored read of a task on the
/// managed-account backend makes no custody resolution. Green on the tip:
/// account resolution skips targets the reader may not invoke
/// (`task_replay.rs:136`). The control, the included key's own read of the
/// same task, resolves, so the counter is live. Mutant S7a-a-m1: the `:136`
/// filter removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s7a_acct_an_excluded_stored_read_resolves_no_account() {
    let fx = fixture().await;
    fx.gateway.answer_next(json!({
        "content": [{"type": "text", "text": MARKER}], "isError": false
    }));
    let mut meta = modern_meta();
    meta[crate::protocol::mrtr::IDEMPOTENCY_KEY_META] = json!("s7a-acct");
    let made = send(
        &fx,
        INCLUDED,
        "tools/call",
        "gateway_invoke",
        json!({"name": "gateway_invoke",
            "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"folder": "inbox"}},
            "task": {}, "_meta": meta}),
    )
    .await;
    let id = made
        .pointer("/result/taskId")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("premise: the included key made a task: {made}"))
        .to_owned();
    let bound = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let got = task_get(&fx, INCLUDED, &id).await;
        if got.to_string().contains(MARKER) {
            break;
        }
        assert!(
            std::time::Instant::now() < bound,
            "premise: the included key is served its task's output: {got}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let before = fx.gateway.resolves();
    let read = task_get(&fx, EXCLUDED, &id).await;
    assert!(
        !read.to_string().contains(MARKER),
        "S7a-acct: the excluded key is not served the output: {read}"
    );
    assert_eq!(
        fx.gateway.resolves(),
        before,
        "S7a-acct: account resolved for an excluded reader; read: {read}"
    );
    let control = task_get(&fx, INCLUDED, &id).await;
    assert!(
        fx.gateway.resolves() > before,
        "S7a-acct control: the included key's read resolves the account: {control}"
    );
}
