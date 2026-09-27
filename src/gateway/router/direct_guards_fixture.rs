// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Shared fixture (test plan `2026-09-27-direct-route-guards-test-plan.md`
//! "Shared fixture") for the direct-route guard cells (MIK-7597). Red-commit
//! scaffolding only: no test module calls these yet.
#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state_with_auth;
use crate::backend::Backend;
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, FailsafeConfig};
use crate::gateway::meta_mcp::MetaMcp;
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;
use crate::protocol::{JsonRpcResponse, RequestId};
use crate::transport::Transport;

/// What a cell wants the shared `alpha` / `alpha-pt` backend to answer with,
/// covering the adapter table's classification rows (design doc §2.1a).
#[derive(Clone, Copy)]
pub(crate) enum Answer {
    /// Ordinary success, `isError: false`.
    Ok,
    /// Success envelope, `isError: true` (a tool refusing a request).
    IsError,
    /// JSON-RPC `error`, an arbitrary non-rate-limit code.
    RpcError(i32),
    /// A rate-limit refusal, carried as `isError: true` (test plan T5/T3b
    /// need the JSON-RPC-error flavour too; build one with `RpcError` and a
    /// "rate limit" message, since `is_rate_limited` matches on text, not
    /// shape).
    RateLimited,
    /// A transport-level failure: the backend was never reachable.
    Transport,
    /// Success, `isError: false`, whose text is the given payload (response
    /// inspection and context-integrity cells).
    Text(&'static str),
}

/// One `Transport` shared by `alpha` and `alpha-pt`, scripted with `Answer`
/// and counting every `tools/call` (`tools/list` always answers empty so
/// catalogue population never spends a call).
struct CountingBackend {
    calls: Arc<AtomicUsize>,
    answer: Answer,
}

#[async_trait::async_trait]
impl Transport for CountingBackend {
    async fn request(
        &self,
        method: &str,
        _params: Option<Value>,
    ) -> crate::Result<JsonRpcResponse> {
        let id = RequestId::Number(1);
        if method == "tools/list" {
            return Ok(JsonRpcResponse::success(id, json!({"tools": []})));
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.answer {
            Answer::Ok => Ok(JsonRpcResponse::success(
                id,
                json!({"content": [{"type": "text", "text": "ok"}], "isError": false}),
            )),
            Answer::IsError => Ok(JsonRpcResponse::success(
                id,
                json!({"content": [{"type": "text", "text": "backend says no"}], "isError": true}),
            )),
            Answer::RpcError(code) => {
                Ok(JsonRpcResponse::error(Some(id), *code, "backend says no"))
            }
            Answer::RateLimited => Ok(JsonRpcResponse::error(
                Some(id),
                -32000,
                "rate limit exceeded",
            )),
            Answer::Transport => Err(crate::Error::Transport("connection refused".to_string())),
            Answer::Text(text) => Ok(JsonRpcResponse::success(
                id,
                json!({"content": [{"type": "text", "text": text}], "isError": false}),
            )),
        }
    }
    async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
        Ok(())
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// A router wired for the direct-route guard cells: non-admin keys
/// (`k-std`, `k-budget`, `k-rl` with a rate limit of 1, `k-deny` denied `read`;
/// all `backends: ["*"]`), and `alpha` / `alpha-pt`
/// (`passthrough: true`) sharing one call counter and one `Answer`.
pub(crate) struct Fx {
    pub state: Arc<super::AppState>,
    pub router: axum::Router,
    pub calls: Arc<AtomicUsize>,
    _store: tempfile::TempDir,
}

fn key(name: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(name.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
    }
}

/// Build the fixture, arming the replaced `MetaMcp` with `arm` before it is
/// installed (idempotency is enabled first, so `arm` can layer more on top).
pub(crate) async fn fixture(answer: Answer, arm: impl FnOnce(&mut MetaMcp)) -> Fx {
    fixture_built(answer, |mut meta| {
        arm(&mut meta);
        meta
    })
    .await
}

/// [`fixture`], for arming that needs the owned builder methods
/// (`with_profile_registry`, `with_cost_governance`).
pub(crate) async fn fixture_built(answer: Answer, build: impl FnOnce(MetaMcp) -> MetaMcp) -> Fx {
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![
            key("k-std"),
            key("k-budget"),
            ApiKeyConfig {
                rate_limit: 1,
                ..key("k-rl")
            },
            ApiKeyConfig {
                denied_tools: Some(vec!["read".to_string()]),
                ..key("k-deny")
            },
        ],
        ..Default::default()
    };
    let (mut state, store) = test_router_app_state_with_auth(&auth).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let state_mut = Arc::get_mut(&mut state).expect("state is unique");
    for (name, passthrough) in [("alpha", false), ("alpha-pt", true)] {
        let backend = Arc::new(Backend::new(
            name,
            BackendConfig {
                passthrough,
                ..BackendConfig::default()
            },
            &FailsafeConfig::default(),
            Duration::from_secs(60),
        ));
        let transport = CountingBackend {
            calls: Arc::clone(&calls),
            answer,
        };
        backend.set_transport_for_test(Arc::new(transport));
        assert!(state_mut.backends.register(backend), "fixture registration");
    }
    let mut meta = MetaMcp::new(Arc::clone(&state_mut.backends));
    meta.enable_idempotency(
        Arc::new(crate::idempotency::IdempotencyCache::new()),
        Duration::from_secs(300),
    );
    state_mut.meta_mcp = Arc::new(build(meta));
    let router = create_router(Arc::clone(&state));
    Fx {
        state,
        router,
        calls,
        _store: store,
    }
}

/// Build `params._meta` carrying an idempotency key, when one is given.
fn set_idem(params: &mut Value, idem: Option<&str>) {
    if let Some(value) = idem {
        params["_meta"] = json!({ IDEMPOTENCY_KEY_META: value });
    }
}

/// `POST /mcp/{backend}` `tools/call`, as the direct route takes it.
pub(crate) async fn post_direct(
    fx: &Fx,
    backend: &str,
    key: &str,
    tool: &str,
    args: Value,
    idem: Option<&str>,
    session: Option<&str>,
) -> (StatusCode, Value) {
    let mut params = json!({ "name": tool, "arguments": args });
    set_idem(&mut params, idem);
    send(
        fx,
        &format!("/mcp/{backend}"),
        key,
        "tools/call",
        params,
        session,
    )
    .await
}

/// `POST /mcp` `tools/call gateway_invoke`, the meta-route twin a parity
/// table compares against `post_direct`.
pub(crate) async fn post_meta_invoke(
    fx: &Fx,
    key: &str,
    server: &str,
    tool: &str,
    args: Value,
    idem: Option<&str>,
    session: Option<&str>,
) -> (StatusCode, Value) {
    let mut params = json!({
        "name": "gateway_invoke",
        "arguments": { "server": server, "tool": tool, "arguments": args },
    });
    set_idem(&mut params, idem);
    send(fx, "/mcp", key, "tools/call", params, session).await
}

async fn send(
    fx: &Fx,
    uri: &str,
    key: &str,
    method: &str,
    params: Value,
    session: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json");
    if let Some(session_id) = session {
        builder = builder.header("mcp-session-id", session_id);
    }
    let request = builder
        .body(axum::body::Body::from(
            json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string(),
        ))
        .unwrap();
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}
