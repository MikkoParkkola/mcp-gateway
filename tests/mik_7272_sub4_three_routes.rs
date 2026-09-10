// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! MIK-7272.SUB.4 — the idempotency key must be honoured on EVERY route a
//! client can reach, not only the meta-tool one.
//!
//! `src/gateway/router/handlers.rs:1222` reads `params._meta` on the
//! `gateway_invoke` path and refuses a malformed key there. The direct
//! backend route (`/mcp/{name}`, `backend_handlers::backend_handler`) parses
//! the same `params` at `backend_handlers.rs:509` and never looks at the
//! field, so a client that sends a key to a backend directly gets no
//! protection and no refusal — silence, which is the one answer a client
//! cannot distinguish from success.
//!
//! Every case counts UPSTREAM `tools/call` deliveries and makes each answer
//! call-distinguishable, so a replay is proved by CONTENT rather than by a
//! count alone: a count of one with the second caller's body would be a
//! different defect wearing the same number.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mcp_gateway::backend::{Backend, BackendRegistry};
use mcp_gateway::config::{BackendConfig, Config, FailsafeConfig, TransportConfig};
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::test_helpers::{AppState, MetaMcp, create_router};
use mcp_gateway::key_server::oidc::VerifiedIdentity;
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::protocol::mrtr::IDEMPOTENCY_KEY_META;
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
use serde_json::{Value, json};
use tower::ServiceExt;

const BACKEND: &str = "backend";
const TOOL: &str = "tool";

/// A loopback MCP server that counts `tools/call` deliveries and answers each
/// one differently.
///
/// The distinguishable body is the point: a suppressed duplicate must return
/// the FIRST call's result, and a test that only counted could not tell that
/// from a second delivery whose answer happened to be discarded.
async fn spawn_counting_backend(calls: Arc<AtomicUsize>) -> String {
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(request): axum::Json<Value>| {
            let calls = Arc::clone(&calls);
            async move { axum::Json(answer(&request, &calls)) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the fixture backend must bind a loopback port");
    let address = listener.local_addr().expect("the bound port must be known");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}/")
}

fn answer(request: &Value, calls: &AtomicUsize) -> Value {
    let result = match request.get("method").and_then(Value::as_str) {
        Some("initialize") => json!({
            "protocolVersion": "2025-06-18",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "fixture", "version": "0" }
        }),
        Some("tools/list") => json!({
            "tools": [ { "name": TOOL, "description": "d", "inputSchema": { "type": "object" } } ]
        }),
        Some("tools/call") => {
            let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
            json!({ "content": [ { "type": "text", "text": format!("call-{n}") } ] })
        }
        _ => json!({}),
    };
    json!({
        "jsonrpc": "2.0",
        "id": request.get("id").cloned().unwrap_or(Value::Null),
        "result": result
    })
}

fn register_backend(state: &Arc<AppState>, url: &str) {
    let config = BackendConfig {
        enabled: true,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: true,
            protocol_version: None,
        },
        ..BackendConfig::default()
    };
    let backend = Backend::new(
        BACKEND,
        config,
        &FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    );
    assert!(
        state.backends.register(Arc::new(backend)),
        "the fixture backend must register under a name nothing else holds"
    );
}

/// One gateway with the idempotency cache ENABLED.
///
/// Enabled deliberately: with the cache off there is no control to test, and
/// a green result would only prove the gateway does nothing either way.
fn state_with_idempotency() -> Arc<AppState> {
    let config = Config::default();
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));

    let mut meta = MetaMcp::new(Arc::clone(&backends));
    meta.enable_idempotency(
        Arc::new(mcp_gateway::idempotency::IdempotencyCache::new()),
        mcp_gateway::idempotency::CLEANUP_INTERVAL,
    );
    let meta_mcp = Arc::new(meta);
    let continuation = meta_mcp.continuation();

    Arc::new(AppState {
        session_lifecycle: None,
        env: None,
        meta_mcp,
        backends,
        meta_mcp_enabled: true,
        multiplexer,
        proxy_manager,
        streaming_config: config.streaming.clone(),
        auth_config: Arc::new(ResolvedAuthConfig::from_config(&config.auth)),
        key_server: None,
        tool_policy: Arc::new(ToolPolicy::from_config(&ToolPolicyConfig::default())),
        mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
        sanitize_input: false,
        ssrf_protection: false,
        trust_configured_backends: false,
        inflight: Arc::new(tokio::sync::Semaphore::new(100)),
        agent_auth: AgentAuthState::new(false, Arc::new(AgentRegistry::new())),
        gateway_key_pair: Arc::new(GatewayKeyPair::generate().expect("RSA key gen")),
        capability_dirs: Vec::new(),
        config_path: None,
        #[cfg(feature = "firewall")]
        firewall: None,
        agent_identity_config: mcp_gateway::config::AgentIdentityConfig::default(),
        control_plane_store: None,
        live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(config.clone())),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
        tasks: Arc::new(mcp_gateway::protocol::task_store::TaskStore::new()),
        subscriptions: Arc::new(
            mcp_gateway::gateway::subscription_registry::SubscriptionRegistry::new(64),
        ),
        continuation,
    })
}

/// A client's own direct-route `tools/call` frame.
///
/// `_meta` sits beside `name` and `arguments` in `params`, which is the only
/// place a client can put it, and `id` varies per call because two retries of
/// one operation are two JSON-RPC requests — a gateway that deduplicated on
/// `id` would be answering a question nobody asked.
fn call_body(id: u32, meta: Option<Value>) -> Value {
    let mut params = json!({ "name": TOOL, "arguments": { "a": 1 } });
    if let Some(meta) = meta {
        params["_meta"] = meta;
    }
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params })
}

/// POST to the DIRECT backend route, optionally as a named end user.
async fn post_direct(
    state: &Arc<AppState>,
    body: Value,
    identity: Option<VerifiedIdentity>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("/mcp/{BACKEND}"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    if let Some(identity) = identity {
        request.extensions_mut().insert(identity);
    }
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("router must answer");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn identity(subject: &str, email: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.to_string(),
        email: email.to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://issuer.example".to_string(),
    }
}

fn key(value: &str) -> Value {
    json!({ IDEMPOTENCY_KEY_META: value })
}

/// `MIK-7272.SUB.4.DIRECT.1` — same key, same arguments, different JSON-RPC
/// ids: the backend is called ONCE and the second caller gets the first
/// call's answer.
#[tokio::test]
async fn direct_route_suppresses_a_keyed_duplicate() {
    let calls = Arc::new(AtomicUsize::new(0));
    let url = spawn_counting_backend(Arc::clone(&calls)).await;
    let state = state_with_idempotency();
    register_backend(&state, &url);

    let (first_status, first) = post_direct(&state, call_body(1, Some(key("k1"))), None).await;
    let (second_status, second) = post_direct(&state, call_body(2, Some(key("k1"))), None).await;

    assert_eq!(first_status, StatusCode::OK, "first call: {first}");
    assert_eq!(second_status, StatusCode::OK, "second call: {second}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "one keyed operation must reach the backend once, not twice"
    );
    assert_eq!(
        second.get("result"),
        first.get("result"),
        "the suppressed duplicate must return the FIRST result, not an empty or fresh one"
    );
}

/// `MIK-7272.SUB.4.DIRECT.2` — one key, two different end users: NO replay
/// across callers.
///
/// A key is a client's private handle, not a global name. Sharing a cache
/// entry between callers would hand one user another user's result, which is
/// a disclosure rather than a deduplication.
#[tokio::test]
async fn direct_route_does_not_replay_across_callers() {
    let calls = Arc::new(AtomicUsize::new(0));
    let url = spawn_counting_backend(Arc::clone(&calls)).await;
    let state = state_with_idempotency();
    register_backend(&state, &url);

    let alice = identity("alice", "alice@id.local");
    let bob = identity("bob", "bob@id.local");
    let (_, first) = post_direct(&state, call_body(1, Some(key("shared"))), Some(alice)).await;
    let (_, second) = post_direct(&state, call_body(2, Some(key("shared"))), Some(bob)).await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "two distinct callers using the same key must each reach the backend"
    );
    assert_ne!(
        first.get("result"),
        second.get("result"),
        "the second caller must receive its OWN result, never the first caller's"
    );
}

/// `MIK-7272.SUB.4.DIRECT.3` — no key, two calls, two deliveries.
///
/// The harness canary. This must be GREEN today: it asserts the UNCHANGED
/// behaviour of the direct route. Red here means the fixture, the route or
/// the counting backend is broken, not that the criterion is unmet — and
/// without it a red suite could not tell those apart.
#[tokio::test]
async fn direct_route_without_a_key_calls_the_backend_each_time() {
    let calls = Arc::new(AtomicUsize::new(0));
    let url = spawn_counting_backend(Arc::clone(&calls)).await;
    let state = state_with_idempotency();
    register_backend(&state, &url);

    let (first_status, first) = post_direct(&state, call_body(1, None), None).await;
    let (second_status, second) = post_direct(&state, call_body(2, None), None).await;

    assert_eq!(first_status, StatusCode::OK, "first call: {first}");
    assert_eq!(second_status, StatusCode::OK, "second call: {second}");
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "an unkeyed call asked for no protection and must not receive any"
    );
}

/// `MIK-7272.SUB.4.MALFORMED.1` (direct leg) — a non-string key is REFUSED,
/// and nothing dispatches.
///
/// Ignoring it runs the call unprotected, which is precisely the outcome the
/// client asked to prevent; the meta route already refuses this shape at
/// `src/gateway/router/handlers.rs:1223`.
#[tokio::test]
async fn direct_route_refuses_a_malformed_key() {
    let calls = Arc::new(AtomicUsize::new(0));
    let url = spawn_counting_backend(Arc::clone(&calls)).await;
    let state = state_with_idempotency();
    register_backend(&state, &url);

    let (status, body) = post_direct(
        &state,
        call_body(1, Some(json!({ IDEMPOTENCY_KEY_META: 42 }))),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "answer: {body}");
    assert_eq!(
        body.pointer("/error/code").and_then(Value::as_i64),
        Some(-32602),
        "answer: {body}"
    );
    let message = body
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert!(
        message.starts_with("malformed request fields:"),
        "the direct route must refuse in the same words as the meta route, got: {message}"
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a refused frame must not reach the backend at all"
    );
}
