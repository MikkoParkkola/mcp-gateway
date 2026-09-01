// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Refusal tests for the controls named in
//! `docs/requirements/nfr-sec1-control-inventory.md`.
//!
//! NFR.SEC.1 says EACH control that constrained a caller under 3.5.0 must have
//! a test asserting refusal when its input is absent. The four tests the
//! release ledger cited all cover controls 4.0.0 *introduced*; none covered a
//! 3.5.0 one. These do, and they do it through the only route a modern caller
//! has — a policy nothing consults refuses nothing, so calling the gate
//! function directly would be a weaker claim than the criterion makes.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::config::{ApiKeyConfig, AuthConfig, Config};
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::test_helpers::{AppState, MetaMcp, create_router};
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

/// A modern request frame: the revision removed the handshake, so every
/// request carries its own `_meta`.
fn modern(method: &str, params: Value) -> Value {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": { "name": "ExampleClient", "version": "1.0.0" }
    });
    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
}

struct Fixture {
    auth: AuthConfig,
    meta_mcp_enabled: bool,
    agent_identity: mcp_gateway::config::AgentIdentityConfig,
    sanitize_input: bool,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            auth: Config::default().auth,
            meta_mcp_enabled: true,
            agent_identity: mcp_gateway::config::AgentIdentityConfig::default(),
            // `SecurityConfig::default()` has this ON (`security.rs:472`).
            // The fixture default is off so the other rows reach their own
            // gate rather than being refused by this one.
            sanitize_input: false,
        }
    }
}

fn state(f: Fixture) -> Arc<AppState> {
    let mut config = Config::default();
    config.server.modern_protocol = true;
    config.auth = f.auth;
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    Arc::new(AppState {
        continuation: Arc::new(mcp_gateway::protocol::continuation::ContinuationState::new()),
        env: None,
        meta_mcp: Arc::new(MetaMcp::new(Arc::clone(&backends))),
        backends,
        meta_mcp_enabled: f.meta_mcp_enabled,
        multiplexer,
        proxy_manager,
        streaming_config: config.streaming.clone(),
        auth_config: Arc::new(ResolvedAuthConfig::from_config(&config.auth)),
        key_server: None,
        tool_policy: Arc::new(ToolPolicy::from_config(&ToolPolicyConfig::default())),
        mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
        sanitize_input: f.sanitize_input,
        ssrf_protection: false,
        trust_configured_backends: false,
        inflight: Arc::new(tokio::sync::Semaphore::new(100)),
        agent_auth: AgentAuthState::new(false, Arc::new(AgentRegistry::new())),
        gateway_key_pair: Arc::new(GatewayKeyPair::generate().expect("RSA key gen")),
        capability_dirs: Vec::new(),
        config_path: None,
        #[cfg(feature = "firewall")]
        firewall: None,
        agent_identity_config: f.agent_identity,
        control_plane_store: None,
        live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(config.clone())),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
        subscriptions: Arc::new(
            mcp_gateway::gateway::subscription_registry::SubscriptionRegistry::new(64),
        ),
    })
}

/// POST to `/mcp` as a conforming modern client: body `_meta` mirrored into the
/// standard headers, plus whatever extra headers the case needs.
async fn post(state: &Arc<AppState>, body: Value, extra: &[(&str, &str)]) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28");
    if let Some(m) = body.get("method").and_then(Value::as_str) {
        builder = builder.header("mcp-method", m);
    }
    // The revision requires a modern caller to mirror the tool name too. Without
    // it the mirrored-header check refuses first and a later gate never runs —
    // which is how a test can pass while the control it names is inoperative.
    if let Some(n) = body.pointer("/params/name").and_then(Value::as_str) {
        builder = builder.header("mcp-name", n);
    }
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
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


/// POST a body that is not necessarily JSON.
///
/// Rows 7 and 8 refuse *before* the body is parsed, so there is nothing to
/// mirror into `mcp-name`; the headers a modern frame always carries are sent
/// so no earlier gate can be the one that answers.
async fn post_raw(state: &Arc<AppState>, body: Vec<u8>) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/list")
        .body(Body::from(body))
        .expect("request");
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

fn api_key(key: &str, rate_limit: u32, allowed: Option<Vec<String>>) -> ApiKeyConfig {
    ApiKeyConfig {
        key: key.to_string(),
        name: "client".to_string(),
        rate_limit,
        backends: Vec::new(),
        allowed_tools: allowed,
        denied_tools: None,
        admin: false,
    }
}

fn auth_with(keys: Vec<ApiKeyConfig>, bearer: Option<&str>) -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: bearer.map(str::to_string),
        api_keys: keys,
        public_paths: Vec::new(),
        client_circuit_breaker: None,
        single_user: false,
    }
}

// ============================================================================
// NFR.SEC.1 control 3 — authentication
// A modern caller with no credential is refused before the handler runs.
// ============================================================================
#[tokio::test]
async fn control_3_a_modern_request_without_a_credential_is_refused() {
    let app = state(Fixture {
        auth: auth_with(Vec::new(), Some("secret-bearer")),
        ..Default::default()
    });
    let (status, _) = post(&app, modern("tools/list", json!({})), &[]).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "removing the handshake must not remove the credential requirement"
    );
    // Falsifier: with the credential present the same frame is served, so the
    // refusal above is this gate's and not something refusing unconditionally.
    let (served, _) = post(
        &app,
        modern("tools/list", json!({})),
        &[("authorization", "Bearer secret-bearer")],
    )
    .await;
    assert_eq!(served, StatusCode::OK);
}

// ============================================================================
// NFR.SEC.1 control 4 — per-client rate limit
// The second call inside the window is refused; the budget is the input.
// ============================================================================
#[tokio::test]
async fn control_4_a_modern_caller_over_its_rate_limit_is_refused() {
    let app = state(Fixture {
        auth: auth_with(vec![api_key("k", 1, None)], None),
        ..Default::default()
    });
    let header = [("authorization", "Bearer k")];
    let (first, _) = post(&app, modern("tools/list", json!({})), &header).await;
    assert_eq!(first, StatusCode::OK, "the first call is inside the budget");
    let (second, _) = post(&app, modern("tools/list", json!({})), &header).await;
    assert_eq!(
        second,
        StatusCode::TOO_MANY_REQUESTS,
        "the rate limit must still bind a caller who never handshook"
    );
}

// ============================================================================
// NFR.SEC.1 control 6 — agent identity
// `require_id` with no `X-Agent-ID` header.
// ============================================================================
#[tokio::test]
async fn control_6_a_modern_request_without_an_agent_id_is_refused() {
    let identity = mcp_gateway::config::AgentIdentityConfig {
        enabled: true,
        require_id: true,
        ..Default::default()
    };
    let app = state(Fixture {
        agent_identity: identity,
        ..Default::default()
    });
    let (status, body) = post(&app, modern("tools/list", json!({})), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], -32600, "body: {body}");
    // Falsifier: the same frame carrying an agent ID is served.
    let (served, _) = post(
        &app,
        modern("tools/list", json!({})),
        &[("x-agent-id", "agent-1")],
    )
    .await;
    assert_eq!(served, StatusCode::OK);
}

// ============================================================================
// NFR.SEC.1 control 9 — the Meta-MCP surface can be switched off
// ============================================================================
#[tokio::test]
async fn control_9_a_modern_request_to_a_disabled_surface_is_refused() {
    let app = state(Fixture {
        meta_mcp_enabled: false,
        ..Default::default()
    });
    let (status, body) = post(&app, modern("tools/list", json!({})), &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], -32600, "body: {body}");
    // Falsifier: the identical frame against an enabled surface is served.
    let enabled = state(Fixture::default());
    let (served, _) = post(&enabled, modern("tools/list", json!({})), &[]).await;
    assert_eq!(served, StatusCode::OK);
}

// ============================================================================
// NFR.SEC.1 control 13 — API-key tool scope
// The existing coverage calls `authorize_tool_target` directly. This crosses
// the handler branch that consults it, by the only route a modern caller has.
// ============================================================================
fn invoke() -> Value {
    modern(
        "tools/call",
        json!({
            "name": "gateway_invoke",
            "arguments": { "server": "some_backend", "tool": "forbidden_tool" }
        }),
    )
}

#[tokio::test]
async fn control_13_a_modern_caller_outside_its_tool_scope_is_refused() {
    let app = state(Fixture {
        auth: auth_with(
            vec![api_key("k", 0, Some(vec!["allowed_tool".to_string()]))],
            None,
        ),
        ..Default::default()
    });
    let (status, body) = post(&app, invoke(), &[("authorization", "Bearer k")]).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "tool scope must still bind a modern caller; body: {body}"
    );
    // Falsifier: a key whose scope covers the target reaches past this gate, so
    // the refusal above is the scope check and not the call failing anyway.
    let in_scope = state(Fixture {
        auth: auth_with(
            vec![api_key("k", 0, Some(vec!["forbidden_tool".to_string()]))],
            None,
        ),
        ..Default::default()
    });
    let (served, body) = post(&in_scope, invoke(), &[("authorization", "Bearer k")]).await;
    assert_ne!(
        served,
        StatusCode::FORBIDDEN,
        "an in-scope key must clear the scope gate; body: {body}"
    );
}


// ============================================================================
// NFR.SEC.1 control 8 — JSON well-formedness
// `-32700` from `serde_json::from_slice` at `handlers.rs:526`. The inventory
// recorded this as "covered by 10" and it was not: a body that fails here
// never reaches `parse_request`, and the `-32700` assertions that existed
// call `build_http_error_response`, the constructor, rather than the gate.
// ============================================================================
#[tokio::test]
async fn control_8_a_modern_request_with_unparseable_json_is_refused() {
    let app = state(Fixture::default());
    let (status, body) = post_raw(&app, b"{\"jsonrpc\": \"2.0\", ".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(
        body["error"]["code"], -32700,
        "the refusal must be this gate's parse error, not a later envelope \
         check or an earlier header check; body: {body}"
    );
    // Falsifier: the same route, same headers, parseable body — served. A test
    // that refused both halves would be measuring some gate ahead of this one.
    let (served, _) = post_raw(
        &app,
        serde_json::to_vec(&modern("tools/list", json!({}))).expect("body"),
    )
    .await;
    assert_eq!(served, StatusCode::OK);
}

// ============================================================================
// NFR.SEC.1 control 7 — request body ceiling (10 MiB)
// `axum::body::to_bytes` at `handlers.rs:513`. Built in memory rather than
// shipped as a fixture, which is what the inventory priced as too expensive.
// ============================================================================
#[tokio::test]
async fn control_7_a_modern_request_over_the_body_ceiling_is_refused() {
    let app = state(Fixture::default());
    let over = modern("tools/list", json!({ "padding": "x".repeat(11 * 1024 * 1024) }));
    let (status, _) = post(&app, over, &[]).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "the 10 MiB ceiling must still bind a caller who never handshook"
    );
    // Falsifier: the SAME shape under the ceiling is served, so the refusal is
    // the size and not the padded frame being rejected on its own account.
    let under = modern("tools/list", json!({ "padding": "x".repeat(1024 * 1024) }));
    let (served, body) = post(&app, under, &[]).await;
    assert_eq!(served, StatusCode::OK, "body: {body}");
}

// ============================================================================
// NFR.SEC.1 control 11 — input sanitization
// The inventory excused this row as "off by default". It is not:
// `SecurityConfig::default()` sets it ON (`src/config/features/security.rs:472`)
// and the gateway reads that field into `AppState`
// (`src/gateway/server/mod.rs:1187`). What the row actually needed was a
// rejection shape that is not a moving target — a null byte, which
// `sanitize_string` refuses by contract.
// ============================================================================
#[tokio::test]
async fn control_11_a_modern_request_carrying_a_null_byte_is_refused() {
    let app = state(Fixture {
        sanitize_input: true,
        ..Default::default()
    });
    let (status, body) = post(&app, modern("tools/list", json!({ "q": "a\u{0}b" })), &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    assert_eq!(
        body["error"]["code"], -32600,
        "the refusal must be the sanitizer's, not the JSON parser's; body: {body}"
    );
    // Falsifier one: the same frame without the null byte is served.
    let (served, body) = post(&app, modern("tools/list", json!({ "q": "ab" })), &[]).await;
    assert_eq!(served, StatusCode::OK, "body: {body}");
    // Falsifier two: with the control off, the null byte itself is served — so
    // the refusal above is this control and not the shape being rejected
    // somewhere else on the path.
    let off = state(Fixture::default());
    let (unguarded, _) = post(&off, modern("tools/list", json!({ "q": "a\u{0}b" })), &[]).await;
    assert_eq!(
        unguarded,
        StatusCode::OK,
        "with sanitization off nothing else on the path rejects a null byte"
    );
}
