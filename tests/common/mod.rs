// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway fixture the NFR refusal suites drive.
//!
//! Cargo compiles this module once per test binary, so an item only one
//! suite uses is genuinely dead in the other. That is a property of the
//! harness layout, not a defect in either suite.
#![allow(dead_code)]

pub use axum::body::Body;
pub use axum::http::{Request, StatusCode};
pub use mcp_gateway::backend::BackendRegistry;
pub use mcp_gateway::config::{ApiKeyConfig, AuthConfig, Config};
pub use mcp_gateway::gateway::auth::ResolvedAuthConfig;
pub use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
pub use mcp_gateway::gateway::proxy::ProxyManager;
pub use mcp_gateway::gateway::streaming::NotificationMultiplexer;
pub use mcp_gateway::gateway::test_helpers::{AppState, MetaMcp, create_router};
pub use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
pub use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
pub use serde_json::{Value, json};
pub use std::sync::Arc;
pub use tower::ServiceExt;

/// A modern request frame: the revision removed the handshake, so every
/// request carries its own `_meta`.
pub fn modern(method: &str, params: Value) -> Value {
    let mut params = params;
    params["_meta"] = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": { "name": "ExampleClient", "version": "1.0.0" }
    });
    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
}

pub struct Fixture {
    pub auth: AuthConfig,
    pub agent_auth_enabled: bool,
    pub meta_mcp_enabled: bool,
    pub agent_identity: mcp_gateway::config::AgentIdentityConfig,
    pub sanitize_input: bool,
    /// The stateless path's master switch. `true` is the shipped default
    /// (`src/config/mod.rs:1236`); `false` is COMPAT.1 C1's falsifier.
    pub modern_protocol: bool,
    /// The gate control 15 names. `None` is the shipped router-test state and
    /// the falsifier for the block below.
    #[cfg(feature = "firewall")]
    pub firewall: Option<Arc<mcp_gateway::security::firewall::Firewall>>,
    /// The lifecycle registry the handler renews deadlines in
    /// (`MIK-7215.CONTROL.4`). `None` is the shipped router-test state, in
    /// which tracking is a no-op.
    pub session_lifecycle: Option<Arc<mcp_gateway::gateway::session_lifecycle::SessionLifecycle>>,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            auth: Config::default().auth,
            // Off, like the shipped default: rows other than 2 must reach
            // their own gate rather than being refused by this one.
            agent_auth_enabled: false,
            meta_mcp_enabled: true,
            agent_identity: mcp_gateway::config::AgentIdentityConfig::default(),
            // `SecurityConfig::default()` has this ON (`security.rs:472`).
            // The fixture default is off so the other rows reach their own
            // gate rather than being refused by this one.
            sanitize_input: false,
            modern_protocol: true,
            #[cfg(feature = "firewall")]
            firewall: None,
            session_lifecycle: None,
        }
    }
}

pub fn state(f: Fixture) -> Arc<AppState> {
    let mut config = Config::default();
    config.server.modern_protocol = f.modern_protocol;
    config.auth = f.auth;
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    Arc::new(AppState {
        session_lifecycle: f.session_lifecycle,
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
        agent_auth: AgentAuthState::new(f.agent_auth_enabled, Arc::new(AgentRegistry::new())),
        gateway_key_pair: Arc::new(GatewayKeyPair::generate().expect("RSA key gen")),
        capability_dirs: Vec::new(),
        config_path: None,
        #[cfg(feature = "firewall")]
        firewall: f.firewall,
        agent_identity_config: f.agent_identity,
        control_plane_store: None,
        live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(config.clone())),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
        tasks: Arc::new(mcp_gateway::protocol::task_store::TaskStore::new()),
        subscriptions: Arc::new(
            mcp_gateway::gateway::subscription_registry::SubscriptionRegistry::new(64),
        ),
    })
}

/// POST to `/mcp` as a conforming modern client: body `_meta` mirrored into the
/// standard headers, plus whatever extra headers the case needs.
pub async fn post(
    state: &Arc<AppState>,
    body: Value,
    extra: &[(&str, &str)],
) -> (StatusCode, Value) {
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
pub async fn post_raw(state: &Arc<AppState>, body: Vec<u8>) -> (StatusCode, Value) {
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

pub fn api_key(key: &str, rate_limit: u32, allowed: Option<Vec<String>>) -> ApiKeyConfig {
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

pub fn auth_with(keys: Vec<ApiKeyConfig>, bearer: Option<&str>) -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: bearer.map(str::to_string),
        api_keys: keys,
        public_paths: Vec::new(),
        client_circuit_breaker: None,
        single_user: false,
    }
}
