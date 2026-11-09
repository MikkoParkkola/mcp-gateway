// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The gateway fixture the A2A outbound rows drive: the integration
//! suites' shared fixture, cut to the parts these rows use.

/// The record key the router's auth config is built with: a self-describing
/// test value, never a deployment's key.
#[cfg(test)]
pub const RECORD_KEY: &str = "test-record-key-not-a-secret-0123456789abcdef";

pub use crate::backend::BackendRegistry;
pub use crate::config::{ApiKeyConfig, AuthConfig, Config};
pub use crate::gateway::auth::ResolvedAuthConfig;
pub use crate::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
pub use crate::gateway::proxy::ProxyManager;
pub use crate::gateway::streaming::NotificationMultiplexer;
pub use crate::gateway::subscription_registry::SubscriptionRegistry;
pub use crate::gateway::test_helpers::{
    AppState, MetaMcp, StoreLimits, auth_state, create_router, open_runtime,
};
pub use crate::mtls::{MtlsConfig, MtlsPolicy};
pub use axum::body::Body;
pub use axum::http::{Request, StatusCode};
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

#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag gates an independent NFR row; grouping them would force \
              every case to name fields it does not vary"
)]
pub struct Fixture {
    pub auth: AuthConfig,
    pub agent_auth_enabled: bool,
    pub meta_mcp_enabled: bool,
    pub agent_identity: crate::config::AgentIdentityConfig,
    pub sanitize_input: bool,
    /// The stateless path's master switch. `true` is the shipped default
    /// (`src/config/mod.rs:1236`); `false` is COMPAT.1 C1's falsifier.
    pub modern_protocol: bool,
    /// The gate control 15 names. `None` is the shipped router-test state and
    /// the falsifier for the block below.
    #[cfg(feature = "firewall")]
    pub firewall: Option<Arc<crate::security::firewall::Firewall>>,
    /// The registry the route tracks scored identities in. `None` is the
    /// shipped router-test state: nothing is tracked and no sweep runs.
    pub session_lifecycle: Option<Arc<crate::gateway::session_lifecycle::SessionLifecycle>>,
    /// Install `firewall` on the Meta-MCP too, as the server does
    /// (`server/mod.rs`): its anomaly screen and delivery pass then run with
    /// the same rules as the router's. Off by default so rows that set only
    /// the router firewall keep their meaning.
    #[cfg(feature = "firewall")]
    pub meta_firewall: bool,
}

impl Default for Fixture {
    fn default() -> Self {
        Self {
            auth: Config::default().auth,
            // Off, like the shipped default: rows other than 2 must reach
            // their own gate rather than being refused by this one.
            agent_auth_enabled: false,
            meta_mcp_enabled: true,
            agent_identity: crate::config::AgentIdentityConfig::default(),
            // `SecurityConfig::default()` has this ON (`security.rs:472`).
            // The fixture default is off so the other rows reach their own
            // gate rather than being refused by this one.
            sanitize_input: false,
            modern_protocol: true,
            #[cfg(feature = "firewall")]
            firewall: None,
            session_lifecycle: None,
            #[cfg(feature = "firewall")]
            meta_firewall: false,
        }
    }
}

/// The gateway state a case drives, plus the directory its task store leases.
///
/// The `TempDir` is returned rather than dropped here because the store holds
/// its directory for the life of the service: dropping it at the end of this
/// function would delete the records under a state the test is still posting
/// to. Callers bind it for the whole test — `let (app, _store_dir) = …` — and
/// each call gets a fresh private directory, so no two cases share a lease.
pub async fn state(f: Fixture) -> (Arc<AppState>, Arc<tempfile::TempDir>) {
    let mut config = Config::default();
    config.server.modern_protocol = f.modern_protocol;
    config.auth = f.auth;
    // The flags apply from the published config (ADR-023); SSRF stays off
    // as these fixtures always had it.
    config.security.sanitize_input = f.sanitize_input;
    config.security.ssrf_protection = false;
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));

    // One registry, shared between the state the router reads and the executor
    // that publishes: two would send a task's notifications to a listener set
    // no client here is on.
    let subscriptions = Arc::new(SubscriptionRegistry::new(
        64,
        auth_state(&config.auth, RECORD_KEY),
    ));
    let store_dir = Arc::new(tempfile::tempdir().expect("a private task-store directory"));
    let (tasks, task_executor) = open_runtime(
        &store_dir.path().join("tasks"),
        config.tasks.max_workers,
        StoreLimits::default(),
        Arc::clone(&subscriptions),
    )
    .await
    .expect("the fixture task store opens");
    // The task worker outlives no store directory: the test's share of it
    // keeps the directory until the worker's last write lands.
    tasks.keep_test_dir(Arc::clone(&store_dir));

    // The router's firewall on the Meta-MCP too when the row asks, as the
    // server installs it on both.
    #[cfg_attr(
        not(feature = "firewall"),
        expect(unused_mut, reason = "only the firewall build sets it")
    )]
    let mut meta = MetaMcp::new(Arc::clone(&backends));
    #[cfg(feature = "firewall")]
    if f.meta_firewall {
        meta.set_firewall(f.firewall.clone());
    }
    let app = Arc::new(AppState {
        process: std::sync::Arc::default(),
        continuation: Arc::new(crate::protocol::continuation::ContinuationState::new()),
        session_lifecycle: f.session_lifecycle,
        env: None,
        meta_mcp: Arc::new(meta),
        backends,
        meta_mcp_enabled: f.meta_mcp_enabled,
        multiplexer,
        proxy_manager,
        streaming_config: config.streaming.clone(),
        key_server: None,
        mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
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
        control_plane_base: None,
        live_config: Arc::new(crate::gateway::test_helpers::live_config(
            config.clone(),
            Arc::new(ResolvedAuthConfig::from_config(&config.auth, RECORD_KEY)),
        )),
        export_status: None,
        transparency_log: None,
        governance_log: None,
        dashboard_bootstrap: Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        tasks,
        task_executor,
        subscriptions,
    });
    (app, store_dir)
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

pub fn api_key(key: &str, rate_limit: u32, allowed: Option<Vec<String>>) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(key.as_bytes())),
        expires_at: None,
        name: "client".to_string(),
        rate_limit,
        backends: vec!["*".to_string()],
        allowed_tools: allowed,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
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
        dashboard_session: crate::config::DashboardSessionConfig::default(),
    }
}
