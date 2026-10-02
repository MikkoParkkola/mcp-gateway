// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The read through the router for the era observability suite.

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::config::Config;
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::subscription_registry::SubscriptionRegistry;
use mcp_gateway::gateway::test_helpers::{
    AppState, MetaMcp, StoreLimits, auth_state, create_router, open_runtime,
};
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The gateway state, plus the directory its task store leases: the store
/// holds that directory while the service lives, so the caller binds it
/// until the response has been read.
async fn state(backends: Arc<BackendRegistry>) -> (Arc<AppState>, tempfile::TempDir) {
    let mut config = Config::default();
    config.server.modern_protocol = true;
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let agent_registry = Arc::new(AgentRegistry::new());

    // One registry, shared with the executor that publishes through it.
    let subscriptions = Arc::new(SubscriptionRegistry::new(64, auth_state(&config.auth)));
    let store_dir = tempfile::tempdir().expect("a private task-store directory");
    let (tasks, task_executor) = open_runtime(
        &store_dir.path().join("tasks"),
        config.tasks.max_workers,
        StoreLimits::default(),
        Arc::clone(&subscriptions),
    )
    .await
    .expect("the fixture task store opens");

    let state = Arc::new(AppState {
        continuation: Arc::new(mcp_gateway::protocol::continuation::ContinuationState::new()),
        session_lifecycle: None,
        env: None,
        meta_mcp: Arc::new(MetaMcp::new(Arc::clone(&backends))),
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
        agent_auth: AgentAuthState::new(false, agent_registry),
        gateway_key_pair: Arc::new(GatewayKeyPair::generate().expect("RSA key gen")),
        capability_dirs: Vec::new(),
        config_path: None,
        #[cfg(feature = "firewall")]
        firewall: None,
        agent_identity_config: mcp_gateway::config::AgentIdentityConfig::default(),
        control_plane_store: None,
        control_plane_base: None,
        live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(config.clone())),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
        tasks,
        task_executor,
        subscriptions,
    });
    (state, store_dir)
}

/// The `servers` array of a `gateway_list_servers` call, as an operator
/// sees it. Through the router, because an accessor would hide exactly the
/// serialisation gap this criterion is about.
pub async fn servers(backends: Arc<BackendRegistry>) -> Vec<Value> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "gateway_list_servers",
            "arguments": {},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        }
    });
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        // The body names a revision, so the header must name the same one:
        // the gateway rejects a mismatch with HEADER_MISMATCH before any
        // handler runs, and that rejection is not what these cases observe.
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        // `tools/call` carries a name, so the header must mirror the body's
        // `params.name` or the guard refuses the call before any handler runs.
        .header("Mcp-Name", "gateway_list_servers")
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    // `_store_dir` stays bound until this helper returns, which is after the
    // response body has been read: the store's directory outlives the request.
    let (app, _store_dir) = state(backends).await;
    let response = create_router(app)
        .oneshot(request)
        .await
        .expect("router must answer");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    let envelope: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let text = envelope["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("gateway_list_servers must answer with content: {envelope}"));
    let payload: Value =
        serde_json::from_str(text).unwrap_or_else(|_| panic!("content must be JSON: {text}"));
    payload["servers"]
        .as_array()
        .unwrap_or_else(|| panic!("response must carry a servers array: {payload}"))
        .clone()
}
