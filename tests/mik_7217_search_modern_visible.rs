// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7217.SEARCH.1` (Linear `MCP728.DISCOVER.6`):
//!
//! > A test proves a 2026-speaking backend becomes visible to `gateway_search` and does not trip
//! > the circuit breaker.
//!
//! The peer is a Streamable HTTP backend: 2026-07-28 removed `initialize` and `ping`, and the HTTP
//! start path is the one that skips the legacy handshake for a peer that answers `server/discover`
//! (a stdio peer is always sent `initialize` by its transport, so it cannot play a modern peer).
//! The mock answers `server/discover` and `tools/list`, and refuses `initialize` and `ping` with
//! JSON-RPC method-not-found, so a gateway that still sends either one fails here.
//!
//! Warm-start (`src/gateway/server/warmstart.rs`) is `pub(super)` and its tool fill
//! (`Backend::warm_tools`) is `pub(crate)`, so neither is reachable from an integration test. The
//! narrowest public equivalent is used: `Backend::ensure_started` (the start path, era probe
//! included) then `Backend::get_tools` (the same cache fill), then the search goes through the
//! real axum router, as a client's would.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::routing::post;
use axum::{Json, Router};
use mcp_gateway::backend::{Backend, BackendRegistry};
use mcp_gateway::config::{BackendConfig, Config, FailsafeConfig, TransportConfig};
use mcp_gateway::failsafe::CircuitState;
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::subscription_registry::SubscriptionRegistry;
use mcp_gateway::gateway::test_helpers::{
    AppState, MetaMcp, StoreLimits, auth_state, create_router, open_runtime,
};
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::protocol::era::Era;
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};
use serde_json::{Value, json};
use tower::ServiceExt;

const BACKEND: &str = "modern-peer";
const TOOL: &str = "modern_only_widget";
const WORD: &str = "zorbulate";

/// Every JSON-RPC method the mock received, in arrival order.
type Seen = Arc<Mutex<Vec<String>>>;

fn answer(id: &Value, payload: &Value) -> Json<Value> {
    let mut frame = json!({ "jsonrpc": "2.0", "id": id });
    frame
        .as_object_mut()
        .expect("object")
        .extend(payload.as_object().expect("object").clone());
    Json(frame)
}

/// A 2026-speaking peer: discovery and one tool, and the removed methods refused.
async fn mock_handler(State(seen): State<Seen>, Json(body): Json<Value>) -> Json<Value> {
    let method = body["method"].as_str().unwrap_or_default().to_string();
    seen.lock().expect("log").push(method.clone());
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    match method.as_str() {
        "server/discover" => answer(
            &id,
            &json!({ "result": {
                "capabilities": {},
                "supportedVersions": ["2026-07-28", "2025-11-25"]
            }}),
        ),
        "tools/list" => answer(
            &id,
            &json!({ "result": { "tools": [{
                "name": TOOL,
                "description": format!("A widget only a 2026 peer can {WORD}"),
                "inputSchema": { "type": "object", "properties": {} }
            }]}}),
        ),
        _ => answer(
            &id,
            &json!({ "error": { "code": -32601, "message": "Method not found" } }),
        ),
    }
}

async fn start_mock() -> (String, Seen) {
    let seen: Seen = Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let app = Router::new()
        .route("/mcp", post(mock_handler))
        .with_state(Arc::clone(&seen));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}/mcp"), seen)
}

fn backend_for(url: &str) -> Arc<Backend> {
    let config = BackendConfig {
        description: "2026-speaking search fixture".to_string(),
        enabled: true,
        transport: TransportConfig::Http {
            http_url: url.to_string(),
            streamable_http: true,
            protocol_version: None,
        },
        stop_when_idle_for: None,
        timeout: Duration::from_secs(10),
        env: HashMap::default(),
        headers: HashMap::default(),
        oauth: None,
        secrets: Vec::new(),
        passthrough: false,
        allow_cleartext_credentials: false,
        input_schema_enforcement: mcp_gateway::config::InputSchemaEnforcement::default(),
        allow_flagged_tools: std::collections::BTreeMap::new(),
        runtime_profile: None,
        identity_propagation: None,
        account: None,
        signature_chain: mcp_gateway::config::ChainMode::default(),
        chain_origins: Vec::new(),
        chain_signer: None,
    };
    Arc::new(Backend::new(
        BACKEND,
        config,
        &FailsafeConfig::default(),
        Duration::from_secs(300),
    ))
}

/// The gateway state over `backends`, plus the directory its task store leases.
async fn state(backends: Arc<BackendRegistry>) -> (Arc<AppState>, tempfile::TempDir) {
    let config = Config::default();
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
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
        agent_auth: AgentAuthState::new(false, Arc::new(AgentRegistry::new())),
        gateway_key_pair: Arc::new(GatewayKeyPair::generate().expect("RSA key gen")),
        capability_dirs: Vec::new(),
        config_path: None,
        #[cfg(feature = "firewall")]
        firewall: None,
        agent_identity_config: mcp_gateway::config::AgentIdentityConfig::default(),
        control_plane_store: None,
        control_plane_base: None,
        live_config: Arc::new(mcp_gateway::config_reload::LiveConfig::new(
            Config::default(),
        )),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: Arc::new(mcp_gateway::gateway::auth::DashboardBootstrap::new()),
        tasks,
        task_executor,
        subscriptions,
    });
    (state, store_dir)
}

/// `tools/call` of a search meta-tool on `POST /mcp`, as a 2026 client sends it. Returns the
/// search result document the tool put in its content.
async fn search(state: &Arc<AppState>, tool: &str, query: &str) -> Value {
    let body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": tool,
            "arguments": { "query": query },
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": { "name": "SearchClient", "version": "1" }
            }
        }
    });
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", tool)
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("router must answer");
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    let frame: Value = serde_json::from_slice(&bytes).expect("a JSON-RPC frame");
    assert!(
        frame.get("error").is_none(),
        "{tool} must not error: {frame}"
    );
    let text = frame["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("{tool} returns its document as content text: {frame}"));
    serde_json::from_str(text).expect("the content text is the search document")
}

/// MIK-7217.SEARCH.1 — a 2026-speaking backend becomes visible to `gateway_search` and does not
/// trip the circuit breaker.
///
/// GIVEN a registered peer that answers `server/discover` and refuses `initialize` and `ping`;
/// WHEN the gateway starts it and fills its tool cache, as warm-start does;
/// THEN its era reads Modern, a search for the tool's description finds it on that backend, and
/// the breaker is still closed after the startup and after the search.
#[tokio::test]
async fn a_2026_speaking_backend_is_visible_to_gateway_search_and_leaves_the_breaker_closed() {
    let (url, seen) = start_mock().await;
    let backend = backend_for(&url);
    let backends = Arc::new(BackendRegistry::new());
    assert!(backends.register(Arc::clone(&backend)), "registered");

    backend
        .ensure_started()
        .await
        .expect("a modern peer starts");
    let tools = backend.get_tools().await.expect("tools are cached");

    assert_eq!(backend.cached_era().await, Some(Era::Modern), "era");
    assert_eq!(tools.len(), 1, "the peer's one tool is cached");
    assert_eq!(backend.circuit_breaker_stats().state, CircuitState::Closed);
    let (state, _store_dir) = state(backends).await;

    let keyword = search(&state, "gateway_search_tools", WORD).await;
    let code_mode = search(&state, "gateway_search", WORD).await;

    let hit = &keyword["matches"][0];
    assert_eq!(
        (hit["server"].as_str(), hit["tool"].as_str()),
        (Some(BACKEND), Some(TOOL))
    );
    assert!(
        code_mode.to_string().contains(&format!("{BACKEND}:{TOOL}")),
        "gateway_search must name the tool as server:tool: {code_mode}"
    );
    assert!(!backend.is_circuit_tripped(), "the breaker stays closed");
    assert_eq!(backend.circuit_breaker_stats().state, CircuitState::Closed);
    let methods = seen.lock().expect("log").clone();
    assert!(
        !methods.iter().any(|m| m == "initialize" || m == "ping"),
        "a modern peer is never sent the removed methods: {methods:?}"
    );
}
