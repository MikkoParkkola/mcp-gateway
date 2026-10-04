// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
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

/// Every state constructor here hands back the directory its task store
/// leases, because the store holds that directory for as long as the
/// service lives. Callers bind it for the whole request.
async fn state() -> (Arc<AppState>, tempfile::TempDir) {
    state_with_modern(true).await
}

async fn state_with_modern(modern: bool) -> (Arc<AppState>, tempfile::TempDir) {
    state_with(modern, Config::default().auth).await
}

/// The destructive-confirmation gate sits behind the admin check, so the
/// only caller who can reach it is an authenticated admin. That needs a
/// real auth config, which is why this is parameterised rather than a
/// second copy of the state below.
async fn state_with(
    modern: bool,
    auth: mcp_gateway::config::AuthConfig,
) -> (Arc<AppState>, tempfile::TempDir) {
    state_with_exposure(modern, auth, &[]).await
}

/// As [`state_with`], plus the operator's meta-tool allow-list. An empty
/// slice exposes every meta-tool, which is what every other caller here
/// wants; the exposure row needs a list that deliberately omits the tool it
/// then calls.
async fn state_with_exposure(
    modern: bool,
    auth: mcp_gateway::config::AuthConfig,
    exposed: &[String],
) -> (Arc<AppState>, tempfile::TempDir) {
    let mut config = Config::default();
    config.server.modern_protocol = modern;
    config.auth = auth;
    let backends = Arc::new(BackendRegistry::new());
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
        meta_mcp: Arc::new(
            MetaMcp::new(Arc::clone(&backends)).with_exposed_meta_tools(exposed),
        ),
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

/// POST to `/mcp`, returning status, the session header if any, and the body.
async fn post_mcp(body: Value) -> (StatusCode, Option<String>, Value) {
    // Bound, not dropped: the store's directory has to outlive the request
    // this helper makes on the state built from it.
    let (state, _store_dir) = state().await;
    post_mcp_against(state, body).await
}

async fn post_mcp_against(
    state: Arc<AppState>,
    body: Value,
) -> (StatusCode, Option<String>, Value) {
    post_mcp_authed(state, body, None).await
}

async fn post_mcp_authed(
    state: Arc<AppState>,
    body: Value,
    bearer: Option<&str>,
) -> (StatusCode, Option<String>, Value) {
    let router = create_router(state);
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json");

    // A conforming modern client mirrors its body into the standard
    // headers. Derived from the body here rather than hard-coded, so these
    // tests always send what they claim to send; increment 3 sends
    // deliberately disagreeing headers of its own.
    if let Some(version) = body
        .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
        .and_then(Value::as_str)
    {
        builder = builder.header("mcp-protocol-version", version);
        if let Some(method) = body.get("method").and_then(Value::as_str) {
            builder = builder.header("mcp-method", method);
            if matches!(method, "tools/call" | "resources/read" | "prompts/get")
                && let Some(name) = body
                    .pointer("/params/name")
                    .or_else(|| body.pointer("/params/uri"))
                    .and_then(Value::as_str)
            {
                builder = builder.header("mcp-name", name);
            }
        }
    }

    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }

    let request = builder
        .body(Body::from(serde_json::to_vec(&body).expect("body")))
        .expect("request");
    let response = router.oneshot(request).await.expect("router must answer");
    let status = response.status();
    let session = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body must read");
    (
        status,
        session,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// A modern `tools/list`, transcribed from the specification's shape.
fn modern_tools_list(id: i64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "ExampleClient", "version": "1.0.0"
                }
            }
        }
    })
}

/// A modern `tools/call`, same shape, for a named tool.
/// The `params._meta` key carrying an idempotency key, spelled out here
/// the way every other scanner in this suite spells it
/// (`crate::protocol::mrtr::IDEMPOTENCY_KEY_META` in the gateway): a test
/// that imports the constant cannot catch a rename of the wire contract.
const IDEMPOTENCY_KEY_META: &str = "io.mcp-gateway/idempotency-key";

fn modern_tools_call(id: i64, name: &str, arguments: Value) -> Value {
    let mut request = modern_tools_list(id);
    request["method"] = json!("tools/call");
    request["params"]["name"] = json!(name);
    request["params"]["arguments"] = arguments;
    // A modern call that could mutate is inadmissible without an explicit
    // idempotency key, and that refusal precedes every branch the rows
    // below observe. Keyed by `id` so no two rows share an operation.
    request["params"]["_meta"][IDEMPOTENCY_KEY_META] = json!(format!("acs-{id}"));
    request
}



mod confirm;
mod stateless_rows;
