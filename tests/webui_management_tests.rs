// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Integration tests for the Web UI management API endpoints.
//!
//! Tests the following endpoint groups end-to-end through the in-process router:
//!
//! Backend management:
//!   POST   /ui/api/backends           — add backend
//!   DELETE /ui/api/backends/:name     — remove backend
//!   PATCH  /ui/api/backends/:name     — update backend
//!   GET    /ui/api/registry           — list built-in registry
//!   GET    /ui/api/registry/search?q= — search registry
//!
//! Capability management:
//!   GET    /ui/api/capabilities        — list capabilities
//!   GET    /ui/api/capabilities/:name  — get YAML
//!   PUT    /ui/api/capabilities/:name  — validate + write
//!   POST   /ui/api/capabilities        — create new
//!   DELETE /ui/api/capabilities/:name  — delete
//!
//! `OpenAPI` import:
//!   POST /ui/api/import/openapi/preview — preview tools from inline spec
//!   POST /ui/api/import/openapi         — import tools from inline spec

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tower::ServiceExt;

use mcp_gateway::backend::{Backend, BackendRegistry};
use mcp_gateway::config::{AuthConfig, BackendConfig, Config, FailsafeConfig, TransportConfig};
use mcp_gateway::config_reload::{LiveConfig, ReloadContext};
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::subscription_registry::SubscriptionRegistry;
use mcp_gateway::gateway::test_helpers::{
    AppState, MetaMcp, StoreLimits, TaskExecutor, TaskService, auth_state, create_router,
    open_runtime, write_owner_only,
};
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};

#[path = "webui_management_tests/access_posture.rs"]
mod access_posture;
#[path = "webui_management_tests/backend_edit_comments.rs"]
mod backend_edit_comments;
#[path = "webui_management_tests/backend_mutation.rs"]
mod backend_mutation;
#[path = "webui_management_tests/capabilities.rs"]
mod capabilities;
#[path = "webui_management_tests/openapi_import.rs"]
mod openapi_import;
#[path = "webui_management_tests/registry.rs"]
mod registry;

// ── Test helpers ─────────────────────────────────────────────────────────────

/// Bearer token the management tests authenticate with. A bearer token is an
/// admin credential, which is what these endpoints require.
const ADMIN_TOKEN: &str = "test-admin-token";

/// Auth config granting admin to [`ADMIN_TOKEN`].
fn admin_auth_config() -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: Some(ADMIN_TOKEN.to_string()),
        ..AuthConfig::default()
    }
}

/// Build a minimal `AppState` suitable for unit-testing the UI management
/// endpoints.
///
/// Auth is ENABLED with [`ADMIN_TOKEN`], because these endpoints are admin-only
/// and the anonymous identity holds no admin. Requests here go through
/// [`admin_request`], which presents that token. Auth-disabled callers are
/// covered separately by `anonymous_is_refused_admin_endpoints`.
/// The durable task runtime the `AppState` fixtures in this file are built on.
///
/// One private `TempDir` per fixture, returned so the test binds it for its own
/// lifetime. The store takes an exclusive lease on its directory, so a shared
/// path would make one fixture's open refuse another's; and a `TempDir` dropped
/// at the end of the fixture would delete the records under a live service.
/// `open_runtime` is the production entry point — nothing here substitutes a
/// store, names a fixed path, or reads a process-wide variable.
async fn task_runtime(
    subscriptions: &Arc<SubscriptionRegistry>,
) -> (Arc<TaskService>, Arc<TaskExecutor>, TempDir) {
    let store_dir = TempDir::new().expect("a private task-store directory");
    let (service, executor) = open_runtime(
        &store_dir.path().join("tasks"),
        mcp_gateway::config::DEFAULT_MAX_WORKERS,
        StoreLimits::default(),
        Arc::clone(subscriptions),
    )
    .await
    .expect("the fixture task store opens");
    (service, executor, store_dir)
}

async fn make_app_state(
    cap_dir: Option<&str>,
    config_path: Option<std::path::PathBuf>,
) -> (Arc<AppState>, TempDir) {
    let config = Config::default();
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));

    let authorizer = auth_state(&admin_auth_config());

    let tool_policy = Arc::new(ToolPolicy::from_config(&ToolPolicyConfig::default()));
    let mtls_policy = Arc::new(MtlsPolicy::from_config(&MtlsConfig::default()));
    let inflight = Arc::new(tokio::sync::Semaphore::new(100));

    let agent_registry = Arc::new(AgentRegistry::new());
    let agent_auth = AgentAuthState::new(false, Arc::clone(&agent_registry));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("RSA key gen failed"));

    let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&backends)));

    let capability_dirs = cap_dir.map(|d| vec![d.to_string()]).unwrap_or_default();

    let subscriptions = Arc::new(SubscriptionRegistry::new(64, authorizer.clone()));
    let (task_service, task_executor, store_dir) = task_runtime(&subscriptions).await;

    let state = Arc::new(AppState {
        continuation: Arc::new(mcp_gateway::protocol::continuation::ContinuationState::new()),
        session_lifecycle: None,
        env: None,
        backends,
        meta_mcp,
        meta_mcp_enabled: false,
        multiplexer,
        proxy_manager,
        streaming_config: config.streaming.clone(),
        auth_config: authorizer.auth_config,
        key_server: None,
        tool_policy,
        mtls_policy,
        sanitize_input: false,
        ssrf_protection: false,
        trust_configured_backends: false,
        inflight,
        agent_auth,
        gateway_key_pair,
        capability_dirs,
        config_path,
        #[cfg(feature = "firewall")]
        firewall: None,
        agent_identity_config: mcp_gateway::config::AgentIdentityConfig::default(),
        control_plane_store: None,
        control_plane_base: None,
        live_config: std::sync::Arc::new(mcp_gateway::config_reload::LiveConfig::new(
            mcp_gateway::config::Config::default(),
        )),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: std::sync::Arc::new(
            mcp_gateway::gateway::auth::DashboardBootstrap::new(),
        ),
        tasks: task_service,
        task_executor,
        subscriptions,
    });
    (state, store_dir)
}

async fn make_app_state_with_auth_config(auth_config: &AuthConfig) -> (Arc<AppState>, TempDir) {
    let (mut state, store_dir) = make_app_state(None, None).await;
    Arc::get_mut(&mut state)
        .expect("test AppState should be uniquely owned")
        .auth_config = Arc::new(ResolvedAuthConfig::from_config(auth_config));
    (state, store_dir)
}

#[allow(clippy::needless_pass_by_value)]
async fn make_app_state_with_reload(
    config: Config,
    cap_dir: Option<&str>,
    config_path: std::path::PathBuf,
) -> (Arc<AppState>, Arc<LiveConfig>, TempDir) {
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let authorizer = auth_state(&admin_auth_config());
    let tool_policy = Arc::new(ToolPolicy::from_config(&ToolPolicyConfig::default()));
    let mtls_policy = Arc::new(MtlsPolicy::from_config(&MtlsConfig::default()));
    let inflight = Arc::new(tokio::sync::Semaphore::new(100));
    let agent_registry = Arc::new(AgentRegistry::new());
    let agent_auth = AgentAuthState::new(false, Arc::clone(&agent_registry));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("RSA key gen failed"));
    let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&backends)));
    let live_config = Arc::new(LiveConfig::new(config.clone()));
    let reload_context = ReloadContext::new(
        config_path.clone(),
        Arc::clone(&live_config),
        Arc::clone(&backends),
        config.failsafe.clone(),
        config.meta_mcp.cache_ttl,
    )
    .map(Arc::new)
    .expect("the registry pairs with the config");
    meta_mcp.set_reload_context(reload_context);
    let capability_dirs = cap_dir.map(|d| vec![d.to_string()]).unwrap_or_default();
    let subscriptions = Arc::new(SubscriptionRegistry::new(64, authorizer.clone()));
    let (task_service, task_executor, store_dir) = task_runtime(&subscriptions).await;

    (
        Arc::new(AppState {
            continuation: Arc::new(mcp_gateway::protocol::continuation::ContinuationState::new()),
            session_lifecycle: None,
            env: None,
            backends,
            meta_mcp,
            meta_mcp_enabled: false,
            multiplexer,
            proxy_manager,
            streaming_config: config.streaming.clone(),
            auth_config: authorizer.auth_config,
            key_server: None,
            tool_policy,
            mtls_policy,
            sanitize_input: false,
            ssrf_protection: false,
            trust_configured_backends: false,
            inflight,
            agent_auth,
            gateway_key_pair,
            capability_dirs,
            config_path: Some(config_path),
            #[cfg(feature = "firewall")]
            firewall: None,
            agent_identity_config: mcp_gateway::config::AgentIdentityConfig::default(),
            control_plane_store: None,
            control_plane_base: None,
            live_config: std::sync::Arc::new(mcp_gateway::config_reload::LiveConfig::new(
                mcp_gateway::config::Config::default(),
            )),
            export_status: None,
            transparency_log: None,
            dashboard_bootstrap: std::sync::Arc::new(
                mcp_gateway::gateway::auth::DashboardBootstrap::new(),
            ),
            tasks: task_service,
            task_executor,
            subscriptions,
        }),
        live_config,
        store_dir,
    )
}

/// Send a JSON-body request and return `(StatusCode, parsed JSON body)`.
async fn send_json(
    router: &axum::Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let (bytes, has_body) = match body {
        Some(v) => (serde_json::to_vec(&v).unwrap(), true),
        None => (Vec::new(), false),
    };

    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"));
    if has_body {
        builder = builder.header("content-type", "application/json");
    }
    let req = builder.body(Body::from(bytes)).unwrap();

    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let rbytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = if rbytes.is_empty() {
        json!(null)
    } else {
        serde_json::from_slice(&rbytes).unwrap_or(json!(null))
    };
    (status, json)
}

/// Send a request with a raw string body (e.g. YAML) and return `(StatusCode, parsed JSON)`.
async fn send_raw(
    router: &axum::Router,
    method: Method,
    uri: &str,
    content_type: &str,
    body: &str,
) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .header("content-type", content_type)
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, json)
}

/// Minimal valid capability YAML for tests.
const VALID_YAML: &str = r#"fulcrum: "1.0"
name: test_cap
description: Test capability for integration tests

schema:
  input:
    type: object
    properties:
      query:
        type: string
    required:
      - query
  output:
    type: object

providers:
  primary:
    service: rest
    config:
      base_url: https://example.com
      path: /api
      method: GET

cache:
  strategy: ttl
  ttl: 60

auth:
  required: false

metadata:
  category: test
  tags: []
  cost_category: free
  read_only: true
"#;

fn register_http_backend(state: &Arc<AppState>, name: &str) {
    register_http_backend_with_url(state, name, format!("http://127.0.0.1:9/{name}"));
}

fn register_http_backend_with_url(
    state: &Arc<AppState>,
    name: &str,
    http_url: String,
) -> Arc<Backend> {
    let backend = Arc::new(Backend::new(
        name,
        BackendConfig {
            transport: TransportConfig::Http {
                http_url,
                streamable_http: Some(true),
                protocol_version: None,
            },
            enabled: true,
            ..BackendConfig::default()
        },
        &FailsafeConfig::default(),
        Duration::from_secs(60),
    ));
    let _ = state.backends.register(Arc::clone(&backend));
    backend
}

async fn spawn_mcp_tools_fixture() -> (String, JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().route("/mcp", post(mcp_tools_fixture_handler));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{addr}/mcp"), server)
}

async fn mcp_tools_fixture_handler(Json(body): Json<Value>) -> Json<Value> {
    let id = body.get("id").cloned().unwrap_or_else(|| json!(1));
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-03-26",
            "capabilities": { "tools": { "listChanged": false } },
            "serverInfo": { "name": "docs-fixture", "version": "test" }
        }),
        "tools/list" => json!({
            "tools": [{
                "name": "search_docs",
                "description": "Search local documentation",
                "inputSchema": {
                    "type": "object",
                    "properties": { "query": { "type": "string" } },
                    "required": ["query"]
                },
                "annotations": {
                    "readOnlyHint": true,
                    "destructiveHint": false,
                    "idempotentHint": true,
                    "openWorldHint": false
                }
            }]
        }),
        _ => {
            return Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "error": { "code": -32601, "message": "Method not found" }
            }));
        }
    };

    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}
