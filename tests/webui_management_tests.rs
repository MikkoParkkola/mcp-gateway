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
use mcp_gateway::config::{
    ApiKeyConfig, AuthConfig, BackendConfig, Config, FailsafeConfig, TransportConfig,
};
use mcp_gateway::config_reload::{LiveConfig, ReloadContext};
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::test_helpers::{AppState, MetaMcp, create_router};
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};

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
fn make_app_state(cap_dir: Option<&str>, config_path: Option<std::path::PathBuf>) -> Arc<AppState> {
    let config = Config::default();
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));

    let auth_config = Arc::new(ResolvedAuthConfig::from_config(&admin_auth_config()));

    let tool_policy = Arc::new(ToolPolicy::from_config(&ToolPolicyConfig::default()));
    let mtls_policy = Arc::new(MtlsPolicy::from_config(&MtlsConfig::default()));
    let inflight = Arc::new(tokio::sync::Semaphore::new(100));

    let agent_registry = Arc::new(AgentRegistry::new());
    let agent_auth = AgentAuthState::new(false, Arc::clone(&agent_registry));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("RSA key gen failed"));

    let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&backends)));

    let capability_dirs = cap_dir.map(|d| vec![d.to_string()]).unwrap_or_default();

    Arc::new(AppState {
        backends,
        meta_mcp,
        meta_mcp_enabled: false,
        multiplexer,
        proxy_manager,
        streaming_config: config.streaming.clone(),
        auth_config,
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
        live_config: std::sync::Arc::new(mcp_gateway::config_reload::LiveConfig::new(
            mcp_gateway::config::Config::default(),
        )),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: std::sync::Arc::new(
subscriptions: Arc::new(
    mcp_gateway::gateway::subscription_registry::SubscriptionRegistry::new(64),
),
            mcp_gateway::gateway::auth::DashboardBootstrap::new(),
        ),
    })
}

fn make_app_state_with_auth_config(auth_config: &AuthConfig) -> Arc<AppState> {
    let mut state = make_app_state(None, None);
    Arc::get_mut(&mut state)
        .expect("test AppState should be uniquely owned")
        .auth_config = Arc::new(ResolvedAuthConfig::from_config(auth_config));
    state
}

#[allow(clippy::needless_pass_by_value)]
fn make_app_state_with_reload(
    config: Config,
    cap_dir: Option<&str>,
    config_path: std::path::PathBuf,
) -> (Arc<AppState>, Arc<LiveConfig>) {
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(&admin_auth_config()));
    let tool_policy = Arc::new(ToolPolicy::from_config(&ToolPolicyConfig::default()));
    let mtls_policy = Arc::new(MtlsPolicy::from_config(&MtlsConfig::default()));
    let inflight = Arc::new(tokio::sync::Semaphore::new(100));
    let agent_registry = Arc::new(AgentRegistry::new());
    let agent_auth = AgentAuthState::new(false, Arc::clone(&agent_registry));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("RSA key gen failed"));
    let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&backends)));
    let live_config = Arc::new(LiveConfig::new(config.clone()));
    let reload_context = Arc::new(ReloadContext::new(
        config_path.clone(),
        Arc::clone(&live_config),
        Arc::clone(&backends),
        config.failsafe.clone(),
        config.meta_mcp.cache_ttl,
    ));
    meta_mcp.set_reload_context(reload_context);

    let capability_dirs = cap_dir.map(|d| vec![d.to_string()]).unwrap_or_default();

    (
        Arc::new(AppState {
            backends,
            meta_mcp,
            meta_mcp_enabled: false,
            multiplexer,
            proxy_manager,
            streaming_config: config.streaming.clone(),
            auth_config,
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
            live_config: std::sync::Arc::new(mcp_gateway::config_reload::LiveConfig::new(
                mcp_gateway::config::Config::default(),
            )),
            export_status: None,
            transparency_log: None,
            dashboard_bootstrap: std::sync::Arc::new(
subscriptions: Arc::new(
    mcp_gateway::gateway::subscription_registry::SubscriptionRegistry::new(64),
),
                mcp_gateway::gateway::auth::DashboardBootstrap::new(),
            ),
        }),
        live_config,
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
                streamable_http: true,
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

#[tokio::test]
async fn test_webui_embeds_control_plane_read_only_page() {
    let state = make_app_state(None, None);
    let router = create_router(state);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/ui")
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(bytes.to_vec()).unwrap();

    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("data-page=\"control-plane\""));
    assert!(html.contains("id=\"page-control-plane\""));
    assert!(html.contains("refreshControlPlane()"));
    assert!(html.contains("/ui/api/control-plane"));
    assert!(html.contains("Decision Queue"));
    assert!(html.contains("Feature Boundary"));
    assert!(html.contains("TrustCards"));
    assert!(html.contains("cp-trustcards-tbody"));
    assert!(html.contains("renderControlPlaneTrustCards"));
    assert!(html.contains("ShadowRadar"));
    assert!(html.contains("cp-shadow-tbody"));
    assert!(html.contains("renderControlPlaneShadow"));
}

// ── Registry tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_control_plane_endpoint_returns_read_only_runtime_projection() {
    let state = make_app_state(None, None);
    let (backend_url, server) = spawn_mcp_tools_fixture().await;
    let backend = register_http_backend_with_url(&state, "docs", backend_url);
    backend.get_tools_shared().await.unwrap();
    let router = create_router(state);

    let (status, body) = send_json(&router, Method::GET, "/ui/api/control-plane", None).await;

    assert_eq!(status, StatusCode::OK, "Expected 200, got: {body}");
    assert_control_plane_route_metadata(&body);
    assert_control_plane_inventory_counts(&body);
    assert_control_plane_shadow_boundary(&body);
    assert_control_plane_views(&body);

    server.abort();
}

fn assert_control_plane_route_metadata(body: &Value) {
    assert_eq!(body["schema_version"], "control_plane.api.v1");
    assert_eq!(body["source"], "local_runtime_snapshot");
    assert_eq!(body["route"]["read_only"], true);
    assert_eq!(body["route"]["mutation_endpoint"], false);
    assert_eq!(body["actor"]["role"], "admin");
    assert_eq!(body["features"][0]["feature"], "local_status");
    assert_eq!(body["features"][0]["license_tier"], "free_core");
    assert_eq!(body["features"][0]["available_in_this_route"], true);
    assert_eq!(body["coverage"]["servers"], true);
    assert_eq!(body["coverage"]["trust_cards"], true);
    assert_eq!(body["coverage"]["runtime_health"], true);
}

fn assert_control_plane_inventory_counts(body: &Value) {
    assert_eq!(body["inventory_counts"]["servers"], 1);
    assert_eq!(body["inventory_counts"]["tools"], 1);
    assert_eq!(body["inventory_counts"]["trust_cards"], 1);
    assert_eq!(body["inventory_counts"]["runtime_health"], 1);
    assert!(body["inventory_counts"]["shadow_assets"].is_u64());
    assert!(body["inventory_counts"]["shadow_high_or_critical_assets"].is_u64());
}

fn assert_control_plane_shadow_boundary(body: &Value) {
    assert_eq!(
        body["shadow_radar"]["schema_version"],
        "shadow_radar.handoff.v1"
    );
    assert_eq!(
        body["shadow_radar"]["source_report_schema"],
        "shadow_radar.v1"
    );
    assert_eq!(body["shadow_radar"]["source"], "local_passive_discovery");
    assert_eq!(body["shadow_radar"]["passive"], true);
    assert_eq!(body["shadow_radar"]["tools_invoked"], false);
    assert!(body["shadow_radar"]["control_plane_assets"].is_array());
    assert_eq!(
        body["shadow_radar"]["enterprise_boundary"]["schema_version"],
        "shadow_radar.enterprise_boundary.v1"
    );
    assert_eq!(
        body["shadow_radar"]["enterprise_boundary"]["free_core_scan"]["license_tier"],
        "free_core"
    );
    assert_eq!(
        body["shadow_radar"]["enterprise_boundary"]["free_core_scan"]["activity"],
        "passive"
    );
    let free_denied =
        body["shadow_radar"]["enterprise_boundary"]["free_core_scan"]["denied_capabilities"]
            .as_array()
            .expect("free/core denied capabilities should be an array");
    assert!(
        free_denied
            .iter()
            .any(|capability| capability.as_str() == Some("network_range_scan"))
    );
    assert!(
        free_denied
            .iter()
            .any(|capability| capability.as_str() == Some("scheduled_scan"))
    );
    assert_eq!(
        body["shadow_radar"]["enterprise_boundary"]["enterprise_scan"]["license_tier"],
        "enterprise"
    );
    assert_eq!(
        body["shadow_radar"]["enterprise_boundary"]["enterprise_scan"]["activity"],
        "passive"
    );
    let enterprise_allowed =
        body["shadow_radar"]["enterprise_boundary"]["enterprise_scan"]["allowed_capabilities"]
            .as_array()
            .expect("enterprise allowed capabilities should be an array");
    assert!(
        enterprise_allowed
            .iter()
            .any(|capability| capability.as_str() == Some("network_range_scan"))
    );
    assert!(
        enterprise_allowed
            .iter()
            .any(|capability| capability.as_str() == Some("scheduled_scan"))
    );
    assert!(
        enterprise_allowed
            .iter()
            .any(|capability| capability.as_str() == Some("fleet_scope"))
    );
    let exports = body["shadow_radar"]["enterprise_boundary"]["evidence_exports"]
        .as_array()
        .expect("enterprise evidence exports should be an array");
    assert!(exports.iter().all(|export| {
        export["requires_enterprise_license"] == true
            && export["sensitive_values_included"] == false
    }));
}

fn assert_control_plane_views(body: &Value) {
    assert_eq!(body["view"]["servers"][0]["name"], "docs");
    assert_eq!(body["view"]["tools"][0]["name"], "search_docs");
    assert_eq!(body["view"]["trust_cards"][0]["server_id"], "backend:docs");
    assert_eq!(
        body["view"]["trust_cards"][0]["schema_version"],
        "trust_card.v1"
    );
    let digest = body["view"]["trust_cards"][0]["trust_card_digest_sha256"]
        .as_str()
        .expect("trust card digest should be a string");
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert_eq!(body["view"]["runtime_health"][0]["health"], "healthy");
    assert_eq!(
        body["authorizations"]["mutate_policy"]["audit_required"],
        true
    );
    assert_eq!(body["current_limits"][0], "read_only_api");

    assert!(body["decision_queue"]["items"].is_array());
}

#[tokio::test]
async fn test_control_plane_endpoint_projects_non_admin_api_key_as_auditor() {
    let auth_config = AuthConfig {
        enabled: true,
        bearer_token: None,
        api_keys: vec![ApiKeyConfig {
            key: "auditor-key".to_string(),
            name: "auditor-client".to_string(),
            rate_limit: 0,
            backends: vec!["docs".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
        }],
        public_paths: vec!["/health".to_string()],
        client_circuit_breaker: None,
        single_user: false,
    };
    let state = make_app_state_with_auth_config(&auth_config);
    register_http_backend(&state, "docs");
    let router = create_router(state);
    let request = Request::builder()
        .method(Method::GET)
        .uri("/ui/api/control-plane")
        .header("authorization", "Bearer auditor-key")
        .body(Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(status, StatusCode::OK, "Expected 200, got: {body}");
    assert_eq!(body["route"]["read_only"], true);
    assert_eq!(body["actor"]["role"], "auditor");
    assert_eq!(body["actor"]["display_name"], "auditor-client");
    assert_eq!(body["view"]["servers"][0]["name"], "docs");
    assert_eq!(body["authorizations"]["read_inventory"]["allowed"], true);
    assert_eq!(body["authorizations"]["read_evidence"]["allowed"], true);
    assert_eq!(body["authorizations"]["mutate_policy"]["allowed"], false);
    assert_eq!(body["authorizations"]["mutate_grant"]["allowed"], false);
}

#[tokio::test]
async fn test_registry_list_returns_entries() {
    // GIVEN: a running gateway with no config_path needed (registry is static)
    let state = make_app_state(None, None);
    let router = create_router(state);

    // WHEN: GET /ui/api/registry
    let (status, body) = send_json(&router, Method::GET, "/ui/api/registry", None).await;

    // THEN: 200 with a list of built-in server entries
    assert_eq!(status, StatusCode::OK, "Expected 200, got: {body}");
    let entries = body["entries"].as_array().expect("entries must be array");
    assert!(!entries.is_empty(), "Registry should have built-in entries");
    assert!(body["total"].as_u64().unwrap_or(0) > 0);

    // Every entry should have a name field
    for entry in entries {
        assert!(entry["name"].as_str().is_some(), "Entry missing name field");
    }
}

#[tokio::test]
async fn test_registry_search_filters_results() {
    // GIVEN: a running gateway
    let state = make_app_state(None, None);
    let router = create_router(state);

    // WHEN: GET /ui/api/registry/search?q=tavily
    let (status, body) = send_json(
        &router,
        Method::GET,
        "/ui/api/registry/search?q=tavily",
        None,
    )
    .await;

    // THEN: 200 with matching results
    assert_eq!(status, StatusCode::OK, "Expected 200, got: {body}");
    let entries = body["entries"].as_array().expect("entries must be array");

    // Every returned entry name/description/category should contain "tavily"
    for entry in entries {
        let name = entry["name"].as_str().unwrap_or("").to_lowercase();
        let desc = entry["description"].as_str().unwrap_or("").to_lowercase();
        let cat = entry["category"].as_str().unwrap_or("").to_lowercase();
        assert!(
            name.contains("tavily") || desc.contains("tavily") || cat.contains("tavily"),
            "Result '{name}' does not match search term 'tavily'"
        );
    }
    // query echoed back
    assert_eq!(body["query"].as_str(), Some("tavily"));
}

// ── Backend mutation tests ────────────────────────────────────────────────────

#[tokio::test]
async fn test_add_backend_without_config_path_returns_503() {
    // GIVEN: state WITHOUT config_path (no persistence available)
    let state = make_app_state(None, None);
    let router = create_router(state);

    // WHEN: POST /ui/api/backends with a stdio command
    let (status, body) = send_json(
        &router,
        Method::POST,
        "/ui/api/backends",
        Some(json!({
            "name": "my-test-backend",
            "command": "echo hello"
        })),
    )
    .await;

    // THEN: 503 Service Unavailable (no config path to persist to)
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "Expected 503 without config_path, got: {body}"
    );
}

#[tokio::test]
async fn test_add_backend_persists_and_duplicate_returns_409() {
    // GIVEN: a temp config file so the handler can persist
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("gateway.yaml");

    // Write a minimal config
    let cfg = Config::default();
    let yaml = serde_yaml::to_string(&cfg).unwrap();
    std::fs::write(&config_path, &yaml).unwrap();

    let state = make_app_state(None, Some(config_path.clone()));
    let router = create_router(state);

    // WHEN: add a new backend
    let (status, body) = send_json(
        &router,
        Method::POST,
        "/ui/api/backends",
        Some(json!({
            "name": "integration-test-backend",
            "command": "echo hello",
            "description": "Integration test backend"
        })),
    )
    .await;

    // THEN: 201 Created
    assert_eq!(status, StatusCode::CREATED, "Expected 201, got: {body}");
    assert_eq!(body["status"], "created");
    assert_eq!(body["name"], "integration-test-backend");
    // AND: reload is null — no ReloadContext in test state (no live watcher)
    assert!(
        body["reload"].is_null(),
        "reload should be null without a live ReloadContext, got: {}",
        body["reload"]
    );

    // AND: the config file was updated
    let saved = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        saved.contains("integration-test-backend"),
        "Config file should contain new backend"
    );

    // WHEN: add the same backend again
    let (status2, body2) = send_json(
        &router,
        Method::POST,
        "/ui/api/backends",
        Some(json!({
            "name": "integration-test-backend",
            "command": "echo hello"
        })),
    )
    .await;

    // THEN: 409 Conflict
    assert_eq!(
        status2,
        StatusCode::CONFLICT,
        "Expected 409 for duplicate, got: {body2}"
    );
}

#[tokio::test]
async fn test_remove_backend_not_found_returns_404() {
    // GIVEN: a temp config file with no backends
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("gateway.yaml");
    let cfg = Config::default();
    let yaml = serde_yaml::to_string(&cfg).unwrap();
    std::fs::write(&config_path, &yaml).unwrap();

    let state = make_app_state(None, Some(config_path));
    let router = create_router(state);

    // WHEN: DELETE /ui/api/backends/nonexistent
    let (status, body) = send_json(
        &router,
        Method::DELETE,
        "/ui/api/backends/nonexistent",
        None,
    )
    .await;

    // THEN: 404 Not Found
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "Expected 404 for unknown backend, got: {body}"
    );
}

#[tokio::test]
async fn test_add_remove_backend_lifecycle() {
    // GIVEN: a temp config file
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("gateway.yaml");
    let cfg = Config::default();
    let yaml = serde_yaml::to_string(&cfg).unwrap();
    std::fs::write(&config_path, &yaml).unwrap();

    let state = make_app_state(None, Some(config_path.clone()));
    let router = create_router(state);

    // WHEN: add a backend
    let (add_status, _) = send_json(
        &router,
        Method::POST,
        "/ui/api/backends",
        Some(json!({
            "name": "lifecycle-backend",
            "command": "echo lifecycle"
        })),
    )
    .await;
    assert_eq!(add_status, StatusCode::CREATED);

    // AND: remove it
    let (del_status, _) = send_json(
        &router,
        Method::DELETE,
        "/ui/api/backends/lifecycle-backend",
        None,
    )
    .await;
    assert_eq!(del_status, StatusCode::NO_CONTENT);

    // THEN: the config file no longer contains the backend
    let saved = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        !saved.contains("lifecycle-backend"),
        "Config should not contain removed backend"
    );
}

#[tokio::test]
async fn test_patch_backend_updates_description() {
    // GIVEN: a temp config with one backend pre-populated
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("gateway.yaml");

    let mut cfg = Config::default();
    cfg.backends.insert(
        "patch-me".to_string(),
        mcp_gateway::config::BackendConfig {
            description: "Original description".to_string(),
            enabled: true,
            transport: mcp_gateway::config::TransportConfig::Stdio {
                command: "echo patch".to_string(),
                cwd: None,
                protocol_version: None,
            },
            ..Default::default()
        },
    );
    let yaml = serde_yaml::to_string(&cfg).unwrap();
    std::fs::write(&config_path, &yaml).unwrap();

    let state = make_app_state(None, Some(config_path.clone()));
    let router = create_router(state);

    // WHEN: PATCH /ui/api/backends/patch-me with a new description
    let (status, body) = send_json(
        &router,
        Method::PATCH,
        "/ui/api/backends/patch-me",
        Some(json!({ "description": "Updated description" })),
    )
    .await;

    // THEN: 200 OK
    assert_eq!(status, StatusCode::OK, "Expected 200 on PATCH, got: {body}");
    assert_eq!(body["status"], "updated");
    assert_eq!(body["name"], "patch-me");
    // AND: reload is null — no ReloadContext in test state (no live watcher)
    assert!(
        body["reload"].is_null(),
        "reload should be null without a live ReloadContext, got: {}",
        body["reload"]
    );

    // AND: config file reflects the change
    let saved = std::fs::read_to_string(&config_path).unwrap();
    assert!(
        saved.contains("Updated description"),
        "Config should contain updated description"
    );
}

#[tokio::test]
async fn test_add_backend_returns_reload_outcome_when_context_available() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("gateway.yaml");
    let cfg = Config::default();
    std::fs::write(&config_path, serde_yaml::to_string(&cfg).unwrap()).unwrap();

    let (state, _) = make_app_state_with_reload(cfg, None, config_path.clone());
    let router = create_router(Arc::clone(&state));

    let (status, body) = send_json(
        &router,
        Method::POST,
        "/ui/api/backends",
        Some(json!({
            "name": "live-reload-backend",
            "command": "echo hello"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "Expected 201, got: {body}");
    assert_eq!(body["status"], "created");
    assert_eq!(body["reload"]["restart_required"], false);
    assert!(
        body["reload"]["changes"].as_str().is_some_and(|changes| {
            changes.contains("added backends") && changes.contains("live-reload-backend")
        }),
        "expected backend reload summary, got: {body}"
    );
    assert!(
        state.backends.get("live-reload-backend").is_some(),
        "backend should be registered after live reload"
    );
}

#[tokio::test]
async fn test_reload_endpoint_without_reload_context_returns_503() {
    let state = make_app_state(None, None);
    let router = create_router(state);

    let (status, body) = send_json(&router, Method::POST, "/ui/api/reload", None).await;

    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "Expected 503 without reload context, got: {body}"
    );
    assert!(
        body["error"]
            .as_str()
            .is_some_and(|error| error.contains("Config reload is not enabled")),
        "unexpected reload-unavailable body: {body}"
    );
}

#[tokio::test]
async fn test_reload_endpoint_returns_structured_outcome_for_profile_change() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("gateway.yaml");
    let initial = Config::default();
    std::fs::write(&config_path, serde_yaml::to_string(&initial).unwrap()).unwrap();

    let (state, live_config) =
        make_app_state_with_reload(initial.clone(), None, config_path.clone());
    let router = create_router(state);

    let mut updated = initial;
    updated.routing_profiles.insert(
        "research".to_string(),
        mcp_gateway::routing_profile::RoutingProfileConfig {
            description: "Research only".to_string(),
            allow_tools: Some(vec!["search_*".to_string()]),
            ..mcp_gateway::routing_profile::RoutingProfileConfig::default()
        },
    );
    updated.default_routing_profile = "research".to_string();
    std::fs::write(&config_path, serde_yaml::to_string(&updated).unwrap()).unwrap();

    let (status, body) = send_json(&router, Method::POST, "/ui/api/reload", None).await;

    assert_eq!(status, StatusCode::OK, "Expected 200, got: {body}");
    assert_eq!(body["status"], "ok");
    // A routing-profile change is NOT applied by a reload: nothing re-reads
    // `routing_profiles` or `default_routing_profile` at request time, and
    // `apply_patch` handles backends only. This assertion previously read
    // `false`, which is what the operator was told while the change sat
    // unapplied — the defect this reporting exists to remove.
    assert_eq!(body["restart_required"], true);
    assert!(
        body["restart_reason"].is_string(),
        "a restart-required outcome must say why: {body}"
    );
    assert!(
        body["changes"]
            .as_str()
            .is_some_and(|changes| changes.contains("profiles/meta config changed")),
        "expected profiles reload summary, got: {body}"
    );
    assert_eq!(live_config.get().default_routing_profile, "research");
}

#[tokio::test]
async fn test_reload_endpoint_reports_restart_required_for_server_change() {
    let tmp = TempDir::new().unwrap();
    let config_path = tmp.path().join("gateway.yaml");
    let initial = Config::default();
    std::fs::write(&config_path, serde_yaml::to_string(&initial).unwrap()).unwrap();

    let (state, _) = make_app_state_with_reload(initial.clone(), None, config_path.clone());
    let router = create_router(state);

    let mut updated = initial;
    updated.server.port += 1;
    std::fs::write(&config_path, serde_yaml::to_string(&updated).unwrap()).unwrap();

    let (status, body) = send_json(&router, Method::POST, "/ui/api/reload", None).await;

    assert_eq!(status, StatusCode::OK, "Expected 200, got: {body}");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["restart_required"], true);
    assert_eq!(body["restart_reason"], "server_address_changed");
    assert!(
        body["changes"]
            .as_str()
            .is_some_and(|changes| changes.contains("restart required")),
        "expected restart-required summary, got: {body}"
    );
}

// ── Capability tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_capabilities_list_returns_empty_without_dirs() {
    // GIVEN: no capability directories configured
    let state = make_app_state(None, None);
    let router = create_router(state);

    // WHEN: GET /ui/api/capabilities
    let (status, body) = send_json(&router, Method::GET, "/ui/api/capabilities", None).await;

    // THEN: 200 with empty list
    assert_eq!(status, StatusCode::OK, "Expected 200, got: {body}");
    let caps = body["capabilities"].as_array().expect("capabilities array");
    assert!(caps.is_empty(), "Should be empty without dirs");
    assert_eq!(body["total"], 0);
}

#[tokio::test]
async fn test_capability_create_read_delete_lifecycle() {
    // GIVEN: a temp directory for capabilities
    let tmp = TempDir::new().unwrap();
    let cap_dir = tmp.path().to_str().unwrap().to_string();

    let state = make_app_state(Some(&cap_dir), None);
    let router = create_router(state);

    // WHEN: POST /ui/api/capabilities with YAML + name
    let (create_status, create_body) = send_json(
        &router,
        Method::POST,
        "/ui/api/capabilities",
        Some(json!({
            "yaml": VALID_YAML,
            "name": "test-cap"
        })),
    )
    .await;

    // THEN: 201 Created
    assert_eq!(
        create_status,
        StatusCode::CREATED,
        "Expected 201, got: {create_body}"
    );
    assert_eq!(create_body["status"], "created");
    assert_eq!(create_body["name"], "test-cap");

    // AND: file was written to the capability directory
    let expected_file = tmp.path().join("test-cap.yaml");
    assert!(expected_file.exists(), "YAML file should exist on disk");

    // WHEN: GET /ui/api/capabilities — should list the new capability
    let (list_status, list_body) =
        send_json(&router, Method::GET, "/ui/api/capabilities", None).await;
    assert_eq!(list_status, StatusCode::OK);
    let caps = list_body["capabilities"].as_array().unwrap();
    assert_eq!(caps.len(), 1, "Should list exactly one capability");
    assert_eq!(caps[0]["name"], "test-cap");

    // WHEN: GET /ui/api/capabilities/test-cap — returns raw YAML
    let get_req = Request::builder()
        .method(Method::GET)
        .uri("/ui/api/capabilities/test-cap")
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let get_resp = Router::clone(&router).oneshot(get_req).await.unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    let ct = get_resp
        .headers()
        .get("content-type")
        .and_then(|v: &axum::http::HeaderValue| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("yaml"),
        "Content-Type should be yaml, got: {ct}"
    );

    // WHEN: DELETE /ui/api/capabilities/test-cap
    let (del_status, del_body) = send_json(
        &router,
        Method::DELETE,
        "/ui/api/capabilities/test-cap",
        None,
    )
    .await;
    assert_eq!(
        del_status,
        StatusCode::OK,
        "Expected 200 on delete, got: {del_body}"
    );
    assert_eq!(del_body["status"], "deleted");

    // AND: file is gone from disk
    assert!(
        !expected_file.exists(),
        "YAML file should be removed from disk"
    );
}

#[tokio::test]
async fn test_capability_put_updates_content() {
    // GIVEN: a temp dir with an existing capability file
    let tmp = TempDir::new().unwrap();
    let cap_dir = tmp.path().to_str().unwrap().to_string();
    let cap_file = tmp.path().join("updatable.yaml");
    std::fs::write(&cap_file, VALID_YAML).unwrap();

    let state = make_app_state(Some(&cap_dir), None);
    let router = create_router(state);

    // WHEN: PUT /ui/api/capabilities/updatable with updated YAML
    let updated_yaml = VALID_YAML.replace(
        "Test capability for integration tests",
        "Updated description",
    );
    let (put_status, put_body) = send_raw(
        &router,
        Method::PUT,
        "/ui/api/capabilities/updatable",
        "text/yaml",
        &updated_yaml,
    )
    .await;

    // THEN: 200 OK
    assert_eq!(
        put_status,
        StatusCode::OK,
        "Expected 200 on PUT, got: {put_body}"
    );
    assert_eq!(put_body["status"], "saved");

    // AND: content was updated on disk
    let on_disk = std::fs::read_to_string(&cap_file).unwrap();
    assert!(
        on_disk.contains("Updated description"),
        "File content should be updated, got: {on_disk}"
    );
}

#[tokio::test]
async fn test_capability_path_traversal_rejected() {
    // GIVEN: any app state (no dirs needed — rejection is name-based)
    let state = make_app_state(None, None);
    let router = create_router(state);

    // WHEN: GET with names that contain characters not allowed by is_safe_name().
    // These would be path traversal attempts if used as filenames.
    // Note: names with '/' can't be tested via URL (axum routes treat '/' as path
    // separator). We test names with '.', '@', uppercase, spaces (URL-encoded), etc.
    let invalid_names = [
        "foo.bar",   // dot not allowed
        "UPPERCASE", // uppercase not allowed
        "foo%40bar", // '@' URL-encoded
        "foo%20bar", // space URL-encoded
    ];
    for name in invalid_names {
        let uri = format!("/ui/api/capabilities/{name}");
        let req = Request::builder()
            .method(Method::GET)
            .uri(&uri)
            .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = Router::clone(&router).oneshot(req).await.unwrap();

        // THEN: 400 Bad Request (invalid name — rejected by is_safe_name())
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "Expected 400 for invalid name '{name}', got: {}",
            resp.status()
        );
    }
}

#[tokio::test]
async fn test_capability_invalid_yaml_rejected_on_put() {
    // GIVEN: a temp dir
    let tmp = TempDir::new().unwrap();
    let cap_dir = tmp.path().to_str().unwrap().to_string();

    let state = make_app_state(Some(&cap_dir), None);
    let router = create_router(state);

    // WHEN: PUT with invalid YAML (unclosed bracket = parse error)
    let bad_yaml = "not: valid: yaml: [unclosed";
    let (status, body) = send_raw(
        &router,
        Method::PUT,
        "/ui/api/capabilities/test-invalid",
        "text/plain",
        bad_yaml,
    )
    .await;

    // THEN: 422 Unprocessable Entity
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 422 for invalid YAML, got: {body}"
    );
}

#[tokio::test]
async fn test_capability_not_found_returns_404() {
    // GIVEN: a temp dir with no files
    let tmp = TempDir::new().unwrap();
    let cap_dir = tmp.path().to_str().unwrap().to_string();

    let state = make_app_state(Some(&cap_dir), None);
    let router = create_router(state);

    // WHEN: GET /ui/api/capabilities/nonexistent
    let (status, body) = send_json(
        &router,
        Method::GET,
        "/ui/api/capabilities/nonexistent",
        None,
    )
    .await;

    // THEN: 404
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "Expected 404 for missing capability, got: {body}"
    );
}

// ── OpenAPI import tests ──────────────────────────────────────────────────────

/// Minimal inline `OpenAPI` 3.0 spec with two operations.
const MINIMAL_OPENAPI_SPEC: &str = r#"
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
paths:
  /users/{id}:
    get:
      operationId: getUser
      summary: Get a user by ID
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: User found
  /users:
    post:
      operationId: createUser
      summary: Create a new user
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
      responses:
        "201":
          description: User created
"#;

#[tokio::test]
async fn test_import_preview_with_inline_spec_returns_tools() {
    // GIVEN: a gateway (no config_path needed for preview)
    let state = make_app_state(None, None);
    let router = create_router(state);

    // WHEN: POST /ui/api/import/openapi/preview with inline spec
    let (status, body) = send_json(
        &router,
        Method::POST,
        "/ui/api/import/openapi/preview",
        Some(json!({ "spec": MINIMAL_OPENAPI_SPEC })),
    )
    .await;

    // THEN: 200 with a list of tools
    assert_eq!(
        status,
        StatusCode::OK,
        "Expected 200 on preview, got: {body}"
    );
    let tools = body["tools"].as_array().expect("tools must be array");
    assert!(!tools.is_empty(), "Preview should return at least one tool");

    // Each tool should have name, method, path
    for tool in tools {
        assert!(tool["name"].as_str().is_some(), "Tool missing name");
        assert!(tool["method"].as_str().is_some(), "Tool missing method");
        assert!(tool["path"].as_str().is_some(), "Tool missing path");
    }
}

#[tokio::test]
async fn test_import_inline_spec_creates_yaml_files() {
    // GIVEN: a temp dir for capability output
    let tmp = TempDir::new().unwrap();
    let cap_dir = tmp.path().to_str().unwrap().to_string();

    let state = make_app_state(Some(&cap_dir), None);
    let router = create_router(state);

    // WHEN: POST /ui/api/import/openapi (write)
    let (status, body) = send_json(
        &router,
        Method::POST,
        "/ui/api/import/openapi",
        Some(json!({ "spec": MINIMAL_OPENAPI_SPEC })),
    )
    .await;

    // THEN: 200 with imported list
    assert_eq!(
        status,
        StatusCode::OK,
        "Expected 200 on import, got: {body}"
    );
    let imported = body["imported"].as_array().expect("imported must be array");
    assert!(!imported.is_empty(), "At least one file should be imported");

    // AND: YAML files exist in the output directory
    let files: Vec<_> = std::fs::read_dir(&cap_dir)
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x == "yaml")
        })
        .collect();
    assert!(!files.is_empty(), "Import should create YAML files on disk");

    // AND: errors list is empty
    let errors = body["errors"].as_array().expect("errors must be array");
    assert!(
        errors.is_empty(),
        "Import should have no errors: {errors:?}"
    );
}

#[tokio::test]
async fn test_import_preview_rejects_both_url_and_spec() {
    // GIVEN: a gateway
    let state = make_app_state(None, None);
    let router = create_router(state);

    // WHEN: both url and spec are provided simultaneously
    let (status, body) = send_json(
        &router,
        Method::POST,
        "/ui/api/import/openapi/preview",
        Some(json!({
            "url": "https://example.com/openapi.yaml",
            "spec": MINIMAL_OPENAPI_SPEC
        })),
    )
    .await;

    // THEN: 422 Unprocessable Entity
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 422 for conflicting url+spec, got: {body}"
    );
}

#[tokio::test]
async fn test_import_preview_rejects_neither_url_nor_spec() {
    // GIVEN: a gateway
    let state = make_app_state(None, None);
    let router = create_router(state);

    // WHEN: no url and no spec in the body
    let (status, body) = send_json(
        &router,
        Method::POST,
        "/ui/api/import/openapi/preview",
        Some(json!({})),
    )
    .await;

    // THEN: 422 Unprocessable Entity
    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "Expected 422 for empty body, got: {body}"
    );
}

/// The auth-disabled anonymous identity must not reach the management API.
///
/// This is the integration-level guard for the CWE-346 fix: every test above
/// authenticates, so without this case the whole file would pass again if the
/// anonymous identity were handed admin a second time.
#[tokio::test]
async fn anonymous_is_refused_admin_endpoints() {
    let config = Config::default();
    assert!(
        !config.auth.enabled,
        "this case is about the shipped default"
    );

    let state = make_app_state_with_auth_config(&config.auth);
    let router = create_router(state);

    for uri in ["/ui/api/config", "/ui/api/registry", "/ui/api/capabilities"] {
        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{uri} must refuse an anonymous caller"
        );
    }
}

/// `/dashboard` renders backend names, tool names and call counts. It is an
/// operator view, so it follows the same rule as the rest of the management
/// surface: admin only.
#[tokio::test]
async fn anonymous_is_refused_the_dashboard() {
    let config = Config::default();
    let state = make_app_state_with_auth_config(&config.auth);
    let router = create_router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/dashboard")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // HTML, not JSON: a browser cannot attach an Authorization header to a
    // navigation, so the refusal has to tell a human what to do next.
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("text/html"),
        "expected an HTML explanation, got {content_type}"
    );
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes);
    assert!(body.contains("/ui"), "the page must point somewhere usable");
}

/// The documented split: `/dashboard` and the management endpoints refuse an
/// anonymous caller outright, while `/ui/api/status` still answers with counts
/// so health probes and status pages keep working without a credential.
#[tokio::test]
async fn anonymous_still_reads_redacted_status() {
    let config = Config::default();
    let state = make_app_state_with_auth_config(&config.auth);
    let router = create_router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/ui/api/status")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    // `backends` is not a field either view sets — the inventory is `servers`,
    // and only the admin view has it. Asserting the absence of a name nothing
    // uses is an assertion that cannot fail.
    assert!(
        body.get("servers").is_none(),
        "an anonymous caller must not receive the server inventory: {body}"
    );
    assert!(
        body.get("server_count").is_some() && body.get("healthy_count").is_some(),
        "and must still get the redacted counts, or this proves only that the \
         endpoint returned something: {body}"
    );
}

/// Three surfaces gated by something other than `.admin`, all reachable by the
/// anonymous identity used when authentication is disabled.
#[tokio::test]
async fn anonymous_is_refused_every_inventory_surface() {
    let config = Config::default();
    let state = make_app_state_with_auth_config(&config.auth);
    let router = create_router(state);

    // /api/costs has no projection model: spend per session and per API key is
    // admin data or nothing, so it refuses.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/api/costs")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "/api/costs exposes cross-tenant spend and must require admin"
    );

    // The control plane is a governance surface. Filtering the backend list was
    // not enough: the snapshot also carries policies and shadow-radar data, and
    // an assertion about one substring cannot see the rest. A caller that
    // presented no credential is refused outright.
    for uri in [
        "/ui/api/control-plane",
        "/ui/api/control-plane/grants",
        "/ui/api/control-plane/policies",
        "/ui/api/control-plane/decisions",
    ] {
        let method = if uri.ends_with("control-plane") {
            Method::GET
        } else {
            Method::POST
        };
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let response = router.clone().oneshot(req).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{uri} is a governance surface and must refuse an unauthenticated caller"
        );
    }
}

/// `/health` computed a variable named `is_admin` from a client-NAME test, so
/// any authenticated API key received full backend detail whether or not it
/// held admin.
#[tokio::test]
async fn a_non_admin_api_key_gets_the_redacted_health_view() {
    let auth = AuthConfig {
        enabled: true,
        // /health is a public path by default, so the middleware assigns the
        // "public" identity before validating any credential and the handler
        // never sees the key. Removing it is what puts the API key on this path
        // at all; without this the case passes without exercising anything.
        public_paths: vec![],
        api_keys: vec![ApiKeyConfig {
            key: "scoped-key".to_string(),
            name: "scoped".to_string(),
            rate_limit: 0,
            backends: vec![],
            allowed_tools: None,
            denied_tools: None,
            admin: false,
        }],
        ..AuthConfig::default()
    };
    let state = make_app_state_with_auth_config(&auth);
    let router = create_router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .header("authorization", "Bearer scoped-key")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    // Asserted on the redacted SHAPE, not on `backends` failing to be an array.
    // Both views put an object there — the admin view a map keyed by backend
    // name, the redacted view `{count, all_healthy}` — so `as_array().is_none()`
    // was true either way and the case passed with the `.admin` check removed.
    let backends = body["backends"]
        .as_object()
        .expect("the redacted view still carries a backends object");
    let mut keys: Vec<&str> = backends.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["all_healthy", "count"],
        "a non-admin key gets counts and nothing that names a backend: {body}"
    );
    assert!(
        body.get("capabilities").is_none(),
        "and no capability detail, which is admin-only: {body}"
    );
}

/// A browser navigating to the dashboard cannot attach an Authorization header,
/// so a token alone does not make the dashboard usable. The gateway prints a
/// one-time link; opening it exchanges the credential for a session cookie and
/// redirects, so the token never stays in the address bar or the history.
#[tokio::test]
async fn the_dashboard_bootstrap_link_opens_the_dashboard() {
    let auth = admin_auth_config();
    let state = make_app_state_with_auth_config(&auth);
    // The link carries a single-use value, NOT the admin token: a query string
    // reaches this gateway's own request log, which outlives the browser tab.
    let bootstrap = state
        .dashboard_bootstrap
        .peek()
        .expect("a fresh gateway has an unused bootstrap value");
    let router = create_router(state);

    // Step 1: the printed link carries that value once.
    //
    // Driven with connect info, because that is how the gateway serves this
    // router: both branches of `Gateway::run` use
    // `into_make_service_with_connect_info`, and redemption now reads the peer
    // address rather than the `Host` header — a header the caller writes and a
    // proxy rewrites (MIK-7257). A `oneshot` with no peer is refused on
    // purpose, so a faithful case has to supply one.
    let mut req = Request::builder()
        .method(Method::GET)
        .uri(format!("/dashboard?bootstrap={bootstrap}"))
        .header("host", "127.0.0.1:39400")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(axum::extract::ConnectInfo(
        "127.0.0.1:52344".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "the link must redirect, so the credential leaves the address bar"
    );
    let cookie = response
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        cookie.contains("HttpOnly"),
        "not readable by script: {cookie}"
    );
    assert!(
        cookie.contains("SameSite=Strict"),
        "not sent cross-site: {cookie}"
    );

    // Step 2: the browser follows the redirect carrying that cookie.
    let session = cookie.split(';').next().unwrap_or_default().to_string();
    let req = Request::builder()
        .method(Method::GET)
        .uri("/dashboard")
        .header(axum::http::header::COOKIE, session)
        .body(Body::empty())
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the dashboard must render"
    );

    // A wrong value opens nothing, and so does the right value a second time:
    // a link left in a shell history is spent.
    for value in ["not-the-value", bootstrap.as_str()] {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/dashboard?bootstrap={value}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "bootstrap value {value} must not open the dashboard"
        );
    }
}

/// The shipped starter posture, end to end: tools open, admin closed.
///
/// A config test shows the file; this shows the behaviour. The regression it
/// guards against is enabling authentication and gating the MCP endpoint with
/// it, which breaks the client the operator already configured.
#[tokio::test]
async fn the_starter_posture_keeps_tools_open_and_admin_closed() {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(ADMIN_TOKEN.to_string()),
        public_paths: vec!["/health".to_string(), "/mcp".to_string()],
        ..AuthConfig::default()
    };
    let state = make_app_state_with_auth_config(&auth);
    let router = create_router(state);

    // An MCP client with no credential still lists tools.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}).to_string(),
        ))
        .unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = String::from_utf8_lossy(&bytes).to_string();
    // The property is that AUTH does not block this path. The fixture has
    // meta-MCP off, so the handler answers with its own error; what must not
    // appear is a credential refusal.
    assert_ne!(
        status,
        StatusCode::UNAUTHORIZED,
        "auth blocked /mcp: {body}"
    );
    assert!(
        !body.contains("Authorization"),
        "the configured client must keep working with no change: {body}"
    );

    // The same caller cannot manage the gateway.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/ui/api/config")
        .body(Body::empty())
        .unwrap();
    let status = router.clone().oneshot(req).await.unwrap().status();
    assert!(
        status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN,
        "management needs the credential, got {status}"
    );

    // The credential opens management.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/ui/api/config")
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(router.oneshot(req).await.unwrap().status(), StatusCode::OK);
}

/// A public path drops the credential REQUIREMENT, not the credential.
///
/// `/mcp` is public on the starter config so ordinary tools stay open. An
/// operator presenting their admin token there must still be admin, or the
/// management tools their token pays for are unreachable.
#[tokio::test]
async fn a_credential_presented_on_a_public_path_still_counts() {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(ADMIN_TOKEN.to_string()),
        public_paths: vec!["/health".to_string(), "/mcp".to_string()],
        ..AuthConfig::default()
    };
    let state = make_app_state_with_auth_config(&auth);
    let router = create_router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/health")
        .header("authorization", format!("Bearer {ADMIN_TOKEN}"))
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    // The redacted view is `{"count": N, "all_healthy": bool}`. Anything else
    // is the admin view, which is what the credential must still buy.
    assert!(
        body["backends"].get("count").is_none(),
        "an admin credential must still grant the admin view, got the redacted one: {body}"
    );
}

/// The printed dashboard link works only from the machine running the gateway.
///
/// The value is printed to the operator's terminal on the assumption that
/// seeing it means being at the machine. Declaring a `public_url` breaks that:
/// the origin gate then admits the published hostname by design, so anyone who
/// obtains the printed value — shipped logs, shared scrollback, a screenshot —
/// could exchange it for an admin session from anywhere. Printing was already
/// gated on a loopback bind; redemption was not.
#[tokio::test]
async fn a_bootstrap_link_is_not_redeemable_through_a_published_host() {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some("admin-token".to_string()),
        ..AuthConfig::default()
    };
    let state = make_app_state_with_auth_config(&auth);
    let bootstrap = state
        .dashboard_bootstrap
        .peek()
        .expect("a bootstrap value is issued at startup");
    let router = create_router(state);

    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/dashboard?bootstrap={bootstrap}"))
        .header("host", "gw.example.com")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(req).await.unwrap();

    // Refused, and which layer refuses depends on the configuration. With no
    // `public_url` declared, as here, the origin gate rejects the unknown Host
    // first and answers 403. With one declared the gate admits that hostname by
    // design, and the loopback restriction on redemption is what refuses,
    // answering 401. Asserting "refused" rather than one code keeps the case
    // honest about which control is doing the work.
    assert!(
        response.status() == StatusCode::UNAUTHORIZED || response.status() == StatusCode::FORBIDDEN,
        "a published Host must not mint an admin session from the printed \
         link, got {}",
        response.status()
    );
}

/// A reload does not change request-time authentication — the invariant the
/// reload posture refusal rests on.
///
/// `network_bind_refusal` is evaluated on a reload against the config that will
/// be IN FORCE: the running snapshot, with only live-applied fields overlaid
/// from the file. That is only safe while `auth` is NOT one of the live fields.
/// It is not, today — `AppState::auth_config` is built once and `config_reload`
/// never touches it — but nothing enforced it, and every unit case in that suite
/// reads `auth` from the running config and would keep agreeing with itself if
/// this changed. This is the test that fails on that day.
///
/// Wired the way production is, because a first draft was not and could not have
/// failed: it gave the router a hard-coded auth config and reloaded a DIFFERENT
/// `LiveConfig` from the one the router held, so no reload could have reached
/// the request path even if `auth` were live. Here one startup config builds the
/// router's authentication, and one `Arc<LiveConfig>` is shared by the router
/// and the reload — the arrangement `Gateway::run` builds.
///
/// See docs/design/unauthenticated-network-posture.md, Decision C.
#[tokio::test]
async fn a_reload_does_not_change_request_time_authentication() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.yaml");

    // GIVEN: one startup config, authentication ON, and it is what both the
    // router's auth state and the shared live snapshot are built from.
    let startup = Config {
        auth: admin_auth_config(),
        ..Config::default()
    };
    std::fs::write(
        &config_path,
        "auth:\n  enabled: true\n  bearer_token: \"test-admin-token\"\n",
    )
    .unwrap();

    let live_config = Arc::new(LiveConfig::new(startup.clone()));
    let mut state = make_app_state(None, Some(config_path.clone()));
    {
        let s = Arc::get_mut(&mut state).expect("test AppState should be uniquely owned");
        s.auth_config = Arc::new(ResolvedAuthConfig::from_config(&startup.auth));
        s.live_config = Arc::clone(&live_config);
    }
    let router = create_router(Arc::clone(&state));

    let unauthenticated = || {
        Request::builder()
            .method(Method::GET)
            .uri("/ui/api/config")
            .body(Body::empty())
            .unwrap()
    };

    // Positive control: without it, a router that never refuses anything would
    // pass the assertion below for the wrong reason.
    let before = router
        .clone()
        .oneshot(unauthenticated())
        .await
        .unwrap()
        .status();
    assert!(
        before == StatusCode::UNAUTHORIZED || before == StatusCode::FORBIDDEN,
        "the fixture does not require a credential, so this test proves nothing: {before}"
    );

    // WHEN: the file turns authentication OFF and is reloaded through the live
    // snapshot the router reads. Nothing here refuses — no public URL is
    // declared — so the reload applies and publishes.
    std::fs::write(&config_path, "auth:\n  enabled: false\n").unwrap();
    let ctx = ReloadContext::new(
        config_path,
        Arc::clone(&live_config),
        Arc::clone(&state.backends),
        startup.failsafe.clone(),
        startup.meta_mcp.cache_ttl,
    );
    ctx.reload_outcome().await.expect("the reload failed");
    assert!(
        !live_config.get().auth.enabled,
        "the reload did not publish, so this proves nothing about what a \
         published change reaches"
    );

    // THEN: the request path is unmoved. The published snapshot says auth is
    // off; what is in force is what the process started with.
    let after = router
        .clone()
        .oneshot(unauthenticated())
        .await
        .unwrap()
        .status();
    assert_eq!(
        after, before,
        "a reload changed request-time authentication — the reload posture \
         overlay reads `auth` from the running config and is now unsound"
    );
}

/// A leaked link cannot be redeemed through a proxy (MIK-7257).
///
/// The check used to read `Host`, which the caller writes and a reverse proxy
/// rewrites — nginx's default for a bare `proxy_pass` is the upstream address.
/// A request forwarded from anywhere therefore arrived carrying a loopback
/// `Host` and was granted an admin session. Both cases below present exactly
/// that: a perfect loopback `Host` and a valid, unspent bootstrap value.
#[tokio::test]
async fn a_forwarded_request_cannot_redeem_the_dashboard_link() {
    for (label, peer, forwarded) in [
        ("straight off the network", "203.0.113.9:41000", false),
        ("through a proxy on this machine", "127.0.0.1:52344", true),
    ] {
        let auth = admin_auth_config();
        let state = make_app_state_with_auth_config(&auth);
        let bootstrap = state
            .dashboard_bootstrap
            .peek()
            .expect("a fresh gateway has an unused bootstrap value");
        let router = create_router(state);

        let mut builder = Request::builder()
            .method(Method::GET)
            .uri(format!("/dashboard?bootstrap={bootstrap}"))
            // The loopback Host the old check trusted.
            .header("host", "127.0.0.1:39400");
        if forwarded {
            builder = builder.header("x-forwarded-for", "203.0.113.9");
        }
        let mut req = builder.body(Body::empty()).unwrap();
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            peer.parse::<std::net::SocketAddr>().unwrap(),
        ));

        let response = router.clone().oneshot(req).await.unwrap();
        assert_ne!(
            response.status(),
            StatusCode::SEE_OTHER,
            "a request {label} redeemed the link and was handed an admin session"
        );
    }
}
