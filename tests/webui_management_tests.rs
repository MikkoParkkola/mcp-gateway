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

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

use axum::Router;
use mcp_gateway::backend::BackendRegistry;
use mcp_gateway::config::Config;
use mcp_gateway::config_reload::{LiveConfig, ReloadContext};
use mcp_gateway::gateway::auth::ResolvedAuthConfig;
use mcp_gateway::gateway::oauth::{AgentAuthState, AgentRegistry, GatewayKeyPair};
use mcp_gateway::gateway::proxy::ProxyManager;
use mcp_gateway::gateway::streaming::NotificationMultiplexer;
use mcp_gateway::gateway::test_helpers::{AppState, MetaMcp, create_router};
use mcp_gateway::mtls::{MtlsConfig, MtlsPolicy};
use mcp_gateway::security::{ToolPolicy, ToolPolicyConfig};

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Build a minimal `AppState` suitable for unit-testing the UI management
/// endpoints.  Auth is disabled so `is_admin()` returns `true` for all
/// requests (anonymous == admin when auth is off).
fn make_app_state(cap_dir: Option<&str>, config_path: Option<std::path::PathBuf>) -> Arc<AppState> {
    let config = Config::default();
    let backends = Arc::new(BackendRegistry::new());
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        config.streaming.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));

    // Disabled auth — all callers become "anonymous" which maps to admin.
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(&config.auth));

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
        inflight,
        agent_auth,
        gateway_key_pair,
        capability_dirs,
        config_path,
        #[cfg(feature = "firewall")]
        firewall: None,
    })
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
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(&config.auth));
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
            inflight,
            agent_auth,
            gateway_key_pair,
            capability_dirs,
            config_path: Some(config_path),
            #[cfg(feature = "firewall")]
            firewall: None,
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

    let mut builder = Request::builder().method(method).uri(uri);
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

// ── Registry tests ────────────────────────────────────────────────────────────

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
    assert_eq!(body["restart_required"], false);
    assert!(
        body["restart_reason"].is_null(),
        "expected no restart reason: {body}"
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
