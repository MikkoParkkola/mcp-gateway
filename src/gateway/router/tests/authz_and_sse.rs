// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tool-target authorization, SSRF checks and the SSE endpoints.

use super::*;
use pretty_assertions::assert_eq;

async fn test_router_app_state_with_ssrf(
    ssrf_protection: bool,
    trust_configured_backends: bool,
) -> (Arc<AppState>, tempfile::TempDir) {
    let backends = Arc::new(BackendRegistry::new());
    let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&backends)));
    let streaming_config = StreamingConfig::default();
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        streaming_config.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(&AuthConfig::default()));
    let agent_auth = AgentAuthState::new(false, Arc::new(AgentRegistry::new()));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("gateway key generation"));

    let subscriptions = test_subscriptions(&auth_config, None, &agent_auth);
    let (task_service, task_executor, store_dir) =
        test_task_runtime(&subscriptions, &meta_mcp).await;

    let state = Arc::new(AppState {
        session_lifecycle: None,
        continuation: Arc::new(crate::protocol::continuation::ContinuationState::new()),
        env: None,
        backends,
        meta_mcp,
        meta_mcp_enabled: true,
        multiplexer,
        proxy_manager,
        streaming_config,
        auth_config,
        key_server: None,
        tool_policy: Arc::new(crate::security::ToolPolicy::default()),
        mtls_policy: Arc::new(MtlsPolicy::from_config(&MtlsConfig::default())),
        sanitize_input: false,
        ssrf_protection,
        trust_configured_backends,
        inflight: Arc::new(tokio::sync::Semaphore::new(8)),
        agent_auth,
        gateway_key_pair,
        capability_dirs: Vec::new(),
        config_path: None,
        #[cfg(feature = "firewall")]
        firewall: None,
        agent_identity_config: crate::config::AgentIdentityConfig::default(),
        control_plane_store: None,
        control_plane_base: None,
        live_config: std::sync::Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
        export_status: None,
        transparency_log: None,
        dashboard_bootstrap: std::sync::Arc::new(crate::gateway::auth::DashboardBootstrap::new()),
        tasks: task_service,
        task_executor,
        subscriptions,
    });
    (state, store_dir)
}

#[tokio::test]
async fn meta_mcp_gateway_execute_enforces_api_key_tool_scope() {
    let (state, _store) = test_router_app_state_with_auth(&scoped_auth_config(false)).await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", "Bearer scoped-key")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "gateway_execute",
                    "arguments": {
                        "tool": "demo:blocked_tool",
                        "arguments": {}
                    }
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"]["code"], -32600);
    assert!(
        json["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("allowlist"))
    );
}

#[tokio::test]
async fn meta_mcp_management_tool_requires_admin_client() {
    let (state, _store) = test_router_app_state_with_auth(&scoped_auth_config(false)).await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", "Bearer scoped-key")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "gateway_reload_config",
                    "arguments": {}
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("admin access"))
    );
}

// Async only because the fixture opens a real durable task store, which is an
// async open. The assertions below are unchanged.
#[tokio::test]
async fn authorize_tool_target_enforces_agent_scope() {
    let (state, _store) = test_router_app_state().await;
    let identity = OAuthAgentIdentity {
        quota_principal: None,
        client_id: "agent-a".to_string(),
        agent_name: "Agent A".to_string(),
        scopes: vec![
            crate::gateway::oauth::Scope::parse("tools:demo:allowed_tool:execute").unwrap(),
        ],
        raw_scopes: vec!["tools:demo:allowed_tool:execute".to_string()],
    };
    let args = json!({});

    let result = authorize_tool_target(
        state.as_ref(),
        None,
        Some(&identity),
        None,
        ToolTarget {
            server: "demo",
            tool: "blocked_tool",
            arguments: &args,
        },
    );

    assert!(
        result.is_ok(),
        "agent auth disabled should not enforce scopes"
    );

    let (enabled_state, _enabled_store) = test_router_app_state_with_agent_auth_enabled().await;
    let result = authorize_tool_target(
        enabled_state.as_ref(),
        None,
        Some(&identity),
        None,
        ToolTarget {
            server: "demo",
            tool: "blocked_tool",
            arguments: &args,
        },
    );

    assert!(result.is_err());
}

#[test]
fn surfaced_tool_calls_resolve_to_backend_authorization_target() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new())).with_surfaced_tools(vec![
        SurfacedToolConfig {
            server: "demo".to_string(),
            tool: "pinned_tool".to_string(),
        },
    ]);

    let targets = backend_tool_targets_for_call(&meta, "pinned_tool", &json!({"x": 1}));

    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].server, "demo");
    assert_eq!(targets[0].tool, "pinned_tool");
}

#[tokio::test]
async fn authorize_tool_target_blocks_ssrf_when_protection_enabled() {
    let (state, _store) = test_router_app_state_with_ssrf(true, false).await;
    let _ = state
        .backends
        .register(http_backend_at("loopback", "http://127.0.0.1:9000/mcp"));
    let args = json!({});

    let result = authorize_tool_target(
        state.as_ref(),
        None,
        None,
        None,
        ToolTarget {
            server: "loopback",
            tool: "echo",
            arguments: &args,
        },
    );

    let err = result.expect_err("loopback backend must be blocked when SSRF protection is on");
    assert!(
        err.message.contains("SSRF blocked"),
        "error should reference SSRF, got: {}",
        err.message
    );
}

#[tokio::test]
async fn authorize_tool_target_allows_public_host_when_ssrf_protection_enabled() {
    let (state, _store) = test_router_app_state_with_ssrf(true, false).await;
    let _ = state
        .backends
        .register(http_backend_at("public", "https://gateway-public.test/mcp"));
    let args = json!({});

    let result = authorize_tool_target(
        state.as_ref(),
        None,
        None,
        None,
        ToolTarget {
            server: "public",
            tool: "echo",
            arguments: &args,
        },
    );

    assert!(
        result.is_ok(),
        "public hostname must pass SSRF gate, got: {}",
        result.err().map(|e| e.message).unwrap_or_default()
    );
}

#[tokio::test]
async fn authorize_tool_target_skips_ssrf_when_trust_configured_backends_enabled() {
    let (state, _store) = test_router_app_state_with_ssrf(true, true).await;
    let _ = state
        .backends
        .register(http_backend_at("loopback", "http://127.0.0.1:9000/mcp"));
    let args = json!({});

    let result = authorize_tool_target(
        state.as_ref(),
        None,
        None,
        None,
        ToolTarget {
            server: "loopback",
            tool: "echo",
            arguments: &args,
        },
    );

    assert!(
        result.is_ok(),
        "trust_configured_backends must bypass SSRF re-check at proxy time, got: {}",
        result.err().map(|e| e.message).unwrap_or_default()
    );
}

#[tokio::test]
async fn sse_handler_rejects_non_sse_accept_with_jsonrpc_error_shape() {
    let (state, _store) = test_router_app_state().await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("accept", "application/json")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_ACCEPTABLE);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["error"]["code"], -32600);
    assert_eq!(
        json["error"]["message"],
        "Must accept text/event-stream for SSE notifications"
    );
    assert_eq!(json["id"], Value::Null);
}

#[tokio::test]
async fn sse_handler_streaming_disabled_returns_jsonrpc_internal_shape() {
    let streaming_config = StreamingConfig {
        enabled: false,
        ..StreamingConfig::default()
    };

    let (state, _store) = test_router_app_state_with_streaming(streaming_config).await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("accept", "text/event-stream")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let object = json.as_object().unwrap();
    assert!(object.contains_key("id"));
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], Value::Null);
    assert_eq!(json["error"]["code"], -32600);
    assert_eq!(
        json["error"]["message"],
        "Streaming not enabled. Use POST to send JSON-RPC requests to /mcp"
    );
}

#[tokio::test]
async fn sse_deprecated_endpoint_returns_jsonrpc_error_with_migration_data() {
    let (state, _store) = test_router_app_state().await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/sse")
        .body(axum::body::Body::empty())
        .unwrap();

    let response = router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::GONE);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let object = json.as_object().unwrap();
    assert!(object.contains_key("id"));
    assert_eq!(json["jsonrpc"], "2.0");
    assert_eq!(json["id"], Value::Null);
    assert_eq!(json["error"]["code"], -32600);
    assert_eq!(
        json["error"]["message"],
        "SSE transport is deprecated. Use Streamable HTTP (POST /mcp) instead."
    );
    assert_eq!(
        json["error"]["data"]["migration"],
        "In settings.json, change: \"type\": \"sse\" -> \"type\": \"http\" and \"url\": \"http://localhost:39400/sse\" -> \"url\": \"http://localhost:39400/mcp\""
    );
    assert_eq!(
        json["error"]["data"]["spec"],
        "https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http"
    );
}
