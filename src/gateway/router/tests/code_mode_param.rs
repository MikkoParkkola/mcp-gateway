// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The per-connection code mode URL override.

use super::*;
use pretty_assertions::assert_eq;

async fn test_router_app_state_with_code_mode(enabled: bool) -> (Arc<AppState>, tempfile::TempDir) {
    let backends = Arc::new(BackendRegistry::new());
    let meta_mcp = Arc::new(MetaMcp::new(Arc::clone(&backends)).with_code_mode(enabled));
    let streaming_config = StreamingConfig::default();
    let multiplexer = Arc::new(NotificationMultiplexer::new(
        Arc::clone(&backends),
        streaming_config.clone(),
    ));
    let proxy_manager = Arc::new(ProxyManager::new(Arc::clone(&multiplexer)));
    let auth_config = Arc::new(ResolvedAuthConfig::from_config(&AuthConfig::default()));
    let agent_auth = AgentAuthState::new(false, Arc::new(AgentRegistry::new()));
    let gateway_key_pair = Arc::new(GatewayKeyPair::generate().expect("gateway key generation"));

    let subscriptions = test_subscriptions(&auth_config, None);
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
        ssrf_protection: false,
        trust_configured_backends: false,
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

// =====================================================================
// ?codemode=search_and_execute per-connection URL override (issue #146)
// =====================================================================

#[tokio::test]
async fn tools_list_without_codemode_param_returns_standard_meta_tools() {
    // GIVEN: Code Mode disabled in config, no URL param
    let (state, _store) = test_router_app_state_with_code_mode(false).await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list"
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let tools = json["result"]["tools"].as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();

    // Standard mode must NOT include gateway_search / gateway_execute as the
    // only tools; it includes the full meta-tool set.
    assert!(
        !names.contains(&"gateway_search") || tools.len() > 2,
        "Standard mode should not return exactly the two code-mode tools; got: {names:?}"
    );
    assert!(
        !names.contains(&"gateway_execute") || tools.len() > 2,
        "Standard mode should not return exactly the two code-mode tools; got: {names:?}"
    );
}

#[tokio::test]
async fn tools_list_with_codemode_param_activates_code_mode_per_connection() {
    // GIVEN: Code Mode disabled in config, but ?codemode=search_and_execute in URL
    let (state, _store) = test_router_app_state_with_code_mode(false).await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp?codemode=search_and_execute")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let tools = json["result"]["tools"].as_array().unwrap();
    // Code Mode always returns exactly two tools: gateway_search and gateway_execute
    assert_eq!(
        tools.len(),
        2,
        "Code Mode must return exactly 2 tools; got: {}",
        tools.len()
    );
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(
        names.contains(&"gateway_search"),
        "gateway_search must be present"
    );
    assert!(
        names.contains(&"gateway_execute"),
        "gateway_execute must be present"
    );
}

#[tokio::test]
async fn tools_list_with_wrong_codemode_value_ignores_param() {
    // GIVEN: Code Mode disabled, URL has ?codemode=wrong_value
    let (state, _store) = test_router_app_state_with_code_mode(false).await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp?codemode=wrong_value")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/list"
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let tools = json["result"]["tools"].as_array().unwrap();
    // Should NOT be Code Mode — wrong value is ignored, standard tools returned
    assert!(
        tools.len() != 2
            || !tools.iter().all(|t| matches!(
                t["name"].as_str().unwrap_or(""),
                "gateway_search" | "gateway_execute"
            )),
        "Wrong codemode value should not activate Code Mode"
    );
}

#[tokio::test]
async fn tools_list_static_code_mode_unaffected_by_absent_param() {
    // GIVEN: Code Mode enabled in static config, no URL param
    let (state, _store) = test_router_app_state_with_code_mode(true).await;
    let router = create_router(state);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/list"
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    let tools = json["result"]["tools"].as_array().unwrap();
    assert_eq!(
        tools.len(),
        2,
        "Static Code Mode must always return exactly 2 tools"
    );
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"gateway_search"));
    assert!(names.contains(&"gateway_execute"));
}

async fn post_mcp(state: &Arc<AppState>, uri: &str, body: &Value) -> Value {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// MIK-7974.URL.1: a caller that turned Code Mode on with the URL parameter
/// sees only `gateway_search` and `gateway_execute`, so a failed
/// `gateway_execute` names `gateway_search`, not `gateway_list_tools`.
#[tokio::test]
async fn a_codemode_param_caller_gets_code_mode_recovery_hints() {
    let (state, _store) = test_router_app_state_with_code_mode(false).await;
    let call = json!({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "gateway_execute",
                   "arguments": {"tool": "absent:missing", "arguments": {}}}
    });
    // Over HTTP the dispatch answer, hint included, rides in the tool
    // result's text as JSON.
    let hint = |answer: &Value| {
        let text = answer["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("no tool result in {answer}"));
        let inner: Value = serde_json::from_str(text).expect("the tool result is JSON");
        inner["recovery"]["suggest"]
            .as_str()
            .unwrap_or_else(|| panic!("no recovery hint in {answer}"))
            .to_owned()
    };
    // Control: without the parameter the caller is on the standard surface.
    let standard = hint(&post_mcp(&state, "/mcp", &call).await);
    assert!(standard.contains("`gateway_list_tools`"), "{standard}");

    let code_mode = hint(&post_mcp(&state, "/mcp?codemode=search_and_execute", &call).await);
    assert!(
        code_mode.contains("`gateway_search`") && !code_mode.contains("gateway_list_tools"),
        "URL.1: {code_mode}"
    );
    // The tool the hint names is one this caller's own listing shows.
    let list = json!({"jsonrpc": "2.0", "id": 6, "method": "tools/list"});
    let listed = post_mcp(&state, "/mcp?codemode=search_and_execute", &list).await;
    let names: Vec<&str> = listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(names.contains(&"gateway_search"), "{names:?}");
}
