// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The embedded page, the backend registry and the control-plane views.

use super::*;

#[tokio::test]
async fn test_webui_embeds_control_plane_read_only_page() {
    let (state, _store) = make_app_state(None, None).await;
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
    let (state, _store) = make_app_state(None, None).await;
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
        api_keys: vec![
            serde_json::from_value(serde_json::json!({
                "key_sha256": mcp_gateway::config::api_key_digest_spec(b"auditor-key"),
                "name": "auditor-client", "backends": ["docs"], "admin": false
            }))
            .expect("api key fixture"),
        ],
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    };
    let (state, _store) = make_app_state_with_auth_config(&auth_config).await;
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
    let (state, _store) = make_app_state(None, None).await;
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
    let (state, _store) = make_app_state(None, None).await;
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
