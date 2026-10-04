// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Adding, updating and removing backends through the management API.

use super::*;

// ── Backend mutation tests ────────────────────────────────────────────────────

#[tokio::test]
async fn test_add_backend_without_config_path_returns_503() {
    // GIVEN: state WITHOUT config_path (no persistence available)
    let (state, _store) = make_app_state(None, None).await;
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
    write_owner_only(&config_path, &yaml).unwrap();

    let (state, _store) = make_app_state(None, Some(config_path.clone())).await;
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
    write_owner_only(&config_path, &yaml).unwrap();

    let (state, _store) = make_app_state(None, Some(config_path)).await;
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
    write_owner_only(&config_path, &yaml).unwrap();

    let (state, _store) = make_app_state(None, Some(config_path.clone())).await;
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
    write_owner_only(&config_path, &yaml).unwrap();

    let (state, _store) = make_app_state(None, Some(config_path.clone())).await;
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
    write_owner_only(&config_path, serde_yaml::to_string(&cfg).unwrap()).unwrap();

    let (state, _, _store) = make_app_state_with_reload(cfg, None, config_path.clone()).await;
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
    let (state, _store) = make_app_state(None, None).await;
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
    write_owner_only(&config_path, serde_yaml::to_string(&initial).unwrap()).unwrap();

    let (state, live_config, _store) =
        make_app_state_with_reload(initial.clone(), None, config_path.clone()).await;
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
    write_owner_only(&config_path, serde_yaml::to_string(&updated).unwrap()).unwrap();

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
    write_owner_only(&config_path, serde_yaml::to_string(&initial).unwrap()).unwrap();

    let (state, _, _store) =
        make_app_state_with_reload(initial.clone(), None, config_path.clone()).await;
    let router = create_router(state);

    let mut updated = initial;
    updated.server.port += 1;
    write_owner_only(&config_path, serde_yaml::to_string(&updated).unwrap()).unwrap();

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
