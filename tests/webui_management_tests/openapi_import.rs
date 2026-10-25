// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Importing capabilities from an `OpenAPI` document.

use super::*;

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
    let (state, _store) = make_app_state(None, None).await;
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

    let (state, _store) = make_app_state(Some(&cap_dir), None).await;
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
    let (state, _store) = make_app_state(None, None).await;
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
    let (state, _store) = make_app_state(None, None).await;
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

/// MIK-8838 AC4: the spec preview carries the same `preview` block as a
/// server preview, and each tool a class from the generated capability's
/// `metadata.read_only` (GET and HEAD read, everything else write).
#[tokio::test]
async fn the_spec_preview_has_the_preview_block_and_a_class_per_tool() {
    let (state, _store) = make_app_state(None, None).await;
    let router = create_router(state);
    let (status, body) = send_json(
        &router,
        Method::POST,
        "/ui/api/import/openapi/preview",
        Some(json!({ "spec": MINIMAL_OPENAPI_SPEC })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["preview"]["transport"], "openapi");
    assert_eq!(
        body["preview"]["url"],
        Value::Null,
        "an inline spec has no URL"
    );
    assert_eq!(
        body["preview"]["publisher"],
        json!({"verified": false, "source": null})
    );
    let tools = body["tools"].as_array().expect("tools");
    let by_method = |method: &str| {
        tools
            .iter()
            .find(|t| t["method"] == method)
            .unwrap_or_else(|| panic!("a {method} tool: {body}"))
            .clone()
    };
    assert_eq!(by_method("GET")["class"], "read");
    assert_eq!(by_method("POST")["class"], "write");
    for tool in tools {
        assert_eq!(tool["class_source"], "inferred", "{tool}");
        assert!(
            tool["path"].as_str().is_some(),
            "existing fields stay: {tool}"
        );
    }
}

/// MIK-8838 AC4: a fetched spec's URL is echoed without its query, so a
/// query-authenticated spec still fetches and its key never comes back.
#[tokio::test]
async fn the_spec_preview_echoes_the_url_without_its_query() {
    let app = axum::Router::new().fallback(|| async { MINIMAL_OPENAPI_SPEC });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let (mut state, _store) = make_app_state(None, None).await;
    Arc::get_mut(&mut state)
        .expect("test AppState should be uniquely owned")
        .ssrf_protection = false;
    let router = create_router(state);
    let url = format!("http://{address}/spec.yaml?api_key=s3cr3t-value");
    let (status, body) = send_json(
        &router,
        Method::POST,
        "/ui/api/import/openapi/preview",
        Some(json!({ "url": url })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["preview"]["url"],
        format!("http://{address}/spec.yaml")
    );
    assert!(!body.to_string().contains("s3cr3t-value"), "{body}");
}

/// MIK-8838: a fetched spec is counted while it is read; one byte over the
/// 32 MiB spec budget is a 502 naming the budget, for preview and import.
#[tokio::test]
async fn a_spec_over_its_budget_is_a_502_naming_the_budget() {
    const SPEC_BUDGET: usize = 32 * 1024 * 1024;
    let app = axum::Router::new().fallback(|| async { "x".repeat(SPEC_BUDGET + 1) });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let (mut state, _store) = make_app_state(None, None).await;
    Arc::get_mut(&mut state)
        .expect("test AppState should be uniquely owned")
        .ssrf_protection = false;
    let router = create_router(state);
    for route in ["/ui/api/import/openapi/preview", "/ui/api/import/openapi"] {
        let (status, body) = send_json(
            &router,
            Method::POST,
            route,
            Some(json!({ "url": format!("http://{address}/spec.yaml") })),
        )
        .await;
        let message = body["error"].as_str().unwrap_or_default();
        let shown: String = message.chars().take(200).collect();
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{route}: {shown}");
        assert!(
            message.contains("32 MiB budget"),
            "{route} names the budget: {shown}"
        );
    }
}
