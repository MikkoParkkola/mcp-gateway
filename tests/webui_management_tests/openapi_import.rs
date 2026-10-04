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
