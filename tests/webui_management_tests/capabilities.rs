// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capability listing and management.

use super::*;

// ── Capability tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_capabilities_list_returns_empty_without_dirs() {
    // GIVEN: no capability directories configured
    let (state, _store) = make_app_state(None, None).await;
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

    let (state, _store) = make_app_state(Some(&cap_dir), None).await;
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
    write_owner_only(&cap_file, VALID_YAML).unwrap();

    let (state, _store) = make_app_state(Some(&cap_dir), None).await;
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
    let (state, _store) = make_app_state(None, None).await;
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

    let (state, _store) = make_app_state(Some(&cap_dir), None).await;
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

    let (state, _store) = make_app_state(Some(&cap_dir), None).await;
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
