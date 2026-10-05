// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Capabilities shipped in the repository load and validate.

use super::*;

fn load_repo_capability(relative_path: &str) -> CapabilityDefinition {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    let yaml = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_yaml::from_str(&yaml)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

#[allow(clippy::needless_pass_by_value)]
fn assert_linear_capability_shape(
    relative_path: &str,
    expected_response_path: &str,
    raw_after_response_path: serde_json::Value,
    expected_shaped: serde_json::Value,
) {
    let cap = load_repo_capability(relative_path);
    let provider = cap
        .providers
        .get("primary")
        .unwrap_or_else(|| panic!("{relative_path} missing primary provider"));

    assert_eq!(
        provider.config.response_path.as_deref(),
        Some(expected_response_path),
        "{relative_path} should keep the GraphQL extraction path wired",
    );

    let pipeline = crate::transform::TransformPipeline::compile(&cap.transform);
    let shaped = pipeline.apply(raw_after_response_path);
    assert_eq!(
        shaped, expected_shaped,
        "{relative_path} should shape payloads to its declared output schema",
    );

    let validation = crate::capability::validate_output(&shaped, &cap.schema.output);
    assert!(
        validation.is_valid(),
        "{}",
        validation.format_error(&cap.schema.output)
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn linear_capability_payload_shapes_match_declared_output_schemas() {
    assert_linear_capability_shape(
        "capabilities/linear/linear_create_issue.yaml",
        "data.issueCreate",
        serde_json::json!({
            "success": true,
            "issue": {
                "id": "issue-1",
                "identifier": "MIK-1",
                "title": "Created issue",
                "url": "https://linear.app/example/issue/MIK-1/test",
                "state": { "name": "Backlog" },
                "team": { "key": "MIK" },
                "priority": 4,
                "priorityLabel": "Low"
            }
        }),
        serde_json::json!({
            "issue": {
                "id": "issue-1",
                "identifier": "MIK-1",
                "title": "Created issue",
                "url": "https://linear.app/example/issue/MIK-1/test",
                "state": { "name": "Backlog" },
                "team": { "key": "MIK" },
                "priority": 4,
                "priorityLabel": "Low"
            }
        }),
    );

    assert_linear_capability_shape(
        "capabilities/linear/linear_update_issue.yaml",
        "data.issueUpdate",
        serde_json::json!({
            "success": true,
            "issue": {
                "id": "issue-1",
                "identifier": "MIK-1",
                "title": "Updated issue",
                "url": "https://linear.app/example/issue/MIK-1/test",
                "state": { "name": "Canceled" },
                "priority": 4,
                "priorityLabel": "Low",
                "assignee": { "name": "alice" }
            }
        }),
        serde_json::json!({
            "issue": {
                "id": "issue-1",
                "identifier": "MIK-1",
                "title": "Updated issue",
                "url": "https://linear.app/example/issue/MIK-1/test",
                "state": { "name": "Canceled" },
                "priority": 4,
                "priorityLabel": "Low",
                "assignee": { "name": "alice" }
            }
        }),
    );

    assert_linear_capability_shape(
        "capabilities/linear/linear_add_comment.yaml",
        "data.commentCreate",
        serde_json::json!({
            "success": true,
            "comment": {
                "id": "comment-1",
                "body": "ok",
                "createdAt": "2026-04-29T10:13:21.226Z",
                "user": { "name": "alice@example.com" },
                "issue": { "identifier": "MIK-1", "title": "Validation" }
            }
        }),
        serde_json::json!({
            "comment": {
                "id": "comment-1",
                "body": "ok",
                "createdAt": "2026-04-29T10:13:21.226Z",
                "user": { "name": "alice@example.com" },
                "issue": { "identifier": "MIK-1", "title": "Validation" }
            }
        }),
    );

    assert_linear_capability_shape(
        "capabilities/linear/linear_get_issue.yaml",
        "data.searchIssues",
        serde_json::json!({
            "nodes": [{
                "id": "issue-1",
                "identifier": "MIK-1",
                "title": "Validation",
                "comments": { "nodes": [] },
                "children": { "nodes": [] }
            }]
        }),
        serde_json::json!({
            "issue": {
                "id": "issue-1",
                "identifier": "MIK-1",
                "title": "Validation",
                "comments": { "nodes": [] },
                "children": { "nodes": [] }
            }
        }),
    );

    assert_linear_capability_shape(
        "capabilities/linear/linear_search_issues.yaml",
        "data.searchIssues",
        serde_json::json!({
            "nodes": [{
                "id": "issue-1",
                "identifier": "MIK-1",
                "title": "Validation",
                "url": "https://linear.app/example/issue/MIK-1/test"
            }],
            "pageInfo": { "hasNextPage": false, "endCursor": "cursor-1" }
        }),
        serde_json::json!({
            "issues": [{
                "id": "issue-1",
                "identifier": "MIK-1",
                "title": "Validation",
                "url": "https://linear.app/example/issue/MIK-1/test"
            }]
        }),
    );

    assert_linear_capability_shape(
        "capabilities/linear/linear_get_teams.yaml",
        "data.teams",
        serde_json::json!({
            "nodes": [{
                "id": "team-1",
                "name": "Alice",
                "key": "MIK",
                "description": null,
                "states": { "nodes": [] },
                "labels": { "nodes": [] }
            }]
        }),
        serde_json::json!({
            "teams": [{
                "id": "team-1",
                "name": "Alice",
                "key": "MIK",
                "description": null,
                "states": { "nodes": [] },
                "labels": { "nodes": [] }
            }]
        }),
    );

    assert_linear_capability_shape(
        "capabilities/linear/linear_list_projects.yaml",
        "data.projects",
        serde_json::json!({
            "nodes": [{
                "id": "project-1",
                "name": "Gateway",
                "description": "Validation",
                "state": "planned",
                "progress": 0.5,
                "completedAt": null,
                "startDate": null,
                "targetDate": null,
                "teams": { "nodes": [] },
                "lead": null,
                "projectMilestones": { "nodes": [] },
                "url": "https://linear.app/example/project/test"
            }]
        }),
        serde_json::json!({
            "projects": [{
                "id": "project-1",
                "name": "Gateway",
                "description": "Validation",
                "state": "planned",
                "progress": 0.5,
                "completedAt": null,
                "startDate": null,
                "targetDate": null,
                "teams": { "nodes": [] },
                "lead": null,
                "projectMilestones": { "nodes": [] },
                "url": "https://linear.app/example/project/test"
            }]
        }),
    );

    assert_linear_capability_shape(
        "capabilities/linear/linear_viewer.yaml",
        "data.viewer",
        serde_json::json!({
            "id": "user-1",
            "name": "alice@example.com",
            "email": "alice@example.com",
            "displayName": "alice",
            "active": true,
            "admin": true,
            "url": "https://linear.app/example/profiles/alice"
        }),
        serde_json::json!({
            "id": "user-1",
            "name": "alice@example.com",
            "email": "alice@example.com",
            "displayName": "alice"
        }),
    );
}

// ── MIK-5877: capability projection specs validate against realistic payloads ──

#[test]
fn linear_get_issue_projection_spec_maps_canonical_fields() {
    let cap = load_repo_capability("capabilities/linear/linear_get_issue.yaml");
    let spec = cap
        .projection
        .as_ref()
        .expect("linear_get_issue must declare a projection spec");

    // Realistic payload AFTER the capability's transform (project nodes[0] ->
    // rename to `issue`) — that is what the projection engine sees at dispatch.
    let payload = serde_json::json!({
        "issue": {
            "id": "uuid-1",
            "identifier": "ENG-123",
            "title": "Fix the bug",
            "assignee": {
                "id": "user-1",
                "name": "alice",
                "displayName": "Alice Example",
                "email": "alice@x.test"
            },
            "createdAt": "2026-01-01T00:00:00Z",
            "updatedAt": "2026-01-02T00:00:00Z",
            "url": "https://linear.app/x/issue/ENG-123"
        }
    });

    let out = crate::projection::project(&payload, spec);

    assert_eq!(out["subject"]["id"], serde_json::json!("ENG-123"));
    assert_eq!(out["subject"]["title"], serde_json::json!("Fix the bug"));
    assert_eq!(out["actor"]["id"], serde_json::json!("user-1"));
    assert_eq!(out["actor"]["handle"], serde_json::json!("alice"));
    assert_eq!(
        out["actor"]["display_name"],
        serde_json::json!("Alice Example")
    );
    assert_eq!(out["actor"]["email"], serde_json::json!("alice@x.test"));
    assert_eq!(
        out["env_time"]["created"],
        serde_json::json!("2026-01-01T00:00:00Z")
    );
    assert_eq!(
        out["env_time"]["updated"],
        serde_json::json!("2026-01-02T00:00:00Z")
    );
    assert_eq!(
        out["url"]["href"],
        serde_json::json!("https://linear.app/x/issue/ENG-123")
    );
    // _raw always preserves the original payload verbatim.
    assert_eq!(out["_raw"], payload);
}

#[test]
fn github_get_repo_projection_spec_maps_canonical_fields() {
    let cap = load_repo_capability("capabilities/knowledge/github_get_repo.yaml");
    let spec = cap
        .projection
        .as_ref()
        .expect("github_get_repo must declare a projection spec");

    // Realistic GitHub REST /repos/{owner}/{repo} response (no transform block,
    // so fields are top-level).
    let payload = serde_json::json!({
        "id": 123_456,
        "name": "mcp-gateway",
        "full_name": "MikkoParkkola/mcp-gateway",
        "owner": {
            "login": "MikkoParkkola",
            "id": 999,
            "html_url": "https://github.com/MikkoParkkola"
        },
        "description": "Universal MCP Gateway",
        "html_url": "https://github.com/MikkoParkkola/mcp-gateway",
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "stargazers_count": 42
    });

    let out = crate::projection::project(&payload, spec);

    assert_eq!(out["subject"]["id"], serde_json::json!("123456"));
    assert_eq!(
        out["subject"]["title"],
        serde_json::json!("MikkoParkkola/mcp-gateway")
    );
    assert_eq!(out["actor"]["id"], serde_json::json!("999"));
    assert_eq!(out["actor"]["handle"], serde_json::json!("MikkoParkkola"));
    assert_eq!(
        out["actor"]["display_name"],
        serde_json::json!("MikkoParkkola")
    );
    assert_eq!(
        out["url"]["href"],
        serde_json::json!("https://github.com/MikkoParkkola/mcp-gateway")
    );
    assert_eq!(
        out["url"]["label"],
        serde_json::json!("MikkoParkkola/mcp-gateway")
    );
    assert_eq!(
        out["env_time"]["created"],
        serde_json::json!("2025-01-01T00:00:00Z")
    );
    assert_eq!(
        out["env_time"]["updated"],
        serde_json::json!("2026-01-01T00:00:00Z")
    );
    assert_eq!(
        out["body"]["text"],
        serde_json::json!("Universal MCP Gateway")
    );
    assert_eq!(out["_raw"], payload);
}
