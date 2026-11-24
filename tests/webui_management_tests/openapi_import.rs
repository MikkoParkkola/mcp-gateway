// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Importing capabilities from an `OpenAPI` document.

use std::path::Path;

use mcp_gateway::capability::OpenApiConverter;
use mcp_gateway::gateway::test_helpers::name_taken;

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

/// The spec preview carries the same `preview` block as a
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
    // No server to ask, so no reported identity; the key is there all the same.
    assert!(
        body["preview"]
            .as_object()
            .is_some_and(|p| p.get("package") == Some(&Value::Null)),
        "{body}"
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

/// A fetched spec's URL is echoed without its query, so a
/// query-authenticated spec still fetches and its key never comes back.
#[tokio::test]
async fn the_spec_preview_echoes_the_url_without_its_query() {
    let app = axum::Router::new().fallback(|| async { MINIMAL_OPENAPI_SPEC });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let (state, _store) = make_app_state(None, None).await;
    // The flag applies from the published config (ADR-023).
    let mut config = (*state.live_config.get()).clone();
    config.security.ssrf_protection = false;
    state.live_config.set(config);
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

/// A fetched spec is counted while it is read; one byte over the
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
    let (state, _store) = make_app_state(None, None).await;
    // The flag applies from the published config (ADR-023).
    let mut config = (*state.live_config.get()).clone();
    config.security.ssrf_protection = false;
    state.live_config.set(config);
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

// ── An import never replaces a capability file ───────────────────────────────

/// Two read operations: `listUsers` (file `listusers.yaml`) and `getUser`.
const USERS_SPEC: &str = r#"
openapi: "3.0.0"
info:
  title: Users
  version: "1.0"
paths:
  /users:
    get:
      operationId: listUsers
      responses:
        "200":
          description: ok
  /users/{id}:
    get:
      operationId: getUser
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      responses:
        "200":
          description: ok
"#;

/// An operator's own `listusers.yaml`, which no import may touch.
const KEPT: &[u8] = b"# the operator's own capability\nname: listusers\n";

/// A capability directory holding [`KEPT`] as `listusers.yaml`.
fn dir_with_listusers() -> TempDir {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join("listusers.yaml"), KEPT).unwrap();
    dir
}

/// The file names in `dir`, sorted.
fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// A router whose capability directories are `dirs`, in that order, and the
/// task store it holds.
async fn router_over(dirs: &[&Path]) -> (Router, TempDir) {
    let (mut state, store) = make_app_state(None, None).await;
    Arc::get_mut(&mut state)
        .expect("test AppState should be uniquely owned")
        .capability_dirs = dirs
        .iter()
        .map(|dir| dir.to_str().expect("utf-8 tempdir").to_string())
        .collect();
    (create_router(state), store)
}

async fn import(router: &Router, body: Value) -> (StatusCode, Value) {
    send_json(router, Method::POST, "/ui/api/import/openapi", Some(body)).await
}

/// The `errors` entry for a tool refused because its file is there.
fn refused(name: &str) -> Value {
    json!(format!("{name}: {}", name_taken(name)))
}

/// `listusers.yaml` is still the operator's own.
fn assert_kept(dir: &Path) {
    let now = std::fs::read(dir.join("listusers.yaml")).unwrap();
    assert_eq!(now, KEPT, "the existing listusers.yaml was changed");
}

/// IMPOW.1, the UI route: the clashing tool is refused and named, its file
/// keeps its bytes, and the other tool is still written.
#[tokio::test]
async fn impow1_an_import_keeps_an_existing_file_and_writes_the_rest() {
    let dir = dir_with_listusers();
    let (router, _store) = router_over(&[dir.path()]).await;

    let (status, body) = import(&router, json!({ "spec": USERS_SPEC })).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["imported"], json!(["getuser.yaml"]), "{body}");
    assert_eq!(body["errors"], json!([refused("listusers")]), "{body}");
    assert_kept(dir.path());
    assert_eq!(names_in(dir.path()), ["getuser.yaml", "listusers.yaml"]);
}

/// IMPOW.1: every selected tool refused is a conflict, not a server failure.
/// The selection names the file name the converter gives, `listusers`.
#[tokio::test]
async fn impow1_an_import_whose_every_tool_is_taken_is_a_409() {
    let dir = dir_with_listusers();
    let (router, _store) = router_over(&[dir.path()]).await;

    let body = json!({ "spec": USERS_SPEC, "selected_tools": ["listusers"] });
    let (status, body) = import(&router, body).await;

    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["imported"], json!([]), "{body}");
    assert_eq!(body["errors"], json!([refused("listusers")]), "{body}");
    assert_kept(dir.path());
    assert_eq!(names_in(dir.path()), ["listusers.yaml"]);
}

/// IMPOW.1, status edge: nothing selected is 200 and writes nothing, as
/// before, even beside an existing file.
#[tokio::test]
async fn impow1_an_import_with_no_tool_selected_is_200_and_writes_nothing() {
    let dir = dir_with_listusers();
    let (router, _store) = router_over(&[dir.path()]).await;

    let body = json!({ "spec": USERS_SPEC, "selected_tools": [] });
    let (status, body) = import(&router, body).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["imported"], json!([]), "{body}");
    assert_eq!(body["errors"], json!([]), "{body}");
    assert_kept(dir.path());
    assert_eq!(names_in(dir.path()), ["listusers.yaml"]);
}

/// IMPOW.1, status edge: a refusal beside a write the file system fails is
/// still a 500, as any failed write is. The failing write is a file name no
/// file system takes (256 letters), so nothing is pre-created for it.
#[tokio::test]
async fn impow1_a_taken_name_beside_a_failed_write_is_a_500() {
    let dir = dir_with_listusers();
    let (router, _store) = router_over(&[dir.path()]).await;
    let long = "a".repeat(256);
    let spec = format!(
        "{USERS_SPEC}  /long:\n    get:\n      operationId: {long}\n      responses:\n        \"200\":\n          description: ok\n"
    );

    let body = json!({ "spec": spec, "selected_tools": ["listusers", long] });
    let (status, body) = import(&router, body).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["imported"], json!([]), "{body}");
    let errors = body["errors"].as_array().expect("errors");
    assert_eq!(errors.len(), 2, "{body}");
    assert!(errors.contains(&refused("listusers")), "{body}");
    assert_kept(dir.path());
    assert_eq!(names_in(dir.path()), ["listusers.yaml"]);
}

/// IMPOW.1: the gateway loads every capability directory, so a name taken in
/// the second one is refused too, and nothing lands in the first.
#[tokio::test]
async fn impow1_a_name_taken_in_a_second_directory_is_refused() {
    let first = TempDir::new().unwrap();
    let second = dir_with_listusers();
    let (router, _store) = router_over(&[first.path(), second.path()]).await;

    let body = json!({ "spec": USERS_SPEC, "selected_tools": ["listusers"] });
    let (status, body) = import(&router, body).await;

    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["errors"], json!([refused("listusers")]), "{body}");
    assert!(names_in(first.path()).is_empty(), "{body}");
    assert_kept(second.path());
}

/// IMPOW.1, `cap import`: the clashing file keeps its bytes, the refusal is
/// on stderr, the other tool is written, and the command exits 1; into a
/// fresh directory it exits 0.
#[test]
fn impow1_cap_import_keeps_an_existing_file_and_exits_1() {
    let work = TempDir::new().unwrap();
    let spec = work.path().join("users.yaml");
    std::fs::write(&spec, USERS_SPEC).unwrap();
    let run = |out: &Path| {
        crate::gateway_bin::run_cli(
            &[
                "cap",
                "import",
                spec.to_str().expect("utf-8 path"),
                "--output",
                out.to_str().expect("utf-8 path"),
            ],
            &[],
            None,
        )
    };

    let dir = dir_with_listusers();
    let out = run(dir.path());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains(&name_taken("listusers")), "{stderr}");
    // The summary counts what was written, not what was generated.
    assert!(stdout.contains("Imported 1 tools"), "{stdout}");
    assert!(stderr.contains("1 tools could not be written"), "{stderr}");
    assert_kept(dir.path());
    assert_eq!(names_in(dir.path()), ["getuser.yaml", "listusers.yaml"]);

    let fresh = TempDir::new().unwrap();
    let out = run(fresh.path());
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(stdout.contains("Imported 2 tools"), "{stdout}");
    assert!(!stderr.contains("could not be written"), "{stderr}");
    assert_eq!(names_in(fresh.path()), ["getuser.yaml", "listusers.yaml"]);
}

/// IMPOW.2: two operations of one document whose names format the same
/// (`listUsers`, `ListUsers`): one is written, the other refused, the name
/// listed once, and the file is exactly one operation's conversion.
#[tokio::test]
async fn impow2_two_operations_with_one_file_name_write_one_of_them() {
    const SPEC: &str = r#"
openapi: "3.0.0"
info:
  title: Users
  version: "1.0"
paths:
  /b:
    get:
      operationId: listUsers
      responses:
        "200":
          description: ok
  /a:
    get:
      operationId: ListUsers
      responses:
        "200":
          description: ok
"#;
    let candidates: Vec<String> = OpenApiConverter::new()
        .convert_string(SPEC)
        .expect("the document converts")
        .into_iter()
        .filter(|cap| cap.name == "listusers")
        .map(|cap| cap.yaml)
        .collect();
    assert_eq!(candidates.len(), 2, "both operations convert to listusers");
    assert_ne!(candidates[0], candidates[1], "the two conversions differ");
    let dir = TempDir::new().unwrap();
    let (router, _store) = router_over(&[dir.path()]).await;

    let (status, body) = import(&router, json!({ "spec": SPEC })).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["imported"], json!(["listusers.yaml"]), "{body}");
    assert_eq!(body["errors"], json!([refused("listusers")]), "{body}");
    let written = std::fs::read_to_string(dir.path().join("listusers.yaml")).unwrap();
    assert!(candidates.contains(&written), "a mix: {written}");
}

/// IMPOW.3: with no clash, an import answers and writes as before.
#[tokio::test]
async fn impow3_an_import_with_no_clash_answers_as_before() {
    let dir = TempDir::new().unwrap();
    let (router, _store) = router_over(&[dir.path()]).await;

    let (status, body) = import(&router, json!({ "spec": USERS_SPEC })).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({
            "imported": ["getuser.yaml", "listusers.yaml"],
            "skipped": [],
            "errors": [],
        })
    );
    for cap in OpenApiConverter::new().convert_string(USERS_SPEC).unwrap() {
        let written = std::fs::read_to_string(dir.path().join(format!("{}.yaml", cap.name)));
        assert_eq!(written.unwrap(), cap.yaml, "{}", cap.name);
    }
}

/// IMPOW.1, the writer's own refusal through the UI: a dangling link at the
/// name passes the directory check (it follows links) but the exclusive
/// create refuses it, and that refusal is a taken name (409), not a failure.
#[cfg(unix)]
#[tokio::test]
async fn impow1_a_name_held_by_a_dangling_link_is_taken_not_a_failure() {
    let dir = TempDir::new().unwrap();
    let link = dir.path().join("listusers.yaml");
    std::os::unix::fs::symlink(dir.path().join("nowhere"), &link).unwrap();
    let (router, _store) = router_over(&[dir.path()]).await;

    let body = json!({ "spec": USERS_SPEC, "selected_tools": ["listusers"] });
    let (status, body) = import(&router, body).await;

    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["errors"], json!([refused("listusers")]), "{body}");
    assert_eq!(
        std::fs::read_link(&link).unwrap(),
        dir.path().join("nowhere")
    );
    assert_eq!(names_in(dir.path()), ["listusers.yaml"]);
}
