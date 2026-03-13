//! Capability YAML file management API endpoints.
//!
//! Provides CRUD operations for capability YAML files stored in the configured
//! capability directories.  All write operations perform YAML validation before
//! persisting.  Path traversal attacks are prevented by restricting file names
//! to `[a-z0-9_-]`.
//!
//! # Endpoints
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | GET | `/ui/api/capabilities` | List all capability YAML files |
//! | GET | `/ui/api/capabilities/:name` | Return raw YAML content |
//! | PUT | `/ui/api/capabilities/:name` | Validate + write YAML |
//! | POST | `/ui/api/capabilities` | Create from template or provided YAML |
//! | DELETE | `/ui/api/capabilities/:name` | Delete a capability file |

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Extension, Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::super::auth::AuthenticatedClient;
use super::super::router::AppState;
use super::is_admin;

// ── Public router builder ─────────────────────────────────────────────────────

/// Register capability management routes on the provided router.
pub fn capabilities_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/ui/api/capabilities",
            get(list_capabilities).post(create_capability),
        )
        .route(
            "/ui/api/capabilities/{name}",
            get(get_capability)
                .put(put_capability)
                .delete(delete_capability),
        )
}

// ── Template YAML ─────────────────────────────────────────────────────────────

const CAPABILITY_TEMPLATE: &str = r#"fulcrum: "1.0"
name: my_capability
description: A brief description of what this capability does.

schema:
  input:
    type: object
    properties:
      query:
        type: string
        description: Input parameter description
    required:
      - query
  output:
    type: object
    properties:
      result:
        type: string
        description: Output result

providers:
  primary:
    service: rest
    cost_per_call: 0
    timeout: 10
    config:
      base_url: https://api.example.com
      path: /v1/endpoint
      method: GET
      headers:
        Authorization: "Bearer {env.API_KEY}"

cache:
  strategy: ttl
  ttl: 60

auth:
  required: true
  type: bearer
  key: env:API_KEY

metadata:
  category: utility
  tags:
    - example
  cost_category: free
  read_only: true
"#;

// ── Name validation ───────────────────────────────────────────────────────────

/// Validate that a capability name contains only safe characters.
///
/// Allowed: lowercase letters, digits, underscore, hyphen.
/// Rejected: slashes, dots, backslashes, null bytes, or anything else that
/// could be used in a path traversal attack.
fn is_safe_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Return a 400 rejection response for invalid capability names.
fn bad_name(name: &str) -> (StatusCode, Json<Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "invalid_name",
            "message": format!(
                "Capability name '{name}' is invalid. Names must match [a-z0-9_-] and be ≤128 chars."
            ),
        })),
    )
}

// ── Directory helpers ─────────────────────────────────────────────────────────

/// Find the YAML file for `name` across all configured capability directories.
///
/// Returns `(path, dir_index)` of the first match found (`.yaml` preferred
/// over `.yml`).
fn find_capability_file(
    dirs: &[String],
    name: &str,
) -> Option<PathBuf> {
    for dir in dirs {
        for ext in &["yaml", "yml"] {
            let candidate = Path::new(dir).join(format!("{name}.{ext}"));
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Return the primary write directory: first entry in `dirs` that exists, or
/// the first entry unconditionally (caller will create it if missing).
fn primary_write_dir(dirs: &[String]) -> Option<&str> {
    // Prefer an existing directory
    for dir in dirs {
        if Path::new(dir).is_dir() {
            return Some(dir.as_str());
        }
    }
    // Fall back to first configured directory
    dirs.first().map(String::as_str)
}

// ── Response types ────────────────────────────────────────────────────────────

/// Metadata entry returned by `GET /ui/api/capabilities`.
#[derive(Debug, Serialize)]
pub struct CapabilityMeta {
    /// Bare file name without extension (e.g. `github_create_issue`).
    pub name: String,
    /// Number of `providers` keys parsed from the YAML.
    pub tool_count: usize,
    /// File size in bytes.
    pub size_bytes: u64,
    /// First non-empty `description` field, if present.
    pub description: Option<String>,
    /// Absolute path to the file on disk.
    pub path: String,
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

/// Count tools in a YAML capability file.
///
/// We count the number of top-level keys in `providers` (named) plus entries
/// in `providers` that are arrays (fallback).  A simpler heuristic — just
/// returning 1 if the file parses — is also acceptable, but extracting the
/// actual provider count gives more useful metadata.
fn count_tools(yaml: &str) -> usize {
    // Use serde_yaml to deserialize as generic Value and count providers keys.
    let Ok(val) = serde_yaml::from_str::<serde_yaml::Value>(yaml) else {
        return 0;
    };
    if let serde_yaml::Value::Mapping(map) = &val {
        if let Some(providers) = map.get("providers") {
            match providers {
                serde_yaml::Value::Mapping(m) => return m.len().max(1),
                serde_yaml::Value::Sequence(s) => return s.len().max(1),
                _ => {}
            }
        }
    }
    // Treat as a single-tool capability if parsing succeeds.
    usize::from(val != serde_yaml::Value::Null)
}

/// Extract the `description` field from raw YAML without full deserialize.
fn extract_description(yaml: &str) -> Option<String> {
    let val: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;
    val.get("description")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /ui/api/capabilities` — list all YAML files with metadata.
pub async fn list_capabilities(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
) -> impl IntoResponse {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Admin authentication required"})),
        )
            .into_response();
    }

    let dirs = state.capability_dirs.as_slice();
    let mut entries: Vec<CapabilityMeta> = Vec::new();

    for dir in dirs {
        let dir_path = Path::new(dir.as_str());
        if !dir_path.is_dir() {
            continue;
        }

        let Ok(read_dir) = std::fs::read_dir(dir_path) else {
            continue;
        };

        for entry in read_dir.flatten() {
            let path = entry.path();
            let Some(ext) = path.extension() else {
                continue;
            };
            if ext != "yaml" && ext != "yml" {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };

            let size_bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
            let yaml = std::fs::read_to_string(&path).unwrap_or_default();
            let tool_count = count_tools(&yaml);
            let description = extract_description(&yaml);

            entries.push(CapabilityMeta {
                name: stem.to_owned(),
                tool_count,
                size_bytes,
                description,
                path: path.to_string_lossy().into_owned(),
            });
        }
    }

    // Stable order by name
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    Json(json!({
        "capabilities": entries,
        "total": entries.len(),
        "directories": dirs,
    }))
    .into_response()
}

/// `GET /ui/api/capabilities/:name` — return raw YAML content.
pub async fn get_capability(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Admin authentication required"})),
        )
            .into_response();
    }

    if !is_safe_name(&name) {
        return bad_name(&name).into_response();
    }

    let dirs = state.capability_dirs.as_slice();
    let Some(path) = find_capability_file(dirs, &name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_found",
                "message": format!("Capability '{name}' not found"),
            })),
        )
            .into_response();
    };

    match tokio::fs::read_to_string(&path).await {
        Ok(content) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/yaml; charset=utf-8")],
            content,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "read_error",
                "message": format!("Failed to read capability file: {e}"),
            })),
        )
            .into_response(),
    }
}

/// `PUT /ui/api/capabilities/:name` — validate YAML and write to disk.
pub async fn put_capability(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    AxumPath(name): AxumPath<String>,
    body: String,
) -> impl IntoResponse {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Admin authentication required"})),
        )
            .into_response();
    }

    if !is_safe_name(&name) {
        return bad_name(&name).into_response();
    }

    // Validate YAML structure before writing.
    let validation = validate_yaml_body(&body);
    if let Some(err) = validation {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "validation_error",
                "message": err,
            })),
        )
            .into_response();
    }

    let dirs = state.capability_dirs.as_slice();

    // Find existing file, or choose primary write dir.
    let target_path = find_capability_file(dirs, &name).unwrap_or_else(|| {
        let dir = primary_write_dir(dirs).unwrap_or("capabilities");
        Path::new(dir).join(format!("{name}.yaml"))
    });

    // Ensure parent directory exists.
    if let Some(parent) = target_path.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "io_error",
                    "message": format!("Failed to create directory: {e}"),
                })),
            )
                .into_response();
        }
    }

    match tokio::fs::write(&target_path, body.as_bytes()).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "status": "saved",
                "path": target_path.to_string_lossy(),
                "name": name,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "write_error",
                "message": format!("Failed to write capability file: {e}"),
            })),
        )
            .into_response(),
    }
}

/// Request body for `POST /ui/api/capabilities`.
#[derive(Debug, Deserialize, Default)]
pub struct CreateCapabilityBody {
    /// Optional YAML content.  When absent a template is returned.
    pub yaml: Option<String>,
    /// Desired file name (without extension).  Required when `yaml` is provided.
    pub name: Option<String>,
}

/// `POST /ui/api/capabilities` — create a new capability.
///
/// - No body (or empty `yaml`): returns the template YAML with 200.
/// - Body with `yaml` + `name`: validates and writes; returns 201 on success.
///
/// # Panics
///
/// Does not panic; the `unwrap()` on `yaml` is guarded by the `is_empty` check above.
pub async fn create_capability(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    body: Option<Json<CreateCapabilityBody>>,
) -> impl IntoResponse {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Admin authentication required"})),
        )
            .into_response();
    }

    let Json(req) = body.unwrap_or_default();

    // No YAML supplied → return template
    let is_empty = req.yaml.as_deref().is_none_or(str::is_empty);
    if is_empty {
        return (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "text/yaml; charset=utf-8")],
            CAPABILITY_TEMPLATE.to_owned(),
        )
            .into_response();
    }

    let yaml = req.yaml.unwrap_or_default();
    let Some(name) = req.name else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "missing_name",
                "message": "Field 'name' is required when providing 'yaml'",
            })),
        )
            .into_response();
    };

    if !is_safe_name(&name) {
        return bad_name(&name).into_response();
    }

    // Validate YAML
    if let Some(err) = validate_yaml_body(&yaml) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "error": "validation_error",
                "message": err,
            })),
        )
            .into_response();
    }

    let dirs = state.capability_dirs.as_slice();

    // Conflict check
    if find_capability_file(dirs, &name).is_some() {
        return (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "already_exists",
                "message": format!("Capability '{name}' already exists. Use PUT to update."),
            })),
        )
            .into_response();
    }

    let dir = primary_write_dir(dirs).unwrap_or("capabilities");
    let target_path = Path::new(dir).join(format!("{name}.yaml"));

    if let Some(parent) = target_path.parent() {
        if let Err(e) = tokio::fs::create_dir_all(parent).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "io_error",
                    "message": format!("Failed to create directory: {e}"),
                })),
            )
                .into_response();
        }
    }

    match tokio::fs::write(&target_path, yaml.as_bytes()).await {
        Ok(()) => (
            StatusCode::CREATED,
            Json(json!({
                "status": "created",
                "path": target_path.to_string_lossy(),
                "name": name,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "write_error",
                "message": format!("Failed to write capability file: {e}"),
            })),
        )
            .into_response(),
    }
}

/// `DELETE /ui/api/capabilities/:name` — remove a capability YAML file.
pub async fn delete_capability(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Admin authentication required"})),
        )
            .into_response();
    }

    if !is_safe_name(&name) {
        return bad_name(&name).into_response();
    }

    let dirs = state.capability_dirs.as_slice();
    let Some(path) = find_capability_file(dirs, &name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "not_found",
                "message": format!("Capability '{name}' not found"),
            })),
        )
            .into_response();
    };

    match tokio::fs::remove_file(&path).await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "status": "deleted",
                "name": name,
                "path": path.to_string_lossy(),
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": "delete_error",
                "message": format!("Failed to delete capability file: {e}"),
            })),
        )
            .into_response(),
    }
}

// ── YAML validation ───────────────────────────────────────────────────────────

/// Validate YAML content for capability definitions.
///
/// Returns `Some(error_message)` on failure, `None` on success.
fn validate_yaml_body(yaml: &str) -> Option<String> {
    if yaml.trim().is_empty() {
        return Some("YAML content must not be empty".to_owned());
    }

    // 1. Parse as generic YAML to catch syntax errors.
    let val: serde_yaml::Value = match serde_yaml::from_str(yaml) {
        Ok(v) => v,
        Err(e) => return Some(format!("YAML syntax error: {e}")),
    };

    // 2. Must be a mapping at the top level.
    let serde_yaml::Value::Mapping(ref map) = val else {
        return Some("YAML must be a mapping (key-value document)".to_owned());
    };

    // 3. Attempt to deserialize into CapabilityDefinition.
    match crate::capability::parse_capability(yaml) {
        Ok(cap) => {
            // 4. Run structural validate_capability check.
            if let Err(e) = crate::capability::validate_capability(&cap) {
                return Some(format!("Capability validation error: {e}"));
            }

            // 5. Run AX-rules structural validator.
            let issues = crate::capability::validate_capability_definition(&cap, None);
            let errors: Vec<String> = issues
                .iter()
                .filter(|i| i.severity == crate::capability::IssueSeverity::Error)
                .map(|i| format!("[{}] {}", i.code, i.message))
                .collect();

            if !errors.is_empty() {
                return Some(format!("Structural errors:\n{}", errors.join("\n")));
            }

            None
        }
        Err(e) => Some(format!("Capability parse error: {e}")),
    };

    // 6. Basic structure checks: `name` key must be present.
    if !map.contains_key("name") {
        return Some("Missing required field: 'name'".to_owned());
    }

    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── is_safe_name ──────────────────────────────────────────────────────────

    #[test]
    fn safe_name_accepts_lowercase_alphanumeric_hyphen_underscore() {
        assert!(is_safe_name("my-tool"));
        assert!(is_safe_name("github_create_issue"));
        assert!(is_safe_name("tool123"));
        assert!(is_safe_name("a"));
    }

    #[test]
    fn safe_name_rejects_path_traversal_patterns() {
        // Classic path traversal
        assert!(!is_safe_name("../etc/passwd"));
        assert!(!is_safe_name("../../secrets"));
        assert!(!is_safe_name("foo/bar"));
        assert!(!is_safe_name("foo\\bar"));
        assert!(!is_safe_name(".hidden"));
        assert!(!is_safe_name("foo.yaml"));
    }

    #[test]
    fn safe_name_rejects_uppercase_and_special_chars() {
        assert!(!is_safe_name("MyTool"));
        assert!(!is_safe_name("tool name"));
        assert!(!is_safe_name("tool!"));
        assert!(!is_safe_name("tool@example"));
        assert!(!is_safe_name("<script>"));
    }

    #[test]
    fn safe_name_rejects_empty_and_too_long() {
        assert!(!is_safe_name(""));
        assert!(!is_safe_name(&"a".repeat(129)));
    }

    #[test]
    fn safe_name_accepts_max_length_128() {
        let name = "a".repeat(128);
        assert!(is_safe_name(&name));
    }

    #[test]
    fn safe_name_rejects_null_bytes() {
        assert!(!is_safe_name("foo\0bar"));
    }

    // ── validate_yaml_body ────────────────────────────────────────────────────

    #[test]
    fn validate_yaml_body_rejects_empty() {
        assert!(validate_yaml_body("").is_some());
        assert!(validate_yaml_body("   ").is_some());
    }

    #[test]
    fn validate_yaml_body_rejects_syntax_errors() {
        let bad = "name: foo\n  bad indent\n::broken";
        assert!(validate_yaml_body(bad).is_some());
    }

    #[test]
    fn validate_yaml_body_accepts_valid_capability() {
        let yaml = r#"
fulcrum: "1.0"
name: test_tool
description: A test capability
providers:
  primary:
    service: rest
    config:
      base_url: https://api.example.com
      path: /test
"#;
        // parse_capability may warn but should not error on this minimal input
        // (validate_capability requires providers.primary which is present)
        let result = validate_yaml_body(yaml);
        assert!(
            result.is_none(),
            "Expected no error, got: {:?}",
            result
        );
    }

    #[test]
    fn validate_yaml_body_requires_name_key() {
        let yaml = "description: no name here\n";
        let result = validate_yaml_body(yaml);
        assert!(result.is_some());
    }

    // ── count_tools ───────────────────────────────────────────────────────────

    #[test]
    fn count_tools_returns_zero_for_invalid_yaml() {
        // A document that is syntactically unparseable (bad indentation / tab char)
        let bad = "key:\n\t- broken\n  - [unterminated";
        assert_eq!(count_tools(bad), 0);
    }

    #[test]
    fn count_tools_returns_one_for_single_provider() {
        let yaml = r#"
name: t
providers:
  primary:
    service: rest
"#;
        assert_eq!(count_tools(yaml), 1);
    }

    #[test]
    fn count_tools_counts_named_providers() {
        let yaml = r#"
name: t
providers:
  primary:
    service: rest
  secondary:
    service: rest
"#;
        assert_eq!(count_tools(yaml), 2);
    }

    // ── extract_description ───────────────────────────────────────────────────

    #[test]
    fn extract_description_returns_none_when_absent() {
        let yaml = "name: foo\n";
        assert_eq!(extract_description(yaml), None);
    }

    #[test]
    fn extract_description_returns_value_when_present() {
        let yaml = "name: foo\ndescription: Does something useful.\n";
        assert_eq!(
            extract_description(yaml),
            Some("Does something useful.".to_owned())
        );
    }

    // ── find_capability_file ──────────────────────────────────────────────────

    #[test]
    fn find_capability_file_returns_none_when_no_dirs() {
        let result = find_capability_file(&[], "my-tool");
        assert!(result.is_none());
    }

    #[test]
    fn find_capability_file_returns_none_for_missing_file() {
        let result = find_capability_file(&["/nonexistent/dir".to_owned()], "my-tool");
        assert!(result.is_none());
    }
}
