// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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
//! | POST | `/ui/api/capabilities/:name/validate` | Validate only; writes nothing |

use crate::gateway::routes;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Extension, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::super::auth::AuthenticatedClient;
use super::super::router::AppState;
use super::errors::structured_error;
use crate::capability::file_writer::{
    self, Base, Change, Committed, Edit, FieldError, PinChange, PinUpdate, Refused,
};
use crate::key_server::oidc::VerifiedIdentity;

// ── Public router builder ─────────────────────────────────────────────────────

/// Register capability management routes on the provided router.
pub fn capabilities_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            routes::UI_CAPABILITIES,
            get(list_capabilities).post(create_capability),
        )
        .route(
            routes::UI_CAPABILITY,
            get(get_capability)
                .put(put_capability)
                .delete(delete_capability),
        )
        .route(
            routes::UI_CAPABILITY_VALIDATE,
            post(validate_capability_route),
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
    structured_error(
        StatusCode::BAD_REQUEST,
        "invalid_name",
        format!(
            "Capability name '{name}' is invalid. Names must match [a-z0-9_-] and be ≤128 chars."
        ),
    )
}

// ── Directory helpers ─────────────────────────────────────────────────────────

/// Find the YAML file for `name` across all configured capability directories.
///
/// Returns `(path, dir_index)` of the first match found (`.yaml` preferred
/// over `.yml`).
fn find_capability_file(dirs: &[String], name: &str) -> Option<PathBuf> {
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
    /// `verified`, `mismatch` or `unpinned`.
    pub pin: &'static str,
    /// SHA-256 of the raw bytes: the editor's base for `If-Match`.
    pub sha256: String,
}

// ── Parse helpers ─────────────────────────────────────────────────────────────

/// Count tools in a YAML capability file.
///
/// We count the number of top-level keys in `providers` (named) plus entries
/// in `providers` that are arrays (fallback).  A simpler heuristic — just
/// returning 1 if the file parses — is also acceptable, but extracting the
/// actual provider count gives more useful metadata.
fn count_tools(yaml: &str) -> usize {
    // Use the YAML parser to deserialize as generic Value and count providers keys.
    let Ok(val) = crate::yaml::from_str::<crate::yaml::Value>(yaml) else {
        return 0;
    };
    if let crate::yaml::Value::Mapping(map) = &val
        && let Some(providers) = map.get("providers")
    {
        match providers {
            crate::yaml::Value::Mapping(m) => return m.len().max(1),
            crate::yaml::Value::Sequence(s) => return s.len().max(1),
            _ => {}
        }
    }
    // Treat as a single-tool capability if parsing succeeds.
    usize::from(val != crate::yaml::Value::Null)
}

/// Extract the `description` field from raw YAML without full deserialize.
fn extract_description(yaml: &str) -> Option<String> {
    let val: crate::yaml::Value = crate::yaml::from_str(yaml).ok()?;
    val.get("description")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /ui/api/capabilities` — list all YAML files with metadata.
pub(super) async fn list_capabilities(
    State(state): State<Arc<AppState>>,
    guard: Guard,
) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
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

            let size_bytes = entry.metadata().map_or(0, |m| m.len());
            let yaml = std::fs::read_to_string(&path).unwrap_or_default();
            let tool_count = count_tools(&yaml);
            let description = extract_description(&yaml);

            entries.push(CapabilityMeta {
                name: stem.to_owned(),
                tool_count,
                size_bytes,
                description,
                path: path.to_string_lossy().into_owned(),
                pin: file_writer::pin_state(&yaml),
                sha256: file_writer::sha256_of(&yaml),
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
pub(super) async fn get_capability(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }

    if !is_safe_name(&name) {
        return bad_name(&name).into_response();
    }

    let dirs = state.capability_dirs.as_slice();
    let Some(path) = find_capability_file(dirs, &name) else {
        return structured_error(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("Capability '{name}' not found"),
        )
        .into_response();
    };

    match tokio::fs::read_to_string(&path).await {
        Ok(content) => (
            StatusCode::OK,
            [
                (
                    axum::http::header::CONTENT_TYPE,
                    "text/yaml; charset=utf-8".to_owned(),
                ),
                (
                    axum::http::header::ETAG,
                    format!("\"{}\"", file_writer::sha256_of(&content)),
                ),
            ],
            content,
        )
            .into_response(),
        Err(e) => structured_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "read_error",
            format!("Failed to read capability file: {e}"),
        )
        .into_response(),
    }
}

// ── The editor's write path (the capability writer) ──────────────────────────

/// How long a write waits for its directory's lock.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The base an `If-Match` names. Strong comparison only: a weak tag or `*`
/// names no file's bytes and never matches; a bare hash is read as the tag.
/// `None` when the header is absent (the caller answers 428).
fn if_match(headers: &HeaderMap) -> Option<Base> {
    let raw = headers
        .get(axum::http::header::IF_MATCH)?
        .to_str()
        .ok()?
        .trim();
    if raw.starts_with("W/") || raw == "*" {
        return Some(Base::Bytes(String::new()));
    }
    Some(Base::Bytes(raw.trim_matches('"').to_ascii_lowercase()))
}

fn etag(sha256: &str) -> [(axum::http::HeaderName, String); 1] {
    [(axum::http::header::ETAG, format!("\"{sha256}\""))]
}

fn not_found(name: &str) -> axum::response::Response {
    structured_error(
        StatusCode::NOT_FOUND,
        "not_found",
        format!("Capability '{name}' not found"),
    )
    .into_response()
}

fn precondition_required() -> axum::response::Response {
    structured_error(
        StatusCode::PRECONDITION_REQUIRED,
        "precondition_required",
        "Send If-Match with the ETag (the sha256) of the file you loaded",
    )
    .into_response()
}

fn pin_name(pin: PinChange) -> &'static str {
    match pin {
        PinChange::Kept => "kept",
        PinChange::Updated => "updated",
        PinChange::Added => "added",
        PinChange::None => "none",
    }
}

/// The editor's `capability_editor` record (D5): what changed, never the
/// content.
fn record_edit(
    state: &AppState,
    client: Option<&AuthenticatedClient>,
    identity: Option<&VerifiedIdentity>,
    action: &str,
    name: &str,
    committed: &Committed,
) -> Option<axum::response::Response> {
    let mut fields = serde_json::Map::new();
    fields.insert("action".into(), action.into());
    fields.insert("capability".into(), name.into());
    fields.insert("sha256_before".into(), json!(committed.before));
    fields.insert("sha256_after".into(), json!(committed.after));
    fields.insert("pin".into(), pin_name(committed.pin).into());
    super::admin_audit::record_admin_action(state, "capability_editor", client, identity, fields)
}

/// Where `name` lives, or where a new one would go: its file's directory, or
/// the primary write directory.
fn capability_dir(dirs: &[String], name: &str) -> Option<(PathBuf, Option<PathBuf>)> {
    if let Some(file) = find_capability_file(dirs, name) {
        let dir = file.parent()?.to_path_buf();
        return Some((dir, Some(file)));
    }
    primary_write_dir(dirs).map(|dir| (PathBuf::from(dir), None))
}

/// `?validate=` on `PUT`: present with any value means validate only.
#[derive(Debug, Deserialize)]
pub struct ValidateQuery {
    /// Any value, empty included, asks for validation without a write.
    pub validate: Option<String>,
}

/// `PUT /ui/api/capabilities/:name` — save through the capability writer.
///
/// With `?validate=1` or an `X-Validate-Only` header it validates and writes
/// nothing: the classic editor validates on blur, and a blur must never save.
/// That check runs before `If-Match`, so a blur never answers 428. A save
/// needs `If-Match` (428 without it) and an existing file (404; `POST`
/// creates).
pub(super) async fn put_capability(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    identity: Option<Extension<VerifiedIdentity>>,
    AxumPath(name): AxumPath<String>,
    Query(query): Query<ValidateQuery>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let client = guard.client.clone();
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    if !is_safe_name(&name) {
        return bad_name(&name).into_response();
    }
    let accounts = state.meta_mcp.account_strategies();
    let dirs = state.capability_dirs.as_slice();
    let Some((dir, file)) = capability_dir(dirs, &name) else {
        return not_found(&name);
    };

    if query.validate.is_some() || headers.contains_key("x-validate-only") {
        return validate_only(&state, &name, &body, &dir, file).await;
    }

    if file.is_none() {
        return not_found(&name);
    }
    let Some(base) = if_match(&headers) else {
        return precondition_required();
    };
    let edit = Edit {
        dir: &dir,
        name: &name,
        base,
        change: Change::Write(body),
        pin: PinUpdate::InPlace,
    };
    match file_writer::commit(edit, Some(&accounts), std::time::Instant::now() + LOCK_WAIT).await {
        Ok(committed) => {
            let identity = identity.map(|Extension(i)| i);
            if let Some(withheld) = record_edit(
                &state,
                client.as_ref(),
                identity.as_ref(),
                "save",
                &name,
                &committed,
            ) {
                return withheld;
            }
            let after = committed.after.unwrap_or_default();
            (
                StatusCode::OK,
                etag(&after),
                Json(json!({ "status": "saved", "name": name, "sha256": after })),
            )
                .into_response()
        }
        Err(refusal) => refused(&name, refusal),
    }
}

/// `POST /ui/api/capabilities/:name/validate` — validate only (D4a). This
/// handler has no writer: it reads the current file and answers what a save
/// would write. The admin audit layer does not record it (by route).
pub(super) async fn validate_capability_route(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    AxumPath(name): AxumPath<String>,
    body: String,
) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    if !is_safe_name(&name) {
        return bad_name(&name).into_response();
    }
    let dirs = state.capability_dirs.as_slice();
    let Some((dir, file)) = capability_dir(dirs, &name) else {
        return not_found(&name);
    };
    validate_only(&state, &name, &body, &dir, file).await
}

/// The one validate contract, shared by `POST .../validate` and `PUT` with
/// `?validate` or `X-Validate-Only`: it judges the bytes a save would write
/// (pin updated), never the raw body, so a check and the save that follows it
/// agree. 200 when valid, 422 when not; both carry the same body.
async fn validate_only(
    state: &AppState,
    name: &str,
    body: &str,
    dir: &Path,
    file: Option<PathBuf>,
) -> axum::response::Response {
    let accounts = state.meta_mcp.account_strategies();
    let current = match &file {
        Some(path) => tokio::fs::read_to_string(path).await.ok(),
        None => None,
    };
    let path = file.unwrap_or_else(|| dir.join(format!("{name}.yaml")));
    let pin_before = current.as_deref().map(file_writer::pin_state);
    let (bytes, errors) = match file_writer::preview(body, current.as_deref()) {
        Ok((bytes, _)) => {
            let errors = file_writer::validate(&bytes, &path, Some(&accounts)).err();
            (Some(bytes), errors.unwrap_or_default())
        }
        Err(refusal) => {
            let message = match refusal {
                Refused::PinMismatch { .. } => {
                    "the file no longer matches its pin; review it, then run `cap pin` or restore a version"
                }
                Refused::Unpin { .. } => "a save would remove the pin, which an edit cannot do",
                _ => "more than one pin line, or text after a line break on the pin line",
            };
            (
                None,
                vec![FieldError {
                    line: None,
                    column: None,
                    field: Some("sha256".into()),
                    message: message.into(),
                }],
            )
        }
    };
    let diff = bytes
        .as_deref()
        .map(|b| file_writer::unified_diff(current.as_deref().unwrap_or_default(), b));
    let valid = errors.is_empty();
    let status = if valid {
        StatusCode::OK
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    let mut answer = json!({
        "status": if valid { "valid" } else { "invalid" },
        "name": name,
        "valid": valid,
        "errors": field_errors(&errors),
        "diff": diff,
        "pin": { "before": pin_before, "after": bytes.as_deref().map(file_writer::pin_state) },
        "sha256": bytes.as_deref().map(file_writer::sha256_of),
    });
    if !valid {
        answer["error"] = json!("invalid");
        answer["message"] = json!(format!("Capability '{name}' would not load"));
    }
    (status, Json(answer)).into_response()
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
pub(super) async fn create_capability(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    identity: Option<Extension<VerifiedIdentity>>,
    body: Option<Json<CreateCapabilityBody>>,
) -> impl IntoResponse {
    let client = guard.client.clone();
    if let Err(refused) = guard.admit() {
        return refused.into_response();
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
        return structured_error(
            StatusCode::BAD_REQUEST,
            "missing_name",
            "Field 'name' is required when providing 'yaml'",
        )
        .into_response();
    };

    if !is_safe_name(&name) {
        return bad_name(&name).into_response();
    }

    let dirs = state.capability_dirs.as_slice();

    // Conflict check across every directory, not only the one written to.
    if find_capability_file(dirs, &name).is_some() {
        return structured_error(
            StatusCode::CONFLICT,
            "already_exists",
            format!("Capability '{name}' already exists. Use PUT to update."),
        )
        .into_response();
    }

    let dir = PathBuf::from(primary_write_dir(dirs).unwrap_or("capabilities"));
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        return structured_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "io_error",
            format!("Failed to create directory: {e}"),
        )
        .into_response();
    }

    let accounts = state.meta_mcp.account_strategies();
    let edit = Edit {
        dir: &dir,
        name: &name,
        base: Base::Absent,
        change: Change::Write(yaml),
        pin: PinUpdate::InPlace,
    };
    match file_writer::commit(edit, Some(&accounts), std::time::Instant::now() + LOCK_WAIT).await {
        Ok(committed) => {
            let identity = identity.map(|Extension(i)| i);
            if let Some(withheld) = record_edit(
                &state,
                client.as_ref(),
                identity.as_ref(),
                "create",
                &name,
                &committed,
            ) {
                return withheld;
            }
            let after = committed.after.unwrap_or_default();
            (
                StatusCode::CREATED,
                etag(&after),
                Json(json!({ "status": "created", "name": name, "sha256": after })),
            )
                .into_response()
        }
        Err(refusal) => refused(&name, refusal),
    }
}

/// `DELETE /ui/api/capabilities/:name` — remove the named file through the
/// writer: `If-Match` required, never follows a link.
pub(super) async fn delete_capability(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    identity: Option<Extension<VerifiedIdentity>>,
    AxumPath(name): AxumPath<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let client = guard.client.clone();
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    if !is_safe_name(&name) {
        return bad_name(&name).into_response();
    }
    let dirs = state.capability_dirs.as_slice();
    let Some((dir, Some(_))) = capability_dir(dirs, &name) else {
        return not_found(&name);
    };
    let Some(base) = if_match(&headers) else {
        return precondition_required();
    };
    let edit = Edit {
        dir: &dir,
        name: &name,
        base,
        change: Change::Delete,
        pin: PinUpdate::InPlace,
    };
    match file_writer::commit(edit, None, std::time::Instant::now() + LOCK_WAIT).await {
        Ok(committed) => {
            let identity = identity.map(|Extension(i)| i);
            if let Some(withheld) = record_edit(
                &state,
                client.as_ref(),
                identity.as_ref(),
                "delete",
                &name,
                &committed,
            ) {
                return withheld;
            }
            Json(json!({ "status": "deleted", "name": name })).into_response()
        }
        Err(refusal) => refused(&name, refusal),
    }
}

#[path = "capabilities_answers.rs"]
mod answers;
use super::guard::Guard;
use answers::{field_errors, refused};

#[cfg(test)]
#[path = "capabilities_tests.rs"]
mod tests;
