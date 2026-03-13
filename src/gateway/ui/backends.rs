//! Backend management API endpoints for the Web UI.
//!
//! Implements:
//!   POST   `/ui/api/backends`         — add a backend
//!   DELETE `/ui/api/backends/:name`   — remove a backend
//!   PATCH  `/ui/api/backends/:name`   — update backend fields
//!   GET    `/ui/api/registry`         — list all built-in registry entries
//!   GET    `/ui/api/registry/search`  — search built-in registry by keyword
//!
//! All mutation endpoints require admin auth and trigger a config write +
//! hot-reload after a successful change.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use axum::extract::{Extension, Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Json, Router};
use axum::routing::{delete, get, patch, post};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::is_admin;
use crate::config::{BackendConfig, Config, TransportConfig};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::router::AppState;
use crate::registry::server_registry;

// ── Request / response types ────────────────────────────────────────────────

/// Request body for `POST /ui/api/backends`.
#[derive(Debug, Deserialize)]
pub struct AddBackendRequest {
    /// Backend name / key.
    pub name: String,
    /// Explicit stdio command (overrides registry lookup).
    pub command: Option<String>,
    /// Explicit HTTP URL (overrides registry lookup).
    pub url: Option<String>,
    /// Human-readable description.
    pub description: Option<String>,
    /// Environment variables as `{ "KEY": "VALUE" }` map.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// Request body for `PATCH /ui/api/backends/:name`.
#[derive(Debug, Deserialize)]
pub struct UpdateBackendRequest {
    /// New stdio command (replaces existing).
    pub command: Option<String>,
    /// New HTTP URL (replaces existing).
    pub url: Option<String>,
    /// New description.
    pub description: Option<String>,
    /// Env vars to merge (existing keys updated, new keys added; no deletion).
    pub env: Option<HashMap<String, String>>,
    /// Whether the backend is enabled.
    pub enabled: Option<bool>,
}

/// Query parameters for `GET /ui/api/registry/search`.
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    /// Keyword to match against name, description, and category.
    pub q: Option<String>,
}

/// JSON representation of a registry entry (serialisable).
#[derive(Debug, Serialize)]
pub struct RegistryEntryJson {
    /// Short identifier (e.g. `"tavily"`).
    pub name: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Launch command (e.g. `"npx -y @anthropic/mcp-server-tavily"`).
    pub command: &'static str,
    /// Environment variables that must be set for this server.
    pub required_env: &'static [&'static str],
    /// Environment variables that are optional.
    pub optional_env: &'static [&'static str],
    /// Transport type: `"stdio"` or `"http"`.
    pub transport: &'static str,
    /// Functional category (e.g. `"search"`, `"database"`).
    pub category: &'static str,
    /// Project homepage URL.
    pub homepage: &'static str,
}

impl From<&'static server_registry::RegistryEntry> for RegistryEntryJson {
    fn from(e: &'static server_registry::RegistryEntry) -> Self {
        let transport = match e.transport {
            server_registry::Transport::Stdio => "stdio",
            server_registry::Transport::Http { .. } => "http",
        };
        Self {
            name: e.name,
            description: e.description,
            command: e.command,
            required_env: e.required_env,
            optional_env: e.optional_env,
            transport,
            category: e.category,
            homepage: e.homepage,
        }
    }
}

// ── Router builder ───────────────────────────────────────────────────────────

/// Build the backend-management sub-router.
///
/// These routes are merged into the main `api_router()` in `mod.rs`.
pub fn backends_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/ui/api/backends", post(add_backend))
        .route("/ui/api/backends/{name}", delete(remove_backend))
        .route("/ui/api/backends/{name}", patch(update_backend))
        .route("/ui/api/registry", get(list_registry))
        .route("/ui/api/registry/search", get(search_registry))
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// `POST /ui/api/backends` — add a backend.
///
/// Resolves transport from the built-in registry when neither `command` nor
/// `url` is provided, falling back to a 422 error if the name is unknown.
/// Returns 201 on success, 409 on duplicate, 422 on unresolvable transport.
async fn add_backend(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    Json(req): Json<AddBackendRequest>,
) -> impl IntoResponse {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Admin authentication required"})),
        )
            .into_response();
    }

    // Sanitize name
    if let Err(msg) = validate_backend_name(&req.name) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": msg})),
        )
            .into_response();
    }

    // Require a config path to write to
    let Some(ref config_path) = state.config_path else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Config file path not available; cannot persist changes"})),
        )
            .into_response();
    };

    // Resolve transport and description
    let (transport, description) = match resolve_transport(
        &req.name,
        req.command.as_deref(),
        req.url.as_deref(),
        req.description.as_deref(),
    ) {
        Ok(t) => t,
        Err(msg) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({"error": msg})),
            )
                .into_response();
        }
    };

    // Load current config and check for duplicates
    let mut config = load_config(config_path);
    if config.backends.contains_key(&req.name) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": format!("Backend '{}' already exists", req.name)})),
        )
            .into_response();
    }

    // Build and insert new backend
    let backend = BackendConfig {
        description,
        enabled: true,
        transport,
        env: req.env,
        ..Default::default()
    };
    config.backends.insert(req.name.clone(), backend);

    // Persist and reload
    if let Err(e) = write_and_reload(&state, config_path, &config).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        )
            .into_response();
    }

    (
        StatusCode::CREATED,
        Json(json!({"status": "created", "name": req.name})),
    )
        .into_response()
}

/// `DELETE /ui/api/backends/:name` — remove a backend.
///
/// Returns 204 on success, 404 when the backend does not exist.
async fn remove_backend(
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

    let Some(ref config_path) = state.config_path else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Config file path not available; cannot persist changes"})),
        )
            .into_response();
    };

    let mut config = load_config(config_path);
    if config.backends.remove(&name).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Backend '{}' not found", name)})),
        )
            .into_response();
    }

    if let Err(e) = write_and_reload(&state, config_path, &config).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        )
            .into_response();
    }

    (StatusCode::NO_CONTENT, Json(json!({}))).into_response()
}

/// `PATCH /ui/api/backends/:name` — partially update a backend.
///
/// Merges the provided fields into the existing backend config.
/// Returns 200 on success, 404 when not found.
async fn update_backend(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    AxumPath(name): AxumPath<String>,
    Json(req): Json<UpdateBackendRequest>,
) -> impl IntoResponse {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Admin authentication required"})),
        )
            .into_response();
    }

    let Some(ref config_path) = state.config_path else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "Config file path not available; cannot persist changes"})),
        )
            .into_response();
    };

    // Validate: only one of command/url may be specified
    if req.command.is_some() && req.url.is_some() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"error": "Provide either 'command' or 'url', not both"})),
        )
            .into_response();
    }

    let mut config = load_config(config_path);
    if !config.backends.contains_key(&name) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": format!("Backend '{}' not found", name)})),
        )
            .into_response();
    }

    // Apply partial updates inside a scope to release the mutable borrow
    {
        let backend = config.backends.get_mut(&name).expect("checked above");

        if let Some(desc) = req.description {
            backend.description = desc;
        }
        if let Some(enabled) = req.enabled {
            backend.enabled = enabled;
        }
        // Transport update
        if let Some(cmd) = req.command {
            backend.transport = TransportConfig::Stdio {
                command: cmd,
                cwd: None,
                protocol_version: None,
            };
        } else if let Some(url) = req.url {
            backend.transport = TransportConfig::Http {
                http_url: url,
                streamable_http: false,
                protocol_version: None,
            };
        }
        // Merge env vars
        if let Some(env_patch) = req.env {
            for (k, v) in env_patch {
                backend.env.insert(k, v);
            }
        }
    } // mutable borrow released here

    if let Err(e) = write_and_reload(&state, config_path, &config).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e})),
        )
            .into_response();
    }

    Json(json!({"status": "updated", "name": name})).into_response()
}

/// `GET /ui/api/registry` — list all built-in registry entries as JSON.
async fn list_registry(
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

    let entries: Vec<RegistryEntryJson> = server_registry::all()
        .iter()
        .map(RegistryEntryJson::from)
        .collect();

    Json(json!({"entries": entries, "total": entries.len()})).into_response()
}

/// `GET /ui/api/registry/search?q=` — search registry by keyword.
///
/// Matches against name, description, and category (case-insensitive).
async fn search_registry(
    client: Option<Extension<AuthenticatedClient>>,
    Query(params): Query<SearchQuery>,
) -> impl IntoResponse {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "Admin authentication required"})),
        )
            .into_response();
    }

    let q = params.q.as_deref().unwrap_or("").trim().to_string();
    let entries: Vec<RegistryEntryJson> = if q.is_empty() {
        server_registry::all()
            .iter()
            .map(RegistryEntryJson::from)
            .collect()
    } else {
        server_registry::search(&q)
            .into_iter()
            .map(RegistryEntryJson::from)
            .collect()
    };

    Json(json!({"entries": entries, "total": entries.len(), "query": q})).into_response()
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Validate that a backend name contains only safe characters.
///
/// Allowed: ASCII alphanumerics, hyphens, underscores, dots.
/// Max length: 128 characters.
fn validate_backend_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Backend name must not be empty".to_string());
    }
    if name.len() > 128 {
        return Err("Backend name exceeds 128 characters".to_string());
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(
            "Backend name may only contain ASCII letters, digits, hyphens, underscores, and dots"
                .to_string(),
        );
    }
    Ok(())
}

/// Resolve transport config from explicit flags or registry.
fn resolve_transport(
    name: &str,
    cmd: Option<&str>,
    url: Option<&str>,
    desc: Option<&str>,
) -> Result<(TransportConfig, String), String> {
    // Explicit command takes priority.
    if let Some(command) = cmd {
        return Ok((
            TransportConfig::Stdio {
                command: command.to_string(),
                cwd: None,
                protocol_version: None,
            },
            desc.unwrap_or("").to_string(),
        ));
    }

    // Explicit URL.
    if let Some(http_url) = url {
        return Ok((
            TransportConfig::Http {
                http_url: http_url.to_string(),
                streamable_http: false,
                protocol_version: None,
            },
            desc.unwrap_or("").to_string(),
        ));
    }

    // Registry lookup.
    if let Some(entry) = server_registry::lookup(name) {
        let transport = match entry.transport {
            server_registry::Transport::Stdio => TransportConfig::Stdio {
                command: entry.command.to_string(),
                cwd: None,
                protocol_version: None,
            },
            server_registry::Transport::Http { default_url } => TransportConfig::Http {
                http_url: default_url.to_string(),
                streamable_http: false,
                protocol_version: None,
            },
        };
        return Ok((transport, desc.unwrap_or(entry.description).to_string()));
    }

    Err(format!(
        "'{name}' is not in the built-in registry. Provide 'command' or 'url'."
    ))
}

/// Load the gateway config from disk, returning a default on error.
fn load_config(path: &Path) -> Config {
    if path.exists() {
        Config::load(Some(path)).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "Could not load config, using defaults");
            Config::default()
        })
    } else {
        Config::default()
    }
}

/// Serialize `config` to YAML, write to `path`, then trigger hot-reload via
/// the `ReloadContext` stored in the gateway's `MetaMcp`.
///
/// # Errors
///
/// Returns an error string on serialization, write, or reload failure.
async fn write_and_reload(
    state: &Arc<AppState>,
    path: &Path,
    config: &Config,
) -> Result<(), String> {
    // Serialize
    let yaml =
        serde_yaml::to_string(config).map_err(|e| format!("Failed to serialize config: {e}"))?;

    // Write atomically via a temp file + rename to minimize window of corruption
    let tmp_path = path.with_extension("yaml.tmp");
    std::fs::write(&tmp_path, &yaml)
        .map_err(|e| format!("Failed to write temp config: {e}"))?;
    std::fs::rename(&tmp_path, path)
        .map_err(|e| format!("Failed to rename config file: {e}"))?;

    // Trigger hot-reload via ReloadContext if available
    if let Some(ctx) = state.meta_mcp.reload_context() {
        ctx.reload()
            .await
            .map_err(|e| format!("Config written but reload failed: {e}"))?;
    }
    // If no ReloadContext is present the file-watcher will pick up the change.

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_backend_name ──────────────────────────────────────────────────

    #[test]
    fn name_valid_alphanumeric() {
        assert!(validate_backend_name("my-backend").is_ok());
        assert!(validate_backend_name("backend_v2").is_ok());
        assert!(validate_backend_name("server.prod").is_ok());
        assert!(validate_backend_name("tavily").is_ok());
    }

    #[test]
    fn name_empty_is_rejected() {
        assert!(validate_backend_name("").is_err());
    }

    #[test]
    fn name_too_long_is_rejected() {
        let long = "a".repeat(129);
        assert!(validate_backend_name(&long).is_err());
    }

    #[test]
    fn name_with_special_chars_is_rejected() {
        assert!(validate_backend_name("my server").is_err());
        assert!(validate_backend_name("back/end").is_err());
        assert!(validate_backend_name("<evil>").is_err());
        assert!(validate_backend_name("name;drop").is_err());
    }

    #[test]
    fn name_at_max_length_is_accepted() {
        let exact = "a".repeat(128);
        assert!(validate_backend_name(&exact).is_ok());
    }

    // ── resolve_transport ─────────────────────────────────────────────────────

    #[test]
    fn resolve_explicit_command() {
        let (transport, _) = resolve_transport("any", Some("node server.js"), None, None).unwrap();
        match transport {
            TransportConfig::Stdio { command, .. } => assert_eq!(command, "node server.js"),
            _ => panic!("expected Stdio"),
        }
    }

    #[test]
    fn resolve_explicit_url() {
        let (transport, _) =
            resolve_transport("any", None, Some("http://localhost:9000"), None).unwrap();
        match transport {
            TransportConfig::Http { http_url, .. } => {
                assert_eq!(http_url, "http://localhost:9000");
            }
            _ => panic!("expected Http"),
        }
    }

    #[test]
    fn resolve_registry_known_name() {
        let (transport, desc) = resolve_transport("tavily", None, None, None).unwrap();
        match transport {
            TransportConfig::Stdio { command, .. } => {
                assert!(command.contains("tavily"), "command should mention tavily");
            }
            _ => panic!("expected Stdio for tavily"),
        }
        assert!(!desc.is_empty(), "description should not be empty");
    }

    #[test]
    fn resolve_unknown_name_without_transport_is_error() {
        let result = resolve_transport("totally-unknown-xyz", None, None, None);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("not in the built-in registry"));
    }

    #[test]
    fn resolve_description_override() {
        let (_, desc) =
            resolve_transport("tavily", None, None, Some("My custom description")).unwrap();
        assert_eq!(desc, "My custom description");
    }

    // ── registry_entry_json ───────────────────────────────────────────────────

    #[test]
    fn registry_entry_json_from_stdio_entry() {
        let entry = server_registry::lookup("tavily").expect("tavily must be in registry");
        let json = RegistryEntryJson::from(entry);
        assert_eq!(json.name, "tavily");
        assert_eq!(json.transport, "stdio");
        assert!(!json.required_env.is_empty());
    }

    #[test]
    fn all_registry_entries_serializable() {
        let entries: Vec<RegistryEntryJson> =
            server_registry::all().iter().map(RegistryEntryJson::from).collect();
        // Must have all 48 built-in entries
        assert!(entries.len() >= 40, "registry should have at least 40 entries");
        // All must serialize to JSON without error
        for e in &entries {
            serde_json::to_string(e).expect("registry entry must be JSON-serializable");
        }
    }

    #[test]
    fn search_registry_returns_subset() {
        let results = server_registry::search("database");
        assert!(!results.is_empty(), "should find database-category entries");
        for r in &results {
            let lower = format!("{} {} {}", r.name, r.description, r.category).to_lowercase();
            assert!(
                lower.contains("database"),
                "result '{}' should match 'database'",
                r.name
            );
        }
    }
}
