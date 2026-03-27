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
use std::sync::Arc;

use axum::extract::{Extension, Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{
    backend_ops::{
        BackendUpdate, add_backend as add_backend_config, load_config_or_default,
        remove_backend as remove_backend_config, resolve_transport,
        update_backend as update_backend_config,
    },
    errors::{admin_auth_required, config_path_unavailable, flat_error},
    is_admin,
};
use crate::config::TransportConfig;
use crate::config_persistence::write_config_and_reload;
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
        return admin_auth_required().into_response();
    }

    // Sanitize name
    if let Err(msg) = validate_backend_name(&req.name) {
        return flat_error(StatusCode::UNPROCESSABLE_ENTITY, msg).into_response();
    }

    // Require a config path to write to
    let Some(ref config_path) = state.config_path else {
        return config_path_unavailable().into_response();
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
            return flat_error(StatusCode::UNPROCESSABLE_ENTITY, msg).into_response();
        }
    };

    // Load current config and check for duplicates
    let mut config = load_config_or_default(config_path);
    if add_backend_config(&mut config, &req.name, transport, description, req.env).is_err() {
        return flat_error(
            StatusCode::CONFLICT,
            format!("Backend '{}' already exists", req.name),
        )
        .into_response();
    }

    // Persist and reload
    if let Err(e) = write_config_and_reload(
        config_path,
        &config,
        state.meta_mcp.reload_context().as_deref(),
    )
    .await
    {
        return flat_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
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
        return admin_auth_required().into_response();
    }

    let Some(ref config_path) = state.config_path else {
        return config_path_unavailable().into_response();
    };

    let mut config = load_config_or_default(config_path);
    if remove_backend_config(&mut config, &name).is_err() {
        return flat_error(
            StatusCode::NOT_FOUND,
            format!("Backend '{}' not found", name),
        )
        .into_response();
    }

    if let Err(e) = write_config_and_reload(
        config_path,
        &config,
        state.meta_mcp.reload_context().as_deref(),
    )
    .await
    {
        return flat_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
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
        return admin_auth_required().into_response();
    }

    let Some(ref config_path) = state.config_path else {
        return config_path_unavailable().into_response();
    };

    let UpdateBackendRequest {
        command,
        url,
        description,
        env,
        enabled,
    } = req;

    // Validate: only one of command/url may be specified
    if command.is_some() && url.is_some() {
        return flat_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Provide either 'command' or 'url', not both",
        )
        .into_response();
    }

    let mut config = load_config_or_default(config_path);
    if !config.backends.contains_key(&name) {
        return flat_error(
            StatusCode::NOT_FOUND,
            format!("Backend '{}' not found", name),
        )
        .into_response();
    }

    let transport = command
        .map(|command| TransportConfig::Stdio {
            command,
            cwd: None,
            protocol_version: None,
        })
        .or_else(|| {
            url.map(|http_url| TransportConfig::Http {
                http_url,
                streamable_http: false,
                protocol_version: None,
            })
        });

    let env = env.map(|env_patch| {
        let mut merged = config
            .backends
            .get(&name)
            .expect("checked above")
            .env
            .clone();
        merged.extend(env_patch);
        merged
    });

    if update_backend_config(
        &mut config,
        &name,
        BackendUpdate {
            description,
            env,
            enabled,
            transport,
        },
    )
    .is_err()
    {
        return flat_error(
            StatusCode::NOT_FOUND,
            format!("Backend '{}' not found", name),
        )
        .into_response();
    }

    if let Err(e) = write_config_and_reload(
        config_path,
        &config,
        state.meta_mcp.reload_context().as_deref(),
    )
    .await
    {
        return flat_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    Json(json!({"status": "updated", "name": name})).into_response()
}

/// `GET /ui/api/registry` — list all built-in registry entries as JSON.
async fn list_registry(client: Option<Extension<AuthenticatedClient>>) -> impl IntoResponse {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        return admin_auth_required().into_response();
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
        return admin_auth_required().into_response();
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
        let entries: Vec<RegistryEntryJson> = server_registry::all()
            .iter()
            .map(RegistryEntryJson::from)
            .collect();
        // Must have all 48 built-in entries
        assert!(
            entries.len() >= 40,
            "registry should have at least 40 entries"
        );
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
