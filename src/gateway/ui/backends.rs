// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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

use crate::gateway::routes;
use std::sync::Arc;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::admin_audit::attach_selection;
use super::guard::Guard;
use super::refusals::WriteTicket;
use super::{
    backend_ops::{
        BackendUpdate, UNRESOLVED_SECRETS, add_backend as add_backend_config,
        remove_backend as remove_backend_config, resolve_backend,
        update_backend as update_backend_config,
    },
    errors::{config_path_unavailable, flat_error},
};
use crate::config::TransportConfig;
use crate::config_persistence::CommentLoss;
use crate::config_reload::refusals::RefusalKind;
use crate::config_reload::{
    ConfigMutation, ConfigWriteError, MutateError, mutate_config_and_reload_detached,
};
use crate::gateway::router::AppState;
use crate::registry::server_registry;

// ── Request / response types ────────────────────────────────────────────────

mod requests;
pub use requests::{AddBackendRequest, UpdateBackendRequest};

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
    /// Launch command (e.g. `"npx -y tavily-mcp@0.2.22"`).
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
    /// What the user supplies: `none`, `env: A, B`, `oauth`, or `header: NAME (VAR)`.
    pub login: String,
    /// True when the server needs an account, key or login.
    pub needs_login: bool,
    /// True for the starter set `mcp-gateway init` writes enabled.
    pub default_enabled: bool,
    /// Why `add` writes it disabled, when its reach is arbitrary.
    pub reach_reason: Option<&'static str>,
    /// What it needs beyond its command (arguments, a running service).
    pub setup: Option<&'static str>,
}

impl From<&'static server_registry::ServerCatalogEntry> for RegistryEntryJson {
    fn from(e: &'static server_registry::ServerCatalogEntry) -> Self {
        let transport = match e.transport {
            server_registry::CatalogTransport::Stdio => "stdio",
            server_registry::CatalogTransport::Http { .. } => "http",
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
            login: match e.auth {
                server_registry::Auth::None => "none".to_string(),
                server_registry::Auth::EnvVars => format!("env: {}", e.required_env.join(", ")),
                server_registry::Auth::OAuth => "oauth".to_string(),
                server_registry::Auth::Header { name, .. } => {
                    format!("header: {name} ({})", e.required_env.join(", "))
                }
            },
            needs_login: e.needs_login(),
            default_enabled: e.default_enabled(),
            reach_reason: match e.reach {
                server_registry::Reach::Arbitrary { reason } => Some(reason),
                server_registry::Reach::Bounded => None,
            },
            setup: match e.setup {
                server_registry::Setup::Ready => None,
                server_registry::Setup::NeedsArgs { hint }
                | server_registry::Setup::NeedsService { hint } => Some(hint),
            },
        }
    }
}

// ── Router builder ───────────────────────────────────────────────────────────

/// Build the backend-management sub-router.
///
/// These routes are merged into the main `api_router()` in `mod.rs`.
pub fn backends_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(routes::UI_BACKENDS, post(add_backend))
        .route(routes::UI_BACKEND, delete(remove_backend))
        .route(routes::UI_BACKEND, patch(update_backend))
        .route(routes::UI_BACKEND_REVIVE, post(revive_backend))
        .route(routes::UI_REGISTRY, get(list_registry))
        .route(routes::UI_REGISTRY_SEARCH, get(search_registry))
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// `POST /ui/api/backends` — add a backend.
///
/// Resolves transport from the built-in registry when neither `command` nor
/// `url` is provided, falling back to a 422 error if the name is unknown.
/// Returns 201 on success, 409 on duplicate, 422 on unresolvable transport.
async fn add_backend(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    Json(req): Json<AddBackendRequest>,
) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }

    // Sanitize name
    if let Err(msg) = validate_backend_name(&req.name) {
        return flat_error(StatusCode::UNPROCESSABLE_ENTITY, msg).into_response();
    }

    if let Some(list) = &req.allowed_tools
        && let Err(refused) = crate::config::check_backend_allowed_tools(&req.name, list)
    {
        return flat_error(StatusCode::UNPROCESSABLE_ENTITY, refused.to_string()).into_response();
    }

    // Require a config path to write to
    let Some(ref config_path) = state.config_path else {
        return config_path_unavailable().into_response();
    };

    // Resolve the whole backend: transport, description, and for a registry
    // entry its login, env templates and default state.
    let resolved = match resolve_backend(
        req.registry.as_deref().unwrap_or(&req.name),
        req.command.as_deref(),
        req.url.as_deref(),
        req.description.as_deref(),
        req.env,
    ) {
        Ok(r) => r,
        Err(msg) => {
            return flat_error(StatusCode::UNPROCESSABLE_ENTITY, msg).into_response();
        }
    };

    // Load, check for duplicates, persist and reload - all inside one lock, so
    // a second request cannot build its change on the pre-edit config.
    let name = req.name.clone();
    let allowed_tools = req.allowed_tools;
    let selected = allowed_tools.clone();
    let ticket = WriteTicket::new(&state);
    let in_lock = ticket.clone();
    let mutation = mutate_config_and_reload_detached(
        config_path.clone(),
        state.meta_mcp.reload_context(),
        CommentLoss::Refuse,
        move |config| {
            add_backend_config(config, &name, resolved)
                .inspect(|_| in_lock.note(RefusalKind::Add, &name, config))
                .map(|notes| {
                    if let Some(backend) = config.backends.get_mut(&name) {
                        backend.allowed_tools = allowed_tools;
                    }
                    // Whether it went in enabled: notes alone do not say, an
                    // OAuth login note comes with an enabled backend.
                    let enabled = config.backends.get(&name).is_some_and(|b| b.enabled);
                    (notes, enabled)
                })
                .map_err(|message| add_refusal(&name, message))
        },
    )
    .await;

    let ((notes, enabled), reload) = match mutation {
        Ok(ConfigMutation::Applied(added, reload)) => {
            ticket.committed(&req.name);
            (added, reload)
        }
        Ok(ConfigMutation::Rejected((code, message))) => {
            return flat_error(code, message).into_response();
        }
        Err(e) => return unwritten(e),
    };

    // The reload registered it; listeners hear of it once its tools are
    // listed, through the change drain (F24, `MIK-8127`).

    let mut response = (
        StatusCode::CREATED,
        Json(json!({
            "status": "created",
            "name": req.name,
            "reload": reload,
            "notes": notes,
            "enabled": enabled,
        })),
    )
        .into_response();
    if selected.is_some() {
        attach_selection(&mut response, &req.name, None, selected.as_deref());
    }
    response
}

/// `DELETE /ui/api/backends/:name` — remove a backend.
///
/// Returns 204 on success, or 200 with `{"note": ...}` naming the comment
/// lines that went with the removed entry (line numbers only); 404 when the
/// backend does not exist.
async fn remove_backend(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }

    let Some(ref config_path) = state.config_path else {
        return config_path_unavailable().into_response();
    };

    // Worked out inside the edit, which runs under the config lock, from the
    // text this removal splices: never another writer's change. The write
    // runs detached (MIK-8120), so the note comes back as its value.
    let removed = name.clone();
    let path = config_path.clone();
    let ticket = WriteTicket::new(&state);
    let in_lock = ticket.clone();
    let mutation = mutate_config_and_reload_detached(
        config_path.clone(),
        state.meta_mcp.reload_context(),
        CommentLoss::Refuse,
        move |config| {
            remove_backend_config(config, &removed).map_err(|_| {
                (
                    StatusCode::NOT_FOUND,
                    format!("Backend '{removed}' not found"),
                )
            })?;
            // Gone: once the write commits, its earlier add and edit
            // refusals no longer apply.
            in_lock.reserve();
            Ok::<Vec<String>, (StatusCode, String)>(
                crate::config_persistence::comments_a_write_drops(&path, config),
            )
        },
    )
    .await;

    let gone = match mutation {
        Ok(ConfigMutation::Applied(gone, _)) => {
            ticket.committed(&name);
            gone
        }
        Ok(ConfigMutation::Rejected((code, message))) => {
            return flat_error(code, message).into_response();
        }
        Err(e) => return unwritten(e),
    };

    // The reload removed it; listeners hear of it if it had tools they could
    // see, through the change drain (F24, `MIK-8127`).

    // A removed entry takes its own comments with it (MIK-8051): name the
    // lines, never their text (a `#` inside a quoted value can be a secret).
    if gone.is_empty() {
        return (StatusCode::NO_CONTENT, Json(json!({}))).into_response();
    }
    let note = format!(
        "Comments inside the removed entry went with it: {}",
        gone.join("; ")
    );
    (StatusCode::OK, Json(json!({ "note": note }))).into_response()
}

/// `PATCH /ui/api/backends/:name` — partially update a backend.
///
/// Merges the provided fields into the existing backend config.
/// Returns 200 on success, 404 when not found.
async fn revive_backend(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "Admin: the operator dashboard behind admin auth; not a tenant read"
    )]
    let Some(backend) = state.backends.get(&name) else {
        return flat_error(StatusCode::NOT_FOUND, format!("Backend '{name}' not found"))
            .into_response();
    };

    let breaker_was_open = backend.is_circuit_tripped();
    backend.reset_circuit_breaker();
    // A backend that is shutting down reports Ok without rebuilding anything;
    // saying "revived" there would misreport it to the operator.
    let outcome = backend.force_restart().await;
    let rebuilt = matches!(outcome, Ok(crate::backend::RestartOutcome::Rebuilt));
    // No announcement: a restart keeps the stored tool list, so what discovery
    // shows is unchanged; a list the new transport stores later is announced by
    // the change drain if it differs (`MIK-8127`).
    let status = if rebuilt { "revived" } else { "not_revived" };

    (
        StatusCode::OK,
        Json(json!({
            "backend": name,
            "status": status,
            "breaker_was_open": breaker_was_open,
            "transport_rebuilt": rebuilt,
        })),
    )
        .into_response()
}

/// The transport a PATCH asks for. A URL goes through
/// [`TransportConfig::for_url`], so a pasted `ws://`/`wss://` URL becomes a
/// WebSocket backend here exactly as it does on add (F17).
fn requested_transport(command: Option<String>, url: Option<String>) -> Option<TransportConfig> {
    command
        .map(|command| TransportConfig::Stdio {
            command,
            cwd: None,
            protocol_version: None,
        })
        .or_else(|| url.map(|url| TransportConfig::for_url(&url)))
}

async fn update_backend(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    AxumPath(name): AxumPath<String>,
    Json(req): Json<UpdateBackendRequest>,
) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }

    let Some(ref config_path) = state.config_path else {
        return config_path_unavailable().into_response();
    };

    let UpdateBackendRequest {
        stop_when_idle_for_secs,
        command,
        url,
        description,
        env,
        enabled,
        allowed_tools,
    } = req;

    if let Some(Some(list)) = &allowed_tools
        && let Err(refused) = crate::config::check_backend_allowed_tools(&name, list)
    {
        return flat_error(StatusCode::UNPROCESSABLE_ENTITY, refused.to_string()).into_response();
    }

    // Validate: only one of command/url may be specified
    if command.is_some() && url.is_some() {
        return flat_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Provide either 'command' or 'url', not both",
        )
        .into_response();
    }

    // Everything from here reads the config and writes it back, so it all runs
    // inside one lock. Splitting the read from the write is what lets one edit
    // overwrite another.
    let updated = name.clone();
    let ticket = WriteTicket::new(&state);
    let in_lock = ticket.clone();
    let mutation = mutate_config_and_reload_detached(
        config_path.clone(),
        state.meta_mcp.reload_context(),
        CommentLoss::Refuse,
        move |config| {
            if !config.backends.contains_key(&name) {
                return Err((StatusCode::NOT_FOUND, format!("Backend '{name}' not found")));
            }

            let transport = requested_transport(command, url);

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

            let stop_when_idle_for = stop_when_idle_for_secs.map(|secs| {
                if secs == 0 {
                    None // explicit clear: never stop
                } else {
                    Some(std::time::Duration::from_secs(secs))
                }
            });

            update_backend_config(
                config,
                &name,
                BackendUpdate {
                    description,
                    env,
                    enabled,
                    transport,
                    stop_when_idle_for,
                },
            )
            .inspect(|()| in_lock.note(RefusalKind::Edit, &name, config))
            .map(|()| {
                let backend = config.backends.get_mut(&name)?;
                let after = allowed_tools?;
                let before = std::mem::replace(&mut backend.allowed_tools, after.clone());
                (before != after).then_some((before, after))
            })
            .map_err(|message| {
                // Surface the refusal verbatim. An operator setting "stop when idle" on a
                // backend the gateway does not start needs to be told why, not silently
                // ignored - being silently ignored is what this whole change corrects.
                let code = in_lock.refused_edit(&name, &message, update_refusal_status(&message));
                (code, message)
            })
        },
    )
    .await;

    let (selection, reload) = match mutation {
        Ok(ConfigMutation::Applied(selection, reload)) => {
            ticket.committed(&updated);
            (selection, reload)
        }
        Ok(ConfigMutation::Rejected((code, message))) => {
            return flat_error(code, message).into_response();
        }
        Err(e) => return unwritten(e),
    };

    let mut response =
        Json(json!({"status": "updated", "name": updated, "reload": reload})).into_response();
    if let Some((before, after)) = selection {
        attach_selection(&mut response, &updated, before.as_deref(), after.as_deref());
    }
    response
}

/// An add that `add_backend` refused: 422 for a secret reference that does
/// not resolve (ADR-028), otherwise the duplicate's 409.
fn add_refusal(name: &str, message: String) -> (StatusCode, String) {
    if message.contains(UNRESOLVED_SECRETS) {
        (StatusCode::UNPROCESSABLE_ENTITY, message)
    } else {
        (
            StatusCode::CONFLICT,
            format!("Backend '{name}' already exists"),
        )
    }
}

/// An update that `update_backend` refused: 404 for a missing backend, 422
/// for a secret reference that does not resolve (ADR-028), else 400.
fn update_refusal_status(message: &str) -> StatusCode {
    // The marker first: an unresolved `env:` names a missing env file in its
    // hint, which says "not found".
    if message.contains(UNRESOLVED_SECRETS) {
        StatusCode::UNPROCESSABLE_ENTITY
    } else if message.contains("not found") {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::BAD_REQUEST
    }
}

/// The answer to a backend write that did not happen.
fn unwritten(e: MutateError) -> axum::response::Response {
    let code = match &e {
        // Nothing was written: the edit cannot be made in place in the file.
        MutateError::CommentLoss(_) => StatusCode::CONFLICT,
        // A busy gateway has written nothing, so this is a retry-me, not a
        // failure. 500 would tell the operator their edit broke something.
        MutateError::Write(ConfigWriteError::Busy) => StatusCode::SERVICE_UNAVAILABLE,
        MutateError::Write(ConfigWriteError::Failed(_)) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    let message = match e {
        MutateError::CommentLoss(message) => message,
        MutateError::Write(e) => e.to_string(),
    };
    flat_error(code, message).into_response()
}

/// `GET /ui/api/registry` — list all built-in registry entries as JSON.
async fn list_registry(guard: Guard) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
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
async fn search_registry(guard: Guard, Query(params): Query<SearchQuery>) -> impl IntoResponse {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
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

pub(super) use crate::config::backend_add::validate_backend_name;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::ui::backend_ops::resolve_parts;

    // ── refusal codes (ADR-028) ───────────────────────────────

    #[test]
    fn b3i_an_unresolved_secret_is_422_on_add_and_patch() {
        let message = format!("Backend 'x' {UNRESOLVED_SECRETS}: backends.x.env.K");
        assert_eq!(
            add_refusal("x", message.clone()).0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            update_refusal_status(&message),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        // A missing env file's hint says "not found"; it is still a 422.
        let hinted = format!("{message} (env file /x/.env not found)");
        assert_eq!(
            update_refusal_status(&hinted),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        // The other refusals keep their codes.
        assert_eq!(
            add_refusal("x", "Backend 'x' already exists. Remove it first.".into()).0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            update_refusal_status("Backend 'x' not found."),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            update_refusal_status("stop when idle refused"),
            StatusCode::BAD_REQUEST
        );
    }

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

    // ── requested_transport (PATCH) ───────────────────────────────────────────

    #[test]
    fn a_patched_wss_url_becomes_a_websocket_backend() {
        for url in ["wss://h/mcp", "WS://h/mcp"] {
            match requested_transport(None, Some(url.to_string())) {
                Some(TransportConfig::WebSocket { ws_url, .. }) => assert_eq!(ws_url, url),
                other => panic!("{url}: expected WebSocket, got {other:?}"),
            }
        }
        assert!(matches!(
            requested_transport(None, Some("https://h/mcp".to_string())),
            Some(TransportConfig::Http { .. })
        ));
    }

    // ── resolve_transport ─────────────────────────────────────────────────────

    #[test]
    fn resolve_explicit_command() {
        let (transport, _) = resolve_parts("any", Some("node server.js"), None, None).unwrap();
        match transport {
            TransportConfig::Stdio { command, .. } => assert_eq!(command, "node server.js"),
            other => panic!("expected Stdio, got {other:?}"),
        }
    }

    #[test]
    fn resolve_explicit_url() {
        let (transport, _) =
            resolve_parts("any", None, Some("http://localhost:9000"), None).unwrap();
        match transport {
            TransportConfig::Http { http_url, .. } => {
                assert_eq!(http_url, "http://localhost:9000");
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn resolve_registry_known_name() {
        let (transport, desc) = resolve_parts("tavily", None, None, None).unwrap();
        match transport {
            TransportConfig::Stdio { command, .. } => {
                assert!(command.contains("tavily"), "command should mention tavily");
            }
            other => panic!("expected Stdio for tavily, got {other:?}"),
        }
        assert!(!desc.is_empty(), "description should not be empty");
    }

    #[test]
    fn resolve_unknown_name_without_transport_is_error() {
        let result = resolve_parts("totally-unknown-xyz", None, None, None);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("not in the built-in registry"));
    }

    #[test]
    fn resolve_description_override() {
        let (_, desc) = resolve_parts("tavily", None, None, Some("My custom description")).unwrap();
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
        assert!(!entries.is_empty(), "the registry has entries");
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
