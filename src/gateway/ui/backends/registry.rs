// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The built-in server registry as the backend routes list and search it.

use axum::Json;
use axum::extract::Query;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::super::guard::Guard;
use crate::registry::server_registry;

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

/// `GET /ui/api/registry` — list all built-in registry entries as JSON.
pub(super) async fn list_registry(guard: Guard) -> impl IntoResponse {
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
pub(super) async fn search_registry(
    guard: Guard,
    Query(params): Query<SearchQuery>,
) -> impl IntoResponse {
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
