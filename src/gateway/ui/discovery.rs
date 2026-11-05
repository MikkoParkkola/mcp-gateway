// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/discovery`: MCP servers named in other clients' config files
//! on this host (ADR-021), with whether each could become a backend, for an
//! admin. Read-only: nothing here writes gateway.yaml.
//!
//! The finds come from the discovery cache, which holds no value, argument
//! or full path. Whether a find is managed or adoptable is judged on every
//! request against one consistent read of gateway.yaml, so a cached scan
//! never lags a config change.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Extension, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::json;

use super::backends::validate_backend_name;
use super::config_file::{Gateway, read_gateway};
use super::errors::flat_error;
use super::guard::Guard;
use crate::discovery::listing::{DiscoveryCache, ListedFind, Listing, Refusal};
use crate::discovery::shadow::ShadowRiskSeverity;
use crate::gateway::router::AppState;
use crate::gateway::routes;

/// The discovery routes over the gateway's shared discovery cache, read at
/// request time from `MetaMcp`: a router built before the cache (or a
/// gateway that never attached one) answers 503 rather than scanning alone.
pub(super) fn discovery_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(routes::UI_DISCOVERY, get(list_discovery))
        .route(routes::UI_DISCOVERY_ADOPT, post(adopt::adopt_discovery))
}

/// The discovery routes over a given cache, for tests.
#[cfg(test)]
pub(super) fn discovery_router_with(cache: Arc<DiscoveryCache>) -> Router<Arc<AppState>> {
    discovery_router().layer(Extension(cache))
}

/// The cache a request reads: one a test router injected, else the
/// gateway's shared one.
fn cache_for(
    state: &AppState,
    injected: Option<Extension<Arc<DiscoveryCache>>>,
) -> Option<Arc<DiscoveryCache>> {
    injected
        .map(|Extension(cache)| cache)
        .or_else(|| state.meta_mcp.discovery_cache().cloned())
}

/// The answer while no discovery cache is attached.
fn discovery_unavailable() -> Response {
    flat_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "discovery is not available",
    )
    .into_response()
}

/// Why `find` cannot be adopted under this gateway.yaml, beyond the adopt
/// rule's own refusals.
fn name_refusal(gateway: &Gateway, name: &str) -> Option<&'static str> {
    let Gateway::File { config, .. } = gateway else {
        return Some("no_config_file");
    };
    if config.backends.contains_key(name) {
        Some("managed")
    } else if config.capabilities.name == name {
        Some("capabilities_name")
    } else if validate_backend_name(name).is_err() {
        Some("invalid_name")
    } else {
        None
    }
}

/// Whether `find` is an adopt decision under this gateway.yaml: the rule the
/// route shows as `adoptable`, one rule for both.
fn adopt_eligible(find: &ListedFind, gateway: &Gateway) -> bool {
    find.refusals.is_empty() && name_refusal(gateway, &find.name).is_none()
}

/// The adopt decisions in `listing` under the gateway.yaml at `config_path`.
/// A gateway.yaml that cannot be loaded makes none: nothing could be
/// adopted into it. Read quietly: the decision set's tick reads it every
/// pass, and the route already logs a file it cannot load.
pub(super) fn adopt_finds(
    listing: &Listing,
    config_path: Option<&Path>,
) -> Vec<crate::decisions::AdoptFind> {
    let Ok(gateway) = load_gateway(config_path) else {
        return Vec::new();
    };
    listing
        .finds
        .iter()
        .filter(|find| adopt_eligible(find, &gateway))
        .map(|find| crate::decisions::AdoptFind {
            find_id: find.find_id.clone(),
            name: find.name.clone(),
            source: find.source.clone(),
            config_file: find.config_file.clone(),
            transport: find.transport,
            command: find.command.clone(),
            url: find.url.clone(),
            severity: find.severity.clone(),
        })
        .collect()
}

fn listed(find: &ListedFind, gateway: &Gateway) -> serde_json::Value {
    let mut refusals: Vec<Refusal> = find.refusals.clone();
    let name = name_refusal(gateway, &find.name);
    if let Some(reason) = name {
        refusals.push(Refusal {
            reason,
            field: "name".to_string(),
        });
    }
    let mut value = serde_json::to_value(find).unwrap_or_default();
    if let Some(object) = value.as_object_mut() {
        object.insert("managed".into(), json!(name == Some("managed")));
        object.insert("adoptable".into(), json!(refusals.is_empty()));
        object.insert("refusals".into(), json!(refusals));
    }
    value
}

async fn list_discovery(
    State(state): State<Arc<AppState>>,
    injected: Option<Extension<Arc<DiscoveryCache>>>,
    guard: Guard,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let Some(cache) = cache_for(&state, injected) else {
        return discovery_unavailable();
    };
    let path = state.config_path.clone();
    let gateway =
        match tokio::task::spawn_blocking(move || read_gateway("discovery", path.as_deref())).await
        {
            Ok(Ok(gateway)) => gateway,
            Ok(Err(message)) => {
                return flat_error(StatusCode::SERVICE_UNAVAILABLE, message).into_response();
            }
            Err(_) => {
                return flat_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "gateway.yaml could not be loaded",
                )
                .into_response();
            }
        };
    let Ok((listing, outdated)) = cache.listing().await else {
        return flat_error(StatusCode::SERVICE_UNAVAILABLE, "discovery scan timed out")
            .into_response();
    };

    (
        [(header::CACHE_CONTROL, "no-store")],
        axum::Json(body(&gateway, &listing, outdated)),
    )
        .into_response()
}

/// The response for one read of gateway.yaml and one cached listing.
fn body(gateway: &Gateway, listing: &Listing, outdated: bool) -> serde_json::Value {
    let servers: Vec<serde_json::Value> = listing
        .finds
        .iter()
        .map(|find| listed(find, gateway))
        .collect();
    // The radar counts the finds not already backends, by severity.
    let mut counts: BTreeMap<ShadowRiskSeverity, usize> = BTreeMap::new();
    let mut findings = Vec::new();
    for find in &listing.finds {
        if name_refusal(gateway, &find.name) == Some("managed") {
            continue;
        }
        *counts.entry(find.severity.clone()).or_default() += 1;
        findings.push(json!({"name": find.name, "severity": find.severity}));
    }
    let revision = match gateway {
        Gateway::File { revision, .. } => Some(revision.as_str().to_owned()),
        Gateway::None => None,
    };
    let unreadable: Vec<serde_json::Value> = listing
        .unreadable
        .iter()
        .map(|file| json!({"source": file.source, "file": file.file}))
        .collect();
    json!({
        "revision": revision,
        "stale": outdated,
        "servers": servers,
        "unreadable_files": unreadable,
        "radar": {"counts": counts, "findings": findings},
    })
}

#[path = "discovery_adopt.rs"]
mod adopt;

#[cfg(test)]
#[path = "discovery_tests.rs"]
mod tests;
