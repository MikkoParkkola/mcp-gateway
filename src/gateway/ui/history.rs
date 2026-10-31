// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/metrics/series` and `GET /ui/api/markers`: the web
//! UI's history, read from the counter store. Admin only: no credential is
//! 401, a non-admin credential 403, as the other admin UI routes answer.

use std::sync::Arc;

use axum::extract::{Query as Params, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use super::guard::Guard;
use crate::counters::{Dim, Filter, Metric, Query, Window};
use crate::gateway::router::AppState;
use crate::gateway::routes;

/// The filter combinations a series read accepts, named in every refusal.
const SUPPORTED_FILTERS: &str = "supported filters: none; server; server and tool; caller; \
                                 caller and server; overflow=server|tool|caller|caller_server";

/// The history routes.
pub(super) fn history_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(routes::UI_METRICS_SERIES, get(series))
        .route(routes::UI_MARKERS, get(markers))
}

/// `GET /ui/api/metrics/series` query parameters, all optional strings so a
/// bad value is refused with the allowed ones, never silently defaulted.
#[derive(Debug, Default, Deserialize)]
pub(super) struct SeriesParams {
    metric: Option<String>,
    window: Option<String>,
    compare: Option<String>,
    server: Option<String>,
    tool: Option<String>,
    caller: Option<String>,
    overflow: Option<String>,
}

/// The read `params` name, or why it is refused.
pub(super) fn parse(params: &SeriesParams) -> Result<Query<'_>, String> {
    let metric = match params.metric.as_deref().unwrap_or("calls") {
        "calls" => Metric::Calls,
        "blocks" => Metric::Blocks,
        "errors" => Metric::Errors,
        "firewall" => Metric::Firewall,
        "cache_hits" => Metric::CacheHits,
        other => {
            return Err(format!(
                "metric {other:?}: must be one of calls, blocks, errors, firewall, cache_hits"
            ));
        }
    };
    let window = match params.window.as_deref().unwrap_or("24h") {
        "24h" => Window::Day,
        "48h" => Window::TwoDays,
        "30d" => Window::Month,
        other => return Err(format!("window {other:?}: must be one of 24h, 48h, 30d")),
    };
    let compare = match params.compare.as_deref() {
        None => false,
        Some("prev") => true,
        Some(other) => return Err(format!("compare {other:?}: must be prev")),
    };
    if compare && window != Window::Day {
        return Err("compare=prev is supported for window=24h only".to_owned());
    }
    let filter = match (
        params.server.as_deref(),
        params.tool.as_deref(),
        params.caller.as_deref(),
        params.overflow.as_deref(),
    ) {
        (None, None, None, None) => Filter::All,
        (Some(server), None, None, None) => Filter::Server(server),
        (Some(server), Some(tool), None, None) => Filter::Tool(server, tool),
        (None, None, Some(caller), None) => Filter::Caller(caller),
        (Some(server), None, Some(caller), None) => Filter::CallerServer(caller, server),
        (None, None, None, Some(dim)) => Filter::Overflow(match dim {
            "server" => Dim::Server,
            "tool" => Dim::Tool,
            "caller" => Dim::Caller,
            "caller_server" => Dim::CallerServer,
            other => return Err(format!("overflow {other:?}: {SUPPORTED_FILTERS}")),
        }),
        _ => return Err(SUPPORTED_FILTERS.to_owned()),
    };
    Ok(Query {
        metric,
        window,
        filter,
        compare,
    })
}

fn unavailable(why: &str) -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error": why}))).into_response()
}

/// The host zone's current offset, so the UI can print the days' zone.
fn zone() -> String {
    crate::clock::utc_now().map_or_else(
        |_| String::new(),
        |now| {
            use chrono::Offset as _;
            now.with_timezone(&crate::local_day::host_zone())
                .offset()
                .fix()
                .to_string()
        },
    )
}

async fn series(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    Params(params): Params<SeriesParams>,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let query = match parse(&params) {
        Ok(query) => query,
        Err(why) => return (StatusCode::BAD_REQUEST, Json(json!({"error": why}))).into_response(),
    };
    let Some(store) = state.meta_mcp.counters() else {
        return unavailable("call counters are not running");
    };
    let Ok(now) = crate::clock::unix_secs() else {
        return unavailable("the system clock reads before 1970");
    };
    let view = store.series(&query, now, &crate::local_day::host_zone());
    let (bucket_secs, day_basis) = match query.window {
        Window::Day | Window::TwoDays => (Some(crate::counters::HALF), None),
        Window::Month => (None, Some("local")),
    };
    Json(json!({
        "metric": params.metric.as_deref().unwrap_or("calls"),
        "window": params.window.as_deref().unwrap_or("24h"),
        "bucket_secs": bucket_secs,
        "day_basis": day_basis,
        "zone": zone(),
        "since": view.since,
        "folded": view.folded,
        "points": view.points,
        "previous": view.previous,
        "previous_complete": view.previous_complete,
    }))
    .into_response()
}

/// `GET /ui/api/markers` query parameters.
#[derive(Debug, Default, Deserialize)]
struct MarkerParams {
    from: Option<u64>,
}

async fn markers(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    Params(params): Params<MarkerParams>,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let Some(store) = state.meta_mcp.counters() else {
        return unavailable("call counters are not running");
    };
    let markers: Vec<_> = store
        .markers(params.from.unwrap_or(0))
        .into_iter()
        .map(|m| json!({"t": m.at, "kind": m.kind, "subject": m.subject}))
        .collect();
    Json(markers).into_response()
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
