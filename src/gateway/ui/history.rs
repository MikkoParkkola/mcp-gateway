// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8854 red stub for the history routes: no role check, every query read
//! as the global calls series, the asked server echoed back, no markers.

use std::sync::Arc;

use axum::extract::Query as Params;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::counters::{Filter, Metric, Query, Window};
use crate::gateway::router::AppState;
use crate::gateway::routes;

pub(super) fn history_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(routes::UI_METRICS_SERIES, get(series))
        .route(routes::UI_MARKERS, get(markers))
}

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

pub(super) fn parse(_params: &SeriesParams) -> Result<Query<'_>, String> {
    Ok(Query::new(Metric::Calls, Window::Day, Filter::All))
}

async fn series(Params(params): Params<SeriesParams>) -> Response {
    let _ = (
        &params.metric,
        &params.window,
        &params.compare,
        &params.tool,
        &params.caller,
        &params.overflow,
    );
    Json(json!({"server": params.server})).into_response()
}

async fn markers() -> Response {
    Json(json!([])).into_response()
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
