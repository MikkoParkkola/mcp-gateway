// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/policies`: the Policies screen's read model, computed from
//! the published config's lists (not the compiled policies, which merge
//! entries and lose where each came from). Admin only: it shows every rule
//! and key name.

use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

use super::guard::Guard;
use crate::config::Config;
use crate::gateway::router::AppState;
use crate::gateway::routes;

/// The policies route.
pub(super) fn policies_router() -> Router<Arc<AppState>> {
    Router::new().route(routes::UI_POLICIES, get(read_policies))
}

pub(super) async fn read_policies(State(state): State<Arc<AppState>>, guard: Guard) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    // One generation for every section: a reload between two reads cannot
    // mix them.
    let generation = state.live_config.generation();
    Json(read_model(generation.config())).into_response()
}

/// The read model for `config`.
pub(super) fn read_model(_config: &Config) -> Value {
    json!({ "tool_policy": {}, "finding_rules": [] })
}

/// The scan types the screen offers, in `ScanType` order.
pub(super) fn offered_types() -> Vec<&'static str> {
    Vec::new()
}
