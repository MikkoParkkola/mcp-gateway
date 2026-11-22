// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The config history routes: the kept versions and reload events (GET),
//! and an admin's restore of one kept version's gateway.yaml (POST) through
//! the shared audited writer.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use super::errors::flat_error;
use super::guard::Guard;
use crate::gateway::router::AppState;
use crate::gateway::routes;

/// Both routes, merged into the UI's API router.
pub(super) fn config_history_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(routes::UI_CONFIG_HISTORY, get(history))
        .route(routes::UI_CONFIG_RESTORE, post(restore))
}

/// Red-run stub: admits the caller, then answers a status no row expects.
async fn history(State(_state): State<Arc<AppState>>, guard: Guard) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    flat_error(StatusCode::NOT_IMPLEMENTED, "not built yet").into_response()
}

/// Red-run stub: admits the caller, then answers a status no row expects.
async fn restore(State(_state): State<Arc<AppState>>, guard: Guard) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    flat_error(StatusCode::NOT_IMPLEMENTED, "not built yet").into_response()
}
