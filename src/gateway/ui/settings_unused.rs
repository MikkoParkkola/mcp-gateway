// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unused secret entries for Gateway › Settings: list them, delete one at a time.
//! The delete holds the reload lock, the config sidecar and the vault lock, in that
//! order, and re-checks every naming source under them.

use std::sync::Arc;

use axum::extract::{Path, Query, State, rejection::QueryRejection};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::gateway::{router::AppState, ui::guard::Guard};

/// `?store=keychain|files` on a delete.
#[derive(Deserialize)]
pub(super) struct StoreQuery {
    pub(super) store: String,
}

/// `GET /ui/api/settings/secrets/unused`.
pub(super) async fn list_unused(State(_state): State<Arc<AppState>>, guard: Guard) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    StatusCode::NOT_IMPLEMENTED.into_response()
}

/// `DELETE /ui/api/settings/secrets/unused/{name}?store=...`.
pub(super) async fn delete_unused_entry(
    State(_state): State<Arc<AppState>>,
    guard: Guard,
    Path(_name): Path<String>,
    _query: Result<Query<StoreQuery>, QueryRejection>,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    StatusCode::NOT_IMPLEMENTED.into_response()
}
