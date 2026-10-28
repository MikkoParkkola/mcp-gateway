// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/stream`: the UI's live event feed (ADR-020).

mod guard;
mod id;
mod merge;

#[cfg(test)]
mod guard_tests;
#[cfg(test)]
mod id_tests;
#[cfg(test)]
mod merge_tests;

use std::sync::Arc;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;

pub(crate) use self::guard::{MAX_PER_CREDENTIAL, MAX_UI_STREAMS, StreamHub};
use crate::gateway::router::AppState;
use crate::gateway::routes;

/// The stream route.
pub(super) fn stream_router() -> Router<Arc<AppState>> {
    Router::new().route(routes::UI_STREAM, get(stream))
}

async fn stream() -> StatusCode {
    StatusCode::NOT_IMPLEMENTED
}
