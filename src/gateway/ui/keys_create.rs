// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/api/keys`: create an API key in gateway.yaml.

#[cfg(test)]
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::guard::Guard;

/// Under test, a request may carry the secret the route hands out, so a row
/// knows it and its digest.
#[cfg(test)]
#[derive(Clone)]
pub(super) struct KnownSecret(pub(super) String);

/// Under test, a request may carry a hook that runs after the route's checks
/// and before it asks the writer for the config lock.
#[cfg(test)]
#[derive(Clone)]
pub(super) struct BeforeLock(pub(super) Arc<dyn Fn() + Send + Sync>);

pub(super) async fn create_key(
    guard: Guard,
    #[cfg(test)] before_lock: Option<axum::Extension<BeforeLock>>,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    #[cfg(test)]
    if let Some(axum::Extension(hook)) = &before_lock {
        (hook.0)();
    }
    StatusCode::NOT_IMPLEMENTED.into_response()
}
