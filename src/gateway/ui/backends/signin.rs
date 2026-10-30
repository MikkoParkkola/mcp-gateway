// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Starting and confirming a person's sign-in to an OAuth backend.
//!
//! Implements:
//!   POST `/ui/api/backends/:name/signin`          — start a sign-in
//!   POST `/ui/api/backends/:name/signin/confirm`  — confirm or cancel it
//!
//! Skeleton: both handlers answer a fixed placeholder under the admin guard.

use axum::Json;
use axum::extract::{Extension, Path as AxumPath};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::ui::errors::admin_auth_required;
use crate::gateway::ui::is_admin;

/// `POST /ui/api/backends/:name/signin` — start a sign-in.
pub(super) async fn start_sign_in(
    client: Option<Extension<AuthenticatedClient>>,
    AxumPath(_name): AxumPath<String>,
) -> Response {
    placeholder(client)
}

/// `POST /ui/api/backends/:name/signin/confirm` — confirm or cancel it.
pub(super) async fn confirm_sign_in(
    client: Option<Extension<AuthenticatedClient>>,
    AxumPath(_name): AxumPath<String>,
) -> Response {
    placeholder(client)
}

/// The fixed answer of an unbuilt route: the admin guard, then 501.
fn placeholder(client: Option<Extension<AuthenticatedClient>>) -> Response {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        return admin_auth_required().into_response();
    }
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({ "skeleton": true })),
    )
        .into_response()
}

/// Whether `authority` (the request's URI authority, else its `Host`) names
/// the gateway host itself: a loopback name or address, with any port.
// Skeleton value: wrong on purpose.
#[allow(dead_code, reason = "skeleton: the start route calls it once built")]
fn is_gateway_host_authority(_authority: &str) -> bool {
    false
}

#[cfg(test)]
#[path = "signin_gate_tests.rs"]
mod gate_tests;

#[cfg(test)]
#[path = "signin_fixture.rs"]
mod fixture;
#[cfg(test)]
#[path = "signin_tests.rs"]
mod tests;
