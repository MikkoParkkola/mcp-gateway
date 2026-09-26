// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E1-f: one layer over the admin UI router. Every request other than `GET`
//! and `HEAD` is admitted by the audit log, run, and recorded as an
//! `admin_action` naming the caller. Control-plane POSTs are included: they
//! answer 409 and write no governance record (E2-min), so this is their only
//! record. The body and the query are never logged; the route is the matched
//! template, never the path.

use std::sync::Arc;

use axum::Router;
use axum::extract::{MatchedPath, Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use super::errors::flat_error;
use super::{AppState, AuthenticatedClient};
use crate::identity_grants::GrantSubject;
use crate::key_server::oidc::VerifiedIdentity;
use crate::security::audit::{AuditEnvelope, AuditOutcome, AuditWho};

/// [`super::api_router`] with the layer on every route in it (E1-f).
pub fn audited_api_router(state: &Arc<AppState>) -> Router<Arc<AppState>> {
    super::api_router().route_layer(axum::middleware::from_fn_with_state(
        Arc::clone(state),
        admin_action_layer,
    ))
}

/// The layer. With no audit log configured it passes every request through.
async fn admin_action_layer(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(log) = state.transparency_log.clone() else {
        return next.run(request).await;
    };
    if matches!(*request.method(), Method::GET | Method::HEAD) {
        return next.run(request).await;
    }
    // A degraded log refuses before the handler runs (D1-f).
    if let Err(error) = log.admit().await {
        return withheld(&error);
    }
    let mut fields = serde_json::Map::new();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(MatchedPath::as_str);
    let _ = route;
    fields.insert("route".into(), request.uri().to_string().into());
    fields.insert("method".into(), request.method().as_str().into());
    let client = request.extensions().get::<AuthenticatedClient>().cloned();
    // (issuer, subject) only, never the email label; a blank one names no one,
    // as in `router::identity::grant_subject_from_verified_identity`.
    let subject = request
        .extensions()
        .get::<VerifiedIdentity>()
        .filter(|id| !id.issuer.is_empty() && !id.subject.is_empty())
        .map(|id| GrantSubject::new(id.issuer.clone(), id.subject.clone(), None));

    let response = next.run(request).await;

    let status = response.status();
    fields.insert("http_status".into(), status.as_u16().into());
    let envelope = AuditEnvelope {
        outcome: AuditOutcome::from_http_status(status, None),
        ..AuditEnvelope::ok(AuditWho::from_request(client.as_ref(), subject.as_ref()))
    };
    match log.append_admin_action("admin_ui", fields, &envelope) {
        Ok(()) => response,
        Err(error) => withheld(&error),
    }
}

/// The `AuditUnavailable` answer: the action may have run, its result is
/// withheld (Revision 3 wording).
fn withheld(error: &crate::Error) -> Response {
    flat_error(StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response()
}
