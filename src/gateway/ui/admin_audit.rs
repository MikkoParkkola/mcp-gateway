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

/// Fields a handler adds to its own `admin_action` record, carried on its
/// response. Names and values the record may hold (never a secret): bodies
/// are otherwise never logged.
#[derive(Clone)]
pub(super) struct AuditDetail(pub(super) serde_json::Map<String, serde_json::Value>);

/// Routes that only read, whatever their method, so the layer neither
/// admits nor records them: keyed by the matched route template, never by a
/// handler, so a handler bug cannot make a write skip the audit.
/// `POST .../validate` writes nothing by construction (its handler has no
/// writer).
const UNRECORDED_ROUTES: &[&str] = &[crate::gateway::routes::UI_CAPABILITY_VALIDATE];

/// Record a change of `name`'s `allowed_tools` on its `admin_action` record:
/// the backend and the list before and after (`null`: every tool).
pub(super) fn attach_selection(
    response: &mut Response,
    name: &str,
    before: Option<&[String]>,
    after: Option<&[String]>,
) {
    let mut detail = serde_json::Map::new();
    detail.insert(
        "allowed_tools".into(),
        serde_json::json!({"backend": name, "before": before, "after": after}),
    );
    response.extensions_mut().insert(AuditDetail(detail));
}

/// [`super::api_router`] with the layer on every route in it (E1-f).
pub fn audited_api_router(state: &Arc<AppState>) -> Router<Arc<AppState>> {
    super::api_router().route_layer(axum::middleware::from_fn_with_state(
        Arc::clone(state),
        admin_action_layer,
    ))
}

/// The layer. With no audit log configured it passes every request through.
/// A refusal is counted on every path (D4), from the handler's own answer.
async fn admin_action_layer(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    // Control-plane pages are refused by their RBAC, and are their own route.
    let control_plane = request
        .extensions()
        .get::<MatchedPath>()
        .is_some_and(|p| p.as_str().starts_with("/ui/api/control-plane"));
    let run = |request| async move {
        let response = next.run(request).await;
        if matches!(
            response.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ) {
            use crate::security::security_metrics::{DenialReason, DenialRoute, denied};
            if control_plane {
                denied(DenialRoute::ControlPlane, DenialReason::Rbac);
            } else {
                denied(DenialRoute::Ui, DenialReason::AdminRequired);
            }
        }
        response
    };
    let Some(log) = state.transparency_log.clone() else {
        return run(request).await;
    };
    let unrecorded = request
        .extensions()
        .get::<MatchedPath>()
        .is_some_and(|p| UNRECORDED_ROUTES.contains(&p.as_str()));
    if unrecorded || matches!(*request.method(), Method::GET | Method::HEAD) {
        return run(request).await;
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
    fields.insert("route".into(), route.unwrap_or_default().into());
    fields.insert("method".into(), request.method().as_str().into());
    let client = request.extensions().get::<AuthenticatedClient>().cloned();
    // (issuer, subject) only, never the email label; a blank one names no one,
    // as in `router::identity::grant_subject_from_verified_identity`.
    let subject = request
        .extensions()
        .get::<VerifiedIdentity>()
        .and_then(|id| GrantSubject::checked(id.issuer.clone(), id.subject.clone(), None));

    let response = run(request).await;

    let status = response.status();
    fields.insert("http_status".into(), status.as_u16().into());
    if let Some(AuditDetail(detail)) = response.extensions().get::<AuditDetail>() {
        fields.extend(detail.clone());
    }
    let envelope = AuditEnvelope {
        outcome: AuditOutcome::from_http_status(status, None),
        ..AuditEnvelope::ok(AuditWho::from_request(
            client.as_ref(),
            subject.as_ref(),
            state.auth_config.record_key(),
        ))
    };
    match log.append_admin_action("admin_ui", fields, &envelope) {
        Ok(()) => response,
        Err(error) => withheld(&error),
    }
}

/// Append one `admin_action` for `surface` naming the caller, the way the
/// layer does: the capability editor's record of what a save changed (D5).
/// With no audit log configured there is nothing to append.
///
/// `Some` is the layer's 503 "withheld" answer, when the append failed.
pub(super) fn record_admin_action(
    state: &AppState,
    surface: &'static str,
    client: Option<&AuthenticatedClient>,
    identity: Option<&VerifiedIdentity>,
    fields: serde_json::Map<String, serde_json::Value>,
) -> Option<Response> {
    let log = state.transparency_log.as_ref()?;
    let subject =
        identity.and_then(|id| GrantSubject::checked(id.issuer.clone(), id.subject.clone(), None));
    let envelope = AuditEnvelope::ok(AuditWho::from_request(
        client,
        subject.as_ref(),
        state.auth_config.record_key(),
    ));
    log.append_admin_action(surface, fields, &envelope)
        .err()
        .map(|error| withheld(&error))
}

/// The `AuditUnavailable` answer: the action may have run, its result is
/// withheld (Revision 3 wording).
fn withheld(error: &crate::Error) -> Response {
    flat_error(StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response()
}
