// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Read-only control-plane API surface.

use super::super::auth::AuthenticatedClient;
use super::super::router::AppState;
use super::errors::{auth_required, flat_error};
use crate::control_plane::role_mapping::ControlPlaneBaseSource;
use crate::control_plane::{ControlPlaneAction, ControlPlaneRbac};
use crate::gateway::routes;
use crate::key_server::oidc::VerifiedIdentity;
use axum::extract::{Extension, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use std::sync::Arc;

#[cfg(test)]
use crate::control_plane::{ControlPlaneHealth, ControlPlaneServerStatus};

#[cfg(test)]
mod grant_projection_tests;
mod mutations;
#[cfg(test)]
mod read_reflect_tests;
#[cfg(test)]
mod role_wiring_tests;
mod snapshot;

#[cfg(test)]
use mutations::{
    Decision, DecisionRequest, GRANT_WRITES_REFUSED, apply_mutation, resolve_decision_core,
};
use mutations::{
    actor_from_client, mutate_grant, mutate_policy, mutation_disabled_reason, resolve_decision,
};
use snapshot::{
    ControlPlaneApiResponse, ControlPlaneResponseFlags, local_runtime_snapshot, local_shadow_radar,
};
#[cfg(test)]
use snapshot::{
    control_plane_grant_from_identity, feature_entitlements, merge_store_into_snapshot,
    runtime_health_from_backend, server_status_from_backend,
};

/// Build the control-plane API router: a read-only snapshot plus the grant,
/// policy and decision write routes, which apply RBAC (MIK-6686) and then
/// refuse with 409 because dispatch never reads the store (E2-min).
pub fn control_plane_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(routes::UI_CONTROL_PLANE, get(control_plane_snapshot))
        .route(routes::UI_CONTROL_PLANE_GRANTS, post(mutate_grant))
        .route(routes::UI_CONTROL_PLANE_POLICIES, post(mutate_policy))
        .route(routes::UI_CONTROL_PLANE_DECISIONS, post(resolve_decision))
        .route(
            routes::UI_CONTROL_PLANE_EXPORT_STATUS,
            get(export_status_handler),
        )
        // Governance data is refused to a caller that presented no credential,
        // as a LAYER rather than a check inside each handler. Every route here
        // derives an actor from the client, and filtering one field of the
        // result missed the rest; a layer also cannot be forgotten when a sixth
        // route is added.
        .layer(axum::middleware::from_fn(require_authenticated))
}

/// Refuse a caller that presented no credential.
///
/// The anonymous identity used when authentication is disabled, and the
/// identity given to a public path, both carry `authenticated: false`.
async fn require_authenticated(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let authenticated = request
        .extensions()
        .get::<AuthenticatedClient>()
        .is_some_and(|c| c.authenticated);
    if !authenticated {
        return auth_required(StatusCode::FORBIDDEN).into_response();
    }
    next.run(request).await
}

/// GET the SIEM export status (MIK-6703 SIEM.RUN.2): per-source forwarded/lag/
/// max-lag/re-anchor/error counters. Requires read-inventory RBAC. Returns 404
/// (via a `configured: false` body) when export is not running.
async fn export_status_handler(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    identity: Option<Extension<VerifiedIdentity>>,
) -> impl IntoResponse {
    let actor = actor_from_client(
        client.map(|Extension(c)| c).as_ref(),
        identity.map(|Extension(id)| id).as_ref(),
        &state.live_config.get().control_plane.role_mapping,
    );
    if !ControlPlaneRbac::authorize(&actor, ControlPlaneAction::ReadInventory).allowed {
        return auth_required(StatusCode::FORBIDDEN).into_response();
    }
    match state.export_status.as_ref() {
        Some(status) => Json(serde_json::json!({
            "configured": true,
            "sources": status.snapshot(),
        }))
        .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "configured": false })),
        )
            .into_response(),
    }
}

async fn control_plane_snapshot(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    identity: Option<Extension<VerifiedIdentity>>,
) -> impl IntoResponse {
    let client = client.map(|Extension(client)| client);
    let identity = identity.map(|Extension(id)| id);
    let actor = actor_from_client(
        client.as_ref(),
        identity.as_ref(),
        &state.live_config.get().control_plane.role_mapping,
    );
    // Grant status is judged against the time; on a clock before 1970 it
    // cannot be, so the view is refused rather than guessed (MIK-8202).
    let Ok(now) = crate::clock::utc_now() else {
        return flat_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "host clock reads before 1970: grant status cannot be judged",
        )
        .into_response();
    };
    let (snapshot, store_read_degraded) =
        local_runtime_snapshot(&state, client.as_ref(), &actor, now);
    let shadow_radar = local_shadow_radar(&state).await;

    let Some(view) = snapshot.read_only_view(&actor) else {
        return auth_required(StatusCode::FORBIDDEN).into_response();
    };
    let Some(decision_queue) = snapshot.decision_queue(&actor) else {
        return auth_required(StatusCode::FORBIDDEN).into_response();
    };

    let response = ControlPlaneApiResponse::from_snapshot(
        actor,
        &snapshot,
        view,
        decision_queue,
        shadow_radar,
        &ControlPlaneResponseFlags {
            // Dispatch reads grants and policies from config, never from the
            // store, so no write here is ever enforced: the route is read-only
            // even while the store is open for the audit log (E2-min).
            mutation_enabled: false,
            mutation_disabled_reason: mutation_disabled_reason(&state),
            base_source: state
                .control_plane_base
                .as_ref()
                .map_or(ControlPlaneBaseSource::Default, |base| base.source),
            store_read_degraded,
            export_configured: state.export_status.is_some(),
        },
    );
    Json(response).into_response()
}

#[cfg(test)]
#[path = "control_plane_mutation_tests.rs"]
mod mutation_tests;

#[cfg(test)]
#[path = "control_plane_authority_tests.rs"]
mod authority_tests;

#[cfg(test)]
#[path = "control_plane_preflight_tests.rs"]
mod preflight_tests;

/// B6 (MIK-7570.BREAKER.1): an open breaker reads `Down` and `Blocked`,
/// through the real `Backend::status()`, never a hand-built status.
#[cfg(test)]
#[path = "control_plane_breaker_tests.rs"]
mod breaker_tests;
