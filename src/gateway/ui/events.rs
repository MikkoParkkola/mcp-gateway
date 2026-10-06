// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Dead-letter administration for MCP Events (MIK-7630, design §3.8, §18):
//!
//!   GET  `/ui/api/events/dead-letters`                    — list
//!   POST `/ui/api/events/dead-letters/{id}/replay`        — replay one
//!   POST `/ui/api/events/dead-letters/replay?all=1&subscription=S` — replay a subscription's
//!
//! Admin only. Never a meta-tool: the meta surface is pinned.

use crate::gateway::routes;
use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use super::errors::{admin_auth_required, flat_error};
use super::is_admin;
use crate::events::{Actor, EventsHub, ReplayRefusal, is_dead_reason};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::router::AppState;
use crate::identity_grants::GrantSubject;
use crate::key_server::oidc::VerifiedIdentity;
use crate::security::audit::AuditWho;

pub(super) fn events_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(routes::UI_DEAD_LETTERS, get(list))
        .route(routes::UI_DEAD_LETTERS_REPLAY, post(replay_all))
        .route(routes::UI_DEAD_LETTER_REPLAY, post(replay_one))
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    subscription: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BulkQuery {
    all: Option<String>,
    subscription: Option<String>,
}

/// The hub for an admin caller, or the answer that refuses the request.
fn admitted(
    state: &AppState,
    client: Option<Extension<AuthenticatedClient>>,
    identity: Option<Extension<VerifiedIdentity>>,
) -> Result<(Arc<EventsHub>, Actor), Box<axum::response::Response>> {
    let client = client.map(|Extension(c)| c);
    if !is_admin(client.as_ref()) {
        return Err(Box::new(admin_auth_required().into_response()));
    }
    // `is_admin` holds only for an authenticated client. (issuer, subject)
    // only, never the email label, as the admin audit layer names an SSO admin.
    let subject = identity
        .map(|Extension(id)| id)
        .filter(|id| !id.issuer.is_empty() && !id.subject.is_empty())
        .map(|id| GrantSubject::new(id.issuer, id.subject, None));
    let actor = client.map(|c| Actor {
        who: AuditWho::from_request(Some(&c), subject.as_ref()),
    });
    let (Some(actor), Some(hub)) = (actor, state.meta_mcp.events()) else {
        return Err(Box::new(
            flat_error(StatusCode::NOT_FOUND, "Events are not enabled").into_response(),
        ));
    };
    Ok((Arc::clone(hub), actor))
}

fn refusal(why: ReplayRefusal) -> axum::response::Response {
    let status = match why {
        ReplayRefusal::NotFound => StatusCode::NOT_FOUND,
        ReplayRefusal::OutboxFull | ReplayRefusal::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::CONFLICT,
    };
    (
        status,
        Json(json!({"error": "replay refused", "reason": why.as_str()})),
    )
        .into_response()
}

async fn list(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    identity: Option<Extension<VerifiedIdentity>>,
    Query(query): Query<ListQuery>,
) -> axum::response::Response {
    let (hub, _) = match admitted(&state, client, identity) {
        Ok(admitted) => admitted,
        Err(answer) => return *answer,
    };
    if query.reason.as_deref().is_some_and(|r| !is_dead_reason(r)) {
        return flat_error(StatusCode::BAD_REQUEST, "Unknown dead-letter reason").into_response();
    }
    let entries = hub.list_dead_letters(query.subscription.as_deref(), query.reason.as_deref());
    Json(json!({ "deadLetters": entries })).into_response()
}

async fn replay_one(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    identity: Option<Extension<VerifiedIdentity>>,
    Path(id): Path<String>,
) -> axum::response::Response {
    let (hub, actor) = match admitted(&state, client, identity) {
        Ok(admitted) => admitted,
        Err(answer) => return *answer,
    };
    match hub.replay_dead(&id, &actor).await {
        Ok(()) => Json(json!({"eventId": id, "status": "queued"})).into_response(),
        Err(why) => refusal(why),
    }
}

async fn replay_all(
    State(state): State<Arc<AppState>>,
    client: Option<Extension<AuthenticatedClient>>,
    identity: Option<Extension<VerifiedIdentity>>,
    Query(query): Query<BulkQuery>,
) -> axum::response::Response {
    let (hub, actor) = match admitted(&state, client, identity) {
        Ok(admitted) => admitted,
        Err(answer) => return *answer,
    };
    let (Some("1"), Some(subscription)) = (query.all.as_deref(), query.subscription.as_deref())
    else {
        return flat_error(
            StatusCode::BAD_REQUEST,
            "Bulk replay needs all=1 and a subscription",
        )
        .into_response();
    };
    let (replayed, refused) = hub.replay_all(subscription, &actor).await;
    let refused: Vec<_> = refused
        .into_iter()
        .map(|(id, why)| json!({"eventId": id, "reason": why.as_str()}))
        .collect();
    Json(json!({"replayed": replayed, "refused": refused})).into_response()
}
