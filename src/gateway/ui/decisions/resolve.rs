// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/api/decisions/{id}/resolve`: an administrator resolves one open
//! access request. The permission comes first, the body is strict, one
//! resolve runs at a time, and the request is judged from one snapshot
//! against the scope digest the administrator was shown. A deny records one
//! governance audit event and folds it into the set at once.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path as RoutePath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{Value, json};

use super::super::control_plane::mutations::admitted_actor;
use super::super::guard::Guard;
use super::unavailable;
use crate::config_reload::Generation;
use crate::control_plane::{
    ControlPlaneAction, ControlPlaneAuditEvent, ControlPlaneRbac, ControlPlaneRollbackPlan,
};
use crate::decisions::{
    Lookup, OpenRequest, Outcome, Shared, decision_record, decisions_of, event_id,
};
use crate::gateway::router::AppState;

/// What a resolve may ask of an open decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ResolveAction {
    Accept,
    Deny,
}

/// The resolve body: strict, so a field this route does not know is refused
/// and never read as something it is not.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveRequest {
    action: ResolveAction,
    reason: String,
    scope_digest: String,
    ttl_seconds: Option<u64>,
    #[serde(default)]
    permanent: bool,
}

/// The longest reason a resolve takes, in characters.
const REASON_MAX: usize = 500;
/// The longest grant an accept may ask for: one year.
const TTL_MAX_SECONDS: u64 = 365 * 24 * 60 * 60;

/// One refusal answer: a status, a code a client branches on, and a fixed
/// sentence. Nothing the caller sent is echoed back.
fn resolve_error(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({"error": code, "message": message}))).into_response()
}

/// The body's own rules, apart from the open item it names.
fn check_resolve(request: &ResolveRequest) -> Result<(), &'static str> {
    // Control characters are refused anywhere, a trailing newline too:
    // the check reads the reason as sent, before any trim.
    if request.reason.chars().any(char::is_control) {
        return Err("the reason must not contain control characters");
    }
    let reason = request.reason.trim();
    if reason.is_empty() || reason.chars().count() > REASON_MAX {
        return Err("the reason must be 1 to 500 characters");
    }
    // Lowercase only, as the listing writes it: an uppercase copy would
    // otherwise pass here and then read as a changed request.
    let digest = request.scope_digest.as_str();
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("scope_digest must be the 64 hex characters the listing gave");
    }
    match (request.action, request.ttl_seconds, request.permanent) {
        (ResolveAction::Accept, Some(ttl), false) if (1..=TTL_MAX_SECONDS).contains(&ttl) => Ok(()),
        (ResolveAction::Accept, None, true) | (ResolveAction::Deny, None, false) => Ok(()),
        (ResolveAction::Accept, ..) => {
            Err("an accept needs ttl_seconds (1 second to 1 year) or permanent: true, not both")
        }
        (ResolveAction::Deny, ..) => Err("a deny takes no ttl_seconds and no permanent"),
    }
}

/// `POST /ui/api/decisions/{id}/resolve`: resolve one open access request.
///
/// This slice is the frame: the strict body, one status per state, the
/// permission, the resolve mutex and the scope check against one snapshot.
/// Neither action has an effect yet; the siblings add accept and deny.
pub(super) async fn resolve_decision(
    State(state): State<Arc<AppState>>,
    Extension(generation): Extension<Arc<Generation>>,
    guard: Guard,
    RoutePath(id): RoutePath<String>,
    body: Bytes,
) -> Response {
    // The permission first: a caller without it learns nothing and writes
    // nothing, whatever the body says. The row names the action; the role
    // the request's pinned generation maps must allow it.
    let (actor, action) = match admitted_actor(&generation, &guard) {
        Ok(admitted) => admitted,
        Err(refused) => return *refused,
    };
    let authorization = ControlPlaneRbac::authorize(&actor, action);
    if !authorization.allowed {
        return resolve_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "this caller may not resolve access requests",
        );
    }
    let request: ResolveRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return resolve_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "invalid_body",
                "the body is not a valid resolve request",
            );
        }
    };
    if let Err(message) = check_resolve(&request) {
        return resolve_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_body", message);
    }
    let Some(decisions) = state.meta_mcp.decisions() else {
        return unavailable(&[]);
    };
    // One resolve at a time: the item is read, judged and written under this
    // mutex, so a second resolve of an id sees what the first one did.
    let _resolving = decisions.resolving().await;
    let open = match decisions.request(&id) {
        Err(sources) => return unavailable(&sources),
        // Gone: resolved here before (a retry gets what was recorded), or
        // never open.
        Ok(None) => {
            return match decisions.outcome(&id, &request.scope_digest) {
                Some(done) => answer_again(&done, &request),
                None if decisions.resolved(&id) => already_resolved(),
                None => resolve_error(
                    StatusCode::NOT_FOUND,
                    "not_found",
                    "no open decision has this id",
                ),
            };
        }
        Ok(Some(Lookup::Other)) => {
            return resolve_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "not_resolvable",
                "only access requests can be resolved here yet",
            );
        }
        Ok(Some(Lookup::Access(open))) => open,
    };
    // A later refusal reopens a denied request under the same id with a new
    // digest: a retry naming the old digest gets the old outcome, and the
    // reopened request can be denied afresh.
    if let Some(done) = decisions.outcome(&id, &request.scope_digest) {
        return answer_again(&done, &request);
    }
    if let Some(changed) = check_scope(&open, &request.scope_digest) {
        return changed;
    }
    match request.action {
        ResolveAction::Deny => deny(&state, decisions, &actor, &id, &open, &request),
        ResolveAction::Accept => resolve_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "not_available_yet",
            "accepting an access request is not available yet",
        ),
    }
}

/// The scope the admin was shown against the request as it is now: a
/// request that changed since is answered with what it is now, and nothing
/// is written.
fn check_scope(open: &OpenRequest, scope_digest: &str) -> Option<Response> {
    let current = open
        .item
        .get("scope_digest")
        .and_then(Value::as_str)
        .unwrap_or_default();
    (current != scope_digest).then(|| {
        (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "scope_changed",
                "message": "the request changed since it was listed; nothing was written",
                "scope": open.item.get("scope").cloned().unwrap_or(Value::Null),
                "scope_digest": current,
            })),
        )
            .into_response()
    })
}

/// A retry of a resolve recorded at this scope digest: a deny gets the
/// recorded outcome and nothing is written; any other action conflicts.
fn answer_again(done: &Outcome, request: &ResolveRequest) -> Response {
    if request.action == ResolveAction::Deny {
        return Json(json!({
            "ok": true,
            "action": "deny",
            "event_id": done.event_id,
            "already_recorded": true,
        }))
        .into_response();
    }
    already_resolved()
}

/// A resolve of an id resolved here at another digest, or with another action.
fn already_resolved() -> Response {
    resolve_error(
        StatusCode::CONFLICT,
        "already_resolved",
        "this request was already resolved",
    )
}

/// The most refusals one deny note names: it must fit one log record.
const MAX_DENY_POSITIONS: usize = 20_000;

/// Deny `open`: write one governance audit record naming every refusal the
/// admin was shown, then fold it into the set. The write and the fold run
/// with no await between them, so a dropped request cannot leave a record
/// the set does not know; a replay of the record later changes nothing.
fn deny(
    state: &AppState,
    decisions: &Shared,
    actor: &crate::control_plane::ControlPlaneActor,
    id: &str,
    open: &OpenRequest,
    request: &ResolveRequest,
) -> Response {
    let total: usize = open
        .entries
        .iter()
        .map(|(_, positions)| positions.len())
        .sum();
    if total > MAX_DENY_POSITIONS {
        return resolve_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "request_too_large",
            "too many refusals to resolve at once",
        );
    }
    let Some(store) = state.control_plane_store.as_ref() else {
        return audit_unavailable();
    };
    let event_id = event_id(open);
    // The admin audit stream every grant decision goes to, under the
    // grant-mutation action: who denied what sits beside who granted what.
    let event = ControlPlaneAuditEvent {
        event_id: event_id.clone(),
        actor_id: actor.actor_id.clone(),
        action: ControlPlaneAction::MutateGrant,
        target_id: format!("access_request:{}", open.agent),
        reason: request.reason.trim().to_owned(),
        rollback: ControlPlaneRollbackPlan {
            summary: "a decline grants and revokes nothing".to_owned(),
            step:
                "grant the capability to allow the agent; a later refusal also reopens the request"
                    .to_owned(),
        },
        grant_change: None,
        ui_decision: Some(decision_record(open, &request.scope_digest)),
    };
    if store.append_audit(&event).is_err() {
        return audit_unavailable();
    }
    decisions.update(|set| set.apply_decisions(decisions_of(open)));
    decisions.remember(
        id,
        Outcome {
            event_id: event_id.clone(),
            scope_digest: request.scope_digest.clone(),
        },
    );
    Json(json!({"ok": true, "action": "deny", "event_id": event_id})).into_response()
}

/// The answer when the record could not be written: nothing was folded.
fn audit_unavailable() -> Response {
    resolve_error(
        StatusCode::SERVICE_UNAVAILABLE,
        "audit_unavailable",
        "the decision could not be recorded; nothing was changed",
    )
}
