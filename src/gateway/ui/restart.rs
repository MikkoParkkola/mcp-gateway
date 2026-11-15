// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restart availability and an audited refusal; no process lifecycle changes.

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::extract::{RawQuery, State};
use axum::http::StatusCode;
use axum::http::{HeaderMap, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::restart_confirm::{Readiness, Reason};
use super::status::StatusView;
use super::{admin_audit::AuditDetail, errors::flat_error, guard::Guard};
use crate::gateway::recent_writes::WriteSample;
use crate::gateway::{router::AppState, routes};

const REASON: &str = Reason::PLATFORM.code();
const RECOVERY: &str = Reason::PLATFORM.recovery();

pub(super) fn restart_router() -> Router<Arc<AppState>> {
    Router::new().route(routes::UI_GATEWAY_RESTART, get(availability).post(refuse))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    confirm: String,
}

async fn availability(
    State(state): State<Arc<AppState>>,
    guard: Guard,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let (view, _) = StatusView::for_client(guard.client.as_ref());
    let confirm = state.process.restart_confirm();
    let sample = if view == StatusView::Full {
        confirm.sample(state.meta_mcp.recent_writes())
    } else {
        None
    };
    // Read once: the body and the mint take this one value.
    let readiness = confirm.readiness(state.transparency_log.is_some());
    let mut body = availability_body(view, sample, readiness);
    // Only the restart dialog asks for a confirmation: polling never mints,
    // so it cannot replace the token an open dialog shows.
    if view == StatusView::Full && asks_to_confirm(query.as_deref()) {
        let boot = state.dashboard_bootstrap.stream_hub().boot();
        if let Some(token) =
            confirm.confirmation(readiness, sample, guard.client.as_ref(), &headers, boot)
        {
            body["confirm"] = token.into();
            return ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response();
        }
    }
    Json(body).into_response()
}

/// True only for a well-formed query holding exactly one `confirm`, and that
/// one `confirm=1`. A malformed query (a pair with two `=`, an empty key, a `%`
/// not followed by two hex digits) answers as a plain GET, never a 400.
fn asks_to_confirm(query: Option<&str>) -> bool {
    let Some(query) = query else {
        return false;
    };
    let well_formed = |pair: &str| {
        let mut parts = pair.split('=');
        let key = parts.next().unwrap_or("");
        let escapes_ok = pair.match_indices('%').all(|(at, _)| {
            pair.get(at + 1..at + 3)
                .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
        });
        !key.is_empty() && parts.nth(1).is_none() && escapes_ok
    };
    if !query.split('&').all(well_formed) {
        return false;
    }
    let mut confirms = query
        .split('&')
        .filter(|pair| pair.split('=').next() == Some("confirm"));
    confirms.next() == Some("confirm=1") && confirms.next().is_none()
}

/// The restart GET body for a caller shown `view`, given restart `readiness`
/// and the recent-write sample when one was taken: only `count` and
/// `complete_secs` of it, and only in the full view.
pub(super) fn availability_body(
    view: StatusView,
    sample: Option<WriteSample>,
    readiness: Readiness,
) -> Value {
    let mut body = match readiness {
        Readiness::Ready { .. } => json!({"available": true}),
        Readiness::Unavailable(reason) => json!({
            "available": false,
            "reason": reason.code(),
            "recovery": reason.recovery(),
        }),
    };
    if view == StatusView::Full
        && let Some(sample) = sample
    {
        body["recent_writes"] = json!({
            "count": sample.count,
            "complete_secs": sample.complete_secs,
        });
    }
    body
}

async fn refuse(guard: Guard, body: Result<Json<Body>, JsonRejection>) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let Ok(Json(body)) = body else {
        return flat_error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_body").into_response();
    };
    // Only the shape is checked: no confirmation token exists while unavailable.
    drop(body.confirm);
    let mut response = (
        StatusCode::CONFLICT,
        Json(json!({"reason": REASON, "recovery": RECOVERY})),
    )
        .into_response();
    let mut detail = Map::new();
    detail.insert("action".into(), "restart".into());
    detail.insert("stage".into(), "refused".into());
    detail.insert("reason".into(), REASON.into());
    response.extensions_mut().insert(AuditDetail(detail));
    response
}
