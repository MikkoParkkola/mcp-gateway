// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restart availability and an audited refusal; no process lifecycle changes.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::status::StatusView;
use super::{admin_audit::AuditDetail, errors::flat_error, guard::Guard};
use crate::gateway::recent_writes::WriteSample;
use crate::gateway::{router::AppState, routes};

const REASON: &str = if cfg!(windows) {
    "windows_manual_restart"
} else {
    "restart_not_available"
};
const RECOVERY: &str = if cfg!(windows) {
    "Restart the service or process through its service or process manager."
} else {
    "This process cannot tell which supervisor runs it; use your supervisor's restart command, \
     for example systemctl restart, brew services restart, or docker restart."
};

pub(super) fn restart_router() -> Router<Arc<AppState>> {
    Router::new().route(routes::UI_GATEWAY_RESTART, get(availability).post(refuse))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    confirm: String,
}

async fn availability(State(state): State<Arc<AppState>>, guard: Guard) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    let (view, _) = StatusView::for_client(guard.client.as_ref());
    let sample =
        (view == StatusView::Full).then(|| state.meta_mcp.recent_writes().sample(Instant::now()));
    Json(availability_body(view, sample)).into_response()
}

/// The restart GET body for a caller shown `view`, with the recent-write
/// sample when one was taken: only `count` and `complete_secs` of it, and
/// only in the full view.
pub(super) fn availability_body(_view: StatusView, _sample: Option<WriteSample>) -> Value {
    json!({"available": false, "reason": REASON, "recovery": RECOVERY})
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
