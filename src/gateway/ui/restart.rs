// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restart availability and an audited refusal; no process lifecycle changes.

use std::sync::Arc;

use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Map, json};

use super::{admin_audit::AuditDetail, errors::flat_error, guard::Guard};
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

async fn availability(guard: Guard) -> Response {
    if let Err(refused) = guard.admit() {
        return refused.into_response();
    }
    Json(json!({"available": false, "reason": REASON, "recovery": RECOVERY})).into_response()
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
