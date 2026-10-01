// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /api/costs`: the admin cost views.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::json;

use super::super::AppState;
use crate::gateway::auth::AuthenticatedClient;

/// GET /api/costs — REST endpoint for per-key and aggregate cost views.
///
/// - `?key=<name>`: view cost for a single API key
/// - `X-Cost-Session-Id: <id>` header: view cost for one session
/// - neither: aggregate view across all sessions and keys
pub(in crate::gateway::router) async fn costs_handler(
    State(state): State<Arc<AppState>>,
    request: axum::http::Request<axum::body::Body>,
) -> impl IntoResponse {
    use std::collections::HashMap;

    // Spend per session and per API key is cross-tenant inventory, and this
    // endpoint consulted no identity at all. `/ui/api/costs` already requires
    // admin; the two views of the same data now agree.
    if !request
        .extensions()
        .get::<AuthenticatedClient>()
        .is_some_and(|c| c.admin)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Admin authentication required" })),
        )
            .into_response();
    }

    let query: HashMap<String, String> = request
        .uri()
        .query()
        .map(|q| {
            q.split('&')
                .filter_map(|part| {
                    let mut kv = part.splitn(2, '=');
                    let k = kv.next()?;
                    let v = kv.next().unwrap_or("");
                    Some((k.to_string(), v.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();

    // A session id is a bearer handle, so it travels in a header, never the
    // URI (#1529): a query value lands in access and trace logs.
    let bad = |message: &str| (StatusCode::BAD_REQUEST, Json(json!({ "error": message })));
    if query.contains_key("session") {
        return bad("Pass the session id in the X-Cost-Session-Id header, not ?session=")
            .into_response();
    }
    let session = match request
        .headers()
        .get("x-cost-session-id")
        .map(|v| v.to_str())
    {
        Some(Ok(id)) if !id.trim().is_empty() => Some(id.trim().to_string()),
        Some(_) => return bad("X-Cost-Session-Id must be a non-empty text value").into_response(),
        None => None,
    };
    if session.is_some() && query.contains_key("key") {
        return bad("Select by ?key= or by X-Cost-Session-Id, not both").into_response();
    }
    let tracker = state.meta_mcp.cost_tracker();

    let body = if let Some(key_name) = query.get("key") {
        match tracker.key_snapshot(key_name) {
            Some(snap) => serde_json::to_value(snap).unwrap_or(serde_json::json!(null)),
            None => serde_json::json!({
                "error": format!("No data for key '{key_name}'")
            }),
        }
    } else if let Some(session_id) = session {
        match tracker.session_snapshot(&session_id) {
            Some(snap) => serde_json::to_value(snap).unwrap_or(serde_json::json!(null)),
            None => serde_json::json!({
                "error": format!("No data for session '{session_id}'")
            }),
        }
    } else {
        // Aggregate view: all sessions, all keys, totals
        serde_json::json!({
            "aggregate": serde_json::to_value(tracker.aggregate()).unwrap_or(serde_json::json!(null)),
            "sessions": serde_json::to_value(tracker.all_sessions()).unwrap_or(serde_json::json!([])),
            "keys": serde_json::to_value(tracker.all_keys()).unwrap_or(serde_json::json!([])),
        })
    };

    (StatusCode::OK, Json(body)).into_response()
}
