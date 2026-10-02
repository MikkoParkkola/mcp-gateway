// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /api/costs` views: one key, one session, and the aggregate, each with
//! its "no data" answer. The admin gate and the selector refusals are pinned
//! in `trace_span_tests`.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use crate::gateway::router::create_router;
use crate::gateway::router::tests::{
    scoped_auth_config, test_router_app_state_with_auth_and_config,
};

async fn call(
    state: &Arc<crate::gateway::router::AppState>,
    uri: &str,
    session: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", "Bearer scoped-key");
    if let Some(id) = session {
        request = request.header("x-cost-session-id", id);
    }
    let response = create_router(Arc::clone(state))
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn admin_state() -> Arc<crate::gateway::router::AppState> {
    test_router_app_state_with_auth_and_config(
        &scoped_auth_config(true),
        crate::config::Config::default(),
    )
    .await
    .0
}

#[tokio::test]
async fn a_key_or_session_with_no_spend_answers_no_data() {
    let state = admin_state().await;
    let (status, body) = call(&state, "/api/costs?key=nobody", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["error"], "No data for key 'nobody'");

    let (status, body) = call(&state, "/api/costs", Some("no-such-session")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["error"], "No data for session 'no-such-session'");
}

#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_recorded_key_and_the_aggregate_carry_the_spend() {
    let state = admin_state().await;
    state
        .meta_mcp
        .cost_tracker()
        .record("sess-1", Some("ops"), "srv", "tool", 0, 1.0);

    let (status, by_key) = call(&state, "/api/costs?key=ops", None).await;
    assert_eq!(status, StatusCode::OK, "{by_key}");
    assert!(by_key.get("error").is_none(), "{by_key}");

    let (status, all) = call(&state, "/api/costs", None).await;
    assert_eq!(status, StatusCode::OK, "{all}");
    for part in ["aggregate", "sessions", "keys"] {
        assert!(all.get(part).is_some(), "{part} missing: {all}");
    }
}
