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

/// The state plus the temp directory backing its stores; keep both alive.
async fn admin_state() -> (Arc<crate::gateway::router::AppState>, tempfile::TempDir) {
    test_router_app_state_with_auth_and_config(
        &scoped_auth_config(true),
        crate::config::Config::default(),
    )
    .await
}

#[tokio::test]
async fn a_key_or_session_with_no_spend_answers_no_data() {
    let (state, _store) = admin_state().await;
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
    let (state, _store) = admin_state().await;
    state
        .meta_mcp
        .cost_tracker()
        .record("sess-1", Some("ops"), "srv", "tool", 2_000_000, 3.0);

    let (status, by_key) = call(&state, "/api/costs?key=ops", None).await;
    assert_eq!(status, StatusCode::OK, "{by_key}");
    assert_eq!(by_key["api_key_name"], "ops", "{by_key}");
    assert_eq!(by_key["window_24h"]["tokens"], 2_000_000, "{by_key}");
    let cost = by_key["window_24h"]["cost_usd"].as_f64().unwrap();
    assert!((cost - 6.0).abs() < 1e-9, "{by_key}");

    let (status, all) = call(&state, "/api/costs", None).await;
    assert_eq!(status, StatusCode::OK, "{all}");
    assert_eq!(all["aggregate"]["total_calls"], 1, "{all}");
    assert_eq!(all["aggregate"]["total_tokens"], 2_000_000, "{all}");
    assert_eq!(all["sessions"].as_array().map(Vec::len), Some(1), "{all}");
    assert_eq!(all["keys"].as_array().map(Vec::len), Some(1), "{all}");
}
