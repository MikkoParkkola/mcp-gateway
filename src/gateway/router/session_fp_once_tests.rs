// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8014.PERF.2a`: a session's log fingerprint is computed once, when the
//! session is created, not on every request that names it.

use axum::http::{HeaderMap, StatusCode};
use serde_json::json;
use tower::ServiceExt;

use super::create_router_with;
use super::tests::test_router_app_state;
use crate::gateway::session_id::FINGERPRINTS;

/// POST a legacy-era `ping` to `/mcp`, resuming `session` when given.
async fn ping(router: axum::Router, session: Option<&str>) -> (StatusCode, HeaderMap) {
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(id) = session {
        request = request.header("mcp-session-id", id);
    }
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}).to_string();
    let response = router
        .oneshot(request.body(axum::body::Body::from(body)).unwrap())
        .await
        .unwrap();
    (response.status(), response.headers().clone())
}

#[tokio::test]
async fn a_resumed_session_is_not_fingerprinted_again() {
    let (state, _store) = test_router_app_state().await;
    let router = create_router_with(std::sync::Arc::clone(&state), None);

    let (status, headers) = ping(router.clone(), None).await;
    assert_eq!(status, StatusCode::OK);
    let id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .expect("a legacy request is answered with its minted session")
        .to_owned();

    FINGERPRINTS.with(|n| n.set(0));
    for _ in 0..2 {
        let (status, headers) = ping(router.clone(), Some(&id)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get("mcp-session-id").and_then(|v| v.to_str().ok()),
            Some(id.as_str()),
            "the request resumed the session it named"
        );
    }
    assert_eq!(
        FINGERPRINTS.with(std::cell::Cell::get),
        0,
        "two requests on a held session computed its fingerprint again"
    );
}
