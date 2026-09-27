// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! #1529: the HTTP trace span records the method and route, never the URI.
//!
//! The span is created by the trace layer before any handler runs, so a secret
//! in a query string reached the log whatever the handlers did with it.

use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

use super::create_router;
use super::tests::{scoped_auth_config, test_router_app_state_with_auth_and_config};
use crate::gateway::session_id::log_capture::capture_debug;

async fn traced(requests: Vec<Request<Body>>) -> String {
    let (state, _store) = test_router_app_state_with_auth_and_config(
        &scoped_auth_config(true),
        crate::config::Config::default(),
    )
    .await;
    let (captured, _guard) = capture_debug();
    for request in requests {
        let _ = create_router(Arc::clone(&state)).oneshot(request).await;
    }
    captured.text()
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("authorization", "Bearer scoped-key")
        .body(Body::empty())
        .unwrap()
}

/// T1: neither a session id nor a bootstrap value in a query reaches the log.
#[tokio::test(flavor = "current_thread")]
async fn t1_query_secrets_never_reach_the_trace_span() {
    let text = traced(vec![
        get("/api/costs?session=gw-trace-canary-5e1"),
        get("/dashboard?bootstrap=boot-trace-canary-9a4"),
    ])
    .await;
    // Positive control: the capture saw the requests at all.
    assert!(text.contains("/api/costs"), "no span captured:\n{text}");
    assert!(
        !text.contains("gw-trace-canary-5e1"),
        "session id logged:\n{text}"
    );
    assert!(
        !text.contains("boot-trace-canary-9a4"),
        "bootstrap value logged:\n{text}"
    );
}

/// T2: the span names the route template, so tracing stays useful, and an
/// unmatched path is not echoed either.
#[tokio::test(flavor = "current_thread")]
async fn t2_the_span_names_the_route_template() {
    let post = Request::builder()
        .method("POST")
        .uri("/mcp/backend-canary-77c")
        .header("authorization", "Bearer scoped-key")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#))
        .unwrap();
    let text = traced(vec![
        get("/dashboard?bootstrap=x"),
        post,
        get("/unrouted-canary-3d2"),
    ])
    .await;
    assert!(text.contains("/dashboard"), "{text}");
    assert!(
        text.contains("/mcp/{name}"),
        "route template missing:\n{text}"
    );
    assert!(
        !text.contains("backend-canary-77c"),
        "path value logged:\n{text}"
    );
    assert!(
        !text.contains("unrouted-canary-3d2"),
        "unmatched path logged:\n{text}"
    );
}

/// T3: `/api/costs` selects a session by the `X-Cost-Session-Id` header and
/// refuses the old query form with a message naming the header.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn t3_costs_select_a_session_by_header_not_query() {
    let (state, _store) = test_router_app_state_with_auth_and_config(
        &scoped_auth_config(true),
        crate::config::Config::default(),
    )
    .await;
    let tracker = state.meta_mcp.cost_tracker();
    tracker.record("gw-cost-a", None, "srv", "tool-a", 0, 1.0);
    tracker.record("gw-cost-b", None, "srv", "tool-b", 0, 2.0);
    let call = |request: Request<Body>| {
        let router = create_router(Arc::clone(&state));
        async move {
            let response = router.oneshot(request).await.unwrap();
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            (status, String::from_utf8(body.to_vec()).unwrap())
        }
    };
    let by_header = |id: &str| {
        Request::builder()
            .method("GET")
            .uri("/api/costs")
            .header("authorization", "Bearer scoped-key")
            .header("x-cost-session-id", id)
            .body(Body::empty())
            .unwrap()
    };
    let (status, body) = call(by_header("gw-cost-b")).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(
        body.contains("gw-cost-b") && !body.contains("gw-cost-a"),
        "{body}"
    );

    let (status, body) = call(get("/api/costs?session=gw-cost-a")).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("X-Cost-Session-Id"), "{body}");
}
