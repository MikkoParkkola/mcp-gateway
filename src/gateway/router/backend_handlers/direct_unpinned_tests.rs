// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A request that never passed the router's outer layer carries no pinned
//! generation. The direct route refuses it rather than judge it by the
//! current configuration (ADR-023: a reader never falls back).

use axum::body::Body;
use axum::http::{Request, StatusCode};

use super::direct_caller::resolve_caller;
use crate::gateway::router::helpers::RpcHttp;
use crate::gateway::router::tests::test_router_app_state;

#[tokio::test]
async fn an_unpinned_request_is_refused_not_judged_by_the_current_config() {
    let (state, _store) = test_router_app_state().await;
    let request = Request::builder()
        .method("POST")
        .uri("/mcp/demo")
        .body(Body::empty())
        .expect("request builds");
    let Err(RpcHttp { status, body, .. }) = resolve_caller(&state, request).await else {
        panic!("a request with no pinned generation was resolved");
    };
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body.0["error"], crate::gateway::router::UNPINNED);
}
