// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7570.CONFIG.3 (C8): `server.max_body_size` caps every route's request body.
//!
//! `/mcp` and `/mcp/{name}` used to hard-code 10 MiB and every extractor route,
//! webhooks included, fell back to axum's 2 MiB default, so the knob did
//! nothing. Each row drives the full router, because layer placement is what
//! decides whether a merged route is covered.

use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::json;
use tower::ServiceExt;

use super::tests::test_router_app_state;
use super::{AppState, create_router_with};
use crate::gateway::webhooks::WebhookRegistry;

/// The shared fixture with `server.max_body_size` set to `cap`.
async fn state_with_cap(cap: Option<usize>) -> (Arc<AppState>, tempfile::TempDir) {
    let (state, store) = test_router_app_state().await;
    if let Some(cap) = cap {
        let mut config = (*state.live_config.get()).clone();
        config.server.max_body_size = cap;
        state.live_config.set(config);
    }
    (state, store)
}

/// The production router with the dynamic webhook routes merged in, as
/// `gateway/server` builds it.
fn router_with_webhooks(state: &Arc<AppState>) -> axum::Router {
    let registry = Arc::new(parking_lot::RwLock::new(WebhookRegistry::new(
        crate::config::WebhookConfig::default(),
    )));
    let webhooks = WebhookRegistry::create_dynamic_routes(registry, Arc::clone(&state.multiplexer));
    create_router_with(Arc::clone(state), Some(webhooks))
}

/// A valid JSON-RPC `ping` padded to at least `size` bytes, so only its size
/// can make it fail.
fn padded_ping(size: usize) -> String {
    json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"_pad": "x".repeat(size)}})
        .to_string()
}

async fn post(router: axum::Router, uri: &str, body: String) -> StatusCode {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap();
    router.oneshot(request).await.unwrap().status()
}

#[tokio::test]
async fn mcp_body_over_configured_cap_is_rejected() {
    let (state, _store) = state_with_cap(Some(1024)).await;
    let status = post(router_with_webhooks(&state), "/mcp", padded_ping(2048)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn direct_route_body_over_cap_is_rejected() {
    let (state, _store) = state_with_cap(Some(1024)).await;
    let status = post(router_with_webhooks(&state), "/mcp/b", padded_ping(2048)).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn webhook_body_over_cap_is_rejected() {
    let (state, _store) = state_with_cap(Some(1024)).await;
    let status = post(
        router_with_webhooks(&state),
        "/webhooks/x",
        padded_ping(2048),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

/// Positive control: the default 10 MiB cap admits a 3 MiB webhook body that
/// axum's 2 MiB default refused. The registry is empty, so a buffered body
/// reaches the handler's 404; `Bytes` is its last extractor.
#[tokio::test]
async fn webhook_body_between_2_and_10_mib_accepted() {
    let (state, _store) = state_with_cap(None).await;
    let status = post(
        router_with_webhooks(&state),
        "/webhooks/x",
        padded_ping(3 * 1024 * 1024),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Positive control: a body under the cap is served on every route.
#[tokio::test]
async fn body_under_cap_accepted() {
    let (state, _store) = state_with_cap(Some(1024)).await;
    let router = router_with_webhooks(&state);
    assert_eq!(
        post(router.clone(), "/mcp", padded_ping(512)).await,
        StatusCode::OK
    );
    // The body is read before the backend lookup, so an unknown backend is 404.
    assert_eq!(
        post(router.clone(), "/mcp/b", padded_ping(512)).await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        post(router, "/webhooks/x", padded_ping(512)).await,
        StatusCode::NOT_FOUND
    );
}
