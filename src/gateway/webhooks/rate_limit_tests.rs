// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `webhooks.rate_limit` is enforced per endpoint.
//!
//! Driven through `create_dynamic_routes`, the route the server mounts, so a
//! limit that is parsed and never consulted fails here.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use parking_lot::RwLock;
use tower::ServiceExt;

use super::WebhookRegistry;
use super::tests::{make_capability_with_webhooks, make_multiplexer};
use crate::config::WebhookConfig;

fn router_with(rate_limit: u32) -> axum::Router {
    let mut registry = WebhookRegistry::new(WebhookConfig {
        require_signature: false,
        rate_limit,
        ..WebhookConfig::default()
    });
    registry.register_capability(&make_capability_with_webhooks(
        "cap",
        &[("a", "/a", false), ("b", "/b", false)],
    ));
    WebhookRegistry::create_dynamic_routes(Arc::new(RwLock::new(registry)), make_multiplexer())
}

async fn post(router: &axum::Router, path: &str) -> StatusCode {
    let request = Request::post(path)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"event":"x"}"#))
        .expect("request");
    router
        .clone()
        .oneshot(request)
        .await
        .expect("infallible")
        .status()
}

#[tokio::test]
async fn an_endpoint_over_its_per_minute_limit_is_refused() {
    let router = router_with(2);
    assert_eq!(post(&router, "/webhooks/a").await, StatusCode::OK);
    assert_eq!(post(&router, "/webhooks/a").await, StatusCode::OK);
    assert_eq!(
        post(&router, "/webhooks/a").await,
        StatusCode::TOO_MANY_REQUESTS,
        "a third request inside the minute must exceed rate_limit: 2"
    );
    assert_eq!(
        post(&router, "/webhooks/b").await,
        StatusCode::OK,
        "the limit is per endpoint, so another endpoint keeps its own budget"
    );
}

#[tokio::test]
async fn a_zero_rate_limit_is_unlimited() {
    let router = router_with(0);
    for _ in 0..20 {
        assert_eq!(post(&router, "/webhooks/a").await, StatusCode::OK);
    }
}
