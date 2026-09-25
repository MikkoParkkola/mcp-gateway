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

/// Unsigned requests are refused at the signature check and do not spend the
/// budget, so junk traffic cannot lock a real sender out for the minute.
#[tokio::test]
async fn unsigned_requests_do_not_spend_a_signed_endpoints_budget() {
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::response::IntoResponse;
    use hmac::{KeyInit, Mac as _};

    let dir = tempfile::tempdir().expect("tempdir");
    let env_file = dir.path().join(".env");
    crate::gateway::test_helpers::write_owner_only(&env_file, "RL_TEST_SECRET=rl-secret\n")
        .expect("env file");
    let env = Arc::new(crate::config::LiveEnv::new(
        Arc::new(crate::config::EnvOverlay::from_paths(&[env_file])),
        crate::config::ResolvedEnvFiles::default(),
    ));

    let mut definition = super::tests::make_definition(false);
    definition.secret = Some("{env.RL_TEST_SECRET}".to_string());
    definition.signature_header = Some("X-Signature".to_string());
    let mut state = super::tests::make_handler_state(make_multiplexer(), definition);
    state.env = env;
    let state_stats = Arc::clone(&state.stats);
    state.limiter = Some(Arc::new(governor::RateLimiter::direct(
        governor::Quota::per_minute(std::num::NonZeroU32::MIN),
    )));

    let body: &[u8] = br#"{"event":"x"}"#;
    for _ in 0..3 {
        let response = super::webhook_handler(
            State(state.clone()),
            HeaderMap::new(),
            axum::body::Bytes::from_static(body),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"rl-secret").expect("key");
    mac.update(body);
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-Signature",
        hex::encode(mac.finalize().into_bytes())
            .parse()
            .expect("header"),
    );
    let signed_headers = headers.clone();
    let state_again = state.clone();
    let response =
        super::webhook_handler(State(state), headers, axum::body::Bytes::from_static(body))
            .await
            .into_response();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "the one signed request in the minute must get the budget"
    );
    assert_eq!(
        state_stats.snapshot().rate_limited,
        0,
        "unsigned refusals are not rate-limit refusals"
    );

    let again = super::webhook_handler(
        State(state_again),
        signed_headers,
        axum::body::Bytes::from_static(body),
    )
    .await
    .into_response();
    assert_eq!(again.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(state_stats.snapshot().rate_limited, 1);
}

#[tokio::test]
async fn a_refused_request_says_when_to_retry() {
    let router = router_with(1);
    assert_eq!(post(&router, "/webhooks/a").await, StatusCode::OK);
    let request = Request::post("/webhooks/a")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"event":"x"}"#))
        .expect("request");
    let response = router.oneshot(request).await.expect("infallible");
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        response.headers().get(axum::http::header::RETRY_AFTER),
        Some(&axum::http::HeaderValue::from_static("60"))
    );
}
