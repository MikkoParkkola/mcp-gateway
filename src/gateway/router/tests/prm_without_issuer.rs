// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8158: a gateway with no authorization server to name publishes no
//! protected-resource metadata, so no client is sent into an OAuth sign-in
//! that cannot complete.

use super::*;
use pretty_assertions::assert_eq;

async fn metadata_status(state: Arc<AppState>) -> StatusCode {
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/.well-known/oauth-protected-resource")
        .body(axum::body::Body::empty())
        .unwrap();
    create_router(state)
        .oneshot(request)
        .await
        .unwrap()
        .status()
}

/// MIK-8158.PRM.1, auth off: there is no protected resource at all.
#[tokio::test]
async fn no_metadata_without_auth() {
    let (state, _store) = test_router_app_state().await;
    assert_eq!(metadata_status(state).await, StatusCode::NOT_FOUND);
}

/// MIK-8158.PRM.1, API keys only: a static key is the credential, and no
/// authorization server can issue one.
#[tokio::test]
async fn no_metadata_for_an_api_key_only_gateway() {
    let mut config = crate::config::Config::default();
    config.auth.enabled = true;
    let (state, _store) = test_router_app_state_with(StreamingConfig::default(), config).await;
    assert_eq!(metadata_status(state).await, StatusCode::NOT_FOUND);
}
