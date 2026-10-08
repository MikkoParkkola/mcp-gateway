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

/// `MIK-8158.PRM.1`, auth off: there is no protected resource at all.
#[tokio::test]
async fn no_metadata_without_auth() {
    let (state, _store) = test_router_app_state().await;
    assert_eq!(metadata_status(state).await, StatusCode::NOT_FOUND);
}

/// An auth-enabled config, run through the real auth fixture.
async fn authed(config: crate::config::Config) -> StatusCode {
    let (state, _store) =
        test_router_app_state_with_auth_and_config(&config.auth.clone(), config).await;
    metadata_status(state).await
}

/// An auth-enabled config that names `issuers` as delegated bearer issuers.
fn delegated(issuers: &[&str]) -> crate::config::Config {
    let mut config = crate::config::Config::default();
    config.server.public_url = Some("https://gw.internal".to_string());
    config.auth.enabled = true;
    config.key_server.enabled = true;
    config.key_server.delegated_bearer = true;
    config.key_server.oidc = issuers
        .iter()
        .map(|issuer| {
            serde_json::from_value(json!({"issuer": issuer, "audiences": ["gateway-client"]}))
                .unwrap()
        })
        .collect();
    config
}

/// `MIK-8158.PRM.1`, API keys only: a static key is the credential, and no
/// authorization server can issue one.
#[tokio::test]
async fn no_metadata_for_an_api_key_only_gateway() {
    let mut config = crate::config::Config::default();
    config.auth.enabled = true;
    assert_eq!(authed(config).await, StatusCode::NOT_FOUND);
}

/// `MIK-8158.PRM.1`: a wildcard bind with no `public_url` used to answer 503,
/// asking the operator to configure an origin for a document it does not
/// need. With no issuer it answers 404 first.
#[tokio::test]
async fn no_issuer_answers_404_before_any_origin_check() {
    let mut config = crate::config::Config::default();
    config.server.host = "0.0.0.0".to_string();
    config.auth.enabled = true;
    assert_eq!(authed(config).await, StatusCode::NOT_FOUND);
}

/// `MIK-8158.PRM.1`: agent auth refuses every issuer token, so it names none.
#[tokio::test]
async fn no_metadata_under_agent_auth() {
    let mut config = delegated(&["https://idp.example"]);
    config.agent_auth.enabled = true;
    assert_eq!(authed(config).await, StatusCode::NOT_FOUND);
}

/// `MIK-8158.PRM.2`: with a delegated issuer the document is served as before.
#[tokio::test]
async fn a_delegated_issuer_is_still_advertised() {
    assert_eq!(
        authed(delegated(&["https://idp.example"])).await,
        StatusCode::OK
    );
}
