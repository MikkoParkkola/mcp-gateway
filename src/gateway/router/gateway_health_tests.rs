// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/gateway/health` through `create_router`, so the real auth
//! middleware runs: refused without a credential and for a standard key, as
//! the gateway status read is. This test part installs no health history, so
//! an admin is admitted and gets the route's own 503.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use super::tests::test_router_app_state_with_auth_and_key_server;
use super::{AppState, create_router};
use crate::config::{ApiKeyConfig, AuthConfig};

const ROUTE: &str = "/ui/api/gateway/health";
const ADMIN: &str = "gateway-health-admin-key";
const STANDARD: &str = "gateway-health-standard-key";

fn key(secret: &str, name: &str, admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin,
        ..ApiKeyConfig::default()
    }
}

async fn fixture() -> (Arc<AppState>, Arc<tempfile::TempDir>) {
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![key(ADMIN, "admin", true), key(STANDARD, "standard", false)],
        ..AuthConfig::default()
    };
    test_router_app_state_with_auth_and_key_server(&auth, None).await
}

async fn get(state: &Arc<AppState>, bearer: Option<&str>) -> (StatusCode, Value) {
    let mut builder = Request::builder().method("GET").uri(ROUTE);
    if let Some(credential) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {credential}"));
    }
    let request = builder.body(Body::empty()).expect("request builds");
    // A hang guard only; no row is decided by time.
    let response = tokio::time::timeout(
        Duration::from_secs(30),
        create_router(Arc::clone(state)).oneshot(request),
    )
    .await
    .expect("the request finished")
    .expect("the router is infallible");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, body)
}

#[tokio::test]
async fn g6_a_non_admin_key_is_refused_and_no_credential_is_401() {
    let (state, _dir) = fixture().await;

    let (standard, body) = get(&state, Some(STANDARD)).await;
    assert_eq!(standard, StatusCode::FORBIDDEN, "{body}");
    // The guard's refusal, word for word as on GET /ui/api/gateway.
    assert_eq!(body, json!({"error": "Authentication required"}));

    let (anonymous, body) = get(&state, None).await;
    assert_eq!(anonymous, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"]["code"], json!(-32_000), "{body}");

    // Admitted: the guard let the admin through to the history check.
    let (admin, body) = get(&state, Some(ADMIN)).await;
    assert_eq!(admin, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body, json!({"error": "the health history is not running"}));
}
