// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T10, the dashboard-session and OIDC parts (slice B test plan r2): only an
//! accepted API-key match records a key's last use. A request carried by a
//! dashboard session, and one carried by a verified OIDC identity, both pass
//! the real auth middleware and leave every key's last use unset.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, header};
use tower::ServiceExt;

use super::tests::test_router_app_state_with_auth_and_key_server;
use super::{AppState, create_router};
use crate::config::{ApiKeyConfig, AuthConfig};
use crate::gateway::auth::{Now, SESSION_COOKIE, SessionLimits};
use crate::key_server::oidc::VerifiedIdentity;

const BEARER: &str = "t10-static-bearer";
const ADMIN_KEY: &str = "t10-admin-key";
const STATUS: &str = "/ui/api/status";

async fn fixture() -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_string()),
        api_keys: vec![ApiKeyConfig {
            key_sha256: Some(crate::config::api_key_digest_spec(ADMIN_KEY.as_bytes())),
            name: "admin".to_string(),
            backends: vec!["*".to_string()],
            admin: true,
            ..Default::default()
        }],
        ..AuthConfig::default()
    };
    test_router_app_state_with_auth_and_key_server(&auth, None).await
}

/// Every configured key's last use, as the published table reads it.
fn last_uses(state: &AppState) -> Vec<Option<i64>> {
    let generation = state.live_config.generation();
    let auth = generation.auth();
    auth.api_keys()
        .iter()
        .map(|key| auth.key_last_used(key))
        .collect()
}

fn from_here(builder: axum::http::request::Builder) -> Request<Body> {
    builder
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_347))))
        .body(Body::empty())
        .expect("request builds")
}

async fn send(state: &Arc<AppState>, request: Request<Body>) -> axum::http::StatusCode {
    create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router is infallible")
        .status()
}

/// The control both rows share: an API-key request does record a time, so
/// an unset time below is the session's or identity's doing, not the probe's.
async fn assert_a_key_request_records(state: &Arc<AppState>) {
    let request = from_here(
        Request::builder()
            .uri(STATUS)
            .header(header::AUTHORIZATION, format!("Bearer {ADMIN_KEY}")),
    );
    assert!(
        send(state, request).await.is_success(),
        "control: the key is admitted"
    );
    assert!(
        last_uses(state).iter().all(Option::is_some),
        "control: an API-key request records its last use"
    );
}

/// T10b: a dashboard session's request writes no key's last use.
#[tokio::test]
async fn t10b_a_session_request_writes_no_last_use() {
    let (state, _dir) = Box::pin(fixture()).await;
    let limits = SessionLimits::from(&state.live_config.get().auth.dashboard_session);
    let handle = state
        .dashboard_bootstrap
        .issue_session_at(Now::read(), &limits);
    let request = from_here(
        Request::builder()
            .uri(STATUS)
            .header(header::COOKIE, format!("{SESSION_COOKIE}={handle}")),
    );
    assert!(
        send(&state, request).await.is_success(),
        "premise: the session is admitted"
    );
    assert!(
        last_uses(&state).iter().all(Option::is_none),
        "a session request recorded a key's last use"
    );
    assert_a_key_request_records(&state).await;
}

/// T10c: a verified OIDC identity's request writes no key's last use.
#[tokio::test]
async fn t10c_an_oidc_request_writes_no_last_use() {
    let (state, _dir) = Box::pin(fixture()).await;
    let identity = VerifiedIdentity {
        subject: "t10-subject".to_string(),
        email: "t10@example.test".to_string(),
        name: None,
        groups: vec!["devs".to_string()],
        issuer: "https://idp.example.test".to_string(),
    };
    let request = from_here(Request::builder().uri(STATUS).extension(identity));
    let _status = send(&state, request).await;
    assert!(
        last_uses(&state).iter().all(Option::is_none),
        "an OIDC request recorded a key's last use"
    );
    assert_a_key_request_records(&state).await;
}
