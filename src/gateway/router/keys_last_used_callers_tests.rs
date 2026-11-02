// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! T10, the dashboard-session and OIDC parts (slice B test plan r2): only an
//! accepted API-key match records a key's last use. A request carried by a
//! dashboard session, and one carried by a verified OIDC identity, both pass
//! the real auth middleware and leave the whole last-use map as it was: one
//! key's time already in it, and a second key never used, so a write that
//! adds an entry or moves one is seen. The OIDC
//! request presents a key-server temporary token, as a signed-in browser's
//! client does, so the identity is verified by the middleware itself.

use std::collections::BTreeMap;
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
use crate::key_server::{InMemoryTokenStore, KeyServer, TemporaryToken};

const BEARER: &str = "t10-static-bearer";
const ADMIN_KEY: &str = "t10-admin-key";
const IDLE_KEY: &str = "t10-idle-key";
const STATUS: &str = "/ui/api/status";

async fn fixture(
    key_server: Option<Arc<KeyServer>>,
) -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_string()),
        api_keys: vec![
            ApiKeyConfig {
                key_sha256: Some(crate::config::api_key_digest_spec(ADMIN_KEY.as_bytes())),
                name: "admin".to_string(),
                backends: vec!["*".to_string()],
                admin: true,
                ..Default::default()
            },
            ApiKeyConfig {
                key_sha256: Some(crate::config::api_key_digest_spec(IDLE_KEY.as_bytes())),
                name: "idle".to_string(),
                backends: vec!["*".to_string()],
                ..Default::default()
            },
        ],
        ..AuthConfig::default()
    };
    test_router_app_state_with_auth_and_key_server(&auth, key_server).await
}

/// A key-server temporary token for a verified OIDC identity.
fn oidc_token() -> TemporaryToken {
    let now = crate::clock::unix_secs().expect("the test clock reads");
    TemporaryToken {
        jti: InMemoryTokenStore::generate_jti(),
        token: InMemoryTokenStore::generate_bearer(),
        identity: VerifiedIdentity {
            subject: "t10-subject".to_string(),
            email: "t10@example.test".to_string(),
            name: None,
            groups: vec!["devs".to_string()],
            issuer: "https://idp.example.test".to_string(),
        },
        scopes: crate::key_server::store::TokenScopes {
            backends: vec!["*".to_string()],
            tools: vec![],
            rate_limit: 0,
        },
        iat: now,
        exp: now + 3600,
        client_ip: None,
    }
}

/// The whole last-use map the published table's runtime holds.
fn last_uses(state: &AppState) -> BTreeMap<String, i64> {
    state.live_config.generation().auth().last_used_all()
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

/// The seed both rows share, and their control: an API-key request records
/// the admin key's time, so the map compared below holds one entry, and the
/// idle key none.
async fn seed(state: &Arc<AppState>) -> BTreeMap<String, i64> {
    let request = from_here(
        Request::builder()
            .uri(STATUS)
            .header(header::AUTHORIZATION, format!("Bearer {ADMIN_KEY}")),
    );
    assert!(
        send(state, request).await.is_success(),
        "control: the key is admitted"
    );
    let seeded = last_uses(state);
    assert_eq!(
        seeded.len(),
        1,
        "control: an API-key request records its last use"
    );
    seeded
}

/// T10b: a dashboard session's request writes no key's last use.
#[tokio::test]
async fn t10b_a_session_request_writes_no_last_use() {
    let (state, _dir) = Box::pin(fixture(None)).await;
    let before = seed(&state).await;
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
    assert_eq!(
        last_uses(&state),
        before,
        "a session request changed the last-use map"
    );
}

/// T10c: a verified OIDC identity's request writes no key's last use.
#[tokio::test]
async fn t10c_an_oidc_request_writes_no_last_use() {
    let key_server = Arc::new(KeyServer::new(crate::config::KeyServerConfig::default()));
    let token = oidc_token();
    let bearer = token.token.clone();
    key_server.store.insert(token).await;
    let (state, _dir) = Box::pin(fixture(Some(key_server))).await;
    let before = seed(&state).await;
    let request = from_here(
        Request::builder()
            .uri(STATUS)
            .header(header::AUTHORIZATION, format!("Bearer {bearer}")),
    );
    assert!(
        send(&state, request).await.is_success(),
        "premise: the verified identity is admitted"
    );
    assert_eq!(
        last_uses(&state),
        before,
        "an OIDC request changed the last-use map"
    );
}
