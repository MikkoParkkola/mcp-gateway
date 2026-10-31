// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! K13: a dashboard link, and the session it opens, stay bound to the key
//! that minted them. A reload that removes the key, demotes it from admin,
//! moves its expiry into the past or replaces its secret under the same name
//! ends the link and the session at their next use. A bearer-minted link and
//! a kept key's session are unaffected.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::Value;
use tower::ServiceExt;

use super::tests::test_router_app_state_with_auth;
use super::{AppState, create_router};
use crate::config::{ApiKeyConfig, AuthConfig};
use crate::gateway::auth::SESSION_COOKIE;

const BEARER: &str = "k13-static-bearer";
const ADMIN: &str = "k13-admin-key";
const OTHER: &str = "k13-other-admin-key";
const STATUS: &str = "/ui/api/status";
const LINK: &str = "/ui/api/dashboard-link";

fn admin_key(secret: &str, name: &str) -> ApiKeyConfig {
    ApiKeyConfig {
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        name: name.to_owned(),
        backends: vec!["*".to_owned()],
        admin: true,
        ..Default::default()
    }
}

fn auth(keys: Vec<ApiKeyConfig>) -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_owned()),
        api_keys: keys,
        ..AuthConfig::default()
    }
}

async fn fixture() -> (Arc<AppState>, super::tests::FixtureDir) {
    test_router_app_state_with_auth(&auth(vec![
        admin_key(ADMIN, ADMIN),
        admin_key(OTHER, OTHER),
    ]))
    .await
}

/// Reload `keys` as the key table; every other setting stays.
fn reload(state: &AppState, keys: Vec<ApiKeyConfig>) {
    let mut config = (*state.live_config.get()).clone();
    config.auth = auth(keys);
    state.live_config.set(config);
}

/// `request` from this machine, with a bearer or a session cookie.
fn local(method: &str, uri: &str, bearer: Option<&str>, cookie: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_345))));
    if let Some(credential) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {credential}"));
    }
    if let Some(handle) = cookie {
        builder = builder.header(header::COOKIE, format!("{SESSION_COOKIE}={handle}"));
    }
    builder.body(Body::empty()).expect("request builds")
}

/// Status, the session handle a response set (if any) and the JSON body.
async fn send(
    state: &Arc<AppState>,
    request: Request<Body>,
) -> (StatusCode, Option<String>, Value) {
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router is infallible");
    let status = response.status();
    let handle = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.strip_prefix(&format!("{SESSION_COOKIE}=")))
        .and_then(|rest| rest.split(';').next())
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    (
        status,
        handle,
        serde_json::from_slice(&body).unwrap_or(Value::Null),
    )
}

/// A link minted with `credential`, as its bootstrap value.
async fn mint(state: &Arc<AppState>, credential: &str) -> String {
    let (status, _, body) = send(state, local("POST", LINK, Some(credential), None)).await;
    assert_eq!(status, StatusCode::OK, "minting a link: {body}");
    let link = body["link"].as_str().expect("a link");
    link.split("bootstrap=").nth(1).expect("a value").to_owned()
}

/// Redeem `value`; the session handle when one was issued.
async fn redeem(state: &Arc<AppState>, value: &str) -> Option<String> {
    let uri = format!("/dashboard?bootstrap={value}");
    send(state, local("GET", &uri, None, None)).await.1
}

/// `true` when `handle` still opens the admin view.
async fn session_works(state: &Arc<AppState>, handle: &str) -> bool {
    let (status, _, body) = send(state, local("GET", STATUS, None, Some(handle))).await;
    status == StatusCode::OK && body.get("tool_count").is_some()
}

/// The reload edits K13 covers, each applied to the minting key ADMIN.
fn edits() -> Vec<(&'static str, Vec<ApiKeyConfig>)> {
    let mut demoted = admin_key(ADMIN, ADMIN);
    demoted.admin = false;
    let mut expired = admin_key(ADMIN, ADMIN);
    expired.expires_at = Some("2001-01-01T00:00:00Z".parse().expect("an instant"));
    let replaced = admin_key("k13-admin-key-reissued", ADMIN);
    vec![
        ("removed", vec![admin_key(OTHER, OTHER)]),
        ("demoted", vec![demoted, admin_key(OTHER, OTHER)]),
        ("expired", vec![expired, admin_key(OTHER, OTHER)]),
        ("replaced", vec![replaced, admin_key(OTHER, OTHER)]),
    ]
}

/// K13: a link minted by a key the reload then removes, demotes, expires or
/// replaces is refused at redemption.
#[tokio::test]
async fn k13_a_link_minted_before_the_reload_dies_with_its_key() {
    for (edit, keys) in edits() {
        let (state, _store) = fixture().await;
        let value = mint(&state, ADMIN).await;
        reload(&state, keys);
        assert!(
            redeem(&state, &value).await.is_none(),
            "{edit}: the link still opened a session"
        );
    }
}

/// K13: an open session minted by such a key ends at its next request.
#[tokio::test]
async fn k13_an_open_session_dies_with_its_key() {
    for (edit, keys) in edits() {
        let (state, _store) = fixture().await;
        let value = mint(&state, ADMIN).await;
        let handle = redeem(&state, &value).await.expect("a session");
        assert!(session_works(&state, &handle).await, "{edit}: precondition");
        reload(&state, keys);
        assert!(
            !session_works(&state, &handle).await,
            "{edit}: the session outlived its key"
        );
    }
}

/// K13 controls: a session whose key the reload keeps still works, and a
/// bearer-minted link still redeems after a key reload.
#[tokio::test]
async fn k13_a_kept_key_and_the_bearer_are_unaffected() {
    let (state, _store) = fixture().await;
    let value = mint(&state, ADMIN).await;
    let handle = redeem(&state, &value).await.expect("a session");
    let bearer_value = mint(&state, BEARER).await;
    reload(&state, vec![admin_key(ADMIN, ADMIN)]);
    assert!(
        session_works(&state, &handle).await,
        "a kept key's session ended"
    );
    let bearer_session = redeem(&state, &bearer_value)
        .await
        .expect("a bearer-minted link redeems");
    assert!(session_works(&state, &bearer_session).await);
}
