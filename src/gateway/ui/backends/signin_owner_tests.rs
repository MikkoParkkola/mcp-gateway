// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `session_owner` on its own, below the auth middleware. The middleware judges
//! a session against the pinned key table first and removes one whose minting
//! key is gone, so a request that reaches the handler through the router can
//! never show whether `session_owner` pins its own check. This row calls it
//! directly.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode, header};
use tower::ServiceExt;

use super::fixture::{ADMIN_KEY, Gw};
use super::session_owner;
use crate::gateway::auth::SESSION_COOKIE;
use crate::gateway::router::create_router;

/// A request from this machine as the admin key.
fn local(method: &str, uri: &str, bearer: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_345))));
    if let Some(credential) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {credential}"));
    }
    builder.body(Body::empty()).expect("request builds")
}

/// A dashboard session the admin key minted, through the link route and the
/// redemption, as an operator would.
async fn minted_by_the_admin_key(gw: &Gw) -> String {
    let router = || create_router(Arc::clone(&gw.state));
    let link = router()
        .oneshot(local("POST", "/ui/api/dashboard-link", Some(ADMIN_KEY)))
        .await
        .expect("the router is infallible");
    assert_eq!(link.status(), StatusCode::OK, "minting a link");
    let body = to_bytes(link.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let value = body["link"]
        .as_str()
        .and_then(|link| link.split("bootstrap=").nth(1))
        .expect("a bootstrap value")
        .to_owned();
    let opened = router()
        .oneshot(local("GET", &format!("/dashboard?bootstrap={value}"), None))
        .await
        .expect("the router is infallible");
    opened
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| c.strip_prefix(&format!("{SESSION_COOKIE}=")))
        .and_then(|rest| rest.split(';').next())
        .filter(|handle| !handle.is_empty())
        .map(str::to_owned)
        .expect("a session handle")
}

/// With the table it was minted under, the session gives an owner; with a
/// table that lacks the minting key, `session_owner` refuses it itself:
/// 403 `dashboard_session_required`. Red under an unpinned session check,
/// which finds the session still valid.
#[tokio::test]
async fn session_owner_refuses_a_session_whose_minting_key_is_gone() {
    let gw = Gw::new().await;
    let handle = minted_by_the_admin_key(&gw).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("{SESSION_COOKIE}={handle}").parse().unwrap(),
    );
    let before = gw.state.live_config.generation();
    assert!(
        session_owner(&gw.state, before.auth(), &headers).is_ok(),
        "control: the original table accepts the session"
    );
    // The fixture seeds the live config with a resolved key table of its own
    // (`LiveConfig::with_auth`) while `config.auth` stays default, so removing
    // the key from `config.auth` would change nothing and `set` would keep the
    // published table. A real reload carries a different auth section, as the
    // K13 rows' `reload` does: here, one without the minting key.
    let mut config = (*gw.state.live_config.get()).clone();
    config.auth = crate::config::AuthConfig {
        enabled: true,
        bearer_token: Some("owner-tests-bearer".to_owned()),
        ..crate::config::AuthConfig::default()
    };
    gw.state.live_config.set(config);
    let after = gw.state.live_config.generation();

    let refused = session_owner(&gw.state, after.auth(), &headers)
        .expect_err("a session whose minting key is gone is no session");

    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let body = to_bytes(refused.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"], "dashboard_session_required", "{body}");
}
