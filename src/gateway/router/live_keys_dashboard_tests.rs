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

/// The reload edits K13 covers, each applied to the minting key ADMIN; and
/// narrowing it to some backends.
fn edits() -> Vec<(&'static str, Vec<ApiKeyConfig>)> {
    let mut demoted = admin_key(ADMIN, ADMIN);
    demoted.admin = false;
    let mut expired = admin_key(ADMIN, ADMIN);
    expired.expires_at = Some("2001-01-01T00:00:00Z".parse().expect("an instant"));
    let replaced = admin_key("k13-admin-key-reissued", ADMIN);
    // A session is unscoped, so a key narrowed to some backends ends it.
    let mut narrowed = admin_key(ADMIN, ADMIN);
    narrowed.backends = vec!["alpha".to_string()];
    vec![
        ("removed", vec![admin_key(OTHER, OTHER)]),
        ("demoted", vec![demoted, admin_key(OTHER, OTHER)]),
        ("expired", vec![expired, admin_key(OTHER, OTHER)]),
        ("replaced", vec![replaced, admin_key(OTHER, OTHER)]),
        ("narrowed", vec![narrowed, admin_key(OTHER, OTHER)]),
    ]
}

/// K13: a link minted by a key the reload then removes, demotes, expires,
/// replaces or narrows is refused at redemption.
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

/// A JSON POST to `uri` as the admin `bearer`, carrying the session cookie
/// `handle`.
fn post_json(uri: &str, bearer: &str, handle: &str, body: &str) -> Request<Body> {
    let mut request = local("POST", uri, Some(bearer), Some(handle));
    request
        .headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    *request.body_mut() = Body::from(body.to_owned());
    request
}

/// K13 on the sign-in routes: a session whose minting key a reload removed,
/// demoted, expired or replaced cannot start or confirm a sign-in, even while
/// the caller presents another admin key. The refusal is the sign-in routes'
/// own, 403 `dashboard_session_required`, and no flow is started. Before the
/// reload the same request gets past the session check.
#[tokio::test]
async fn a_session_whose_minting_key_a_reload_removed_cannot_sign_in() {
    use crate::config::{BackendConfig, FailsafeConfig, OAuthConfig};
    const START: &str = "/ui/api/backends/oauthy/signin";
    const CONFIRM: &str = "/ui/api/backends/oauthy/signin/confirm";
    const DECISION: &str = r#"{"decision":"confirm","attempt_id":"earlier"}"#;
    for (edit, keys) in edits() {
        let (state, _store) = fixture().await;
        let backend = Arc::new(crate::backend::Backend::new(
            "oauthy",
            BackendConfig {
                oauth: Some(OAuthConfig {
                    enabled: true,
                    scopes: Vec::new(),
                    client_id: None,
                    client_secret: None,
                    callback_host: None,
                    callback_port: None,
                    callback_path: None,
                    token_refresh_buffer_secs: None,
                    shared_account: false,
                }),
                ..BackendConfig::default()
            },
            &FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        ));
        assert!(
            state.backends.register(Arc::clone(&backend)),
            "registration"
        );
        let value = mint(&state, ADMIN).await;
        let handle = redeem(&state, &value).await.expect("a session");
        let (before, _, _) = send(&state, post_json(START, OTHER, &handle, "{}")).await;
        assert_ne!(
            before,
            StatusCode::FORBIDDEN,
            "{edit}: the session passes the check before the reload"
        );

        reload(&state, keys);

        for (uri, body) in [(START, "{}"), (CONFIRM, DECISION)] {
            let (status, _, answer) = send(&state, post_json(uri, OTHER, &handle, body)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{edit} {uri}: {answer}");
            assert_eq!(
                answer["error"], "dashboard_session_required",
                "{edit} {uri}"
            );
        }
        assert!(
            backend.with_flow(|slot| slot.is_none()),
            "{edit}: a flow was started"
        );
    }
}
