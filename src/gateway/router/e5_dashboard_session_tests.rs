// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E5 (MIK-7570.SESSION.1): dashboard sessions end after 30 minutes idle and
//! 8 hours absolute, and logout ends them.
//!
//! Every request goes through `create_router`, so the real `auth_middleware`,
//! the E1-f audit layer and the origin guard all run. Expiry is reached with
//! `DashboardBootstrap::backdate`, which moves both clocks of one session back,
//! so no test sleeps.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode, header};
use serde_json::Value;
use tower::ServiceExt;

use super::tests::test_router_app_state_with_auth_and_key_server;
use super::{AppState, create_router};
use crate::config::{ApiKeyConfig, AuthConfig};
use crate::gateway::auth::{Now, SESSION_COOKIE, SessionCheck, SessionLimits, Touch};

const BEARER: &str = "e5-static-bearer";
const ADMIN_KEY: &str = "e5-admin-key";
const STANDARD_KEY: &str = "e5-standard-key";
const STATUS: &str = "/ui/api/status";
const LOGOUT: &str = "/dashboard/logout";
const LINK: &str = "/ui/api/dashboard-link";
const POLL_HEADER: &str = "x-mcp-gateway-poll";
const IDLE: Duration = Duration::from_secs(1800);
const MIN: Duration = Duration::from_secs(60);

fn api_key(key: &str, admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(key.as_bytes())),
        expires_at: None,
        name: key.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin,
    }
}

/// Auth on with a static bearer, one admin and one standard key, and
/// `public` as the public paths.
async fn fixture_with(public: &[&str]) -> (Arc<AppState>, tempfile::TempDir) {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_string()),
        api_keys: vec![api_key(ADMIN_KEY, true), api_key(STANDARD_KEY, false)],
        public_paths: public.iter().map(ToString::to_string).collect(),
        ..AuthConfig::default()
    };
    test_router_app_state_with_auth_and_key_server(&auth, None).await
}

async fn fixture() -> (Arc<AppState>, tempfile::TempDir) {
    fixture_with(&["/health"]).await
}

/// Apply `edit` to the live config, as a reload would.
fn reload(state: &AppState, edit: impl FnOnce(&mut crate::config::Config)) {
    let mut config = (*state.live_config.get()).clone();
    edit(&mut config);
    state.live_config.set(config);
}

fn limits(state: &AppState) -> SessionLimits {
    SessionLimits::from(&state.live_config.get().auth.dashboard_session)
}

/// A session issued now, as a redeemed link would issue it.
fn issue(state: &AppState) -> String {
    state
        .dashboard_bootstrap
        .issue_session_at(Now::read(), &limits(state))
}

/// Move `handle`'s clocks back by `by`: the same as `by` passing.
fn age(state: &AppState, handle: &str, by: Duration) {
    state.dashboard_bootstrap.backdate(handle, by);
}

/// What the store says about `handle` now, without counting as activity.
fn check(state: &AppState, handle: &str) -> SessionCheck {
    state
        .dashboard_bootstrap
        .check_session(handle, Now::read(), &limits(state), Touch::No)
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    /// Every `Set-Cookie` value, joined.
    fn set_cookie(&self) -> String {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    fn clears_cookie(&self) -> bool {
        let c = self.set_cookie();
        c.contains(&format!("{SESSION_COOKIE}=;")) && c.contains("Max-Age=0")
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

async fn send(state: &Arc<AppState>, request: Request<Body>) -> Reply {
    let response = tokio::time::timeout(
        Duration::from_secs(30),
        create_router(Arc::clone(state)).oneshot(request),
    )
    .await
    .expect("the request finished")
    .expect("the router is infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    Reply {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

/// A request from this machine, optionally with a session cookie, a bearer
/// credential and the poll marker.
fn request(
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    bearer: Option<&str>,
    poll: bool,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_344))));
    if let Some(handle) = cookie {
        builder = builder.header(header::COOKIE, format!("{SESSION_COOKIE}={handle}"));
    }
    if let Some(credential) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {credential}"));
    }
    if poll {
        builder = builder.header(POLL_HEADER, "1");
    }
    builder.body(Body::empty()).expect("request builds")
}

fn get(uri: &str, cookie: Option<&str>) -> Request<Body> {
    request("GET", uri, cookie, None, false)
}

fn poll(uri: &str, cookie: &str) -> Request<Body> {
    request("GET", uri, Some(cookie), None, true)
}

fn logout(cookie: Option<&str>) -> Request<Body> {
    request("POST", LOGOUT, cookie, None, false)
}

/// Redeem `value` as the startup link would be, from this machine.
fn redeem(value: &str, cookie: Option<&str>) -> Request<Body> {
    get(&format!("/dashboard?bootstrap={value}"), cookie)
}

/// `true` when `/ui/api/status` answered with the admin view.
fn is_admin_view(reply: &Reply) -> bool {
    reply.status == StatusCode::OK && reply.json().get("tool_count").is_some()
}

/// A real audit log on `state`, as the server wires it.
fn with_audit(
    state: &mut Arc<AppState>,
) -> (Arc<crate::security::TransparencyLogger>, tempfile::TempDir) {
    use crate::security::transparency_log::TransparencyLogConfig;
    let dir = tempfile::tempdir().expect("tempdir");
    let log = Arc::new(
        crate::security::TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: dir
                .path()
                .join("audit.jsonl")
                .to_string_lossy()
                .into_owned(),
            key_id: "e5".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("open log"),
    );
    Arc::get_mut(state)
        .expect("state is unique")
        .transparency_log = Some(Arc::clone(&log));
    (log, dir)
}

// ── Logout ──────────────────────────────────────────────────────────────

/// E5-T4: logout revokes the session on the server, not just in the browser.
#[tokio::test]
async fn logout_revokes_server_side() {
    let (state, _dir) = fixture().await;
    let h = issue(&state);
    assert!(is_admin_view(&send(&state, get(STATUS, Some(&h))).await));

    let out = send(&state, logout(Some(&h))).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert_eq!(
        out.headers
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/dashboard")
    );
    assert!(
        out.clears_cookie(),
        "logout clears the cookie: {}",
        out.set_cookie()
    );
    let c = out.set_cookie();
    assert!(c.contains("HttpOnly") && c.contains("SameSite=Strict") && c.contains("Path=/"));
    assert!(
        !c.contains("Secure"),
        "no Secure on a plain-HTTP listener: {c}"
    );

    let replay = send(&state, get(STATUS, Some(&h))).await;
    assert_eq!(
        replay.status,
        StatusCode::UNAUTHORIZED,
        "a copied cookie is dead after logout"
    );
}

/// E5-T5: an audit outage never blocks logout, and neither does an expired
/// session: logout sits outside the auth and audit layers.
#[tokio::test]
async fn logout_works_while_audit_degraded_or_expired() {
    let (mut state, _dir) = fixture().await;
    let (log, _log_dir) = with_audit(&mut state);
    log.set_append_failure_for_test(true);
    assert!(log.probe().is_err(), "the priming append fails");
    assert!(log.is_degraded(), "the audit log is degraded");

    let h = issue(&state);
    let out = send(&state, logout(Some(&h))).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert!(out.clears_cookie());
    assert_eq!(
        check(&state, &h),
        SessionCheck::Unknown,
        "the handle is gone"
    );

    let expired = issue(&state);
    age(&state, &expired, IDLE + MIN);
    let out = send(&state, logout(Some(&expired))).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert!(out.clears_cookie());
    assert_eq!(check(&state, &expired), SessionCheck::Unknown);

    let out = send(&state, logout(None)).await;
    assert_eq!(
        out.status,
        StatusCode::SEE_OTHER,
        "no cookie is still a clean logout"
    );
}

/// Logout writes one `admin_action` record when the log is healthy, and the
/// record never carries the handle.
#[tokio::test]
async fn logout_writes_one_admin_action_record() {
    let (mut state, _dir) = fixture().await;
    let (log, _log_dir) = with_audit(&mut state);
    let h = issue(&state);
    let out = send(&state, logout(Some(&h))).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER);
    let raw = std::fs::read_to_string(log.path()).unwrap_or_default();
    let records = raw
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|e| e["event"] == "admin_action" && e.to_string().contains(LOGOUT))
        .count();
    assert_eq!(records, 1, "one logout record: {raw}");
    assert!(!raw.contains(&h), "the handle never reaches the log");
}

/// E5-T15: GET cannot log anybody out, so a link or an image cannot either.
#[tokio::test]
async fn logout_is_post_only() {
    let (state, _dir) = fixture().await;
    let h = issue(&state);
    let out = send(&state, get(LOGOUT, Some(&h))).await;
    assert_eq!(out.status, StatusCode::METHOD_NOT_ALLOWED, "{}", out.body);
    assert_eq!(
        check(&state, &h),
        SessionCheck::Valid,
        "the session survives"
    );
}

/// E5-T11: on a TLS-fronted gateway the clearing cookie is `Secure` too.
#[tokio::test]
async fn logout_cookie_is_secure_on_tls() {
    let (state, _dir) = fixture().await;
    reload(&state, |c| {
        c.server.public_url = Some("https://gateway.example".to_string());
    });
    let h = issue(&state);
    let out = send(&state, logout(Some(&h))).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert!(out.clears_cookie());
    assert!(out.set_cookie().contains("Secure"), "{}", out.set_cookie());
}

// ── Expiry through the middleware ──────────────────────────────────────

/// E5-T10: a dead cookie gets its own answer, not "Missing credential", and a
/// bearer presented with it is still honoured.
#[tokio::test]
async fn expired_cookie_gets_session_expired_401() {
    let (state, _dir) = fixture().await;
    let expired = issue(&state);
    age(&state, &expired, IDLE + MIN);
    let out = send(&state, get("/dashboard", Some(&expired))).await;
    assert_eq!(out.status, StatusCode::UNAUTHORIZED, "{}", out.body);
    assert!(out.body.contains("session expired"), "{}", out.body);
    assert!(out.body.contains("dashboard-link"), "{}", out.body);
    assert!(!out.body.contains("Missing"), "{}", out.body);
    assert!(out.clears_cookie(), "{}", out.set_cookie());

    // A second, separately stored expired handle, so this request meets an
    // Expired entry and not one the first request already removed.
    let also_expired = issue(&state);
    age(&state, &also_expired, IDLE + MIN);
    let with_bearer = send(
        &state,
        request("GET", STATUS, Some(&also_expired), Some(BEARER), false),
    )
    .await;
    assert!(
        is_admin_view(&with_bearer),
        "the bearer beside a dead cookie still authenticates: {} {}",
        with_bearer.status,
        with_bearer.body
    );
    assert_eq!(check(&state, &also_expired), SessionCheck::Unknown);

    // A handle this process never issued (a restart, a sweep) reads the same.
    let never = send(&state, get("/dashboard", Some("never-issued"))).await;
    assert_eq!(never.status, StatusCode::UNAUTHORIZED);
    assert!(never.body.contains("dashboard-link"), "{}", never.body);
    assert!(never.clears_cookie());
}

/// E5-T12 (router half): the dashboard's own refreshes are answered but never
/// extend the session, so an unattended tab ends at the idle limit.
#[tokio::test]
async fn poll_marked_requests_do_not_extend() {
    let (state, _dir) = fixture().await;
    let h = issue(&state);
    age(&state, &h, IDLE - MIN);
    assert!(is_admin_view(&send(&state, poll(STATUS, &h)).await));
    let page = send(&state, get("/dashboard?poll=1", Some(&h))).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    age(&state, &h, MIN * 2);
    let out = send(&state, poll(STATUS, &h)).await;
    assert_eq!(
        out.status,
        StatusCode::UNAUTHORIZED,
        "a poll-only tab ends at the idle limit, not at the absolute cap"
    );
}

/// E5-T12b: the server-rendered dashboard refreshes to the poll URL, because
/// a meta refresh cannot set a header.
#[tokio::test]
async fn dashboard_meta_refresh_targets_poll_url() {
    let (state, _dir) = fixture().await;
    let h = issue(&state);
    let page = send(&state, get("/dashboard", Some(&h))).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body.contains(r#"content="5;url=/dashboard?poll=1""#),
        "the refresh must carry the poll marker"
    );
    assert!(
        page.body.contains(r#"action="/dashboard/logout""#)
            && page.body.contains("method=\"post\""),
        "the dashboard offers a POST logout"
    );
}

/// E5-T12c (guard, passes today): an unmarked request is activity.
#[tokio::test]
async fn unmarked_activity_extends() {
    let (state, _dir) = fixture().await;
    let h = issue(&state);
    age(&state, &h, IDLE - MIN);
    assert!(is_admin_view(&send(&state, get(STATUS, Some(&h))).await));
    age(&state, &h, MIN * 2);
    assert!(
        is_admin_view(&send(&state, get(STATUS, Some(&h))).await),
        "activity restarted the idle clock"
    );
}

/// E5-T13: delivery re-checks (`auth::live::current_client`) never count as
/// activity, so server push cannot keep a session alive.
#[tokio::test]
async fn delivery_check_does_not_touch() {
    let (state, _dir) = fixture().await;
    let h = issue(&state);
    let auth = super::build_auth_state(&state);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("{SESSION_COOKIE}={h}").parse().expect("header"),
    );
    let held = crate::gateway::auth::live::held_credential(&headers);

    age(&state, &h, IDLE - MIN);
    assert!(
        crate::gateway::auth::live::current_client(&auth, held.as_ref())
            .await
            .is_some(),
        "a live session still receives deliveries"
    );
    age(&state, &h, MIN * 2);
    assert_eq!(
        send(&state, get(STATUS, Some(&h))).await.status,
        StatusCode::UNAUTHORIZED,
        "the delivery re-check did not restart the idle clock"
    );
    assert!(
        crate::gateway::auth::live::current_client(&auth, held.as_ref())
            .await
            .is_none(),
        "and a dead session stops receiving deliveries"
    );
}

/// E5-T16: a dead cookie on a public path is dropped, not fatal: the request
/// proceeds as the public identity, and a bearer beside it still counts.
#[tokio::test]
async fn expired_cookie_on_public_path_passes() {
    let (state, _dir) = fixture_with(&["/health", STATUS]).await;
    let expired = issue(&state);
    age(&state, &expired, IDLE + MIN);
    let out = send(&state, get(STATUS, Some(&expired))).await;
    assert_eq!(out.status, StatusCode::OK, "{}", out.body);
    assert!(!is_admin_view(&out), "a dead session is not admin");
    assert!(out.clears_cookie(), "{}", out.set_cookie());
    assert_eq!(check(&state, &expired), SessionCheck::Unknown);

    let also_expired = issue(&state);
    age(&state, &also_expired, IDLE + MIN);
    let with_bearer = send(
        &state,
        request("GET", STATUS, Some(&also_expired), Some(BEARER), false),
    )
    .await;
    assert!(is_admin_view(&with_bearer), "{}", with_bearer.body);
}

/// E5-T17: limits come from the live config, so a reload applies to sessions
/// already open, for both the idle and the absolute limit.
#[tokio::test]
async fn reload_changes_limits() {
    let (state, _dir) = fixture().await;
    reload(&state, |c| c.auth.dashboard_session.idle_timeout_secs = 600);
    let h = issue(&state);
    age(&state, &h, Duration::from_secs(601));
    assert_eq!(
        send(&state, get(STATUS, Some(&h))).await.status,
        StatusCode::UNAUTHORIZED,
        "a shortened idle limit applies at the next check"
    );

    reload(&state, |c| {
        c.auth.dashboard_session.idle_timeout_secs = 1800;
        c.auth.dashboard_session.absolute_timeout_secs = 3600;
    });
    let h = issue(&state);
    for _ in 0..2 {
        age(&state, &h, Duration::from_secs(1700));
        assert!(is_admin_view(&send(&state, get(STATUS, Some(&h))).await));
    }
    age(&state, &h, Duration::from_secs(300));
    assert_eq!(
        send(&state, get(STATUS, Some(&h))).await.status,
        StatusCode::UNAUTHORIZED,
        "a shortened absolute limit ends an active session"
    );
}

// ── Sign-in and re-entry ───────────────────────────────────────────────

/// E5-T6: the cookie's lifetime is the absolute limit the server enforces,
/// including a configured one.
#[tokio::test]
async fn cookie_max_age_equals_absolute_timeout() {
    let (state, _dir) = fixture().await;
    let value = state.dashboard_bootstrap.peek().expect("startup value");
    let out = send(&state, redeem(&value, None)).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert!(
        out.set_cookie().contains("Max-Age=28800"),
        "{}",
        out.set_cookie()
    );

    let (state, _dir) = fixture().await;
    reload(&state, |c| {
        c.auth.dashboard_session.absolute_timeout_secs = 3600;
    });
    let value = state.dashboard_bootstrap.peek().expect("startup value");
    let out = send(&state, redeem(&value, None)).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert!(
        out.set_cookie().contains("Max-Age=3600"),
        "{}",
        out.set_cookie()
    );
}

/// E5-T18: a fresh link works even while the browser still holds a dead
/// cookie; that is exactly when an operator uses one.
#[tokio::test]
async fn bootstrap_redeems_past_a_dead_cookie() {
    let (state, _dir) = fixture().await;
    let dead = issue(&state);
    age(&state, &dead, IDLE + MIN);
    let value = state.dashboard_bootstrap.peek().expect("startup value");
    let out = send(&state, redeem(&value, Some(&dead))).await;
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert!(
        out.set_cookie().contains(&format!("{SESSION_COOKIE}=")) && !out.clears_cookie(),
        "a new session cookie is set: {}",
        out.set_cookie()
    );
}

/// The link the dashboard-link endpoint returned, for `credential`.
async fn mint(state: &Arc<AppState>, credential: Option<&str>, cookie: Option<&str>) -> Reply {
    send(state, request("POST", LINK, cookie, credential, false)).await
}

fn bootstrap_value(link: &str) -> String {
    link.split_once("/dashboard?bootstrap=")
        .map(|(_, v)| v.to_string())
        .unwrap_or_default()
}

/// E5-T7: an admin credential re-arms a fresh single-use link without a
/// restart; the replaced value is dead.
#[tokio::test]
async fn rearm_issues_fresh_single_use_link() {
    let (state, _dir) = fixture().await;
    let old = state.dashboard_bootstrap.peek().expect("startup value");

    let out = mint(&state, Some(ADMIN_KEY), None).await;
    assert_eq!(out.status, StatusCode::OK, "{}", out.body);
    let link = out.json()["link"].as_str().unwrap_or_default().to_string();
    assert!(link.starts_with("http://127.0.0.1:"), "{link}");
    let new = bootstrap_value(&link);
    assert!(!new.is_empty(), "{link}");
    assert_ne!(new, old, "a fresh value");

    assert_eq!(
        send(&state, redeem(&old, None)).await.status,
        StatusCode::UNAUTHORIZED,
        "the replaced value no longer redeems"
    );
    assert_eq!(
        send(&state, redeem(&new, None)).await.status,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        send(&state, redeem(&new, None)).await.status,
        StatusCode::UNAUTHORIZED,
        "single use"
    );

    let by_bearer = mint(&state, Some(BEARER), None).await;
    assert_eq!(
        by_bearer.status,
        StatusCode::OK,
        "the static bearer may mint"
    );
}

/// E5-T7 (refusals): only a credential that redemption itself accepts may
/// mint a link; a session cannot renew itself past the absolute cap.
#[tokio::test]
async fn only_a_static_admin_credential_may_mint_a_link() {
    let (state, _dir) = fixture().await;
    let before = state.dashboard_bootstrap.peek();

    let standard = mint(&state, Some(STANDARD_KEY), None).await;
    assert_eq!(standard.status, StatusCode::FORBIDDEN, "{}", standard.body);

    let h = issue(&state);
    let by_session = mint(&state, None, Some(&h)).await;
    assert_eq!(
        by_session.status,
        StatusCode::FORBIDDEN,
        "a dashboard session may not mint a link: {}",
        by_session.body
    );
    assert_eq!(
        state.dashboard_bootstrap.peek(),
        before,
        "a refused mint changes nothing"
    );
}
