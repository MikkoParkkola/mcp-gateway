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
/// A minute short of the idle limit.
const NEARLY_IDLE: Duration = Duration::from_secs(1740);

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
        kind: crate::config::ApiKeyKind::Shared,
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
    send_to(create_router(Arc::clone(state)), request).await
}

/// `request` through an already built router, so state captured when the
/// router was built (as in production) stays captured across reloads.
async fn send_to(router: axum::Router, request: Request<Body>) -> Reply {
    let response = tokio::time::timeout(Duration::from_secs(30), router.oneshot(request))
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

/// `state` with `running` as the process's startup config, as if it had been
/// started with it: host, port and TLS are read from there, not from reloads.
fn with_running(mut state: Arc<AppState>, running: crate::config::Config) -> Arc<AppState> {
    Arc::get_mut(&mut state)
        .expect("state is unique")
        .live_config = Arc::new(crate::config_reload::LiveConfig::new(running));
    state
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
        .expect("open log")
        // Fail-closed, as with auth on: a failed append degrades the log.
        .with_failure_policy(crate::security::audit::AuditFailurePolicy::FailClosed),
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
        Some("/ui"),
        "logout lands on a page that needs no session"
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

/// E5-T20: a stuck audit write never holds a logout: the record is written
/// through the bounded append, and the 303 comes back on the bound's answer.
/// The oracle is that answer, not the elapsed time (MIK-8222): a logout that
/// waited on the write would get the write's answer, and none from the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn logout_is_not_held_by_a_stalled_audit_write() {
    let (mut state, _dir) = fixture().await;
    let (log, _log_dir) = with_audit(&mut state);
    let h = issue(&state);
    let release = log.stall_next_write_for_test(Duration::from_millis(200));
    let out = send(&state, logout(Some(&h))).await;
    let answered_by_the_bound = log.stall_answers_for_test();
    release.release();
    assert_eq!(out.status, StatusCode::SEE_OTHER, "{}", out.body);
    assert_eq!(
        answered_by_the_bound, 1,
        "logout waited on the audit write instead of the bound"
    );
    assert_eq!(
        check(&state, &h),
        SessionCheck::Unknown,
        "and still revoked"
    );
}

/// E5-T19 (route): logging out with a cookie already past its limit writes
/// no logout record: that session ended at its limit.
#[tokio::test]
async fn logout_of_an_expired_session_writes_no_record() {
    let (mut state, _dir) = fixture().await;
    let (log, _log_dir) = with_audit(&mut state);
    let h = issue(&state);
    age(&state, &h, IDLE + MIN);
    assert_eq!(
        send(&state, logout(Some(&h))).await.status,
        StatusCode::SEE_OTHER
    );
    let raw = std::fs::read_to_string(log.path()).unwrap_or_default();
    assert!(
        !raw.contains(LOGOUT),
        "no logout record for an expired session: {raw}"
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
    let record = raw
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|e| e["event"] == "admin_action" && e.to_string().contains(LOGOUT))
        .expect("the logout record");
    assert_eq!(
        record["who"]["credential_kind"], "dashboard_session",
        "the record names the dashboard session that logged out: {record}"
    );
    assert!(!raw.contains(&h), "the handle never reaches the log");

    // The route is unauthenticated, so attempts that end nothing write nothing.
    for cookie in [None, Some("never-issued"), Some(h.as_str())] {
        assert_eq!(
            send(&state, logout(cookie)).await.status,
            StatusCode::SEE_OTHER
        );
    }
    let after = std::fs::read_to_string(log.path()).unwrap_or_default();
    assert_eq!(after, raw, "no record for a logout that ended no session");
}

/// A cross-site page cannot log the operator out: the origin guard refuses a
/// foreign `Origin` before the route runs.
#[tokio::test]
async fn a_cross_site_logout_is_refused() {
    let (state, _dir) = fixture().await;
    let h = issue(&state);
    let mut forged = logout(Some(&h));
    forged.headers_mut().insert(
        header::ORIGIN,
        "https://attacker.example".parse().expect("origin"),
    );
    assert_eq!(send(&state, forged).await.status, StatusCode::FORBIDDEN);
    assert_eq!(
        check(&state, &h),
        SessionCheck::Valid,
        "the session survives"
    );
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

/// E5-T24: an HTTPS `public_url` written in any letter case marks cookies
/// `Secure`; the scheme is case-insensitive.
#[tokio::test]
async fn an_uppercase_https_public_url_still_marks_cookies_secure() {
    let (state, _dir) = fixture().await;
    reload(&state, |c| {
        c.server.public_url = Some("HTTPS://Gateway.Example".to_string());
    });
    let h = issue(&state);
    let out = send(&state, logout(Some(&h))).await;
    assert!(out.set_cookie().contains("Secure"), "{}", out.set_cookie());
    assert!(crate::gateway::auth::is_https_url("Https://x"));
    assert!(!crate::gateway::auth::is_https_url("http://x"));
    assert!(!crate::gateway::auth::is_https_url("https:/"));
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
    age(&state, &h, NEARLY_IDLE);
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
    age(&state, &h, NEARLY_IDLE);
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

    age(&state, &h, NEARLY_IDLE);
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
    let h = issue(&state);
    reload(&state, |c| c.auth.dashboard_session.idle_timeout_secs = 600);
    age(&state, &h, Duration::from_secs(601));
    assert_eq!(
        send(&state, get(STATUS, Some(&h))).await.status,
        StatusCode::UNAUTHORIZED,
        "a shortened idle limit applies at the next check"
    );

    reload(&state, |c| {
        c.auth.dashboard_session.idle_timeout_secs = 1800;
    });
    let h = issue(&state);
    reload(&state, |c| {
        c.auth.dashboard_session.absolute_timeout_secs = 3600;
    });
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

#[path = "e5_dashboard_session_tests/link.rs"]
mod link;

#[path = "e5_dashboard_session_tests/handoff.rs"]
mod handoff;

#[path = "e5_dashboard_session_tests/clock.rs"]
mod clock;

/// D4 (MIK-7570.METRICS.2): an expired session answered with its own 401 is
/// counted as `session_expired`; a bearer beside the dead cookie is not.
#[cfg(feature = "metrics")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expired_session_refusal_is_counted() {
    let (state, _dir) = fixture().await;
    let expired = issue(&state);
    age(&state, &expired, IDLE + MIN);
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    telemetry_metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let out = send(&state, get("/dashboard", Some(&expired))).await;
                assert_eq!(out.status, StatusCode::UNAUTHORIZED, "{}", out.body);
                // Issued only now: issuing sweeps expired entries, and the
                // first handle must still be stored when its request arrives.
                let also_expired = issue(&state);
                age(&state, &also_expired, IDLE + MIN);
                let _ = send(
                    &state,
                    request("GET", STATUS, Some(&also_expired), Some(BEARER), false),
                )
                .await;
            });
        });
    });
    let text = handle.render();
    let counted: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("mcp_auth_failures_total{"))
        .collect();
    assert_eq!(
        counted.len(),
        1,
        "one refusal, one series; the bearer request is not a failure: {text}"
    );
    assert!(counted[0].contains(r#"kind="session_expired""#), "{text}");
    assert!(
        matches!(counted[0].rsplit(' ').next(), Some("1" | "1.0")),
        "{text}"
    );
}
