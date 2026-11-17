// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Proves `POST /ui/signin` mints a dashboard session from a form with script
//! off: the origin rule, the admin-key check, a fresh handle, the
//! audit record, and the router's own refusals.
//!
//! Requests use the literal path `/ui/signin`. Rows that read
//! `mcp_auth_failures_total` are `feature = "metrics"` (the default features
//! include it). The origin rules, the URL and header rows and the router's own
//! answers are in `signin_form_boundary_tests.rs`.

use std::collections::BTreeSet;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::Value;

use super::AppState;
use super::e5_dashboard_session_tests::link::session_handle;
use super::e5_dashboard_session_tests::{Reply, get, send, with_audit};
use super::tests::test_router_app_state_with_auth_and_key_server;
use crate::config::{ApiKeyConfig, AuthConfig};
use crate::gateway::auth::{Now, SESSION_COOKIE, SessionCheck, SessionLimits, Touch};

#[cfg(feature = "metrics")]
use std::collections::BTreeMap;

const ADMIN_SECRET: &str = "signin-admin-key";
const ADMIN_NAME: &str = "signin-admin";
const STANDARD_SECRET: &str = "signin-standard-key";
const STANDARD_NAME: &str = "signin-standard";
const WRONG_SECRET: &str = "signin-wrong-key";
/// 32 characters, and not a substring of [`N8_WRONG`] or of [`N8_NAME`].
const N8_SECRET: &str = "n8-audit-key-0123456789abcdef012";
/// 32 characters, and not a substring of [`N8_SECRET`].
const N8_WRONG: &str = "n8-wrong-key-fedcba9876543210fff";
const N8_NAME: &str = "n8-admin";
const SIGNIN: &str = "/ui/signin";
const FORM: &str = "application/x-www-form-urlencoded";
const REFUSED: &str = "/ui/overview/status#signin-refused";
const DASHBOARD: &str = "/dashboard";

/// Top-level keys of one `append_admin_action` with an empty domain map and an
/// ok envelope. No `error_code`, no `otel_trace_id`, and no `sig`/`key_id`
/// (the fixture's shared secret is empty).
const MINT_KEYS: &[&str] = &[
    "counter",
    "entry_hash",
    "event",
    "outcome",
    "prev_entry_hash",
    "schema_version",
    "surface",
    "timestamp",
    "trace_id",
    "who",
];
/// The refusal record adds `error_code`, which a non-ok envelope writes.
const REFUSAL_KEYS: &[&str] = &[
    "counter",
    "entry_hash",
    "error_code",
    "event",
    "outcome",
    "prev_entry_hash",
    "schema_version",
    "surface",
    "timestamp",
    "trace_id",
    "who",
];

fn named_key(name: &str, secret: &str, admin: bool) -> ApiKeyConfig {
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
        kind: crate::config::ApiKeyKind::Shared,
        ..Default::default()
    }
}

/// The fixture's keys: one admin key and one standard key.
fn fixture_keys() -> Vec<ApiKeyConfig> {
    vec![
        named_key(ADMIN_NAME, ADMIN_SECRET, true),
        named_key(STANDARD_NAME, STANDARD_SECRET, false),
    ]
}

fn auth_with(keys: Vec<ApiKeyConfig>) -> AuthConfig {
    AuthConfig {
        enabled: true,
        bearer_token: Some("signin-static-bearer".to_string()),
        api_keys: keys,
        public_paths: vec!["/health".to_string()],
        ..AuthConfig::default()
    }
}

async fn fixture() -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    test_router_app_state_with_auth_and_key_server(&auth_with(fixture_keys()), None).await
}

/// A key reload. The published config does not carry the fixture's key table
/// (the fixture installs it directly), so a key edit replaces the whole auth
/// section, as `live_keys_dashboard_tests.rs` does.
fn reload_keys(state: &AppState, keys: Vec<ApiKeyConfig>) {
    reload(state, |config| config.auth = auth_with(keys));
}

fn reload(state: &AppState, edit: impl FnOnce(&mut crate::config::Config)) {
    let mut config = (*state.live_config.get()).clone();
    edit(&mut config);
    state.live_config.set(config);
}

fn limits(state: &AppState) -> SessionLimits {
    SessionLimits::from(&state.live_config.get().auth.dashboard_session)
}

fn issue(state: &AppState) -> String {
    state
        .dashboard_bootstrap
        .issue_session_at(Now::read(), &limits(state))
}

fn check(state: &AppState, handle: &str) -> SessionCheck {
    state
        .dashboard_bootstrap
        .check_session(handle, Now::read(), &limits(state), Touch::No)
}

/// The listener port the origin guard snapshotted. Nothing is bound in these
/// tests, so this is `server.port`, not a bound port.
fn listener_port(state: &AppState) -> u16 {
    state.live_config.get().server.port
}

fn http_origin(state: &AppState, host: &str) -> String {
    format!("http://{host}:{}", listener_port(state))
}

fn form_post(
    uri: &str,
    origin: Option<&str>,
    body: Body,
    content_type: &str,
    cookie: Option<&str>,
    document: bool,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_344))))
        .header(header::CONTENT_TYPE, content_type);
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    if let Some(handle) = cookie {
        builder = builder.header(header::COOKIE, format!("{SESSION_COOKIE}={handle}"));
    }
    if document {
        builder = builder
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-dest", "document");
    }
    builder.body(body).expect("request builds")
}

fn post_signin(
    origin: Option<&str>,
    body: &str,
    cookie: Option<&str>,
    document: bool,
) -> Request<Body> {
    form_post(
        SIGNIN,
        origin,
        Body::from(body.to_string()),
        FORM,
        cookie,
        document,
    )
}

fn assert_no_store(reply: &Reply) {
    assert_eq!(
        reply.header(header::CACHE_CONTROL).as_deref(),
        Some("no-store"),
        "status {}",
        reply.status
    );
}

fn assert_no_cookie(reply: &Reply) {
    assert!(
        reply.set_cookie().is_empty(),
        "no Set-Cookie, got {}",
        reply.set_cookie()
    );
}

/// `Secure` is the leading-space spelling `session_cookie` writes.
fn assert_cookie_flags(cookie: &str, secure: bool) {
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite=Strict"), "{cookie}");
    assert_eq!(cookie.contains(" Secure;"), secure, "{cookie}");
}

fn assert_mint(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.header(header::LOCATION).as_deref(), Some(DASHBOARD));
    assert_no_store(reply);
    assert!(
        !reply.set_cookie().is_empty(),
        "a session cookie is set: {}",
        reply.body
    );
}

#[cfg(feature = "metrics")]
fn assert_document_refusal(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.header(header::LOCATION).as_deref(), Some(REFUSED));
    assert_no_store(reply);
    assert_no_cookie(reply);
}

fn assert_bearer_refusal(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
    assert_no_store(reply);
    assert_no_cookie(reply);
    assert_eq!(
        reply.header(header::WWW_AUTHENTICATE).as_deref(),
        Some("Bearer")
    );
    assert_eq!(
        reply.json(),
        serde_json::json!({
            "jsonrpc": "2.0",
            "error": { "code": -32000, "message": "Invalid token" },
            "id": null
        })
    );
}

/// The route's own origin refusal: 401, no-store, JSON-RPC shaped. The
/// message is the route's, so it is not pinned here.
fn assert_route_origin_refusal(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{}", reply.body);
    assert_no_store(reply);
    assert_no_cookie(reply);
    let body = reply.json();
    assert!(body.get("jsonrpc").is_some(), "{}", reply.body);
    assert!(body["error"]["code"].is_number(), "{}", reply.body);
    assert!(body["error"]["message"].is_string(), "{}", reply.body);
}

fn cookie_max_age(cookie: &str) -> u64 {
    cookie
        .split(';')
        .find_map(|part| part.trim().strip_prefix("Max-Age=")?.parse().ok())
        .expect("Max-Age")
}

fn signin_records(log: &crate::security::TransparencyLogger) -> Vec<Value> {
    let raw = std::fs::read_to_string(log.path()).expect("the audit log reads");
    raw.lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("an audit line is JSON"))
        .filter(|entry| entry["event"] == "admin_action" && entry["surface"] == "ui_signin")
        .collect()
}

fn assert_key_set(record: &Value, expected: &[&str]) {
    let got: BTreeSet<_> = record
        .as_object()
        .expect("an audit record is an object")
        .keys()
        .cloned()
        .collect();
    let want: BTreeSet<_> = expected.iter().map(|key| (*key).to_string()).collect();
    assert_eq!(got, want, "{record}");
}

fn record_principal(state: &AppState, secret: &str) -> String {
    let generation = state.live_config.generation();
    let auth = generation.auth();
    let client = auth.validate_token(secret).expect("the admin key resolves");
    client
        .principal
        .record_form(auth.record_key())
        .as_str()
        .to_string()
}

fn rotate(state: &AppState, name: &str, new_secret: &str) {
    let mut keys = fixture_keys();
    let key = keys
        .iter_mut()
        .find(|key| key.name == name)
        .expect("the key is in the fixture");
    key.key_sha256 = Some(crate::config::api_key_digest_spec(new_secret.as_bytes()));
    key.previous_key_sha256 = None;
    key.previous_expires_at = None;
    reload_keys(state, keys);
}

struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `op` on this thread under a DEBUG subscriber. A handler spawned onto
/// another thread would miss the capture.
fn traced<F, T>(op: impl FnOnce() -> F) -> (T, String)
where
    F: std::future::Future<Output = T>,
{
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || Captured(Arc::clone(&writer)))
        .finish();
    crate::test_log_capture::keep_interest_open();
    let out = tracing::subscriber::with_default(subscriber, || {
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(op()))
    });
    let text = String::from_utf8(buffer.lock().expect("log").clone()).expect("log is utf-8");
    (out, text)
}

#[cfg(feature = "metrics")]
fn series(text: &str) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("mcp_auth_failures_total{") else {
            continue;
        };
        let Some((labels, value)) = rest.rsplit_once(' ') else {
            continue;
        };
        let Some(kind) = labels
            .split("kind=\"")
            .nth(1)
            .and_then(|tail| tail.split('"').next())
        else {
            continue;
        };
        out.insert(kind.to_string(), value.parse().unwrap_or(f64::NAN));
    }
    out
}

#[cfg(feature = "metrics")]
fn assert_delta(
    before: &BTreeMap<String, f64>,
    after: &BTreeMap<String, f64>,
    kind: &str,
    delta: f64,
) {
    let prior = before.get(kind).copied().unwrap_or(0.0);
    let later = after.get(kind).copied().unwrap_or(0.0);
    assert!(
        (later - prior - delta).abs() < 1e-6,
        "{kind} moved by {} (want {delta}); before={before:?} after={after:?}",
        later - prior
    );
    let mut kinds: BTreeSet<String> = before.keys().chain(after.keys()).cloned().collect();
    kinds.remove(kind);
    for other in kinds {
        let prior = before.get(&other).copied().unwrap_or(0.0);
        let later = after.get(&other).copied().unwrap_or(0.0);
        assert!(
            (later - prior).abs() < 1e-6,
            "{other} moved while only {kind} may; before={before:?} after={after:?}"
        );
    }
}

#[cfg(feature = "metrics")]
macro_rules! recorded {
    ($read:ident, $body:expr) => {{
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        telemetry_metrics::with_local_recorder(&recorder, || {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    let $read = || series(&handle.render());
                    $body
                })
            })
        })
    }};
}

/// Wrong key, document navigation: 303 to the fixed refused address, no
/// cookie, no-store, and `auth_failure` +1. The admin key beside it mints.
/// `routes::UI_SIGNIN` equals the literal `/ui/signin` once, here.
#[cfg(feature = "metrics")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n3a_wrong_key_document_303s_to_the_fixed_refused_address() {
    assert_eq!(crate::gateway::routes::UI_SIGNIN, SIGNIN);
    let (state, _dir) = fixture().await;
    let origin = http_origin(&state, "127.0.0.1");
    recorded!(read, {
        let before = read();
        let refused = send(
            &state,
            post_signin(Some(&origin), &format!("key={WRONG_SECRET}"), None, true),
        )
        .await;
        let after_refusal = read();
        assert_document_refusal(&refused);
        assert_delta(&before, &after_refusal, "invalid_credential", 1.0);

        let before_mint = read();
        let minted = send(
            &state,
            post_signin(Some(&origin), &format!("key={ADMIN_SECRET}"), None, true),
        )
        .await;
        let after_mint = read();
        assert_mint(&minted);
        assert_delta(&before_mint, &after_mint, "invalid_credential", 0.0);
    });
}

/// Wrong key, not a document: the bearer 401, unchanged, and no cookie.
#[tokio::test]
async fn n3b_wrong_key_without_document_headers_is_401() {
    let (state, _dir) = fixture().await;
    let origin = http_origin(&state, "127.0.0.1");
    let refused = send(
        &state,
        post_signin(Some(&origin), &format!("key={WRONG_SECRET}"), None, false),
    )
    .await;
    assert_bearer_refusal(&refused);
}

/// A standard key is refused exactly as a wrong key is: 303, the fixed
/// address, no cookie. Asserted absolutely first, then those three fields
/// against the wrong-key refusal. The only difference between the two posts
/// is the key.
#[tokio::test]
async fn n3c_standard_key_document_matches_the_wrong_key_refusal() {
    let (state, _dir) = fixture().await;
    let origin = http_origin(&state, "127.0.0.1");
    let standard = send(
        &state,
        post_signin(Some(&origin), &format!("key={STANDARD_SECRET}"), None, true),
    )
    .await;
    assert_eq!(standard.status, StatusCode::SEE_OTHER, "{}", standard.body);
    assert_eq!(standard.header(header::LOCATION).as_deref(), Some(REFUSED));
    assert_no_cookie(&standard);

    let wrong = send(
        &state,
        post_signin(Some(&origin), &format!("key={WRONG_SECRET}"), None, true),
    )
    .await;
    assert_eq!(standard.status, wrong.status);
    assert_eq!(
        standard.header(header::LOCATION),
        wrong.header(header::LOCATION)
    );
    assert_eq!(
        standard.set_cookie().is_empty(),
        wrong.set_cookie().is_empty()
    );
}

/// A body with the valid key plus an unexpected field is 400 and sets no
/// cookie. The key-only body beside it mints. Neither is a document
/// navigation, so the extra field is the only difference and the answer is
/// 400 rather than the document 303.
#[tokio::test]
async fn n3d_unexpected_field_is_400_and_the_key_only_body_mints() {
    let (state, _dir) = fixture().await;
    let origin = http_origin(&state, "127.0.0.1");
    let extra = send(
        &state,
        post_signin(
            Some(&origin),
            &format!("key={ADMIN_SECRET}&extra=1"),
            None,
            false,
        ),
    )
    .await;
    assert_eq!(extra.status, StatusCode::BAD_REQUEST, "{}", extra.body);
    assert_no_cookie(&extra);
    assert_no_store(&extra);

    let only = send(
        &state,
        post_signin(Some(&origin), &format!("key={ADMIN_SECRET}"), None, false),
    )
    .await;
    assert_mint(&only);
}

/// A presented handle is revoked and the answer carries a new one. H1 is
/// live before the POST. The POST fails while the route answers 501, before
/// the new cookie is parsed.
#[tokio::test]
async fn n7_a_presented_handle_is_replaced_and_the_old_one_is_not_live() {
    let (state, _dir) = fixture().await;
    let origin = http_origin(&state, "127.0.0.1");
    let h1 = issue(&state);
    assert_eq!(check(&state, &h1), SessionCheck::Valid);
    let reply = send(
        &state,
        post_signin(
            Some(&origin),
            &format!("key={ADMIN_SECRET}"),
            Some(&h1),
            true,
        ),
    )
    .await;
    assert_mint(&reply);
    let h2 = session_handle(&reply);
    assert_ne!(h2, h1);
    assert_cookie_flags(&reply.set_cookie(), false);
    assert_ne!(check(&state, &h1), SessionCheck::Valid);
    assert_eq!(check(&state, &h2), SessionCheck::Valid);
}

/// The session is bound to its key, observed through the authenticated
/// middleware: `GET /ui/api/status` is 200, stays 200 when an unrelated key
/// is rotated, and is 401 after the admin key's digest is dropped. The mint
/// fails while the route answers 501, before either status check.
#[tokio::test]
async fn n7b_rotating_the_admin_key_ends_the_session_through_the_middleware() {
    let (state, _dir) = fixture().await;
    let origin = http_origin(&state, "127.0.0.1");
    let minted = send(
        &state,
        post_signin(Some(&origin), &format!("key={ADMIN_SECRET}"), None, true),
    )
    .await;
    assert_mint(&minted);
    let h2 = session_handle(&minted);
    let before = send(&state, get("/ui/api/status", Some(&h2))).await;
    assert_eq!(before.status, StatusCode::OK, "{}", before.body);
    assert!(before.json().get("tool_count").is_some(), "{}", before.body);

    rotate(&state, STANDARD_NAME, "signin-standard-rotated");
    let unrelated = send(&state, get("/ui/api/status", Some(&h2))).await;
    assert_eq!(unrelated.status, StatusCode::OK, "{}", unrelated.body);
    assert!(
        unrelated.json().get("tool_count").is_some(),
        "{}",
        unrelated.body
    );

    rotate(&state, ADMIN_NAME, "signin-admin-rotated");
    let ended = send(&state, get("/ui/api/status", Some(&h2))).await;
    assert_eq!(ended.status, StatusCode::UNAUTHORIZED, "{}", ended.body);
}

/// An expiring key caps the session at that expiry. The plan's "backdated"
/// check is a synthetic `Now`: `backdate` moves `issued` and `last_seen`, not
/// `not_after`, and sleeping to cross the cap is ruled out. Idle is longer
/// than the window, and the session is touched one second before the cap.
/// The mint fails while the route answers 501.
#[tokio::test]
async fn n7c_an_expiring_key_caps_the_session_at_the_key_expiry() {
    let (state, _dir) = fixture().await;
    assert!(limits(&state).idle > Duration::from_secs(121));
    let now = Now::read();
    let expires = chrono::DateTime::<chrono::Utc>::from(now.wall + Duration::from_secs(120));
    let mut keys = fixture_keys();
    keys.iter_mut()
        .find(|key| key.name == ADMIN_NAME)
        .expect("the admin key")
        .expires_at = Some(expires);
    reload_keys(&state, keys);
    let origin = http_origin(&state, "127.0.0.1");
    let reply = send(
        &state,
        post_signin(Some(&origin), &format!("key={ADMIN_SECRET}"), None, true),
    )
    .await;
    assert_mint(&reply);
    assert_cookie_flags(&reply.set_cookie(), false);
    let max_age = cookie_max_age(&reply.set_cookie());
    assert!(
        (90..=120).contains(&max_age),
        "Max-Age {max_age} is the seconds to the key's expiry, not 28800"
    );
    let h2 = session_handle(&reply);
    let at = |secs| Now {
        mono: now.mono + Duration::from_secs(secs),
        wall: now.wall + Duration::from_secs(secs),
    };
    let limits = limits(&state);
    assert_eq!(
        state
            .dashboard_bootstrap
            .check_session(&h2, at(119), &limits, Touch::Yes),
        SessionCheck::Valid
    );
    assert_eq!(
        state
            .dashboard_bootstrap
            .check_session(&h2, at(121), &limits, Touch::No),
        SessionCheck::Expired
    );
}

/// One mint record and one refusal record, each by its exact key set, and
/// neither key literal in the log or the captured trace. 303, 401, the
/// origin refusal, GET 405 and the over-limit 413 are no-store. The mint's
/// status is first, so a 501 fails there. The body limit is lowered only
/// after the mint: the mint body is 36 bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n8_mint_and_refusal_are_audited_and_the_key_stays_out_of_the_log() {
    assert_eq!(N8_SECRET.len(), 32);
    assert_eq!(N8_WRONG.len(), 32);
    assert!(!N8_SECRET.contains(N8_WRONG) && !N8_WRONG.contains(N8_SECRET));
    assert!(!N8_SECRET.contains(N8_NAME) && !N8_WRONG.contains(N8_NAME));
    let (mut state, _dir) = fixture().await;
    let (log, _audit_dir) = with_audit(&mut state);
    reload_keys(
        &state,
        vec![
            named_key(N8_NAME, N8_SECRET, true),
            named_key(STANDARD_NAME, STANDARD_SECRET, false),
        ],
    );
    let origin = http_origin(&state, "127.0.0.1");
    let principal = record_principal(&state, N8_SECRET);
    let ((), captured) = traced(|| async {
        let minted = send(
            &state,
            post_signin(Some(&origin), &format!("key={N8_SECRET}"), None, false),
        )
        .await;
        assert_mint(&minted);
        assert_cookie_flags(&minted.set_cookie(), false);
        let records = signin_records(&log);
        assert_eq!(records.len(), 1, "one mint record: {records:?}");
        assert_key_set(&records[0], MINT_KEYS);
        assert_eq!(records[0]["outcome"].as_str(), Some("ok"));
        assert_eq!(
            records[0]["who"]["principal"].as_str(),
            Some(principal.as_str())
        );
        assert_eq!(records[0]["who"]["account"].as_str(), Some(N8_NAME));

        let refused = send(
            &state,
            post_signin(Some(&origin), &format!("key={N8_WRONG}"), None, false),
        )
        .await;
        assert_eq!(refused.status, StatusCode::UNAUTHORIZED, "{}", refused.body);
        assert_no_store(&refused);
        assert_no_cookie(&refused);
        let records = signin_records(&log);
        assert_eq!(records.len(), 2, "one refusal record: {records:?}");
        assert_key_set(&records[1], REFUSAL_KEYS);
        // A refused sign-in is recorded as the admin UI's status table records a
        // 401: outcome `denied` with the INVALID_REQUEST code (literals, A8).
        assert_eq!(records[1]["outcome"].as_str(), Some("denied"));
        assert_eq!(records[1]["error_code"].as_i64(), Some(-32600));
        assert_eq!(records[1]["who"]["principal"].as_str(), Some(""));
        assert_eq!(records[1]["who"]["account"].as_str(), Some(""));

        let origin_refused = send(
            &state,
            post_signin(None, &format!("key={N8_SECRET}"), None, false),
        )
        .await;
        assert_route_origin_refusal(&origin_refused);

        let got = send(&state, get(SIGNIN, None)).await;
        assert_eq!(got.status, StatusCode::METHOD_NOT_ALLOWED, "{}", got.body);
        assert_no_store(&got);
        assert_no_cookie(&got);

        reload(&state, |config| config.server.max_body_size = 32);
        let over = send(
            &state,
            post_signin(Some(&origin), &"x".repeat(64), None, false),
        )
        .await;
        assert_eq!(over.status, StatusCode::PAYLOAD_TOO_LARGE, "{}", over.body);
        assert_no_store(&over);
        assert_no_cookie(&over);
    });
    let bytes = std::fs::read(log.path()).expect("the audit log reads");
    let raw = String::from_utf8_lossy(&bytes);
    for secret in [N8_SECRET, N8_WRONG] {
        assert!(!raw.contains(secret), "the audit log contains the key");
        assert!(!captured.contains(secret), "a log line contains the key");
    }
}

/// The origin rules, the URL and header rows and the router's own answers.
/// Declared after `recorded!`, which those rows use.
#[path = "signin_form_boundary_tests.rs"]
mod boundary;
