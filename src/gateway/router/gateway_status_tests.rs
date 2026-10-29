// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `GET /ui/api/gateway`: admin only, every field of the contract, uptime from
//! the process start, TLS from the bound state, and clients by reported name
//! without any session identifier. Requests go through `create_router`, so the
//! real auth middleware runs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use serde_json::Value;
use tower::ServiceExt;

use super::tests::test_router_app_state_with_auth_and_key_server;
use super::{AppState, ProcessFacts, ProcessStart, create_router};
use crate::config::{ApiKeyConfig, AuthConfig, Config};
use crate::config_reload::{LiveConfig, ReloadContext};
use crate::counters::VersionChange;
use crate::gateway::session_id::SessionOwner;

const ROUTE: &str = "/ui/api/gateway";
const ADMIN: &str = "gateway-status-admin-key";
const STANDARD: &str = "gateway-status-standard-key";

fn key(secret: &str, admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        expires_at: None,
        name: secret.to_string(),
        rate_limit: 0,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin,
        ..ApiKeyConfig::default()
    }
}

/// Auth on, one admin and one standard key.
async fn fixture() -> (Arc<AppState>, Arc<tempfile::TempDir>) {
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![key(ADMIN, true), key(STANDARD, false)],
        ..AuthConfig::default()
    };
    test_router_app_state_with_auth_and_key_server(&auth, None).await
}

/// `fixture`, with `config` as the configuration the process started with.
async fn fixture_with(config: Config) -> (Arc<AppState>, Arc<tempfile::TempDir>) {
    let (mut state, dir) = fixture().await;
    Arc::get_mut(&mut state).expect("unshared").live_config = Arc::new(LiveConfig::new(config));
    (state, dir)
}

/// Replace the process facts, which a fixture holds uniquely.
fn with_process(state: &mut Arc<AppState>, facts: ProcessFacts) {
    Arc::get_mut(state).expect("unshared").process = Arc::new(facts);
}

async fn get_at(state: &Arc<AppState>, uri: &str, bearer: Option<&str>) -> (StatusCode, String) {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(credential) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {credential}"));
    }
    let request = builder.body(Body::empty()).expect("request builds");
    let response = tokio::time::timeout(
        Duration::from_secs(30),
        create_router(Arc::clone(state)).oneshot(request),
    )
    .await
    .expect("the request finished")
    .expect("the router is infallible");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    (status, String::from_utf8_lossy(&body).into_owned())
}

async fn read(state: &Arc<AppState>) -> Value {
    let (status, body) = get_at(state, ROUTE, Some(ADMIN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    serde_json::from_str(&body).expect("a JSON body")
}

/// A reload context on a real file, attached to the state's meta-MCP.
fn attach_reload_context(state: &AppState, dir: &tempfile::TempDir) -> Arc<ReloadContext> {
    let path = dir.path().join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(
        &path,
        crate::yaml::to_string(&Config::default()).expect("yaml"),
    )
    .expect("config written owner-only");
    let context = Arc::new(
        ReloadContext::new(
            path,
            Arc::clone(&state.live_config),
            Arc::clone(&state.backends),
            crate::config::FailsafeConfig::default(),
            Duration::from_secs(60),
        )
        .expect("context builds"),
    );
    state.meta_mcp.set_reload_context(Arc::clone(&context));
    context
}

/// Open an ordinary session for `who`, reporting `name`; returns its id.
fn connect(state: &AppState, who: &str, name: &str) -> String {
    let owner = SessionOwner::Credential(who.to_owned());
    let id = state
        .multiplexer
        .get_or_create_session_id_scoped(None, &owner, None);
    state
        .multiplexer
        .record_reported_name(id.expose_secret(), &owner, name);
    id.expose_secret().to_owned()
}

#[tokio::test]
async fn only_an_admin_reads_the_route() {
    let (state, _dir) = fixture().await;
    let (anonymous, _) = get_at(&state, ROUTE, None).await;
    assert_eq!(anonymous, StatusCode::UNAUTHORIZED);
    let (standard, body) = get_at(&state, ROUTE, Some(STANDARD)).await;
    assert_eq!(standard, StatusCode::FORBIDDEN, "{body}");
    assert!(!body.contains("uptime_secs"), "{body}");
}

#[tokio::test]
async fn an_admin_gets_every_field_of_the_contract() {
    let (state, dir) = fixture().await;
    attach_reload_context(&state, &dir);
    let body = read(&state).await;
    for key in [
        "version",
        "started_at",
        "uptime_secs",
        "environment",
        "reloads",
        "tls",
        "upgrade",
        "clients",
        "refused_at_start",
    ] {
        assert!(body.get(key).is_some(), "missing {key}: {body}");
    }
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert!(body["environment"]["name"].is_string(), "{body}");
    assert_eq!(body["reloads"]["attempts"], 0, "{body}");
    assert!(body["reloads"]["last"].is_null(), "{body}");
    assert_eq!(body["clients"]["named_total"], 0, "{body}");
    assert_eq!(body["clients"]["truncated"], false, "{body}");
    assert!(body["refused_at_start"].is_array(), "{body}");
}

#[tokio::test]
async fn uptime_counts_from_the_process_start_not_the_first_request() {
    let (mut state, _dir) = fixture().await;
    let mono = Instant::now()
        .checked_sub(Duration::from_secs(3600))
        .expect("a host up for an hour");
    with_process(
        &mut state,
        ProcessFacts::new(ProcessStart::at(None, mono), None),
    );
    let body = read(&state).await;
    assert!(
        body["uptime_secs"].as_u64().is_some_and(|s| s >= 3600),
        "{body}"
    );
    assert!(
        body["started_at"].is_null(),
        "no wall clock was given: {body}"
    );
    for uri in ["/ui/api/status", "/ui/api/overview"] {
        let (_, raw) = get_at(&state, uri, Some(ADMIN)).await;
        let json: Value = serde_json::from_str(&raw).expect("JSON");
        let uptime = json["uptime_secs"]
            .as_u64()
            .or_else(|| json["kpi"]["uptime_secs"].as_u64());
        assert!(uptime.is_some_and(|s| s >= 3600), "{uri}: {raw}");
    }
}

#[tokio::test]
async fn a_reload_shows_in_the_tally_with_its_outcome() {
    let (state, dir) = fixture().await;
    let context = attach_reload_context(&state, &dir);
    context.reload_outcome().await.expect("applied");
    let body = read(&state).await;
    assert_eq!(body["reloads"]["attempts"], 1, "{body}");
    assert_eq!(body["reloads"]["applied"], 1, "{body}");
    assert_eq!(body["reloads"]["last"]["outcome"], "applied", "{body}");
    assert!(body["reloads"]["last"]["at"].is_string(), "{body}");
}

fn mtls_config(enabled: bool, require_client_cert: bool) -> Config {
    let mut config = Config::default();
    config.mtls.enabled = enabled;
    config.mtls.require_client_cert = require_client_cert;
    config
}

#[tokio::test]
async fn tls_reports_enabled_and_required_for_each_combination() {
    for (enabled, required, expect_required) in [
        (false, false, false),
        (false, true, false),
        (true, false, false),
        (true, true, true),
    ] {
        let (state, _dir) = fixture_with(mtls_config(enabled, required)).await;
        let body = read(&state).await;
        assert_eq!(body["tls"]["enabled"], enabled, "{body}");
        assert_eq!(
            body["tls"]["client_certificates_required"], expect_required,
            "enabled={enabled} required={required}: {body}"
        );
    }
}

#[tokio::test]
async fn a_staged_reload_does_not_change_the_reported_tls_state() {
    let (state, _dir) = fixture_with(mtls_config(false, true)).await;
    state.live_config.set(mtls_config(true, true));
    let body = read(&state).await;
    assert_eq!(body["tls"]["enabled"], false, "{body}");
    assert_eq!(body["tls"]["client_certificates_required"], false, "{body}");
}

#[tokio::test]
async fn a_configured_environment_name_is_reported_as_config() {
    let config = Config {
        environment: Some("prod-eu".to_owned()),
        ..Config::default()
    };
    let (state, _dir) = fixture_with(config).await;
    let body = read(&state).await;
    assert_eq!(
        body["environment"],
        serde_json::json!({"name": "prod-eu", "source": "config"})
    );
}

#[tokio::test]
async fn without_a_configured_name_the_environment_is_hostname_or_default() {
    let (state, _dir) = fixture().await;
    let body = read(&state).await;
    let source = body["environment"]["source"].as_str().expect("a source");
    assert!(["hostname", "default"].contains(&source), "{body}");
}

#[tokio::test]
async fn the_recorded_version_change_is_served_with_its_items() {
    let (mut state, _dir) = fixture().await;
    let change = VersionChange {
        from: "3.5.1".to_owned(),
        to: "4.0.0".to_owned(),
    };
    with_process(
        &mut state,
        ProcessFacts::new(ProcessStart::now(), Some(change)),
    );
    let body = read(&state).await;
    assert_eq!(body["upgrade"]["from"], "3.5.1", "{body}");
    assert!(
        body["upgrade"]["items"]
            .as_array()
            .is_some_and(|i| !i.is_empty()),
        "{body}"
    );
}

#[tokio::test]
async fn the_refused_at_start_snapshot_is_served() {
    let (state, _dir) = fixture().await;
    let refusal = crate::config_reload::refusals::startup_refusal("inventory", &[]);
    state.process.record_refused_at_start(vec![refusal]);
    let body = read(&state).await;
    assert_eq!(body["refused_at_start"][0]["kind"], "startup", "{body}");
    assert_eq!(
        body["refused_at_start"][0]["backend"], "inventory",
        "{body}"
    );
}

#[tokio::test]
async fn clients_are_listed_by_reported_name_and_never_by_session_id() {
    let (state, _dir) = fixture().await;
    let id = connect(&state, "alice", "Claude Desktop");
    connect(&state, "bob", "<script>alert(1)</script>");
    let (status, raw) = get_at(&state, ROUTE, Some(ADMIN)).await;
    assert_eq!(status, StatusCode::OK);
    let body: Value = serde_json::from_str(&raw).expect("JSON");
    let names: Vec<&str> = body["clients"]["named"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|c| c["reported_name"].as_str().expect("a name"))
        .collect();
    assert!(names.contains(&"Claude Desktop"), "{raw}");
    assert!(names.contains(&"<script>alert(1)</script>"), "{raw}");
    assert!(
        body["clients"]["named"][0]["last_seen"].is_string(),
        "{raw}"
    );
    assert!(!raw.contains(&id), "no session id anywhere: {raw}");
    assert!(!raw.contains("gw-"), "no session id anywhere: {raw}");
    assert!(!raw.contains("fingerprint"), "{raw}");
}

#[tokio::test]
async fn provisional_sessions_and_unnamed_clients_are_counted_apart() {
    let (state, _dir) = fixture().await;
    connect(&state, "alice", "Cursor");
    let owner = SessionOwner::Credential("bob".to_owned());
    state
        .multiplexer
        .get_or_create_session_id_scoped(None, &owner, None);
    let _provisional = state
        .multiplexer
        .open_request_session_scoped(
            None,
            &SessionOwner::Credential("carol".to_owned()),
            None,
            crate::gateway::streaming::MintKind::Provisional,
        )
        .expect("below the cap");
    let body = read(&state).await;
    assert_eq!(body["clients"]["named_total"], 1, "{body}");
    assert_eq!(body["clients"]["unnamed"], 1, "{body}");
}

/// POST `body` to `/mcp` as `bearer`, in session `session`; returns the
/// status, the session id the answer names, and the body. Offers JSON only:
/// `Accept` alone picks the body shape, and an offered event stream would
/// answer as SSE.
async fn mcp(
    state: &Arc<AppState>,
    bearer: &str,
    session: Option<&str>,
    body: &Value,
) -> (StatusCode, Option<String>, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json");
    if let Some(session) = session {
        builder = builder.header("mcp-session-id", session);
    }
    let request = builder
        .body(Body::from(body.to_string()))
        .expect("request builds");
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router is infallible");
    let status = response.status();
    let id = response
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let raw = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, id, String::from_utf8_lossy(&raw).into_owned())
}

/// A reported name equal to another key's name changes neither what the
/// session may list nor what it may reach: both sessions see the same
/// successful tool listing, and the standard key still gets 403 on the admin
/// route. Attribution is not observed here; it is keyed on the credential, and
/// the name is stored where no attribution path reads it.
#[tokio::test]
async fn a_reported_name_does_not_change_what_a_session_may_do() {
    let (state, _dir) = fixture().await;
    let init = |name: &str| {
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                       "clientInfo": {"name": name, "version": "1"}}})
    };
    let (status, plain, _) = mcp(&state, STANDARD, None, &init("honest-client")).await;
    assert_eq!(status, StatusCode::OK);
    let (status, spoof, _) = mcp(&state, STANDARD, None, &init(ADMIN)).await;
    assert_eq!(status, StatusCode::OK);
    let list = serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let (status, _, plain_tools) = mcp(&state, STANDARD, plain.as_deref(), &list).await;
    assert_eq!(status, StatusCode::OK, "{plain_tools}");
    let (status, _, spoof_tools) = mcp(&state, STANDARD, spoof.as_deref(), &list).await;
    assert_eq!(status, StatusCode::OK, "{spoof_tools}");
    assert_eq!(plain_tools, spoof_tools, "the name changed what is listed");
    let listed: Value =
        serde_json::from_str(&plain_tools).unwrap_or_else(|e| panic!("{e}: {plain_tools:?}"));
    assert!(
        listed["result"]["tools"]
            .as_array()
            .is_some_and(|t| !t.is_empty()),
        "{plain_tools}"
    );
    assert!(listed.get("error").is_none(), "{plain_tools}");
    let (denied, body) = get_at(&state, ROUTE, Some(STANDARD)).await;
    assert_eq!(denied, StatusCode::FORBIDDEN, "{body}");
    let listed = read(&state).await;
    assert_eq!(listed["clients"]["named_total"], 2, "{listed}");
}

#[tokio::test]
async fn a_markup_client_name_reaches_the_api_verbatim() {
    const NAME: &str = "<img src=x onerror=alert(1)>";
    let (state, _dir) = fixture().await;
    let init = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                   "clientInfo": {"name": NAME, "version": "1"}}});
    let (status, _, _) = mcp(&state, STANDARD, None, &init).await;
    assert_eq!(status, StatusCode::OK);
    let (_, raw) = get_at(&state, ROUTE, Some(ADMIN)).await;
    let body: Value = serde_json::from_str(&raw).expect("JSON");
    assert_eq!(body["clients"]["named"][0]["reported_name"], NAME, "{raw}");
    assert!(
        raw.contains(NAME),
        "served un-escaped at the API layer: {raw}"
    );
}
