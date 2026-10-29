// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The UI's config view follows a reload (ADR-023): the two security flags
//! and the environment name are read from the published config on each
//! response, never from startup state or the session.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, header};
use serde_json::Value;
use tower::ServiceExt;

use super::tests::test_router_app_state_with_auth_and_key_server;
use super::{AppState, create_router};
use crate::config::{AuthConfig, Config};

const BEARER: &str = "live-view-bearer";

async fn fixture() -> (Arc<AppState>, crate::gateway::router::tests::FixtureDir) {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_string()),
        ..AuthConfig::default()
    };
    test_router_app_state_with_auth_and_key_server(&auth, None).await
}

/// `GET /ui/api/config` as the admin bearer, on `router`: one router per
/// test, kept across reloads as the long-lived server keeps it.
async fn view(router: &axum::Router) -> Value {
    let request = Request::builder()
        .uri("/ui/api/config")
        .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_346))))
        .body(Body::empty())
        .expect("request builds");
    let response = router
        .clone()
        .oneshot(request)
        .await
        .expect("the router is infallible");
    assert!(response.status().is_success(), "{}", response.status());
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    serde_json::from_slice(&body).expect("json")
}

/// Publish the running config with `key` set to `value` at the top level, as
/// a reload of an edited file would. Through JSON so the row compiles before
/// the key exists.
fn reload_top(state: &AppState, key: &str, value: Value) {
    let mut v = serde_json::to_value(&*state.live_config.get()).expect("serializes");
    v[key] = value;
    let config: Config = serde_json::from_value(v).expect("still a config");
    state.live_config.set(config);
}

// E1: no name serves none; added, changed and removed by reload, each served
// on the next response, with no restart.
#[tokio::test]
async fn e1_the_environment_name_follows_reloads() {
    let (state, _dir) = Box::pin(fixture()).await;
    let router = create_router(Arc::clone(&state));
    assert_eq!(view(&router).await["environment"], Value::Null, "unset");

    reload_top(&state, "environment", "staging".into());
    assert_eq!(view(&router).await["environment"], "staging");

    reload_top(&state, "environment", "prod".into());
    assert_eq!(view(&router).await["environment"], "prod");

    reload_top(&state, "environment", Value::Null);
    assert_eq!(view(&router).await["environment"], Value::Null, "removed");
}

// F8 (view): the flags the view reports are the published ones.
#[tokio::test]
async fn f8_the_view_reports_the_flags_after_a_reload() {
    let (state, _dir) = Box::pin(fixture()).await;
    let router = create_router(Arc::clone(&state));
    let before = view(&router).await;
    let (sanitize, ssrf) = (
        before["sanitize_input"].as_bool().expect("bool"),
        before["ssrf_protection"].as_bool().expect("bool"),
    );

    let mut config = (*state.live_config.get()).clone();
    config.security.sanitize_input = !sanitize;
    config.security.ssrf_protection = !ssrf;
    state.live_config.set(config);

    let after = view(&router).await;
    assert_eq!(after["sanitize_input"], !sanitize, "{after}");
    assert_eq!(after["ssrf_protection"], !ssrf, "{after}");
}

const SPEC: &str = "openapi: 3.0.0\ninfo:\n  title: T\n  version: '1'\npaths:\n  /items:\n    get:\n      operationId: listItems\n      responses:\n        '200':\n          description: ok\n";

/// Serve `SPEC` on loopback; the counter records each fetch.
async fn spec_server() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let app = axum::Router::new().route(
        "/spec.yaml",
        axum::routing::get(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            async { SPEC }
        }),
    );
    let listener = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        tokio::net::TcpListener::bind("127.0.0.1:0"),
    )
    .await
    .expect("bounded")
    .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (format!("http://127.0.0.1:{port}/spec.yaml"), hits)
}

/// `POST` the import preview for `url` as the admin bearer: the status and
/// the body text.
async fn preview(router: &axum::Router, url: &str) -> (axum::http::StatusCode, String) {
    let request = Request::builder()
        .method("POST")
        .uri("/ui/api/import/openapi/preview")
        .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .header(header::CONTENT_TYPE, "application/json")
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_347))))
        .body(Body::from(serde_json::json!({ "url": url }).to_string()))
        .expect("request builds");
    let response = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        router.clone().oneshot(request),
    )
    .await
    .expect("bounded")
    .expect("the router is infallible");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn set_ssrf(state: &AppState, on: bool) {
    let mut config = (*state.live_config.get()).clone();
    config.security.ssrf_protection = on;
    state.live_config.set(config);
}

// F5: the import's fetch follows `ssrf_protection` across reloads. A spec on
// loopback is fetched while off; turned on, the import is refused and the
// server sees no fetch; turned off again, it is fetched.
#[tokio::test]
async fn f5_the_ui_import_follows_ssrf_protection() {
    use std::sync::atomic::Ordering;
    let (state, _dir) = Box::pin(fixture()).await;
    let router = create_router(Arc::clone(&state));
    let (url, hits) = spec_server().await;

    set_ssrf(&state, false);
    let (status, body) = preview(&router, &url).await;
    assert!(status.is_success(), "off: {body}");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "off: fetched");

    set_ssrf(&state, true);
    let (status, body) = preview(&router, &url).await;
    assert!(
        !status.is_success() && body.contains("SSRF protection blocked URL"),
        "on after reload: not the SSRF refusal: {status} {body}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1, "on after reload: fetched");

    set_ssrf(&state, false);
    let (status, body) = preview(&router, &url).await;
    assert!(status.is_success(), "off after reload: {body}");
    assert_eq!(hits.load(Ordering::SeqCst), 2, "off after reload: fetched");
}

/// `GET uri` on the UI routes alone, with `generation` pinned by hand and no
/// outer layer to replace it, as an admin client.
async fn view_pinned(
    state: &Arc<AppState>,
    uri: &str,
    generation: Arc<crate::config_reload::Generation>,
) -> Value {
    let request = Request::builder()
        .uri(uri)
        .extension(generation)
        .extension(crate::gateway::auth::AuthenticatedClient {
            admin: true,
            authenticated: true,
            // No credential was presented, so no principal (MIK-6704.IDENT.1a).
            principal: crate::gateway::record_principal::InternalPrincipal::new(String::new()),
            ..crate::gateway::auth::anonymous_client()
        })
        .body(Body::empty())
        .expect("request builds");
    let response = crate::gateway::ui::api_router()
        .with_state(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("the router is infallible");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    assert!(
        status.is_success(),
        "{uri}: {status} {}",
        String::from_utf8_lossy(&body)
    );
    serde_json::from_slice(&body).expect("json")
}

// F8: one response, one generation. The view and the control-plane snapshot
// are served from the generation pinned on the request, here one that
// differs from the published config in every field read; a field read from
// the published config instead would show its value.
#[tokio::test]
async fn f8_a_response_reads_only_the_request_generation() {
    let (state, _dir) = Box::pin(fixture()).await;
    let published = state.live_config.get();
    let mut pinned = (*published).clone();
    pinned.security.sanitize_input = !published.security.sanitize_input;
    pinned.security.ssrf_protection = !published.security.ssrf_protection;
    pinned.environment = Some("pinned-only".to_string());
    let pinned = crate::config_reload::LiveConfig::new(pinned).generation();
    assert_ne!(published.environment.as_deref(), Some("pinned-only"));

    let v = view_pinned(&state, "/ui/api/config", Arc::clone(&pinned)).await;
    assert_eq!(v["sanitize_input"], pinned.sanitize_input(), "{v}");
    assert_eq!(v["ssrf_protection"], pinned.ssrf_protection(), "{v}");
    assert_eq!(v["environment"], "pinned-only", "{v}");

    let snap = view_pinned(&state, "/ui/api/control-plane", pinned.clone()).await;
    let enforced = |id: &str| {
        snap.pointer("/view/policies")
            .and_then(Value::as_array)
            .and_then(|rows| rows.iter().find(|p| p["policy_id"] == id))
            .map(|p| p["enforced"].clone())
    };
    assert_eq!(
        enforced("local:input_sanitization"),
        Some(Value::Bool(pinned.sanitize_input())),
        "{snap}"
    );
    assert_eq!(
        enforced("local:ssrf_protection"),
        Some(Value::Bool(pinned.ssrf_protection())),
        "{snap}"
    );
}
