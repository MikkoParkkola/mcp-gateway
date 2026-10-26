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

async fn fixture() -> (Arc<AppState>, tempfile::TempDir) {
    let auth = AuthConfig {
        enabled: true,
        bearer_token: Some(BEARER.to_string()),
        ..AuthConfig::default()
    };
    test_router_app_state_with_auth_and_key_server(&auth, None).await
}

/// `GET /ui/api/config` as the admin bearer.
async fn view(state: &Arc<AppState>) -> Value {
    let request = Request::builder()
        .uri("/ui/api/config")
        .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_346))))
        .body(Body::empty())
        .expect("request builds");
    let response = create_router(Arc::clone(state))
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
    assert_eq!(view(&state).await["environment"], Value::Null, "unset");

    reload_top(&state, "environment", "staging".into());
    assert_eq!(view(&state).await["environment"], "staging");

    reload_top(&state, "environment", "prod".into());
    assert_eq!(view(&state).await["environment"], "prod");

    reload_top(&state, "environment", Value::Null);
    assert_eq!(view(&state).await["environment"], Value::Null, "removed");
}

// F8 (view): the flags the view reports are the published ones.
#[tokio::test]
async fn f8_the_view_reports_the_flags_after_a_reload() {
    let (state, _dir) = Box::pin(fixture()).await;
    let before = view(&state).await;
    let (sanitize, ssrf) = (
        before["sanitize_input"].as_bool().expect("bool"),
        before["ssrf_protection"].as_bool().expect("bool"),
    );

    let mut config = (*state.live_config.get()).clone();
    config.security.sanitize_input = !sanitize;
    config.security.ssrf_protection = !ssrf;
    state.live_config.set(config);

    let after = view(&state).await;
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

/// `POST` the import preview for `url` as the admin bearer: the status.
async fn preview(state: &Arc<AppState>, url: &str) -> axum::http::StatusCode {
    let request = Request::builder()
        .method("POST")
        .uri("/ui/api/import/openapi/preview")
        .header(header::AUTHORIZATION, format!("Bearer {BEARER}"))
        .header(header::CONTENT_TYPE, "application/json")
        .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 52_347))))
        .body(Body::from(serde_json::json!({ "url": url }).to_string()))
        .expect("request builds");
    tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        create_router(Arc::clone(state)).oneshot(request),
    )
    .await
    .expect("bounded")
    .expect("the router is infallible")
    .status()
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
    let (url, hits) = spec_server().await;

    set_ssrf(&state, false);
    assert!(preview(&state, &url).await.is_success(), "off");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "off: fetched");

    set_ssrf(&state, true);
    assert!(!preview(&state, &url).await.is_success(), "on after reload");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "on after reload: fetched");

    set_ssrf(&state, false);
    assert!(preview(&state, &url).await.is_success(), "off after reload");
    assert_eq!(hits.load(Ordering::SeqCst), 2, "off after reload: fetched");
}
