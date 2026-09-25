// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `/metrics` answers only the dedicated scrape token (MIK 7570 METRICS.1).
//!
//! Two credentials, two surfaces: the admin bearer does not open `/metrics`,
//! and the scrape token does not open `/mcp`. A missing `env:` variable leaves
//! the gateway running with `/metrics` closed rather than refusing to start.

use super::*;
use crate::config::Config;
use axum::http::header;
use pretty_assertions::assert_eq;
use std::os::unix::fs::PermissionsExt as _;

const ADMIN: &str = "admin-bearer-c7";
const SCRAPE: &str = "scrape-token-c7";

/// A gateway with auth on (admin bearer `ADMIN`) and the given config.
async fn router_with(config: Config) -> (axum::Router, tempfile::TempDir) {
    let (mut state, store) = test_router_app_state_with(StreamingConfig::default(), config).await;
    Arc::get_mut(&mut state)
        .expect("state is uniquely owned here")
        .auth_config = Arc::new(ResolvedAuthConfig::from_config(&AuthConfig {
        enabled: true,
        bearer_token: Some(ADMIN.to_string()),
        ..Default::default()
    }));
    (create_router(state), store)
}

fn with_token(token: Option<&str>) -> Config {
    let mut config = Config::default();
    config.server.metrics_token = token.map(str::to_string);
    config
}

async fn scrape(router: &axum::Router, bearer: Option<&str>) -> axum::response::Response {
    let mut request = axum::http::Request::builder().method("GET").uri("/metrics");
    if let Some(bearer) = bearer {
        request = request.header(header::AUTHORIZATION, format!("Bearer {bearer}"));
    }
    let request = request.body(axum::body::Body::empty()).unwrap();
    router.clone().oneshot(request).await.unwrap()
}

fn assert_refused(response: &axum::response::Response, case: &str) {
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{case}");
    assert_eq!(
        response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok()),
        Some("Bearer"),
        "{case}: a 401 must carry WWW-Authenticate"
    );
}

/// An env file at mode 0600 holding `line`, wired into `config.env_files`.
fn env_file(dir: &tempfile::TempDir, config: &mut Config, line: &str) {
    let path = dir.path().join("metrics.env");
    std::fs::write(&path, format!("{line}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    config.env_files = vec![path.display().to_string()];
}

#[tokio::test]
async fn metrics_without_token_is_401() {
    let (router, _store) = router_with(with_token(Some(SCRAPE))).await;
    assert_refused(&scrape(&router, None).await, "no Authorization header");
}

#[tokio::test]
async fn metrics_wrong_token_is_401() {
    let (router, _store) = router_with(with_token(Some(SCRAPE))).await;
    assert_refused(&scrape(&router, Some("nope")).await, "wrong token");
}

#[tokio::test]
async fn metrics_admin_bearer_is_401() {
    let (router, _store) = router_with(with_token(Some(SCRAPE))).await;
    assert_refused(&scrape(&router, Some(ADMIN)).await, "admin bearer");
}

#[tokio::test]
async fn metrics_unset_token_is_401() {
    let (router, _store) = router_with(with_token(None)).await;
    assert_refused(&scrape(&router, None).await, "no token, no header");
    assert_refused(&scrape(&router, Some(ADMIN)).await, "no token, admin");
    assert_refused(&scrape(&router, Some("")).await, "no token, empty bearer");
}

#[tokio::test]
async fn metrics_token_missing_env_starts_and_401s() {
    const VAR: &str = "MCP_GATEWAY_C7_METRICS_UNSET_VAR";
    let reference = format!("env:{VAR}");
    let dir = tempfile::tempdir().unwrap();

    // The loader `serve` uses accepts the reference with the variable unset.
    let path = dir.path().join("gateway.yaml");
    std::fs::write(
        &path,
        format!("server:\n  metrics_token: \"{reference}\"\n"),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let loaded = Config::load_evaluated(Some(&path));
    assert!(
        loaded.is_ok(),
        "a missing metrics variable must not fail the load: {:?}",
        loaded.err()
    );

    // Unset: the gateway builds, and neither the admin bearer nor the
    // unresolved spelling itself opens /metrics.
    let (router, _store) = router_with(with_token(Some(&reference))).await;
    assert_refused(
        &scrape(&router, Some(&reference)).await,
        "unset, literal reference",
    );
    assert_refused(&scrape(&router, Some(ADMIN)).await, "unset, admin");

    // Set to "": still no token.
    let mut config = with_token(Some(&reference));
    env_file(&dir, &mut config, &format!("{VAR}="));
    let (router, _store) = router_with(config).await;
    assert_refused(&scrape(&router, None).await, "empty, no header");
    assert_refused(&scrape(&router, Some("")).await, "empty, empty bearer");
}

/// Positive control for the `env:` path.
#[tokio::test]
async fn metrics_token_env_resolves() {
    const VAR: &str = "MCP_GATEWAY_C7_METRICS_SET_VAR";
    let dir = tempfile::tempdir().unwrap();
    let mut config = with_token(Some(&format!("env:{VAR}")));
    env_file(&dir, &mut config, &format!("{VAR}=t"));
    let (router, _store) = router_with(config).await;
    assert_eq!(scrape(&router, Some("t")).await.status(), StatusCode::OK);
}

/// Positive control with a body check: the handler returns an empty 200 when
/// no recorder is installed, so status alone cannot tell a live scrape from a
/// dark one.
#[tokio::test]
async fn metrics_right_token_serves_series() {
    crate::metrics::install();
    let (router, _store) = router_with(with_token(Some(SCRAPE))).await;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {ADMIN}"))
        .body(axum::body::Body::from(
            json!({
                "jsonrpc": "2.0",
                "id": "metrics-jsonrpc-counter",
                "method": "metrics/test-counter",
                "params": {}
            })
            .to_string(),
        ))
        .unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = scrape(&router, Some(SCRAPE)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("mcp_jsonrpc_requests_total"), "{text}");
    assert!(text.contains("method=\"metrics/test-counter\""), "{text}");
}

#[tokio::test]
async fn metrics_token_cannot_open_mcp() {
    let (router, _store) = router_with(with_token(Some(SCRAPE))).await;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {SCRAPE}"))
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}).to_string(),
        ))
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
