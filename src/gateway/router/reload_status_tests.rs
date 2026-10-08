// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/api/reload` answers a failed reload with a status that says
//! whose fault it is (MIK-8058): a file the posture policy refuses is the
//! operator's config (409), a reload cut short by shutdown is the gateway
//! being unavailable (503), and anything else is an internal fault (500). The
//! refusal text reaches the caller unchanged.

use std::sync::Arc;
use std::time::Duration;

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::Value;
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state_with_auth;
use crate::backend::BackendRegistry;
use crate::config::{ApiKeyConfig, AuthConfig, Config, FailsafeConfig};
use crate::config_reload::{LiveConfig, ReloadContext};
use crate::gateway::test_helpers::write_owner_only;

const KEY: &str = "reload-status-admin";

/// A reload context over `file`, running a default (loopback, no public URL)
/// config against `registry`.
fn context(dir: &tempfile::TempDir, file: &str, registry: Arc<BackendRegistry>) -> ReloadContext {
    let path = dir.path().join("gateway.yaml");
    write_owner_only(&path, file).expect("write config");
    ReloadContext::new(
        path,
        Arc::new(LiveConfig::new(Config::default())),
        registry,
        FailsafeConfig::default(),
        Duration::from_secs(60),
    )
    .expect("the registry pairs with the config")
}

/// Send `POST /ui/api/reload` as an admin to a gateway reloading through `ctx`.
async fn reload_as_admin(ctx: ReloadContext) -> (StatusCode, Value) {
    let auth = AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key: None,
            key_sha256: Some(crate::config::api_key_digest_spec(KEY.as_bytes())),
            expires_at: None,
            name: KEY.to_string(),
            rate_limit: 0,
            backends: vec!["*".to_string()],
            allowed_tools: None,
            denied_tools: None,
            admin: true,
            kind: crate::config::ApiKeyKind::Shared,
        }],
        ..Default::default()
    };
    let (state, _store) = test_router_app_state_with_auth(&auth).await;
    state.meta_mcp.set_reload_context(Arc::new(ctx));
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/ui/api/reload")
        .header("authorization", format!("Bearer {KEY}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from("{}"))
        .unwrap();
    let response = create_router(state).oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}

/// STATUS.1: a file that would publish the gateway over open tools is the
/// operator's config refused, not a server fault.
#[tokio::test]
async fn a_posture_refusal_is_a_conflict_with_its_text_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let file = "server:\n  public_url: \"https://gw.example.com\"\n";
    let ctx = context(&dir, file, Arc::new(BackendRegistry::new()));

    let (status, body) = reload_as_admin(ctx).await;

    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    let text = body["error"].as_str().unwrap_or_default();
    assert!(text.starts_with("config reload refused:"), "{body}");
}

/// STATUS.2: a reload the registry refused because shutdown began is the
/// gateway unavailable, not an internal fault.
#[tokio::test]
async fn a_reload_cut_short_by_shutdown_is_service_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let registry = Arc::new(BackendRegistry::new());
    registry.stop_all().await;
    let file = "backends:\n  added:\n    command: \"true\"\n";
    let ctx = context(&dir, file, registry);

    let (status, body) = reload_as_admin(ctx).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let text = body["error"].as_str().unwrap_or_default();
    assert!(text.contains("shutting down"), "{body}");
}

/// STATUS.2: a reload stopped by the gateway's own shutdown signal is the
/// gateway unavailable too, not an internal fault.
#[tokio::test]
async fn a_reload_stopped_by_the_shutdown_signal_is_service_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let stop = tokio_util::sync::CancellationToken::new();
    stop.cancel();
    let ctx = context(&dir, "{}\n", Arc::new(BackendRegistry::new())).with_stop(stop);

    let (status, body) = reload_as_admin(ctx).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    let text = body["error"].as_str().unwrap_or_default();
    assert!(text.contains("shutting down"), "{body}");
}

/// STATUS.2: any other failure, here a file that does not parse, stays 500.
#[tokio::test]
async fn any_other_reload_failure_stays_an_internal_error() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = context(&dir, "server: [\n", Arc::new(BackendRegistry::new()));

    let (status, body) = reload_as_admin(ctx).await;

    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
}
