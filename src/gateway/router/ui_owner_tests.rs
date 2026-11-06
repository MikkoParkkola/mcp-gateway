// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A server's owner reaches the UI only through the admin-only
//! `/ui/api/config`, read from the request's published generation (so an
//! owner-only reload shows at once); the open `/ui/api/status` never carries
//! it, for any caller.

use std::sync::Arc;

use axum::body::to_bytes;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::create_router;
use super::tests::{http_backend_at, test_router_app_state_with_auth};
use crate::config::{ApiKeyConfig, AuthConfig, BackendConfig, Config};
use crate::gateway::router::AppState;

const ADMIN: &str = "owner-admin-key";
const MEMBER: &str = "owner-member-key";
const URL: &str = "http://127.0.0.1:9/mcp";

fn key(name: &str, admin: bool) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(name.as_bytes())),
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

fn auth() -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![key(ADMIN, true), key(MEMBER, false)],
        // The status route open, as deployments that publish it run it, so
        // the anonymous case reaches the handler.
        public_paths: vec![
            "/health".to_string(),
            crate::gateway::routes::UI_STATUS.to_string(),
        ],
        ..Default::default()
    }
}

/// Publish a generation whose `svc` backend has `owner`, keeping the
/// fixture's auth.
fn publish_owner(state: &Arc<AppState>, owner: Option<&str>) {
    let mut config: Config = (*state.live_config.get()).clone();
    config.backends.insert(
        "svc".to_string(),
        BackendConfig {
            owner: owner.map(str::to_owned),
            ..BackendConfig::default()
        },
    );
    state.live_config.set(config);
}

async fn get(state: &Arc<AppState>, path: &str, bearer: Option<&str>) -> (u16, Value) {
    let mut request = axum::http::Request::builder().method("GET").uri(path);
    if let Some(key) = bearer {
        request = request.header("authorization", format!("Bearer {key}"));
    }
    let request = request.body(axum::body::Body::empty()).unwrap();
    let response = create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

fn server<'a>(body: &'a Value, name: &str) -> &'a Value {
    body["servers"]
        .as_array()
        .and_then(|s| s.iter().find(|s| s["name"] == name))
        .unwrap_or_else(|| panic!("no server {name}: {body}"))
}

/// O7: the admin's `/ui/api/config` shows each server's owner from the
/// published generation: `null` without one, then each reloaded value,
/// although the registered backend instance never changes.
#[tokio::test]
async fn o7_the_admin_config_shows_the_published_owner() {
    let (state, _dir) = test_router_app_state_with_auth(&auth()).await;
    let _ = state.backends.register(http_backend_at("svc", URL));
    publish_owner(&state, None);
    let (status, body) = get(&state, crate::gateway::routes::UI_CONFIG, Some(ADMIN)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(server(&body, "svc")["owner"], Value::Null, "{body}");
    assert!(
        server(&body, "svc").get("owner").is_some(),
        "the key is present: {body}"
    );
    for (written, shown) in [
        (Some("Team A"), json!("Team A")),
        (Some("Team B"), json!("Team B")),
        (Some("  Team C  "), json!("Team C")),
        (Some("   "), Value::Null),
        (None, Value::Null),
    ] {
        publish_owner(&state, written);
        let (status, body) = get(&state, crate::gateway::routes::UI_CONFIG, Some(ADMIN)).await;
        assert_eq!(status, 200, "{written:?}: {body}");
        // Present even when `null`: a missing key also reads as `null`.
        assert_eq!(
            server(&body, "svc").get("owner"),
            Some(&shown),
            "{written:?}: {body}"
        );
    }
}

/// O7b: a registered backend the request's generation does not hold (a
/// concurrent reload added it) answers `owner: null`, without a panic.
#[tokio::test]
async fn o7b_a_backend_missing_from_the_generation_has_no_owner() {
    let (state, _dir) = test_router_app_state_with_auth(&auth()).await;
    let _ = state.backends.register(http_backend_at("ghost", URL));
    let (status, body) = get(&state, crate::gateway::routes::UI_CONFIG, Some(ADMIN)).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        server(&body, "ghost").get("owner"),
        Some(&Value::Null),
        "{body}"
    );
}

/// O9: `/ui/api/status`, open to every caller, never carries an owner. An
/// unscoped admin gets the full view, with the server listed and no
/// `owner` in its row; a member key and an anonymous caller get the
/// counts-only view, which names no server at all. Each answer is a 200 from
/// the handler, so the absence is the projection's, not a refusal's.
#[tokio::test]
async fn o9_status_never_carries_the_owner() {
    let (state, _dir) = test_router_app_state_with_auth(&auth()).await;
    let _ = state.backends.register(http_backend_at("svc", URL));
    publish_owner(&state, Some("owner-marker-7f3e"));

    let (status, body) = get(&state, crate::gateway::routes::UI_STATUS, Some(ADMIN)).await;
    assert_eq!(status, 200, "admin: {body}");
    let servers = body["servers"]
        .as_array()
        .expect("the admin's full view lists servers");
    assert!(servers.iter().any(|s| s["name"] == "svc"), "admin: {body}");
    for s in servers {
        assert!(s.get("owner").is_none(), "admin: {s}");
    }
    assert!(
        !body.to_string().contains("owner-marker-7f3e"),
        "admin: {body}"
    );

    for bearer in [Some(MEMBER), None] {
        let (status, body) = get(&state, crate::gateway::routes::UI_STATUS, bearer).await;
        assert_eq!(status, 200, "{bearer:?}: {body}");
        assert!(
            body.get("servers").is_none(),
            "{bearer:?}: counts only: {body}"
        );
        assert_eq!(body["server_count"], json!(1), "{bearer:?}: {body}");
        assert!(
            !body.to_string().contains("owner-marker-7f3e"),
            "{bearer:?}: {body}"
        );
    }
}
