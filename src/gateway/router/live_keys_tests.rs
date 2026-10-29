// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The API key table applies on reload (ADR-023, amended): a key added,
//! removed or expired by a reload is judged by the next request, on `/mcp`
//! and on `/mcp/{name}`.

use std::sync::Arc;

use axum::http::StatusCode;
use tower::ServiceExt;

use super::create_router;
use super::tests::test_router_app_state_with_auth;
use crate::config::{ApiKeyConfig, AuthConfig};
use crate::config_reload::ReloadContext;

const KEPT: &str = "live-keys-kept-secret";
const ADDED: &str = "live-keys-added-secret";

fn key(secret: &str, expires_at: Option<&str>) -> ApiKeyConfig {
    ApiKeyConfig {
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        expires_at: expires_at.map(|at| at.parse().expect("an RFC 3339 instant")),
        name: secret.to_owned(),
        backends: vec!["*".to_owned()],
        ..Default::default()
    }
}

fn auth(keys: Vec<ApiKeyConfig>) -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: keys,
        ..AuthConfig::default()
    }
}

/// The YAML for `keys`, as an operator writes it.
fn file_text(keys: &[ApiKeyConfig]) -> String {
    let mut text = String::from("auth:\n  enabled: true\n  api_keys:\n");
    for k in keys {
        text.push_str(&format!(
            "    - name: {}\n      key_sha256: \"{}\"\n      backends: [\"*\"]\n",
            k.name,
            k.key_sha256.as_deref().expect("a digest")
        ));
        if let Some(at) = k.expires_at {
            text.push_str(&format!("      expires_at: \"{}\"\n", at.to_rfc3339()));
        }
    }
    text
}

/// A reload context over `state`'s live config, reading `path`.
fn reloader(state: &Arc<super::AppState>, path: &std::path::Path) -> ReloadContext {
    ReloadContext::new(
        path.to_path_buf(),
        Arc::clone(&state.live_config),
        Arc::clone(&state.backends),
        crate::config::FailsafeConfig::default(),
        std::time::Duration::from_secs(60),
    )
    .expect("the registry pairs with the config")
}

/// Reload `keys` from a file into `state`.
async fn reload_keys(state: &Arc<super::AppState>, dir: &std::path::Path, keys: &[ApiKeyConfig]) {
    let path = dir.join("gateway.yaml");
    crate::gateway::test_helpers::write_owner_only(&path, file_text(keys)).expect("write");
    reloader(state, &path)
        .reload_outcome()
        .await
        .expect("the key edit applies");
}

/// The status `secret` gets on `path`.
async fn status(state: &Arc<super::AppState>, path: &str, secret: &str) -> StatusCode {
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    let request = axum::http::Request::post(path)
        .header("authorization", format!("Bearer {secret}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(axum::body::Body::from(body.to_string()))
        .expect("a request");
    create_router(Arc::clone(state))
        .oneshot(request)
        .await
        .expect("a response")
        .status()
}

/// K1: a key added by reload is accepted on the next call, on `/mcp` and on
/// `/mcp/{name}`; the kept key still works (control).
#[tokio::test]
async fn k1_a_key_added_by_reload_is_accepted_on_the_next_call() {
    let (state, _store) = test_router_app_state_with_auth(&auth(vec![key(KEPT, None)])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    for path in ["/mcp", "/mcp/absent"] {
        assert_eq!(
            status(&state, path, ADDED).await,
            StatusCode::UNAUTHORIZED,
            "{path}: precondition, the new key is unknown before the reload"
        );
    }

    reload_keys(&state, dir.path(), &[key(KEPT, None), key(ADDED, None)]).await;

    for path in ["/mcp", "/mcp/absent"] {
        assert_ne!(
            status(&state, path, ADDED).await,
            StatusCode::UNAUTHORIZED,
            "{path}: a key added by reload was refused"
        );
        assert_ne!(
            status(&state, path, KEPT).await,
            StatusCode::UNAUTHORIZED,
            "{path}: the kept key stopped working"
        );
    }
}

/// K2: a key removed by reload is refused on the next call, and a key whose
/// `expires_at` moves into the past is refused as expired.
#[tokio::test]
async fn k2_a_key_removed_or_expired_by_reload_is_refused_on_the_next_call() {
    let (state, _store) =
        test_router_app_state_with_auth(&auth(vec![key(KEPT, None), key(ADDED, None)])).await;
    let dir = tempfile::tempdir().expect("tempdir");
    for secret in [KEPT, ADDED] {
        assert_ne!(
            status(&state, "/mcp", secret).await,
            StatusCode::UNAUTHORIZED,
            "precondition: {secret} works before the reload"
        );
    }

    // ADDED removed; KEPT now expired.
    reload_keys(
        &state,
        dir.path(),
        &[key(KEPT, Some("2001-01-01T00:00:00Z"))],
    )
    .await;

    for path in ["/mcp", "/mcp/absent"] {
        assert_eq!(
            status(&state, path, ADDED).await,
            StatusCode::UNAUTHORIZED,
            "{path}: a key removed by reload still works"
        );
        assert_eq!(
            status(&state, path, KEPT).await,
            StatusCode::UNAUTHORIZED,
            "{path}: a key expired by reload still works"
        );
    }
}
