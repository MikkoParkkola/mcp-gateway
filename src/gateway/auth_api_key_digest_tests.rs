// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E4 (APIKEY.1): a configured API key is a sha256 digest. The presented key
//! is hashed once and compared with each digest; an expired key is refused.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::Service;

use super::{AuthState, AuthenticatedClient, DashboardBootstrap, ResolvedAuthConfig};
use crate::config::AuthConfig;

const KEY: &str = "k-abc";

fn hex_of(key: &str) -> String {
    crate::hashing::sha256_hex(key.as_bytes())
}

fn resolved(key: &serde_json::Value) -> ResolvedAuthConfig {
    let config: AuthConfig = serde_json::from_value(serde_json::json!({
        "enabled": true,
        "api_keys": [key]
    }))
    .expect("auth config fixture deserializes");
    ResolvedAuthConfig::try_from_config(&config, &crate::config::EnvOverlay::none())
        .expect("resolves")
}

fn digest_key(expires_at: Option<String>) -> ResolvedAuthConfig {
    let mut key = serde_json::json!({
        "name": "ops",
        "key_sha256": format!("sha256:{}", hex_of(KEY)),
        "backends": ["*"]
    });
    if let Some(at) = expires_at {
        key["expires_at"] = serde_json::Value::String(at);
    }
    resolved(&key)
}

// E4-T2
#[test]
fn digest_key_authenticates_plaintext_token() {
    let config = digest_key(None);
    let client = config.validate_token(KEY).expect("the key authenticates");
    assert_eq!(client.name, "ops");
    assert!(config.validate_token("k-abd").is_none());
}

// E4-T3
#[test]
fn digest_itself_is_not_a_credential() {
    let config = digest_key(None);
    assert!(
        config
            .validate_token(&format!("sha256:{}", hex_of(KEY)))
            .is_none()
    );
    assert!(config.validate_token(&hex_of(KEY)).is_none());
}

// E4-T4 (positive control): principal is the same 12 hex characters 3.x
// derived from the plaintext, so session owners and cache keys survive.
#[test]
fn principal_unchanged_across_migration() {
    let expected = hex_of(KEY)[..12].to_string();
    assert_eq!(super::principal_of(KEY), expected, "today's formula");
    let client = digest_key(None).validate_token(KEY).expect("authenticates");
    assert_eq!(client.principal, expected);
}

/// Drive the real middleware on a protected path. Returns the status and
/// whether a client extension reached the handler.
async fn call_protected(config: ResolvedAuthConfig, bearer: &str) -> (StatusCode, bool) {
    let seen: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let sink = Arc::clone(&seen);
    let state = AuthState {
        auth_config: Arc::new(config),
        key_server: None,
        dashboard_bootstrap: Arc::new(DashboardBootstrap::new()),
        tls_enabled: false,
        live_config: Arc::new(crate::config_reload::LiveConfig::new(
            crate::config::Config::default(),
        )),
    };
    let mut router = axum::Router::new()
        .route(
            "/protected",
            axum::routing::get(
                move |client: Option<axum::Extension<AuthenticatedClient>>| {
                    let sink = Arc::clone(&sink);
                    async move {
                        *sink.lock().expect("sink") = client.is_some();
                        StatusCode::OK
                    }
                },
            ),
        )
        .layer(axum::middleware::from_fn_with_state(
            state,
            super::auth_middleware,
        ));
    let request = Request::builder()
        .uri("/protected")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .expect("request builds");
    let response = router.call(request).await.expect("infallible");
    let reached = *seen.lock().expect("sink");
    (response.status(), reached)
}

// E4-T5
#[tokio::test]
async fn expired_key_is_refused() {
    let past = (chrono::Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
    let (status, reached) = call_protected(digest_key(Some(past)), KEY).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!reached, "an expired key must publish no client");
}

// E4-T6 (positive control against an inverted comparison)
#[tokio::test]
async fn unexpired_key_is_accepted() {
    let ahead = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let (status, reached) = call_protected(digest_key(Some(ahead)), KEY).await;
    assert_eq!(status, StatusCode::OK);
    assert!(reached);
}

// E4-T14
#[test]
fn resolved_auth_config_debug_shows_no_digest() {
    let printed = format!("{:?}", digest_key(None));
    assert!(!printed.contains(KEY), "{printed}");
    assert!(printed.contains("<redacted:"), "{printed}");
    let longest_hex_run = printed
        .split(|c: char| !c.is_ascii_hexdigit())
        .map(str::len)
        .max()
        .unwrap_or(0);
    assert!(longest_hex_run < 64, "a digest leaked: {printed}");
    assert!(!printed.contains(&hex_of(KEY)[..13]), "{printed}");
}
