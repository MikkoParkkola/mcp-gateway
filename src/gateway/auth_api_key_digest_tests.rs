// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! E4 (APIKEY.1): a configured API key is a sha256 digest. The presented key
//! is hashed once and compared with each digest; an expired key is refused.

#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        reason = "test code reads the host clock (MIK-8202 AC.14)"
    )
)]
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
    ResolvedAuthConfig::try_from_config(
        &config,
        &crate::config::EnvOverlay::none(),
        crate::gateway::record_principal::TEST_RECORD_KEY,
    )
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
    assert_eq!(
        super::principal_of(KEY).storage_form(),
        expected,
        "today's formula"
    );
    let client = digest_key(None).validate_token(KEY).expect("authenticates");
    assert_eq!(client.principal.storage_form(), expected);
}

/// Drive the real middleware on a protected path. Returns the status and
/// whether a client extension reached the handler.
async fn call_protected(config: ResolvedAuthConfig, bearer: &str) -> (StatusCode, bool) {
    let seen: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));
    let sink = Arc::clone(&seen);
    let state = AuthState {
        key_server: None,
        dashboard_bootstrap: Arc::new(DashboardBootstrap::new()),
        tls_enabled: false,
        live_config: Arc::new(crate::config_reload::LiveConfig::with_auth(
            crate::config::Config::default(),
            Arc::new(config),
        )),
        agent_auth: crate::gateway::oauth::AgentAuthState::new(false, std::sync::Arc::default()),
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
            state.clone(),
            super::auth_middleware,
        ))
        // The pin the router puts on every request (ADR-023).
        .layer(axum::Extension(state.live_config.generation()));
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
    let past = (chrono::Utc::now() - crate::duration_bound::delta!(seconds, 1)).to_rfc3339();
    let (status, reached) = call_protected(digest_key(Some(past)), KEY).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!reached, "an expired key must publish no client");
}

// E4-T6 (positive control against an inverted comparison)
#[tokio::test]
async fn unexpired_key_is_accepted() {
    let ahead = (chrono::Utc::now() + crate::duration_bound::delta!(hours, 1)).to_rfc3339();
    let (status, reached) = call_protected(digest_key(Some(ahead)), KEY).await;
    assert_eq!(status, StatusCode::OK);
    assert!(reached);
}

// E4-T14
#[test]
fn resolved_auth_config_debug_shows_no_digest() {
    let printed = format!("{:?}", digest_key(None));
    assert!(!printed.contains(KEY), "{printed}");
    assert!(printed.contains("<redacted>"), "{printed}");
    let longest_hex_run = printed
        .split(|c: char| !c.is_ascii_hexdigit())
        .map(str::len)
        .max()
        .unwrap_or(0);
    // Not even the 12-hex stored principal (MIK-8697).
    assert!(longest_hex_run < 12, "a digest leaked: {printed}");
    assert!(!printed.contains(&hex_of(KEY)[..13]), "{printed}");
}

/// MIK-8202: a clock before 1970 refuses an API key the real clock still admits.
#[test]
fn a_clock_before_the_epoch_refuses_a_live_api_key() {
    let ahead = (chrono::Utc::now() + crate::duration_bound::delta!(hours, 1)).to_rfc3339();
    let config = digest_key(Some(ahead));
    assert!(
        config.validate_token(KEY).is_some(),
        "control: a key expiring in an hour authenticates on the real clock"
    );

    let _clock = crate::clock::test_clock::before_epoch();
    assert!(
        config.validate_token(KEY).is_none(),
        "an unreadable clock admitted an API key"
    );
}

/// MIK-8202: a clock before 1970 refuses a live key's work done on its behalf.
#[test]
fn a_clock_before_the_epoch_refuses_a_live_key_on_its_behalf() {
    let ahead = (chrono::Utc::now() + crate::duration_bound::delta!(hours, 1)).to_rfc3339();
    let config = digest_key(Some(ahead));
    let principal = &hex_of(KEY)[..12];
    assert!(
        config.client_for_key("ops", principal).is_some(),
        "control: a key expiring in an hour resolves on the real clock"
    );

    let _clock = crate::clock::test_clock::before_epoch();
    assert!(
        config.client_for_key("ops", principal).is_none(),
        "an unreadable clock resolved an API key's caller"
    );
}

/// MIK-8202 A6: `client_for_key_at` judges a key's expiry at the caller's
/// reading and reads no clock of its own: live at a reading before
/// `expires_at`, refused at one after it, with the thread's clock unreadable
/// throughout.
#[test]
fn a_key_is_judged_at_the_callers_reading() {
    let now = crate::clock::utc_now().expect("a readable clock");
    let config = digest_key(Some(
        (now + crate::duration_bound::delta!(hours, 1)).to_rfc3339(),
    ));
    let principal = &hex_of(KEY)[..12];
    let _clock = crate::clock::test_clock::before_epoch();
    assert!(
        config.client_for_key_at("ops", principal, now).is_some(),
        "refused at a reading before its expiry"
    );
    assert!(
        config
            .client_for_key_at(
                "ops",
                principal,
                now + crate::duration_bound::delta!(hours, 2)
            )
            .is_none(),
        "resolved at a reading after its expiry"
    );
}

/// MIK-8659: an API-key resolution is always an authenticated API key. Every
/// per-key budget and grant rests on this: `api_key_name` gives a name only
/// when both hold, so a mint that produced an unauthenticated `ApiKey` client
/// would silently carry no per-key budget at all.
#[test]
fn an_api_key_resolution_is_an_authenticated_api_key() {
    let config = digest_key(None);
    let client = config.validate_token(KEY).expect("the key authenticates");
    assert!(client.authenticated, "an API key client is authenticated");
    assert_eq!(
        client.credential_kind,
        crate::security::audit::CredentialKind::ApiKey,
        "an API key client is an ApiKey"
    );
    assert_eq!(
        client.api_key_identity(),
        Some("ops"),
        "and is named by the predicate"
    );
}
