// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! R1: two resolved auth configs built over one `AuthRuntime` share every
//! client's rate-limit usage and breaker state, so rebuilding the key list on
//! a reload resets neither.

use std::sync::Arc;
use std::time::Duration;

use super::AuthRuntime;
use crate::config::{ApiKeyConfig, AuthConfig, CircuitBreakerConfig};
use crate::gateway::auth::ResolvedAuthConfig;

const SECRET: &str = "the-runtime-test-secret";

fn config(rate_limit: u32) -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: vec![ApiKeyConfig {
            key_sha256: Some(crate::config::api_key_digest_spec(SECRET.as_bytes())),
            name: "runtime".to_string(),
            rate_limit,
            backends: vec!["*".to_string()],
            ..Default::default()
        }],
        client_circuit_breaker: Some(CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 1,
            reset_timeout: Duration::from_secs(60),
        }),
        ..AuthConfig::default()
    }
}

/// A resolved config over `runtime`, as a reload would build one.
fn built_over(runtime: &Arc<AuthRuntime>) -> ResolvedAuthConfig {
    built_with_rate(runtime, 1)
}

/// [`built_over`] with the key's `rate_limit` set to `rate`.
fn built_with_rate(runtime: &Arc<AuthRuntime>, rate: u32) -> ResolvedAuthConfig {
    ResolvedAuthConfig::from_config(
        &config(rate),
        crate::gateway::record_principal::TEST_RECORD_KEY,
    )
    .with_runtime(Arc::clone(runtime))
}

/// Whether the key's next request under `cfg` is admitted.
fn admitted(cfg: &ResolvedAuthConfig) -> bool {
    let client = cfg.validate_token(SECRET).expect("the key validates");
    cfg.check_authenticated_client_rate_limit(&client)
}

/// The one request a 1-per-minute key allows, spent through the first config,
/// is spent for the second.
#[test]
fn usage_spent_through_one_config_is_spent_through_the_next() {
    let runtime = Arc::new(AuthRuntime::default());
    let before = built_over(&runtime);
    let client = before.validate_token(SECRET).expect("the key validates");
    assert!(
        before.check_authenticated_client_rate_limit(&client),
        "premise: the first request is admitted"
    );
    let after = built_over(&runtime);
    let client = after.validate_token(SECRET).expect("the key validates");
    assert!(
        !after.check_authenticated_client_rate_limit(&client),
        "a rebuilt config gave the client a fresh window"
    );
}

/// A breaker opened through the first config is still open through the second.
#[test]
fn a_breaker_opened_through_one_config_stays_open_through_the_next() {
    let runtime = Arc::new(AuthRuntime::default());
    let before = built_over(&runtime);
    let client = before.validate_token(SECRET).expect("the key validates");
    before.record_client_failure(&client);
    before.record_client_failure(&client);
    assert!(
        !before.check_client_circuit_breaker(&client),
        "premise: two failures open the breaker"
    );
    let after = built_over(&runtime);
    let client = after.validate_token(SECRET).expect("the key validates");
    assert!(
        !after.check_client_circuit_breaker(&client),
        "a rebuilt config closed the client's breaker"
    );
}

/// R3: a key's `rate_limit` lowered below what it has already used denies its
/// next request: the usage is kept and judged at the new rate.
#[test]
fn a_rate_tightened_below_usage_denies_the_next_request() {
    let runtime = Arc::new(AuthRuntime::default());
    let before = built_with_rate(&runtime, 3);
    assert!(
        admitted(&before) && admitted(&before),
        "premise: two of three spent"
    );
    let after = built_with_rate(&runtime, 1);
    assert!(
        !admitted(&after),
        "the tightened key started a fresh window"
    );
}

/// R3: a key's `rate_limit` raised keeps what it has used: three of three
/// spent at 3/min leaves two of five at 5/min.
#[test]
fn a_rate_loosened_keeps_the_usage() {
    let runtime = Arc::new(AuthRuntime::default());
    let before = built_with_rate(&runtime, 3);
    assert!(
        (0..3).all(|_| admitted(&before)),
        "premise: three of three spent"
    );
    let after = built_with_rate(&runtime, 5);
    assert!(
        admitted(&after) && admitted(&after),
        "two more fit at 5/min"
    );
    assert!(!admitted(&after), "the loosened key started a fresh window");
}

/// No input from outside grows the store: random bearer tokens, a forged
/// near-miss of the configured key, and a configured key past its expiry are
/// all refused through the real middleware and leave no bucket and no
/// breaker. The live key then makes exactly one of each (control).
#[tokio::test]
async fn rejected_credentials_create_no_store_entry() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::Service;

    use crate::gateway::auth::{AuthState, DashboardBootstrap, auth_middleware};

    const EXPIRED: &str = "the-expired-runtime-test-secret";
    let mut with_expired = config(1);
    with_expired.api_keys.push(ApiKeyConfig {
        key_sha256: Some(crate::config::api_key_digest_spec(EXPIRED.as_bytes())),
        name: "expired".to_string(),
        rate_limit: 1,
        backends: vec!["*".to_string()],
        expires_at: Some(
            "2001-01-01T00:00:00Z"
                .parse()
                .expect("a fixed past instant"),
        ),
        ..Default::default()
    });
    let runtime = Arc::new(AuthRuntime::default());
    let resolved = ResolvedAuthConfig::from_config(
        &with_expired,
        crate::gateway::record_principal::TEST_RECORD_KEY,
    )
    .with_runtime(Arc::clone(&runtime));
    let state = AuthState {
        key_server: None,
        dashboard_bootstrap: Arc::new(DashboardBootstrap::new()),
        tls_enabled: false,
        live_config: Arc::new(crate::config_reload::LiveConfig::with_auth(
            crate::config::Config::default(),
            Arc::new(resolved),
        )),
        agent_auth: crate::gateway::oauth::AgentAuthState::new(false, Arc::default()),
    };
    let mut router = axum::Router::new()
        .route(
            "/protected",
            axum::routing::get(|| async { StatusCode::OK }),
        )
        // The pin the router puts on every request (ADR-023).
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(axum::Extension(state.live_config.generation()));
    let mut call = |bearer: &str| {
        let request = Request::builder()
            .uri("/protected")
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .body(Body::empty())
            .expect("request builds");
        router.call(request)
    };

    let forged = format!("{}X", &SECRET[..SECRET.len() - 1]);
    let mut refused: Vec<String> = (0..200)
        .map(|i| format!("random-token-{i}-not-configured"))
        .collect();
    refused.extend([forged, EXPIRED.to_string()]);
    for token in &refused {
        let response = call(token).await.expect("infallible");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{token}");
    }
    assert_eq!(runtime.buckets.len(), 0, "a refused token made a bucket");
    assert_eq!(runtime.breakers.len(), 0, "a refused token made a breaker");

    let response = call(SECRET).await.expect("infallible");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "premise: the key authenticates"
    );
    assert_eq!(runtime.buckets.len(), 1, "the key's bucket");
    assert_eq!(runtime.breakers.len(), 1, "the key's breaker");
}
