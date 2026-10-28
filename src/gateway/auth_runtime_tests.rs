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
