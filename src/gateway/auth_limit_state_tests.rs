// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! ROT.11 at startup load: a key's rate-limit window and client breaker
//! follow its principal, not its current digest (design slice B r2 and
//! delta d1). Every transition is a reload in one process: two resolved
//! configs over one `AuthRuntime`.

use std::sync::Arc;
use std::time::Duration;

use super::ResolvedAuthConfig;
use crate::config::{ApiKeyConfig, AuthConfig, CircuitBreakerConfig};
use crate::gateway::auth::runtime::AuthRuntime;

const A: &str = "limit-state-secret-a";
const B: &str = "limit-state-secret-b";
const P1: &str = "a1b2c3d4e5f6";
const P2: &str = "0f0e0d0c0b0a";

fn digest(secret: &str) -> [u8; 32] {
    <sha2::Sha256 as sha2::Digest>::digest(secret.as_bytes()).into()
}

/// The principal `secret` derives, by the one derivation.
fn derived(secret: &str) -> String {
    super::configured_key_principal(None, &digest(secret))
        .storage_form()
        .to_owned()
}

fn key(name: &str, secret: &str, principal: Option<&str>) -> ApiKeyConfig {
    ApiKeyConfig {
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        name: name.to_string(),
        rate_limit: 3,
        admin: true,
        principal: principal.map(str::to_owned),
        backends: vec!["*".to_string()],
        ..Default::default()
    }
}

fn config(keys: Vec<ApiKeyConfig>) -> AuthConfig {
    AuthConfig {
        enabled: true,
        api_keys: keys,
        client_circuit_breaker: Some(CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 1,
            reset_timeout: Duration::from_secs(60),
        }),
        ..AuthConfig::default()
    }
}

/// `keys` resolved over `runtime`, as a reload builds them.
fn over(runtime: &Arc<AuthRuntime>, keys: Vec<ApiKeyConfig>) -> ResolvedAuthConfig {
    ResolvedAuthConfig::from_config(
        &config(keys),
        crate::gateway::record_principal::TEST_RECORD_KEY,
    )
    .with_runtime(Arc::clone(runtime))
}

fn admits(cfg: &ResolvedAuthConfig, secret: &str) -> bool {
    let client = cfg.validate_token(secret).expect("the key validates");
    cfg.check_authenticated_client_rate_limit(&client)
}

/// Spends the 3-per-minute window under `secret`.
fn spend(cfg: &ResolvedAuthConfig, secret: &str) {
    for _ in 0..3 {
        assert!(admits(cfg, secret), "premise: within the window");
    }
}

fn open_breaker(cfg: &ResolvedAuthConfig, secret: &str) {
    let client = cfg.validate_token(secret).expect("the key validates");
    cfg.record_client_failure(&client);
    cfg.record_client_failure(&client);
}

fn breaker_open(cfg: &ResolvedAuthConfig, secret: &str) -> bool {
    let client = cfg.validate_token(secret).expect("the key validates");
    cfg.client_circuit_state(&client) == Some(crate::failsafe::CircuitState::Open)
}

fn quota_of(cfg: &ResolvedAuthConfig, secret: &str) -> super::QuotaPrincipal {
    cfg.validate_token(secret)
        .expect("the key validates")
        .quota_principal
        .expect("an API key carries a quota principal")
}

/// T1: a rotation under one explicit principal keeps the window.
#[test]
fn t1_explicit_rotation_keeps_the_window() {
    let runtime = Arc::new(AuthRuntime::default());
    spend(&over(&runtime, vec![key("k", A, Some(P1))]), A);
    let after = over(&runtime, vec![key("k", B, Some(P1))]);
    assert!(!admits(&after, B), "the rotated secret got a fresh window");
}

/// T1c (K20): a derived-principal rotation starts a fresh window.
#[test]
fn t1c_derived_rotation_starts_fresh() {
    let runtime = Arc::new(AuthRuntime::default());
    spend(&over(&runtime, vec![key("k", A, None)]), A);
    let after = over(&runtime, vec![key("k", B, None)]);
    assert!(
        admits(&after, B),
        "a new derived principal shared the window"
    );
}

/// T2: the breaker follows an explicit-principal rotation.
#[test]
fn t2_explicit_rotation_keeps_the_breaker() {
    let runtime = Arc::new(AuthRuntime::default());
    open_breaker(&over(&runtime, vec![key("k", A, Some(P1))]), A);
    let after = over(&runtime, vec![key("k", B, Some(P1))]);
    assert!(
        breaker_open(&after, B),
        "the rotated secret's breaker is closed"
    );
}

/// T2c: a derived-principal rotation has no breaker yet.
#[test]
fn t2c_derived_rotation_has_no_breaker() {
    let runtime = Arc::new(AuthRuntime::default());
    open_breaker(&over(&runtime, vec![key("k", A, None)]), A);
    let after = over(&runtime, vec![key("k", B, None)]);
    let client = after.validate_token(B).expect("the key validates");
    assert_eq!(after.client_circuit_state(&client), None);
}

/// T3: a rotation widens no authority: a session minted under A is not live
/// once the table holds B.
#[test]
fn t3_rotation_widens_no_authority() {
    let runtime = Arc::new(AuthRuntime::default());
    let before = over(&runtime, vec![key("k", A, Some(P1))]);
    let minter = quota_of(&before, A);
    let now = chrono::Utc::now();
    assert!(
        before.admin_key_live(&minter, now),
        "premise: live on A's table"
    );
    let after = over(&runtime, vec![key("k", B, Some(P1))]);
    assert!(
        !after.admin_key_live(&minter, now),
        "A's session outlived the rotation"
    );
}

/// T3b (d1): same secret, principal P1 then P2: the identity changed, so
/// A's session is not live and the window is fresh.
#[test]
fn t3b_a_changed_principal_ends_the_session_and_the_window() {
    let runtime = Arc::new(AuthRuntime::default());
    let before = over(&runtime, vec![key("k", A, Some(P1))]);
    let minter = quota_of(&before, A);
    spend(&before, A);
    let after = over(&runtime, vec![key("k", A, Some(P2))]);
    assert!(
        !after.admin_key_live(&minter, chrono::Utc::now()),
        "a session outlived its principal"
    );
    assert!(admits(&after, A), "the new principal shared the old window");
}

/// T3c (d1): same secret, adopting the principal it derives: nothing about
/// the key changed, so the session stays live and the window is kept.
#[test]
fn t3c_adopting_the_derived_principal_changes_nothing() {
    let runtime = Arc::new(AuthRuntime::default());
    let before = over(&runtime, vec![key("k", A, None)]);
    let minter = quota_of(&before, A);
    spend(&before, A);
    let after = over(&runtime, vec![key("k", A, Some(&derived(A)))]);
    assert!(
        after.admin_key_live(&minter, chrono::Utc::now()),
        "adopting the derived principal ended the session"
    );
    assert!(
        !admits(&after, A),
        "adopting the derived principal reset the window"
    );
}

/// The limit key's golden, in `credential()`'s layout: the domain, then the
/// kind and the principal, each prefixed by its length as u64 big-endian.
fn golden(principal: &str) -> String {
    use sha2::Digest as _;
    let kind = b"api-key-principal";
    let mut hash = sha2::Sha256::new();
    hash.update(b"mcp-gateway/nonce-quota/v1\0");
    hash.update((kind.len() as u64).to_be_bytes());
    hash.update(kind);
    hash.update((principal.len() as u64).to_be_bytes());
    hash.update(principal.as_bytes());
    hex::encode(hash.finalize())
}

/// T4: every API key's limit key is the principal's golden, never its store
/// key, and never carries the principal string.
#[test]
fn t4_the_limit_key_is_the_principals_hash() {
    let runtime = Arc::new(AuthRuntime::default());
    let cfg = over(&runtime, vec![key("e", A, Some(P1)), key("d", B, None)]);
    for (secret, principal) in [(A, P1.to_owned()), (B, derived(B))] {
        let quota = quota_of(&cfg, secret);
        let limit = quota.limit_store_key();
        assert_eq!(limit, golden(&principal), "{secret}");
        assert_ne!(limit, quota.as_store_key(), "{secret}: the store key");
        assert!(!limit.contains(&principal), "{secret}: the principal");
    }
}

/// T5a: two principals keep separate windows and breakers.
#[test]
fn t5a_two_principals_stay_apart() {
    let runtime = Arc::new(AuthRuntime::default());
    let cfg = over(
        &runtime,
        vec![key("one", A, Some(P1)), key("two", B, Some(P2))],
    );
    spend(&cfg, A);
    open_breaker(&cfg, A);
    assert!(admits(&cfg, B), "P2 shared P1's window");
    assert!(!breaker_open(&cfg, B), "P2 shared P1's breaker");
}

/// T6: the per-digest budgets (nonce admission, passthrough slots) key on
/// the store key, which a rotation changes even under one principal.
#[test]
fn t6_per_digest_budgets_follow_the_digest() {
    let runtime = Arc::new(AuthRuntime::default());
    let before = quota_of(&over(&runtime, vec![key("k", A, Some(P1))]), A);
    let after = quota_of(&over(&runtime, vec![key("k", B, Some(P1))]), B);
    assert_ne!(before.as_store_key(), after.as_store_key());
}

/// T5b: within a key's grace, its previous and current secrets are one key:
/// what the previous secret spends counts against the current one's window,
/// and both see one breaker.
#[test]
fn t5b_the_previous_secret_shares_the_keys_state() {
    let runtime = Arc::new(AuthRuntime::default());
    let mut rotated = key("k", B, Some(P1));
    rotated.previous_key_sha256 = Some(crate::config::api_key_digest_spec(A.as_bytes()));
    rotated.previous_expires_at = Some(chrono::Utc::now() + chrono::Duration::days(1));
    let cfg = over(&runtime, vec![rotated]);
    spend(&cfg, A);
    assert!(!admits(&cfg, B), "the current secret got its own window");
    open_breaker(&cfg, A);
    assert!(
        breaker_open(&cfg, B),
        "the current secret got its own breaker"
    );
}

/// T9f: with the clock unreadable an undated key still authenticates, and no
/// last-use time is written, since none was read.
#[test]
fn t9f_an_unreadable_clock_writes_no_last_use() {
    let runtime = Arc::new(AuthRuntime::default());
    let cfg = over(&runtime, vec![key("k", A, Some(P1))]);
    {
        let _clock = crate::clock::test_clock::before_epoch();
        assert!(
            cfg.validate_token(A).is_some(),
            "an undated key needs no clock"
        );
    }
    let only = cfg.api_keys()[0].clone();
    assert_eq!(cfg.key_last_used(&only), None, "a time was written unread");
    assert!(cfg.validate_token(A).is_some(), "control: readable clock");
    assert!(
        cfg.key_last_used(&only).is_some(),
        "control: the match is recorded"
    );
}
