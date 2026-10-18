// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8489: per-client rate limits and circuit breakers belong to the
//! credential, never to its display name.
//!
//! A name is operator-chosen data. Two API keys may carry the same one when a
//! config skips `Config::validate`, and an API key may carry the name another
//! identity kind uses (`bearer`, an OIDC actor id), which no key-name check can
//! see. Each case below is a pair of callers whose names collide while their
//! credentials differ: they must not share a bucket or a breaker. The last two
//! pin the other direction: one credential presented twice, or one OIDC
//! identity under two tokens, still shares one bucket.

use std::time::Duration;

use super::*;
use crate::config::{ApiKeyConfig, AuthConfig, CircuitBreakerConfig};

fn key(secret: &str, name: &str, rate_limit: u32) -> ApiKeyConfig {
    ApiKeyConfig {
        key: None,
        key_sha256: Some(crate::config::api_key_digest_spec(secret.as_bytes())),
        expires_at: None,
        name: name.to_string(),
        rate_limit,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        kind: crate::config::ApiKeyKind::Shared,
    }
}

/// Built the way `try_from_config` sees a config: without `Config::validate`,
/// so the state maps must hold the invariant themselves.
fn resolved(config: AuthConfig) -> ResolvedAuthConfig {
    ResolvedAuthConfig::from_config(&AuthConfig {
        enabled: true,
        ..config
    })
}

fn client(cfg: &ResolvedAuthConfig, secret: &str) -> AuthenticatedClient {
    cfg.validate_token(secret)
        .expect("a configured credential validates")
}

/// The advisory's case: A allows 1/min, B allows 3/min, one shared (or
/// omitted) name, in both entry orders. Each key gets exactly its own limit,
/// and A's traffic does not spend B's.
#[test]
fn same_named_keys_each_get_their_own_rate_limit_in_either_order() {
    // Every combination is run before asserting, so a failure names all of
    // them rather than the first.
    let mut admitted = Vec::new();
    for name in ["shared", ""] {
        let a = key("secret-a", name, 1);
        let b = key("secret-b", name, 3);
        for (order, keys) in [("A,B", vec![a.clone(), b.clone()]), ("B,A", vec![b, a])] {
            let cfg = resolved(AuthConfig {
                api_keys: keys,
                ..AuthConfig::default()
            });
            let (a, b) = (client(&cfg, "secret-a"), client(&cfg, "secret-b"));
            // A goes first and tries twice, then B tries four times.
            let a_admits = (0..2)
                .filter(|_| cfg.check_authenticated_client_rate_limit(&a))
                .count();
            let b_admits = (0..4)
                .filter(|_| cfg.check_authenticated_client_rate_limit(&b))
                .count();
            admitted.push((name, order, a_admits, b_admits));
        }
    }
    assert_eq!(
        admitted,
        [
            ("shared", "A,B", 1, 3),
            ("shared", "B,A", 1, 3),
            ("", "A,B", 1, 3),
            ("", "B,A", 1, 3),
        ],
        "(name, order, A admitted of 2, B admitted of 4): A holds 1/min, B 3/min"
    );
}

/// An API key named `bearer` is not the bearer: its dispatch failures open
/// its own breaker, and the admin bearer is still admitted.
#[test]
fn a_key_named_bearer_cannot_open_the_bearer_circuit() {
    let cfg = resolved(AuthConfig {
        bearer_token: Some("the-bearer-secret".to_string()),
        api_keys: vec![key("the-key-secret", "bearer", 0)],
        client_circuit_breaker: Some(CircuitBreakerConfig {
            enabled: true,
            failure_threshold: 2,
            success_threshold: 1,
            reset_timeout: Duration::from_secs(60),
        }),
        ..AuthConfig::default()
    });
    let bearer = client(&cfg, "the-bearer-secret");
    let impostor = client(&cfg, "the-key-secret");
    assert_eq!(
        (bearer.name.as_str(), impostor.name.as_str()),
        ("bearer", "bearer"),
        "the precondition: two credentials, one display name"
    );

    // As the dispatch paths record an outcome (backend_handlers.rs).
    cfg.record_client_failure(&impostor);
    cfg.record_client_failure(&impostor);

    assert!(
        client_preflight(&cfg, &impostor, "/mcp").is_some(),
        "the failing key's own breaker opens"
    );
    assert!(
        client_preflight(&cfg, &bearer, "/mcp").is_none(),
        "the bearer's breaker is its own and is still closed"
    );
}

/// The other half of the breaker: a success recorded for the key named
/// `bearer` does not reset the bearer's failure count. (A closed breaker
/// clears its count on a success, so a shared breaker would forget the
/// bearer's first failure and stay closed after its second.)
#[test]
fn a_key_named_bearer_cannot_reset_the_bearer_circuit() {
    let cfg = resolved(AuthConfig {
        bearer_token: Some("the-bearer-secret".to_string()),
        api_keys: vec![key("the-key-secret", "bearer", 0)],
        client_circuit_breaker: Some(breaker()),
        ..AuthConfig::default()
    });
    let bearer = client(&cfg, "the-bearer-secret");
    let impostor = client(&cfg, "the-key-secret");

    cfg.record_client_failure(&bearer);
    cfg.record_client_success(&impostor);
    cfg.record_client_failure(&bearer);
    assert!(
        client_preflight(&cfg, &bearer, "/mcp").is_some(),
        "two bearer failures open its circuit; another credential's success is not its own"
    );
}

/// An API key named exactly like an OIDC actor id does not spend that
/// person's bucket.
#[test]
fn a_key_named_like_an_oidc_actor_does_not_spend_its_bucket() {
    let actor = "oidc:24:https://issuer.example:5:alice";
    let cfg = resolved(AuthConfig {
        api_keys: vec![key("the-key-secret", actor, 1)],
        ..AuthConfig::default()
    });
    let impostor = client(&cfg, "the-key-secret");
    let person = oidc_client(actor, "token-1");

    assert!(cfg.check_authenticated_client_rate_limit(&impostor));
    assert!(
        !cfg.check_authenticated_client_rate_limit(&impostor),
        "the key spent its own 1/min"
    );
    assert!(
        cfg.check_authenticated_client_rate_limit(&person),
        "the OIDC identity has its own bucket"
    );
}

/// One key presented twice is one caller: the second request shares the
/// first one's bucket.
#[test]
fn one_key_presented_twice_shares_one_bucket() {
    let cfg = resolved(AuthConfig {
        api_keys: vec![key("secret-a", "laptop", 1)],
        ..AuthConfig::default()
    });
    assert!(cfg.check_authenticated_client_rate_limit(&client(&cfg, "secret-a")));
    assert!(!cfg.check_authenticated_client_rate_limit(&client(&cfg, "secret-a")));
}

/// Two key-server tokens for one OIDC identity carry different `principal`s
/// (each is a digest of its token) and one quota principal: a fresh token
/// exchange must not buy a fresh rate limit.
#[test]
fn two_tokens_of_one_oidc_identity_share_one_bucket() {
    let actor = "oidc:24:https://issuer.example:5:alice";
    let cfg = resolved(AuthConfig::default());
    let (first, second) = (oidc_client(actor, "token-1"), oidc_client(actor, "token-2"));
    assert_ne!(first.principal, second.principal, "the precondition");

    assert!(cfg.check_authenticated_client_rate_limit(&first));
    assert!(
        !cfg.check_authenticated_client_rate_limit(&second),
        "the second token draws on the same 1/min"
    );
}

/// The same identity holds for the breaker: failures under one token open
/// the circuit the other token is refused by.
#[test]
fn two_tokens_of_one_oidc_identity_share_one_breaker() {
    let actor = "oidc:24:https://issuer.example:5:alice";
    let cfg = resolved(AuthConfig {
        client_circuit_breaker: Some(breaker()),
        ..AuthConfig::default()
    });
    let (first, second) = (oidc_client(actor, "token-1"), oidc_client(actor, "token-2"));

    cfg.record_client_failure(&first);
    cfg.record_client_failure(&first);
    assert!(
        client_preflight(&cfg, &second, "/mcp").is_some(),
        "the second token is the same person, behind the same open circuit"
    );
}

/// Two OIDC identities stay apart: one exhausting its bucket leaves the
/// other's untouched.
#[test]
fn two_oidc_identities_keep_separate_buckets() {
    let cfg = resolved(AuthConfig::default());
    let alice = oidc_client("oidc:24:https://issuer.example:5:alice", "token-a");
    let bob = oidc_client("oidc:24:https://issuer.example:3:bob", "token-b");

    assert!(cfg.check_authenticated_client_rate_limit(&alice));
    assert!(!cfg.check_authenticated_client_rate_limit(&alice));
    assert!(
        cfg.check_authenticated_client_rate_limit(&bob),
        "bob's 1/min is his own"
    );
}

/// Two keys sharing a name keep separate breakers: one key's failures do not
/// refuse the other.
#[test]
fn same_named_keys_keep_separate_breakers() {
    let cfg = resolved(AuthConfig {
        api_keys: vec![key("secret-a", "shared", 0), key("secret-b", "shared", 0)],
        client_circuit_breaker: Some(breaker()),
        ..AuthConfig::default()
    });
    let (a, b) = (client(&cfg, "secret-a"), client(&cfg, "secret-b"));

    cfg.record_client_failure(&a);
    cfg.record_client_failure(&a);
    assert!(
        client_preflight(&cfg, &a, "/mcp").is_some(),
        "A's circuit opens"
    );
    assert!(
        client_preflight(&cfg, &b, "/mcp").is_none(),
        "B's circuit is its own and still closed"
    );
}

/// Trips after two failures and stays open for the test's lifetime.
fn breaker() -> CircuitBreakerConfig {
    CircuitBreakerConfig {
        enabled: true,
        failure_threshold: 2,
        success_threshold: 1,
        reset_timeout: Duration::from_secs(60),
    }
}

/// Shaped like the client `KeyServer::lookup` builds for a temporary token
/// (quota from the identity, principal from the token), limited to 1/min.
fn oidc_client(actor: &str, token: &str) -> AuthenticatedClient {
    AuthenticatedClient {
        quota_principal: Some(QuotaPrincipal::oidc_identity(actor)),
        name: actor.to_string(),
        // As `runtime_principal(RuntimeIssuer::KeyServerToken, token)`.
        principal: format!("kst:{}", crate::hashing::sha256_hex(token.as_bytes())),
        rate_limit: 1,
        backends: vec!["*".to_string()],
        allowed_tools: None,
        denied_tools: None,
        admin: false,
        authenticated: true,
        credential_kind: CredentialKind::KeyServerToken,
    }
}
