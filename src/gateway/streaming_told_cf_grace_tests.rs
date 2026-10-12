// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Grace rows for held Cloudflare re-verification.

use serde_json::json;

use super::*;
use crate::key_server::oidc::{OidcError, OidcVerifier, VerifiedIdentity};
use crate::key_server::oidc_test_harness::{AUD, Harness, ISS_A, config_yaml};

fn identity() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "alice".to_string(),
        email: "alice@example.invalid".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: ISS_A.to_string(),
    }
}

#[test]
fn cf_verdict_classifies_each_error() {
    use super::told::{CfVerdict, cf_verdict};
    assert_eq!(cf_verdict(&Ok(identity())), CfVerdict::Good);
    let Err(http) = reqwest::Proxy::all("::not-a-url") else {
        panic!("a malformed proxy URL must fail");
    };
    assert_eq!(
        cf_verdict(&Err(OidcError::HttpError(http))),
        CfVerdict::Transient
    );
    assert_eq!(
        cf_verdict(&Err(OidcError::DiscoveryStatus(500))),
        CfVerdict::Transient
    );
    assert_eq!(
        cf_verdict(&Err(OidcError::ClientUnavailable)),
        CfVerdict::Transient
    );
    let dead = [
        OidcError::JwtError(jsonwebtoken::errors::ErrorKind::InvalidToken.into()),
        OidcError::UnknownIssuer("https://x.example".to_string()),
        OidcError::MissingKeyId,
        OidcError::UnknownKeyId("kid".to_string()),
        OidcError::DomainNotAllowed("example".to_string()),
        OidcError::NoPolicyMatch("alice".to_string()),
        OidcError::TokenTooOld { iat_ago: 9, max: 1 },
        OidcError::IssuerMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
        },
        OidcError::InsecureJwksUri("http://x.example/j".to_string()),
        OidcError::InsecureIssuer,
        OidcError::InsecureFetch,
    ];
    for err in dead {
        assert_eq!(cf_verdict(&Err(err)), CfVerdict::Dead);
    }
}

async fn closed_jwks_uri() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    format!("http://{addr}/.well-known/jwks.json")
}

fn unreachable_verifier(jwks_uri: String) -> OidcVerifier {
    let provider = crate::config::KeyServerProviderConfig {
        issuer: ISS_A.to_string(),
        jwks_uri: Some(jwks_uri),
        discovery_url: None,
        auto_discover: false,
        audiences: vec![AUD.to_string()],
        allowed_domains: Vec::new(),
    };
    OidcVerifier::with_http_client(vec![provider], reqwest::Client::new())
}

fn good_verifier(harness: &Harness) -> OidcVerifier {
    OidcVerifier::with_http_client(harness.ks.config.oidc.clone(), reqwest::Client::new())
}

#[tokio::test]
async fn two_transients_stay_open_third_closes() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let token = harness.mint(ISS_A, "alice", &json!({}));
    let verifier = unreachable_verifier(closed_jwks_uri().await);
    let identity_cfg = crate::security::caller_identity::CallerIdentityConfig::default();
    let ctx = LiveCtx {
        agent: None,
        caller_identity: &identity_cfg,
        cf_verifier: Some(&verifier),
    };
    let subject = ViewSubject {
        cf_assertion: Some(Redacted::new(token)),
        ..ViewSubject::default()
    };
    assert_eq!(
        subject.verify_held_cf(&ctx).await,
        Ok(()),
        "first transient stays"
    );
    assert_eq!(
        subject.verify_held_cf(&ctx).await,
        Ok(()),
        "second transient stays"
    );
    assert_eq!(
        subject.verify_held_cf(&ctx).await,
        Err(DeadReason::Cf),
        "third transient fails closed"
    );
}

#[tokio::test]
async fn stale_last_good_fails_closed_on_first_transient() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let good = good_verifier(&harness);
    let ttl = good.jwks_ttl().as_secs();
    let bad = unreachable_verifier(closed_jwks_uri().await);
    let identity_cfg = crate::security::caller_identity::CallerIdentityConfig::default();
    let t0 = crate::clock::unix_secs().expect("a clock after the epoch");
    let held = crate::clock::test_clock::at_secs(t0);
    let token = harness.mint(ISS_A, "alice", &json!({}));
    let subject = ViewSubject {
        cf_assertion: Some(Redacted::new(token)),
        ..ViewSubject::default()
    };
    let good_ctx = LiveCtx {
        agent: None,
        caller_identity: &identity_cfg,
        cf_verifier: Some(&good),
    };
    assert_eq!(
        subject.verify_held_cf(&good_ctx).await,
        Ok(()),
        "premise: a good verification sets last good"
    );
    drop(held);
    let stale = t0.saturating_add(ttl).saturating_add(1);
    let _past = crate::clock::test_clock::at_secs(stale);
    let bad_ctx = LiveCtx {
        agent: None,
        caller_identity: &identity_cfg,
        cf_verifier: Some(&bad),
    };
    assert_eq!(
        subject.verify_held_cf(&bad_ctx).await,
        Err(DeadReason::Cf),
        "a stale last good fails closed at once"
    );
}

#[tokio::test]
async fn good_between_failures_resets_the_count() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let token = harness.mint(ISS_A, "alice", &json!({}));
    let good = good_verifier(&harness);
    let bad = unreachable_verifier(closed_jwks_uri().await);
    let identity_cfg = crate::security::caller_identity::CallerIdentityConfig::default();
    let good_ctx = LiveCtx {
        agent: None,
        caller_identity: &identity_cfg,
        cf_verifier: Some(&good),
    };
    let bad_ctx = LiveCtx {
        agent: None,
        caller_identity: &identity_cfg,
        cf_verifier: Some(&bad),
    };
    let subject = ViewSubject {
        cf_assertion: Some(Redacted::new(token)),
        ..ViewSubject::default()
    };
    assert_eq!(
        subject.verify_held_cf(&bad_ctx).await,
        Ok(()),
        "first transient stays"
    );
    assert_eq!(
        subject.verify_held_cf(&bad_ctx).await,
        Ok(()),
        "second transient stays"
    );
    assert_eq!(
        subject.verify_held_cf(&good_ctx).await,
        Ok(()),
        "a good verification resets"
    );
    assert_eq!(
        subject.verify_held_cf(&bad_ctx).await,
        Ok(()),
        "the count restarted"
    );
}
