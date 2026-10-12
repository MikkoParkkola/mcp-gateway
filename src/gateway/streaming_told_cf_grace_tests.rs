// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Grace rows for held Cloudflare re-verification.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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

// A loopback JWKS endpoint that accepts each connection and drops it
// without replying, so a fetch fails promptly with a disconnect rather
// than a refusal or a timeout. The fixture owns the server task (and
// that task owns the one listener) for the whole test; dropping the
// fixture aborts only that task.
struct DisconnectJwks {
    jwks_uri: String,
    accepted: Arc<AtomicUsize>,
    server: tokio::task::JoinHandle<std::result::Result<(), std::io::Error>>,
}

impl DisconnectJwks {
    async fn start() -> Self {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => {
                panic!("premise: disconnect mock setup failed to bind loopback: {error}")
            }
        };
        let addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(error) => {
                panic!("premise: disconnect mock setup failed to read its address: {error}")
            }
        };
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&accepted);
        let server: tokio::task::JoinHandle<std::result::Result<(), std::io::Error>> =
            tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await?;
                    counted.fetch_add(1, Ordering::SeqCst);
                    drop(stream);
                }
            });
        Self {
            jwks_uri: format!("http://{addr}/.well-known/jwks.json"),
            accepted,
            server,
        }
    }

    fn assert_live(&self, when: &str) {
        assert!(
            !self.server.is_finished(),
            "premise: disconnect mock task exited {when} the raw verifier premise"
        );
    }
}

impl Drop for DisconnectJwks {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn disconnecting_verifier(fixture: &DisconnectJwks) -> OidcVerifier {
    let provider = crate::config::KeyServerProviderConfig {
        issuer: ISS_A.to_string(),
        jwks_uri: Some(fixture.jwks_uri.clone()),
        discovery_url: None,
        auto_discover: false,
        audiences: vec![AUD.to_string()],
        allowed_domains: Vec::new(),
    };
    let client = match reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(error) => panic!("premise: disconnect verifier client build failed: {error}"),
    };
    OidcVerifier::with_http_client(vec![provider], client)
}

fn good_verifier(harness: &Harness) -> OidcVerifier {
    OidcVerifier::with_http_client(harness.ks.config.oidc.clone(), reqwest::Client::new())
}

// Prove the bad verifier's failure really is the mock's prompt disconnect,
// before any grace decision is taken on it. N6: prove the raw non-timeout
// `HttpError` only, never its `CfVerdict`, so a Dead-classification fault
// still passes this premise and fails at the grace assertions below.
async fn assert_disconnect_premise(
    fixture: &DisconnectJwks,
    verifier: &OidcVerifier,
    subject: &ViewSubject,
) {
    fixture.assert_live("before");
    let before = fixture.accepted.load(Ordering::SeqCst);
    let Some(assertion) = subject.cf_assertion.as_ref() else {
        panic!("premise: the subject holds no CF assertion for the raw verifier premise");
    };
    let age = crate::config::KeyServerOidcConfig {
        token_age: crate::key_server::TokenAgeCap::ExpOnly,
    };
    match verifier.verify(assertion.expose(), &age).await {
        Err(OidcError::HttpError(error)) if error.is_timeout() => {
            panic!("premise: raw verifier HTTP error was a timeout, not a disconnect: {error}")
        }
        Err(OidcError::HttpError(_)) => {}
        Err(error) => {
            panic!("premise: raw verifier expected a non-timeout HttpError, got: {error}")
        }
        Ok(_) => {
            panic!("premise: raw verifier unexpectedly verified against the disconnect mock")
        }
    }
    fixture.assert_live("after");
    assert!(
        fixture.accepted.load(Ordering::SeqCst) > before,
        "premise: disconnect mock accepted no connection during the raw verifier premise"
    );
}

#[tokio::test]
async fn two_transients_stay_open_third_closes() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let token = harness.mint(ISS_A, "alice", &json!({}));
    let disconnect_jwks = DisconnectJwks::start().await;
    let verifier = disconnecting_verifier(&disconnect_jwks);
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
    assert_disconnect_premise(&disconnect_jwks, &verifier, &subject).await;
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
    let disconnect_jwks = DisconnectJwks::start().await;
    let bad = disconnecting_verifier(&disconnect_jwks);
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
    assert_disconnect_premise(&disconnect_jwks, &bad, &subject).await;
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
    let disconnect_jwks = DisconnectJwks::start().await;
    let bad = disconnecting_verifier(&disconnect_jwks);
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
    assert_disconnect_premise(&disconnect_jwks, &bad, &subject).await;
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
