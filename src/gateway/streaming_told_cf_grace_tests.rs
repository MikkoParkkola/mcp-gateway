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

async fn admitted_subject(verifier: &OidcVerifier, token: String) -> ViewSubject {
    let age = crate::config::KeyServerOidcConfig {
        token_age: crate::key_server::TokenAgeCap::ExpOnly,
    };
    let receipt = match verifier.verify_checked(token, &age).await {
        Ok((_identity, receipt)) => receipt,
        Err(error) => panic!("premise: the admission verification failed: {error}"),
    };
    ViewSubject {
        identity_source: HeldSource::Cloudflare(receipt),
        ..ViewSubject::default()
    }
}

// Independent of the held path: the cached good verifier itself now
// refuses the token as a JWT error (its life plus leeway has passed),
// never as an HTTP failure.
async fn assert_good_verifier_refuses_expired(good: &OidcVerifier, token: &str) {
    let age = crate::config::KeyServerOidcConfig {
        token_age: crate::key_server::TokenAgeCap::ExpOnly,
    };
    match good.verify(token, &age).await {
        Err(OidcError::JwtError(_)) => {}
        Err(error) => {
            panic!("premise: cached good verifier expected a JwtError refusal, got: {error}")
        }
        Ok(_) => panic!("premise: cached good verifier accepted the expired minted token"),
    }
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
    let HeldSource::Cloudflare(assertion) = &subject.identity_source else {
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
    let good = good_verifier(&harness);
    let disconnect_jwks = DisconnectJwks::start().await;
    let verifier = disconnecting_verifier(&disconnect_jwks);
    let identity_cfg = crate::security::caller_identity::CallerIdentityConfig::default();
    let ctx = LiveCtx {
        agent: None,
        caller_identity: &identity_cfg,
        cf_verifier: Some(&verifier),
    };
    let subject = admitted_subject(&good, token).await;
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
    let token = harness.mint(
        ISS_A,
        "alice",
        &json!({"exp": t0.saturating_add(ttl).saturating_add(600)}),
    );
    let minted = token.clone();
    let subject = admitted_subject(&good, token).await;
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
    let age = crate::config::KeyServerOidcConfig {
        token_age: crate::key_server::TokenAgeCap::ExpOnly,
    };
    assert!(
        good.verify(&minted, &age).await.is_ok(),
        "premise: the assertion is still live at the stale clock"
    );
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
    let subject = admitted_subject(&good, token).await;
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

/// C0 T1: an assertion that has expired (past its minted `exp` plus the
/// verifier's 60 s leeway) must fail the stream on the first transient
/// failure, even though the last good verification is still well inside
/// the JWKS TTL. The known mint at the held clock `t0` expires at
/// `t0 + 300`; the outage decision is taken at `t0 + 361`.
#[tokio::test]
async fn expired_held_assertion_fails_on_first_transient_even_within_jwks_ttl() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
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
    let t0 = crate::clock::unix_secs().expect("a clock after the epoch");
    let held = crate::clock::test_clock::at_secs(t0);
    let token = harness.mint(ISS_A, "alice", &json!({}));
    let minted = token.clone();
    let subject = admitted_subject(&good, token).await;
    assert_eq!(
        subject.verify_held_cf(&good_ctx).await,
        Ok(()),
        "premise: a good verification at t0 sets last good"
    );
    assert_disconnect_premise(&disconnect_jwks, &bad, &subject).await;
    drop(held);
    let _past = crate::clock::test_clock::at_secs(t0 + 361);
    assert_good_verifier_refuses_expired(&good, &minted).await;
    assert!(
        361 < good.jwks_ttl().as_secs(),
        "premise: the outage decision is inside the JWKS TTL: {}",
        good.jwks_ttl().as_secs()
    );
    let accepted_before = disconnect_jwks.accepted.load(Ordering::SeqCst);
    assert_eq!(
        subject.verify_held_cf(&bad_ctx).await,
        Err(DeadReason::Cf),
        "own T1: an expired held assertion fails on the first transient"
    );
    assert_eq!(
        disconnect_jwks.accepted.load(Ordering::SeqCst),
        accepted_before,
        "own T1: the expired assertion is refused without a JWKS fetch"
    );
}

// As `DisconnectJwks`, but each accepted connection is held until the
// fixture releases it, so a fetch can be provably in flight while the
// test clock moves. One listener owned by one spawned task owned by the
// fixture; dropping the fixture aborts only that task.
struct GatedDisconnectJwks {
    jwks_uri: String,
    accepted: Arc<AtomicUsize>,
    arrived: Arc<tokio::sync::Notify>,
    releases: tokio::sync::mpsc::UnboundedReceiver<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<std::result::Result<(), std::io::Error>>,
}

impl GatedDisconnectJwks {
    async fn start() -> Self {
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => {
                panic!("premise: gated mock setup failed to bind loopback: {error}")
            }
        };
        let addr = match listener.local_addr() {
            Ok(addr) => addr,
            Err(error) => {
                panic!("premise: gated mock setup failed to read its address: {error}")
            }
        };
        let accepted = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&accepted);
        let arrived = Arc::new(tokio::sync::Notify::new());
        let signal = Arc::clone(&arrived);
        let (release_requests, releases) = tokio::sync::mpsc::unbounded_channel();
        let server: tokio::task::JoinHandle<std::result::Result<(), std::io::Error>> =
            tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await?;
                    counted.fetch_add(1, Ordering::SeqCst);
                    let (release, connection_gate) = tokio::sync::oneshot::channel();
                    if release_requests.send(release).is_err() {
                        drop(stream);
                        continue;
                    }
                    signal.notify_one();
                    let _ = connection_gate.await;
                    drop(stream);
                }
            });
        Self {
            jwks_uri: format!("http://{addr}/.well-known/jwks.json"),
            accepted,
            arrived,
            releases,
            server,
        }
    }

    async fn await_arrival(&mut self) -> tokio::sync::oneshot::Sender<()> {
        self.arrived.notified().await;
        match self.releases.recv().await {
            Some(release) => release,
            None => panic!("premise: gated mock closed before handing out a release"),
        }
    }
}

impl Drop for GatedDisconnectJwks {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn gated_verifier(fixture: &GatedDisconnectJwks) -> OidcVerifier {
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
        Err(error) => panic!("premise: gated verifier client build failed: {error}"),
    };
    OidcVerifier::with_http_client(vec![provider], client)
}

/// T1b: an assertion live when the JWKS fetch starts but expired by the
/// time the fetch fails transiently must fail closed at that decision,
/// on the first transient and inside the JWKS TTL. Current-thread, so
/// the spawned task reads this thread's forced test clock.
#[tokio::test(flavor = "current_thread")]
async fn assertion_expiring_during_jwks_fetch_fails_closed() {
    let harness = Harness::start(&config_yaml("[]", "")).await;
    let good = good_verifier(&harness);
    let mut gated = GatedDisconnectJwks::start().await;
    let identity_cfg = crate::security::caller_identity::CallerIdentityConfig::default();
    let good_ctx = LiveCtx {
        agent: None,
        caller_identity: &identity_cfg,
        cf_verifier: Some(&good),
    };
    let age = crate::config::KeyServerOidcConfig {
        token_age: crate::key_server::TokenAgeCap::ExpOnly,
    };
    let t0 = crate::clock::unix_secs().expect("a clock after the epoch");
    let held = crate::clock::test_clock::at_secs(t0);
    let token = harness.mint(ISS_A, "alice", &json!({}));
    let minted = token.clone();
    let subject = admitted_subject(&good, token).await;
    assert_eq!(
        subject.verify_held_cf(&good_ctx).await,
        Ok(()),
        "premise: a good verification at t0 sets last good"
    );
    // The gated mock's own raw behaviour, in one independent gated
    // cycle: a non-timeout disconnect `HttpError`, as in the premise
    // discipline of `assert_disconnect_premise`.
    let raw_verifier = gated_verifier(&gated);
    let raw_token = minted.clone();
    let raw = tokio::spawn(async move {
        let age = crate::config::KeyServerOidcConfig {
            token_age: crate::key_server::TokenAgeCap::ExpOnly,
        };
        raw_verifier.verify(&raw_token, &age).await
    });
    let release = gated.await_arrival().await;
    assert!(
        release.send(()).is_ok(),
        "premise: the gated raw connection closed before its release"
    );
    match raw.await {
        Ok(Err(OidcError::HttpError(error))) if error.is_timeout() => {
            panic!("premise: gated raw HTTP error was a timeout, not a disconnect: {error}")
        }
        Ok(Err(OidcError::HttpError(_))) => {}
        Ok(Err(error)) => {
            panic!("premise: gated raw verifier expected a non-timeout HttpError, got: {error}")
        }
        Ok(Ok(_)) => {
            panic!("premise: gated raw verifier unexpectedly verified against the mock")
        }
        Err(error) => panic!("premise: the gated raw task failed: {error}"),
    }
    drop(held);
    let live_at = t0 + 359;
    let live = crate::clock::test_clock::at_secs(live_at);
    assert!(
        good.verify(&minted, &age).await.is_ok(),
        "premise: the assertion is still live when the gated fetch starts"
    );
    let verifier = gated_verifier(&gated);
    let accepted_before = gated.accepted.load(Ordering::SeqCst);
    let task = tokio::spawn(async move {
        assert_eq!(
            crate::clock::unix_secs(),
            Ok(live_at),
            "premise: the spawned task reads the forced test clock"
        );
        let identity_cfg = crate::security::caller_identity::CallerIdentityConfig::default();
        let ctx = LiveCtx {
            agent: None,
            caller_identity: &identity_cfg,
            cf_verifier: Some(&verifier),
        };
        subject.verify_held_cf(&ctx).await
    });
    let release = gated.await_arrival().await;
    assert!(
        gated.accepted.load(Ordering::SeqCst) > accepted_before,
        "premise: the gated fetch is in flight"
    );
    drop(live);
    let _past = crate::clock::test_clock::at_secs(t0 + 361);
    assert_good_verifier_refuses_expired(&good, &minted).await;
    assert!(
        361 <= good.jwks_ttl().as_secs(),
        "premise: the outage decision is inside the JWKS TTL: {}",
        good.jwks_ttl().as_secs()
    );
    assert!(
        release.send(()).is_ok(),
        "premise: the gated connection closed before its release"
    );
    let joined = match task.await {
        Ok(joined) => joined,
        Err(error) => panic!("premise: the spawned verify task failed: {error}"),
    };
    assert_eq!(
        joined,
        Err(DeadReason::Cf),
        "own T1b: an assertion expiring during the JWKS fetch fails closed"
    );
}
