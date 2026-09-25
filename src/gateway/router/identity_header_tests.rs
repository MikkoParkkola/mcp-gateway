// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A8: identity headers are honoured only from where the mode says.
//!
//! Cells drive [`caller_grant_subject`] with a header map, a peer and a mode.
//! The Access cells sign ES256 assertions with a local [`GatewayKeyPair`] and
//! serve its JWKS on a loopback port through the verifier's test HTTP seam.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::json;
use telemetry_metrics::{
    Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
};

use super::*;
use crate::config::{
    KeyServerConfig, KeyServerPolicyConfig, PolicyMatchConfig, PolicyScopesConfig,
};
use crate::gateway::oauth::{GatewayKeyPair, jwks_handler};
use crate::key_server::oidc::cloudflare_access_provider;
use crate::security::caller_identity::CloudflareAccessConfig;

const TEAM: &str = "acme.cloudflareaccess.com";
const AUD: &str = "aud-tag-1";

fn proxy_mode() -> CallerIdentityConfig {
    CallerIdentityConfig {
        mode: CallerIdentityMode::TrustedProxy,
        trusted_proxies: vec!["10.0.0.5".parse().unwrap()],
        authority: "corp-sso".to_string(),
        ..CallerIdentityConfig::default()
    }
}

fn access_mode() -> CallerIdentityConfig {
    CallerIdentityConfig {
        mode: CallerIdentityMode::CloudflareAccess,
        cloudflare_access: CloudflareAccessConfig {
            team_domain: TEAM.to_string(),
            audiences: vec![AUD.to_string()],
        },
        ..CallerIdentityConfig::default()
    }
}

fn peer(addr: &str) -> SocketAddr {
    SocketAddr::new(addr.parse().unwrap(), 40000)
}

const TRUSTED: &str = "10.0.0.5";
const OUTSIDER: &str = "203.0.113.9";

fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        map.append(*name, HeaderValue::from_str(value).unwrap());
    }
    map
}

async fn resolve(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    config: &CallerIdentityConfig,
    access: Option<&OidcVerifier>,
) -> Result<Option<GrantSubject>, IdentityHeaderRefusal> {
    caller_grant_subject(None, headers, peer, config, access, None, None).await
}

fn subject_pair(subject: Option<GrantSubject>) -> Option<(String, String)> {
    subject.map(|s| (s.authority, s.subject))
}

fn verified_oidc() -> VerifiedIdentity {
    VerifiedIdentity {
        subject: "oidc-subject".to_string(),
        email: "owner@corp.example".to_string(),
        name: None,
        groups: Vec::new(),
        issuer: "https://issuer.example".to_string(),
    }
}

// ── Access assertion fixture ────────────────────────────────────────────────

/// A signing key and a loopback JWKS endpoint serving its public half.
struct AccessIdp {
    key: Arc<GatewayKeyPair>,
    jwks_uri: String,
}

impl AccessIdp {
    async fn start() -> Self {
        let key = Arc::new(GatewayKeyPair::generate().unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new()
            .route("/cdn-cgi/access/certs", axum::routing::get(jwks_handler))
            .with_state(Arc::clone(&key));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            key,
            jwks_uri: format!("http://{addr}/cdn-cgi/access/certs"),
        }
    }

    /// The production provider for `access_mode()`, with only the certs URL
    /// pointed at the loopback server.
    fn verifier(&self) -> OidcVerifier {
        let provider = crate::config::KeyServerProviderConfig {
            jwks_uri: Some(self.jwks_uri.clone()),
            ..cloudflare_access_provider(&access_mode().cloudflare_access)
        };
        OidcVerifier::with_http_client(vec![provider], reqwest::Client::new())
    }

    fn sign(&self, claims: &serde_json::Value) -> String {
        sign_with(&self.key, &self.key.key_info().kid, claims)
    }
}

/// Sign with `key` but name `kid`, so a forged token can claim a trusted key id.
fn sign_with(key: &GatewayKeyPair, kid: &str, claims: &serde_json::Value) -> String {
    let info = key.key_info();
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(kid.to_string());
    let encoding = EncodingKey::from_ec_pem(info.private_key_pem.as_bytes()).unwrap();
    jsonwebtoken::encode(&header, claims, &encoding).unwrap()
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// Access-shaped claims for `sub`, issued `iat_ago` seconds ago and expiring
/// `exp_in` seconds from now.
fn access_claims(sub: &str, aud: &str, iat_ago: i64, exp_in: i64) -> serde_json::Value {
    json!({
        "iss": format!("https://{TEAM}"),
        "sub": sub,
        "aud": [aud],
        "email": "u@corp.example",
        "iat": now() - iat_ago,
        "exp": now() + exp_in,
    })
}

// ── Counter capture ─────────────────────────────────────────────────────────

#[derive(Clone, Default)]
struct Hits(Arc<AtomicU64>);

impl CounterFn for Hits {
    fn increment(&self, value: u64) {
        self.0.fetch_add(value, Ordering::SeqCst);
    }
    fn absolute(&self, value: u64) {
        self.0.fetch_max(value, Ordering::SeqCst);
    }
}

/// Tallies one counter series: `name{reason=<reason>}`.
struct Watch {
    name: &'static str,
    reason: &'static str,
    hits: Hits,
}

impl Recorder for Watch {
    fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
    fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
        let reason = key
            .labels()
            .any(|l| l.key() == "reason" && l.value() == self.reason);
        if key.name() == self.name && reason {
            Counter::from_arc(Arc::new(self.hits.clone()))
        } else {
            Counter::noop()
        }
    }
    fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
        Gauge::noop()
    }
    fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
        Histogram::noop()
    }
}

/// Run `case` with a thread-local recorder and return how often the watched
/// series was incremented. `#[tokio::test]` is single-threaded.
async fn count<T>(
    name: &'static str,
    reason: &'static str,
    case: impl std::future::Future<Output = T>,
) -> (T, u64) {
    let watch = Watch {
        name,
        reason,
        hits: Hits::default(),
    };
    let out = {
        let _guard = telemetry_metrics::set_default_local_recorder(&watch);
        case.await
    };
    (out, watch.hits.0.load(Ordering::SeqCst))
}

// ── trusted_proxy ───────────────────────────────────────────────────────────

/// A8-T1: a subject header from a peer that is not a trusted proxy is 403.
#[tokio::test]
async fn untrusted_peer_identity_header_is_refused() {
    let h = headers(&[(HEADER_GATEWAY_IDENTITY_SUBJECT, "alice")]);
    let refusal = resolve(&h, Some(peer(OUTSIDER)), &proxy_mode(), None).await;
    assert_eq!(refusal, Err(IdentityHeaderRefusal::UntrustedPeer));
    assert_eq!(
        IdentityHeaderRefusal::UntrustedPeer.status(),
        StatusCode::FORBIDDEN
    );
}

/// A8-T2: the authority never comes from the request, so a caller cannot
/// name an OIDC issuer and land on that issuer's subject.
#[tokio::test]
async fn caller_cannot_set_authority() {
    let h = headers(&[
        (HEADER_GATEWAY_IDENTITY_SUBJECT, "victim-sub"),
        (
            HEADER_GATEWAY_IDENTITY_AUTHORITY,
            "https://accounts.google.com",
        ),
    ]);
    let result = resolve(&h, Some(peer(TRUSTED)), &proxy_mode(), None).await;
    assert_eq!(result, Err(IdentityHeaderRefusal::RemovedHeader));
    assert_eq!(
        IdentityHeaderRefusal::RemovedHeader.status(),
        StatusCode::BAD_REQUEST
    );
}

/// A8-T3 (positive control): the proxy's subject lands under the configured
/// authority.
#[tokio::test]
async fn trusted_peer_gets_configured_authority() {
    let h = headers(&[(HEADER_GATEWAY_IDENTITY_SUBJECT, "alice")]);
    let subject = resolve(&h, Some(peer(TRUSTED)), &proxy_mode(), None)
        .await
        .unwrap();
    assert_eq!(
        subject_pair(subject),
        Some(("corp-sso".to_string(), "alice".to_string()))
    );
}

/// A8-T8: over 512 bytes (also when under 512 characters) or repeated is 400,
/// never truncated or first-wins.
#[tokio::test]
async fn overlong_or_repeated_header_is_refused() {
    let ascii = "a".repeat(513);
    let wide = "\u{20ac}".repeat(200); // 200 characters, 600 bytes
    for value in [ascii.as_str(), wide.as_str()] {
        let mut h = HeaderMap::new();
        h.insert(
            HEADER_GATEWAY_IDENTITY_SUBJECT,
            HeaderValue::from_bytes(value.as_bytes()).unwrap(),
        );
        let result = resolve(&h, Some(peer(TRUSTED)), &proxy_mode(), None).await;
        assert_eq!(
            result,
            Err(IdentityHeaderRefusal::Malformed),
            "{} bytes",
            value.len()
        );
    }
    let repeated = headers(&[
        (HEADER_GATEWAY_IDENTITY_SUBJECT, "alice"),
        (HEADER_GATEWAY_IDENTITY_SUBJECT, "bob"),
    ]);
    let result = resolve(&repeated, Some(peer(TRUSTED)), &proxy_mode(), None).await;
    assert_eq!(result, Err(IdentityHeaderRefusal::Malformed));
    assert_eq!(
        IdentityHeaderRefusal::Malformed.status(),
        StatusCode::BAD_REQUEST
    );
}

/// A8-T9 (positive control): mode `off` reads no identity header and refuses
/// none, whatever the peer.
#[tokio::test]
async fn mode_off_ignores_all_identity_headers() {
    let h = headers(&[
        (HEADER_GATEWAY_IDENTITY_SUBJECT, "alice"),
        (HEADER_GATEWAY_IDENTITY, "alice"),
        (
            HEADER_GATEWAY_IDENTITY_AUTHORITY,
            "https://accounts.google.com",
        ),
        (HEADER_GATEWAY_IDENTITY_SUBJECT, "bob"),
        (HEADER_CF_ACCESS_USER_ID, "u1"),
        (HEADER_CF_ACCESS_EMAIL, "u1@corp.example"),
    ]);
    let off = CallerIdentityConfig::default();
    for p in [Some(peer(OUTSIDER)), Some(peer(TRUSTED)), None] {
        assert_eq!(resolve(&h, p, &off, None).await, Ok(None));
    }
}

/// A8-T10 (positive control): verified OIDC wins over a valid header
/// identity, and the ignored header is counted.
#[tokio::test]
async fn oidc_outranks_header_identity() {
    let h = headers(&[(HEADER_GATEWAY_IDENTITY_SUBJECT, "alice")]);
    let (config, oidc) = (proxy_mode(), verified_oidc());
    let (result, ignored) = count(
        "mcp_identity_header_ignored_total",
        "oidc_precedence",
        async {
            caller_grant_subject(
                Some(&oidc),
                &h,
                Some(peer(TRUSTED)),
                &config,
                None,
                None,
                None,
            )
            .await
        },
    )
    .await;
    assert_eq!(
        subject_pair(result.unwrap()),
        Some((
            "https://issuer.example".to_string(),
            "oidc-subject".to_string()
        ))
    );
    assert_eq!(ignored, 1, "the outranked header identity was not counted");
}

/// A8-T12: no `ConnectInfo` means no proven peer, so the header is refused.
#[tokio::test]
async fn missing_connect_info_is_untrusted() {
    let h = headers(&[(HEADER_GATEWAY_IDENTITY_SUBJECT, "alice")]);
    let result = resolve(&h, None, &proxy_mode(), None).await;
    assert_eq!(result, Err(IdentityHeaderRefusal::UntrustedPeer));
}

/// A8-T12b: an IPv4-mapped IPv6 peer is the same host as its IPv4 entry.
#[tokio::test]
async fn ipv4_mapped_peer_matches_ipv4_entry() {
    let h = headers(&[(HEADER_GATEWAY_IDENTITY_SUBJECT, "alice")]);
    let subject = resolve(&h, Some(peer("::ffff:10.0.0.5")), &proxy_mode(), None).await;
    assert_eq!(
        subject_pair(subject.unwrap()),
        Some(("corp-sso".to_string(), "alice".to_string()))
    );
}

/// A8-T17: `Cf-Access-*` in `trusted_proxy` mode is ignored and counted.
#[tokio::test]
async fn cf_access_headers_counted_in_trusted_proxy_mode() {
    let h = headers(&[(HEADER_CF_ACCESS_USER_ID, "u1")]);
    let config = proxy_mode();
    let (result, ignored) = count(
        "mcp_identity_header_ignored_total",
        "cf_access_in_trusted_proxy",
        resolve(&h, Some(peer(TRUSTED)), &config, None),
    )
    .await;
    assert_eq!(result, Ok(None));
    assert_eq!(ignored, 1, "the ignored Cf-Access header was not counted");
}

// ── cloudflare_access ───────────────────────────────────────────────────────

/// The team domain becomes Cloudflare's issuer and certs URL.
#[test]
fn access_provider_derives_issuer_and_certs_from_team_domain() {
    let provider = cloudflare_access_provider(&access_mode().cloudflare_access);
    assert_eq!(provider.issuer, format!("https://{TEAM}"));
    assert_eq!(
        provider.jwks_uri.as_deref(),
        Some("https://acme.cloudflareaccess.com/cdn-cgi/access/certs")
    );
    assert_eq!(provider.audiences, vec![AUD.to_string()]);
}

/// A8-T4: Access user headers without an assertion are 401.
#[tokio::test]
async fn cf_user_headers_without_assertion_are_refused() {
    let idp = AccessIdp::start().await;
    let verifier = idp.verifier();
    let h = headers(&[(HEADER_CF_ACCESS_USER_ID, "u1")]);
    let result = resolve(&h, Some(peer(OUTSIDER)), &access_mode(), Some(&verifier)).await;
    assert_eq!(result, Err(IdentityHeaderRefusal::AccessAssertion));
    assert_eq!(
        IdentityHeaderRefusal::AccessAssertion.status(),
        StatusCode::UNAUTHORIZED
    );
}

/// A8-T5 (positive control): a valid assertion yields `(https://<team>, sub)`.
/// The label is not asserted.
#[tokio::test]
async fn cf_assertion_verified_yields_team_subject() {
    let idp = AccessIdp::start().await;
    let verifier = idp.verifier();
    let jwt = idp.sign(&access_claims("u1", AUD, 10, 3600));
    let h = headers(&[(HEADER_CF_ACCESS_JWT, jwt.as_str())]);
    let subject = resolve(&h, Some(peer(OUTSIDER)), &access_mode(), Some(&verifier)).await;
    assert_eq!(
        subject_pair(subject.unwrap()),
        Some((format!("https://{TEAM}"), "u1".to_string()))
    );
}

/// A8-T6: a foreign `aud`, or a signature by another key, is 401.
#[tokio::test]
async fn cf_assertion_wrong_aud_or_signature_is_refused() {
    let idp = AccessIdp::start().await;
    let verifier = idp.verifier();
    let stranger = GatewayKeyPair::generate().unwrap();
    let foreign_aud = idp.sign(&access_claims("u1", "other-app", 10, 3600));
    // The forgery names the team's own kid, so only the signature check stops it.
    let team_kid = idp.key.key_info().kid;
    let foreign_key = sign_with(&stranger, &team_kid, &access_claims("u1", AUD, 10, 3600));
    for (case, jwt) in [("aud", foreign_aud), ("key", foreign_key)] {
        let h = headers(&[(HEADER_CF_ACCESS_JWT, jwt.as_str())]);
        let result = resolve(&h, Some(peer(OUTSIDER)), &access_mode(), Some(&verifier)).await;
        assert_eq!(
            result,
            Err(IdentityHeaderRefusal::AccessAssertion),
            "{case}"
        );
    }
}

/// A8-T7: the subject is the assertion's `sub`, never the user-id header.
#[tokio::test]
async fn cf_mode_ignores_user_id_header_for_subject() {
    let idp = AccessIdp::start().await;
    let verifier = idp.verifier();
    let jwt = idp.sign(&access_claims("u1", AUD, 10, 3600));
    let h = headers(&[
        (HEADER_CF_ACCESS_JWT, jwt.as_str()),
        (HEADER_CF_ACCESS_USER_ID, "u2"),
    ]);
    let subject = resolve(&h, Some(peer(OUTSIDER)), &access_mode(), Some(&verifier)).await;
    assert_eq!(subject.unwrap().map(|s| s.subject).as_deref(), Some("u1"));
}

/// A8-T14: an assertion issued two hours ago and still unexpired is
/// accepted; `iat` is the Access session start, not a replay signal.
#[tokio::test]
async fn aged_unexpired_access_assertion_is_accepted() {
    let idp = AccessIdp::start().await;
    let verifier = idp.verifier();
    let jwt = idp.sign(&access_claims("u1", AUD, 7200, 3600));
    let h = headers(&[(HEADER_CF_ACCESS_JWT, jwt.as_str())]);
    let subject = resolve(&h, Some(peer(OUTSIDER)), &access_mode(), Some(&verifier)).await;
    assert_eq!(subject.unwrap().map(|s| s.subject).as_deref(), Some("u1"));
}

/// A8-T15: an assertion expired beyond the 60 s leeway is 401.
#[tokio::test]
async fn expired_access_assertion_is_refused() {
    let idp = AccessIdp::start().await;
    let verifier = idp.verifier();
    let jwt = idp.sign(&access_claims("u1", AUD, 3600, -120));
    let h = headers(&[(HEADER_CF_ACCESS_JWT, jwt.as_str())]);
    let result = resolve(&h, Some(peer(OUTSIDER)), &access_mode(), Some(&verifier)).await;
    assert_eq!(result, Err(IdentityHeaderRefusal::AccessAssertion));
}

/// A8-T16 (positive control): the key server's delegated-bearer path still
/// caps `iat`. A fresh token resolves, the same token 600 s old does not.
#[tokio::test]
async fn key_server_still_enforces_iat_cap() {
    let idp = AccessIdp::start().await;
    let provider = crate::config::KeyServerProviderConfig {
        issuer: "https://idp.example".to_string(),
        jwks_uri: Some(idp.jwks_uri.clone()),
        discovery_url: None,
        auto_discover: false,
        audiences: vec!["client".to_string()],
        allowed_domains: Vec::new(),
    };
    let policy = KeyServerPolicyConfig {
        match_criteria: PolicyMatchConfig {
            domain: Some("corp.example".to_string()),
            issuer: None,
            email: None,
            group: None,
        },
        scopes: PolicyScopesConfig {
            backends: vec!["*".to_string()],
            tools: vec!["*".to_string()],
            rate_limit: 0,
        },
    };
    let config = KeyServerConfig {
        enabled: true,
        oidc: vec![provider.clone()],
        policies: vec![policy],
        max_oidc_token_age_secs: 300,
        ..KeyServerConfig::default()
    };
    let key_server = crate::key_server::KeyServer {
        store: Arc::new(crate::key_server::InMemoryTokenStore::new()),
        oidc: Arc::new(OidcVerifier::with_http_client(
            vec![provider],
            reqwest::Client::new(),
        )),
        policy: Arc::new(crate::key_server::policy::PolicyEngine::new(
            config.policies.clone(),
        )),
        config,
    };
    let token = |iat_ago| {
        idp.sign(&json!({
            "iss": "https://idp.example", "sub": "alice", "aud": "client",
            "email": "alice@corp.example", "iat": now() - iat_ago, "exp": now() + 3600,
        }))
    };
    assert!(
        key_server
            .verify_bearer_identity(&token(10))
            .await
            .is_some()
    );
    assert!(
        key_server
            .verify_bearer_identity(&token(600))
            .await
            .is_none()
    );
}
