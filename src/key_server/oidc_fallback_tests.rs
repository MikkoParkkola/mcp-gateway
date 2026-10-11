// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8044.SURF.2 (AUTO `auto_discover`): when discovery of a derived URL
//! fails in transport, keys come from `{issuer}/.well-known/jwks.json`; a
//! discovery document that answers but fails validation stays an error.
//!
//! One loopback server is the issuer. It serves two key sets under one `kid`:
//! `K_disc` at `/disc/jwks` (the URI a good discovery document names) and
//! `K_fb` at `/.well-known/jwks.json` (the fallback). Every row checks which key
//! validated and how often each path was fetched.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use parking_lot::Mutex;
use serde_json::{Value, json};

use crate::config::{KeyServerConfig, KeyServerOidcConfig};
use crate::gateway::oauth::GatewayKeyPair;
use crate::key_server::OidcVerifier;
use crate::key_server::oidc::OidcError;

const AUD: &str = "surf2-aud";
const KID: &str = "k1";

/// What the discovery path answers.
#[derive(Clone)]
enum Discovery {
    Status(u16, String),
    /// Never answers: the request times out at the client.
    Stall,
}

struct State {
    discovery: Mutex<Discovery>,
    disc_jwks: Mutex<Value>,
    fb_jwks: Mutex<Value>,
    hits_discovery: AtomicUsize,
    hits_disc_jwks: AtomicUsize,
    hits_fb_jwks: AtomicUsize,
    /// When set, every discovery request waits here until the barrier's count
    /// of requests has arrived, so concurrent first lookups all see the cold
    /// cache before any of them records a fallback (D10b).
    gate: Mutex<Option<Arc<tokio::sync::Barrier>>>,
}

struct Fixture {
    issuer: String,
    state: Arc<State>,
    k_disc: GatewayKeyPair,
    k_fb: GatewayKeyPair,
}

/// A key set holding `pair`'s public key under `KID`.
fn jwks_of(pair: &GatewayKeyPair) -> Value {
    let mut set = serde_json::to_value(pair.jwks()).expect("jwks");
    for key in set["keys"].as_array_mut().expect("keys") {
        key["kid"] = json!(KID);
    }
    set
}

fn answer(status: u16, body: String) -> Response {
    let code = StatusCode::from_u16(status).expect("status");
    (code, [("content-type", "application/json")], body).into_response()
}

async fn start() -> Fixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let issuer = format!("http://{addr}");
    let k_disc = GatewayKeyPair::generate().expect("k_disc");
    let k_fb = GatewayKeyPair::generate().expect("k_fb");
    let good = json!({"issuer": issuer, "jwks_uri": format!("{issuer}/disc/jwks")}).to_string();
    let state = Arc::new(State {
        discovery: Mutex::new(Discovery::Status(200, good)),
        disc_jwks: Mutex::new(jwks_of(&k_disc)),
        fb_jwks: Mutex::new(jwks_of(&k_fb)),
        hits_discovery: AtomicUsize::new(0),
        hits_disc_jwks: AtomicUsize::new(0),
        hits_fb_jwks: AtomicUsize::new(0),
        gate: Mutex::new(None),
    });
    let (s1, s2, s3) = (Arc::clone(&state), Arc::clone(&state), Arc::clone(&state));
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || {
                let s = Arc::clone(&s1);
                async move {
                    s.hits_discovery.fetch_add(1, Ordering::SeqCst);
                    let gate = s.gate.lock().clone();
                    if let Some(gate) = gate {
                        gate.wait().await;
                    }
                    let discovery = s.discovery.lock().clone();
                    match discovery {
                        Discovery::Status(code, body) => answer(code, body),
                        Discovery::Stall => std::future::pending().await,
                    }
                }
            }),
        )
        .route(
            "/disc/jwks",
            get(move || {
                let s = Arc::clone(&s2);
                async move {
                    s.hits_disc_jwks.fetch_add(1, Ordering::SeqCst);
                    axum::Json(s.disc_jwks.lock().clone()).into_response()
                }
            }),
        )
        .route(
            "/.well-known/jwks.json",
            get(move || {
                let s = Arc::clone(&s3);
                async move {
                    s.hits_fb_jwks.fetch_add(1, Ordering::SeqCst);
                    axum::Json(s.fb_jwks.lock().clone()).into_response()
                }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    Fixture {
        issuer,
        state,
        k_disc,
        k_fb,
    }
}

fn verifier(fx: &Fixture, extra: &str) -> OidcVerifier {
    let yaml = format!(
        "enabled: true\nadmin_token: \"surf2-admin\"\noidc:\n  - issuer: \"{}\"\n    \
         audiences: [\"{AUD}\"]\n{extra}",
        fx.issuer
    );
    let cfg: KeyServerConfig = serde_yaml::from_str(&yaml).expect("key server yaml");
    cfg.validate().expect("valid key server config");
    OidcVerifier::with_http_client(cfg.oidc, reqwest::Client::new())
}

fn mint(fx: &Fixture, pair: &GatewayKeyPair) -> String {
    let info = pair.key_info();
    let now = crate::clock::utc_now()
        .expect("clock after the epoch")
        .timestamp();
    let claims = json!({"iss": fx.issuer, "sub": "u1", "aud": AUD, "iat": now, "exp": now + 300});
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(KID.to_owned());
    let enc = jsonwebtoken::EncodingKey::from_ec_pem(info.private_key_pem.as_bytes()).expect("pem");
    jsonwebtoken::encode(&header, &claims, &enc).expect("sign")
}

async fn verify(v: &OidcVerifier, token: &str) -> Result<(), OidcError> {
    let cfg = KeyServerOidcConfig {
        token_age: crate::key_server::TokenAgeCap::MaxIat(300),
    };
    v.verify(token, &cfg).await.map(|_| ())
}

fn hits(fx: &Fixture) -> (usize, usize, usize) {
    (
        fx.state.hits_discovery.load(Ordering::SeqCst),
        fx.state.hits_disc_jwks.load(Ordering::SeqCst),
        fx.state.hits_fb_jwks.load(Ordering::SeqCst),
    )
}

fn set_discovery(fx: &Fixture, status: u16, body: &str) {
    *fx.state.discovery.lock() = Discovery::Status(status, body.to_owned());
}

/// D1: derived discovery answers 404 -> the fallback's key validates.
#[tokio::test]
async fn a_missing_discovery_document_falls_back_to_the_issuer_jwks() {
    let fx = start().await;
    set_discovery(&fx, 404, "{}");
    let v = verifier(&fx, "");
    verify(&v, &mint(&fx, &fx.k_fb))
        .await
        .expect("the fallback key validates");
    let (_, disc_jwks, fb_jwks) = hits(&fx);
    assert_eq!((disc_jwks, fb_jwks), (0, 1));
}

/// D2: a 300 with a valid discovery body is not a discovery answer: the
/// fallback key validates, the discovered one does not.
#[tokio::test]
async fn a_non_success_status_falls_back_even_with_a_valid_body() {
    let fx = start().await;
    let body = json!({"issuer": fx.issuer, "jwks_uri": format!("{}/disc/jwks", fx.issuer)});
    set_discovery(&fx, 300, &body.to_string());
    let v = verifier(&fx, "");
    verify(&v, &mint(&fx, &fx.k_fb))
        .await
        .expect("the fallback key validates");
    assert!(verify(&v, &mint(&fx, &fx.k_disc)).await.is_err());
}

/// D3: a 200 whose body is not JSON falls back.
#[tokio::test]
async fn a_non_json_discovery_body_falls_back() {
    let fx = start().await;
    set_discovery(&fx, 200, "<html>not json</html>");
    let v = verifier(&fx, "");
    verify(&v, &mint(&fx, &fx.k_fb))
        .await
        .expect("the fallback key validates");
}

/// D4: JSON that is not a discovery document (no `jwks_uri`) falls back.
#[tokio::test]
async fn a_discovery_body_without_jwks_uri_falls_back() {
    let fx = start().await;
    set_discovery(&fx, 200, &json!({"issuer": fx.issuer}).to_string());
    let v = verifier(&fx, "");
    verify(&v, &mint(&fx, &fx.k_fb))
        .await
        .expect("the fallback key validates");
}

/// D5 (guard, poisoned): an issuer mismatch stays an error; the fallback
/// is never fetched even though it would validate.
#[tokio::test]
async fn an_issuer_mismatch_never_falls_back() {
    let fx = start().await;
    let body =
        json!({"issuer": "http://127.0.0.1:1", "jwks_uri": format!("{}/disc/jwks", fx.issuer)});
    set_discovery(&fx, 200, &body.to_string());
    let v = verifier(&fx, "");
    assert!(verify(&v, &mint(&fx, &fx.k_fb)).await.is_err());
    assert_eq!(hits(&fx).2, 0, "the fallback was fetched");
}

/// D6 (guard, poisoned): a cleartext non-loopback `jwks_uri` stays an error.
#[tokio::test]
async fn an_insecure_jwks_uri_never_falls_back() {
    let fx = start().await;
    let body = json!({"issuer": fx.issuer, "jwks_uri": "http://jwks.invalid/keys"});
    set_discovery(&fx, 200, &body.to_string());
    let v = verifier(&fx, "");
    let err = verify(&v, &mint(&fx, &fx.k_fb))
        .await
        .expect_err("insecure jwks_uri");
    assert!(err.to_string().contains("non-HTTPS"), "{err}");
    assert_eq!(hits(&fx).2, 0, "the fallback was fetched");
}

/// D7 (guard, poisoned): an explicit `discovery_url` that fails is the
/// operator's choice; no fallback.
#[tokio::test]
async fn an_explicit_discovery_url_never_falls_back() {
    let fx = start().await;
    set_discovery(&fx, 404, "{}");
    let extra = format!(
        "    discovery_url: \"{}/.well-known/openid-configuration\"\n",
        fx.issuer
    );
    let v = verifier(&fx, &extra);
    assert!(verify(&v, &mint(&fx, &fx.k_fb)).await.is_err());
    assert_eq!(hits(&fx).2, 0, "the fallback was fetched");
}

/// D8 (guard): with a good discovery document the discovered key validates
/// and the fallback is never fetched.
#[tokio::test]
async fn a_good_discovery_document_uses_its_jwks() {
    let fx = start().await;
    let v = verifier(&fx, "");
    verify(&v, &mint(&fx, &fx.k_disc))
        .await
        .expect("the discovered key validates");
    assert!(verify(&v, &mint(&fx, &fx.k_fb)).await.is_err());
    assert_eq!(hits(&fx).2, 0);
}

fn verifier_ttls(fx: &Fixture, ttl: Duration, fallback_ttl: Duration) -> OidcVerifier {
    let yaml = format!(
        "enabled: true\nadmin_token: \"surf2-admin\"\noidc:\n  - issuer: \"{}\"\n    \
         audiences: [\"{AUD}\"]\n",
        fx.issuer
    );
    let cfg: KeyServerConfig = serde_yaml::from_str(&yaml).expect("key server yaml");
    cfg.validate().expect("valid key server config");
    OidcVerifier::with_ttls(cfg.oidc, reqwest::Client::new(), ttl, fallback_ttl)
}

fn good_discovery(fx: &Fixture) -> String {
    json!({"issuer": fx.issuer, "jwks_uri": format!("{}/disc/jwks", fx.issuer)}).to_string()
}

/// D9: after the fallback's lifetime, a recovered discovery's keys serve and
/// the fallback's keys (same `kid`, still fresh in the JWKS cache) do not.
#[tokio::test]
async fn a_fallback_stops_serving_once_discovery_recovers() {
    let fx = start().await;
    set_discovery(&fx, 404, "{}");
    let v = verifier_ttls(&fx, Duration::from_secs(3600), Duration::from_millis(200));
    verify(&v, &mint(&fx, &fx.k_fb))
        .await
        .expect("the fallback key validates");
    set_discovery(&fx, 200, &good_discovery(&fx));
    // Poll until the fallback record lapses and discovery is tried again.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let disc_token = mint(&fx, &fx.k_disc);
    while verify(&v, &disc_token).await.is_err() {
        assert!(
            std::time::Instant::now() < deadline,
            "discovery never took over"
        );
        tokio::task::yield_now().await;
    }
    assert!(
        verify(&v, &mint(&fx, &fx.k_fb)).await.is_err(),
        "the fallback key still serves"
    );
}

/// D10: inside one fallback lifetime, a second verification neither asks
/// discovery again nor logs again.
#[test]
fn one_fallback_is_fetched_and_logged_once() {
    use crate::test_log_capture::{count, records};
    let mut discovery_hits = 0;
    let logs = records(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let fx = start().await;
            set_discovery(&fx, 404, "{}");
            let v = verifier(&fx, "");
            for _ in 0..2 {
                verify(&v, &mint(&fx, &fx.k_fb))
                    .await
                    .expect("the fallback key validates");
            }
            discovery_hits = hits(&fx).0;
        });
    });
    assert_eq!(discovery_hits, 1);
    assert_eq!(count(&logs, "WARN", "OIDC discovery for"), 1, "{logs:?}");
}

/// D10b: concurrent first lookups all validate and log the fallback once.
#[test]
fn concurrent_first_lookups_log_the_fallback_once() {
    use crate::test_log_capture::{count, records};
    let logs = records(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let fx = start().await;
            set_discovery(&fx, 404, "{}");
            let v = verifier(&fx, "");
            // All 8 discovery requests are held until the 8th arrives, so each
            // lookup has passed the cold-cache check before any records.
            *fx.state.gate.lock() = Some(Arc::new(tokio::sync::Barrier::new(8)));
            let token = mint(&fx, &fx.k_fb);
            let all = futures::future::join_all((0..8).map(|_| verify(&v, &token))).await;
            assert!(all.iter().all(Result::is_ok), "{all:?}");
            assert_eq!(hits(&fx).0, 8, "every lookup reached discovery cold");
        });
    });
    assert_eq!(count(&logs, "WARN", "OIDC discovery for"), 1, "{logs:?}");
}

/// D10c: a fallback stands for min(cache lifetime, 300 s).
#[tokio::test]
async fn a_fallback_stands_at_most_five_minutes() {
    for (ttl, expected) in [(60, 60), (3600, 300)] {
        let fx = start().await;
        set_discovery(&fx, 404, "{}");
        let v = verifier_ttls(&fx, Duration::from_secs(ttl), Duration::from_secs(300));
        verify(&v, &mint(&fx, &fx.k_fb))
            .await
            .expect("the fallback key validates");
        assert_eq!(
            v.discovery_ttl(&fx.issuer),
            Some(Duration::from_secs(expected))
        );
    }
}

/// D8b (guard): `auto_discover: false` goes straight to the issuer's JWKS,
/// never asking discovery.
#[tokio::test]
async fn auto_discover_off_goes_straight_to_the_issuer_jwks() {
    let fx = start().await;
    let v = verifier(&fx, "    auto_discover: false\n");
    verify(&v, &mint(&fx, &fx.k_fb))
        .await
        .expect("the issuer jwks key validates");
    assert_eq!(hits(&fx).0, 0, "discovery was asked");
}

/// D8c (guard): an explicit `jwks_uri` overrides discovery and fallback.
#[tokio::test]
async fn an_explicit_jwks_uri_overrides_both() {
    let fx = start().await;
    set_discovery(&fx, 404, "{}");
    let extra = format!("    jwks_uri: \"{}/disc/jwks\"\n", fx.issuer);
    let v = verifier(&fx, &extra);
    verify(&v, &mint(&fx, &fx.k_disc))
        .await
        .expect("the named key validates");
    assert_eq!((hits(&fx).0, hits(&fx).2), (0, 0));
}

/// D11: a derived discovery that times out falls back. The handler never
/// answers; the client's own timeout ends the request, so a slow host only
/// delays the row and cannot change its outcome.
#[tokio::test]
async fn a_discovery_timeout_falls_back() {
    let fx = start().await;
    *fx.state.discovery.lock() = Discovery::Stall;
    let yaml = format!(
        "enabled: true\nadmin_token: \"surf2-admin\"\noidc:\n  - issuer: \"{}\"\n    \
         audiences: [\"{AUD}\"]\n",
        fx.issuer
    );
    let cfg: KeyServerConfig = serde_yaml::from_str(&yaml).expect("key server yaml");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(300))
        .build()
        .expect("client");
    let v = OidcVerifier::with_http_client(cfg.oidc, client);
    verify(&v, &mint(&fx, &fx.k_fb))
        .await
        .expect("the fallback key validates");
    assert_eq!(hits(&fx).2, 1, "the fallback was not fetched");
}
