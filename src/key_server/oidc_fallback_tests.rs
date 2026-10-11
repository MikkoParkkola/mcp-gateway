// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8044.SURF.2 (AUTO `auto_discover`): when discovery of a derived URL
//! fails in transport, keys come from `{issuer}/.well-known/jwks.json`; a
//! discovery document that answers but fails validation stays an error.
//!
//! One loopback server is the issuer. It serves two key sets under one `kid`:
//! K_disc at `/disc/jwks` (the URI a good discovery document names) and K_fb
//! at `/.well-known/jwks.json` (the fallback). Every row checks which key
//! validated and how often each path was fetched.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

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
}

struct State {
    discovery: Mutex<Discovery>,
    disc_jwks: Mutex<Value>,
    fb_jwks: Mutex<Value>,
    hits_discovery: AtomicUsize,
    hits_disc_jwks: AtomicUsize,
    hits_fb_jwks: AtomicUsize,
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
    });
    let (s1, s2, s3) = (Arc::clone(&state), Arc::clone(&state), Arc::clone(&state));
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || {
                let s = Arc::clone(&s1);
                async move {
                    s.hits_discovery.fetch_add(1, Ordering::SeqCst);
                    let Discovery::Status(code, body) = s.discovery.lock().clone();
                    answer(code, body)
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
    let now = chrono::Utc::now().timestamp();
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
