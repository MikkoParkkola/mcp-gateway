// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use super::*;

#[test]
fn default_jwks_uri_appends_well_known() {
    // GIVEN/WHEN: an issuer URL
    let uri = default_jwks_uri("https://accounts.google.com");

    // THEN: the standard JWKS discovery path is appended
    assert_eq!(uri, "https://accounts.google.com/.well-known/jwks.json");
}

#[test]
fn default_jwks_uri_handles_trailing_slash() {
    // GIVEN: issuer with trailing slash
    let uri = default_jwks_uri("https://accounts.google.com/");

    // THEN: no double slash
    assert_eq!(uri, "https://accounts.google.com/.well-known/jwks.json");
}

#[test]
fn default_discovery_url_appends_openid_configuration() {
    assert_eq!(
        default_discovery_url("https://accounts.google.com/"),
        "https://accounts.google.com/.well-known/openid-configuration"
    );
}

#[test]
fn validate_discovery_accepts_matching_issuer_and_https() {
    let doc = OidcDiscoveryDocument {
        issuer: "https://accounts.google.com".to_string(),
        jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".to_string(),
    };
    let uri = validate_discovery_document("https://accounts.google.com", doc)
        .expect("matching issuer + https jwks_uri must be accepted");
    assert_eq!(uri, "https://www.googleapis.com/oauth2/v3/certs");
}

#[test]
fn validate_discovery_accepts_uppercase_https_jwks_uri() {
    // The scheme is case-insensitive (RFC 3986 section 3.1); a discovery
    // document naming `HTTPS://...` is exactly as secure as lowercase and
    // must not be rejected as `InsecureJwksUri`.
    let doc = OidcDiscoveryDocument {
        issuer: "https://accounts.google.com".to_string(),
        jwks_uri: "HTTPS://www.googleapis.com/oauth2/v3/certs".to_string(),
    };
    let uri = validate_discovery_document("https://accounts.google.com", doc)
        .expect("uppercase-scheme https jwks_uri must be accepted");
    assert_eq!(uri, "HTTPS://www.googleapis.com/oauth2/v3/certs");
}

#[test]
fn validate_discovery_rejects_issuer_mismatch() {
    // Mix-up defense: a document whose issuer differs from the requested one
    // must be rejected even if it is otherwise well-formed.
    let doc = OidcDiscoveryDocument {
        issuer: "https://attacker.invalid".to_string(),
        jwks_uri: "https://attacker.invalid/jwks".to_string(),
    };
    let err = validate_discovery_document("https://accounts.google.com", doc)
        .expect_err("issuer mismatch must be rejected");
    assert!(
        matches!(err, OidcError::IssuerMismatch { .. }),
        "got {err:?}"
    );
}

#[test]
fn validate_discovery_rejects_non_https_jwks_uri() {
    let doc = OidcDiscoveryDocument {
        issuer: "https://accounts.google.com".to_string(),
        jwks_uri: "http://accounts.google.com/jwks".to_string(),
    };
    let err = validate_discovery_document("https://accounts.google.com", doc)
        .expect_err("non-https jwks_uri must be rejected");
    assert!(matches!(err, OidcError::InsecureJwksUri(_)), "got {err:?}");
}

#[test]
fn check_audience_accepts_string_match() {
    // GIVEN: string aud claim matching expected
    let aud = serde_json::json!("my-client-id");
    let expected = vec!["my-client-id".to_string()];

    // THEN: no error
    assert!(check_audience(&aud, &expected).is_ok());
}

#[test]
fn check_audience_accepts_array_member_match() {
    // GIVEN: array aud claim where one element matches
    let aud = serde_json::json!(["other-client", "my-client-id"]);
    let expected = vec!["my-client-id".to_string()];

    // THEN: no error
    assert!(check_audience(&aud, &expected).is_ok());
}

#[test]
fn check_audience_rejects_no_match() {
    // GIVEN: aud claim with no matching value
    let aud = serde_json::json!("wrong-client");
    let expected = vec!["my-client-id".to_string()];

    // THEN: error
    assert!(check_audience(&aud, &expected).is_err());
}

#[test]
fn check_audience_rejects_empty_array() {
    // GIVEN: empty aud array
    let aud = serde_json::json!([]);
    let expected = vec!["my-client-id".to_string()];

    // THEN: error
    assert!(check_audience(&aud, &expected).is_err());
}

#[test]
fn find_key_rejects_unknown_jwk_types() {
    let jwks: JwkSet = serde_json::from_value(serde_json::json!({
        "keys": [{"kid": "future-key", "kty": "FUTURE", "x-vendor": "opaque"}]
    }))
    .expect("unknown JWK types should remain deserializable");

    assert!(find_key_in_jwks(&jwks, "future-key").is_none());
}

#[test]
fn extract_unverified_claims_rejects_malformed_token() {
    // GIVEN: a malformed token (not valid base64url parts)
    let result = extract_unverified_claims("not-a-jwt");

    // THEN: error
    assert!(result.is_err());
}

#[test]
fn verified_identity_serializes_to_json() {
    // GIVEN: a verified identity
    let identity = VerifiedIdentity {
        subject: "12345".to_string(),
        email: "alice@company.com".to_string(),
        name: Some("Alice".to_string()),
        groups: vec!["ml-engineers".to_string()],
        issuer: "https://accounts.google.com".to_string(),
    };

    // WHEN: serialized to JSON
    let json = serde_json::to_string(&identity).unwrap();

    // THEN: contains expected fields
    assert!(json.contains("alice@company.com"));
    assert!(json.contains("ml-engineers"));
}

// MIK-6702.CP.ID.1 — stable_actor_id is collision-safe when an issuer
// contains ':' (the naive "oidc:{issuer}:{subject}" form would collide).
#[test]
fn stable_actor_id_is_collision_safe() {
    let a = VerifiedIdentity {
        subject: "b:c".to_string(),
        email: "x@y".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp/a".to_string(),
    };
    let b = VerifiedIdentity {
        subject: "c".to_string(),
        email: "x@y".to_string(),
        name: None,
        groups: vec![],
        issuer: "https://idp/a:b".to_string(),
    };
    // Naive format collides: "oidc:https://idp/a:b:c" for both.
    assert_eq!(
        format!("oidc:{}:{}", a.issuer, a.subject),
        format!("oidc:{}:{}", b.issuer, b.subject),
        "precondition: the naive format collides for these inputs"
    );
    // Length-prefixed form keeps them distinct.
    assert_ne!(a.stable_actor_id(), b.stable_actor_id());
}

// MIK-7704: a discovery document is remote input. It may point a loopback
// issuer's keys at loopback, but an https issuer's document naming any
// cleartext jwks_uri, loopback included, is refused.
#[test]
fn validate_discovery_keeps_loopback_keys_to_a_loopback_issuer() {
    let doc = |issuer: &str| OidcDiscoveryDocument {
        issuer: issuer.to_string(),
        jwks_uri: "http://127.0.0.1:39400/jwks".to_string(),
    };
    let err = validate_discovery_document("https://idp.example", doc("https://idp.example"))
        .expect_err("an https issuer may not hand out a cleartext jwks_uri");
    assert!(err.to_string().contains("non-HTTPS"), "{err}");
    let uri = validate_discovery_document("http://127.0.0.1:8080", doc("http://127.0.0.1:8080"))
        .expect("a loopback issuer may name loopback keys");
    assert_eq!(uri, "http://127.0.0.1:39400/jwks");
}

/// A loopback server answering `/jwks` with an empty key set and `/hop`
/// with a redirect to `/jwks` over plain http. The counter is `/jwks` hits.
async fn loopback_jwks_server() -> (
    std::net::SocketAddr,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
) {
    use axum::{Router, response::Redirect, routing::get};
    use std::sync::{Arc, atomic::AtomicUsize, atomic::Ordering};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let app = Router::new()
        .route(
            "/jwks",
            get(move || async move {
                counter.fetch_add(1, Ordering::SeqCst);
                axum::Json(serde_json::json!({"keys": []}))
            }),
        )
        .route(
            "/hop",
            get(move || async move { Redirect::temporary(&format!("http://{addr}/jwks")) }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    (addr, hits)
}

// The production client honours the loopback carve-out the config allows,
// and never sends a loopback fetch through a proxy: an inherited proxy would
// carry the cleartext request off this machine. The proxy here is a dead
// port, so a loopback fetch routed through it fails.
#[tokio::test]
async fn production_client_fetches_loopback_jwks_without_a_proxy() {
    let (addr, hits) = loopback_jwks_server().await;
    let dead_proxy = reqwest::Proxy::all("http://127.0.0.1:9").expect("proxy url");
    for cache in [
        JwksCache::new(),
        JwksCache::with_remote_proxy(Some(dead_proxy)),
    ] {
        let jwks = cache
            .get_or_fetch("http://127.0.0.1", &format!("http://{addr}/jwks"), false)
            .await
            .expect("loopback http is allowed and fetched directly");
        assert!(jwks.keys.is_empty());
    }
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2);
}

// Every fetch is checked where it happens, so no caller can skip it. A
// loopback fetch follows no redirect; a remote one may not leave the fetched
// URL's origin (`remote_redirects_stay_on_the_fetched_origin`).
#[tokio::test]
async fn production_client_refuses_cleartext_fetches_and_hops() {
    let cache = JwksCache::new();
    let err = cache
        .get_or_fetch("https://idp.example", "http://idp.example/jwks", false)
        .await
        .expect_err("cleartext jwks off this machine");
    assert!(err.to_string().contains("non-HTTPS"), "{err}");
    let err = cache
        .resolve_jwks_uri(
            "https://idp.example",
            "http://idp.example/.well-known/openid-configuration",
        )
        .await
        .expect_err("cleartext discovery off this machine");
    assert!(err.to_string().contains("non-HTTPS"), "{err}");

    let (addr, hits) = loopback_jwks_server().await;
    let err = cache
        .get_or_fetch("http://127.0.0.1", &format!("http://{addr}/hop"), true)
        .await
        .expect_err("a redirect hop must be https");
    let chain = std::iter::successors(Some(&err as &dyn std::error::Error), |e| e.source())
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" / ");
    assert!(chain.contains("redirect from a loopback fetch"), "{chain}");
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the cleartext hop target was never requested"
    );
}

// The https client's hop rule: the fetched URL's origin, and nothing else.
#[test]
fn remote_redirects_stay_on_the_fetched_origin() {
    let from =
        url::Url::parse("https://idp.example/.well-known/openid-configuration").expect("url");
    let hop = |u: &str| remote_hop_allowed(&from, &url::Url::parse(u).expect("url"));
    assert!(hop("https://idp.example/jwks"));
    assert!(hop("HTTPS://IDP.example:443/jwks"));
    assert!(!hop("http://idp.example/jwks"));
    assert!(!hop("https://idp.example:8443/jwks"));
    assert!(!hop("https://other.example/jwks"));
    assert!(!hop("https://sub.idp.example/jwks"));
    assert!(!hop("https://idp.example./jwks"));
    assert!(!hop("https://[::1]/jwks"));
    assert!(!hop("https://ïdp.example/jwks"));
    // The issuer's name as userinfo: the host is attacker.example.
    assert!(!hop("https://idp.example@attacker.example/jwks"));
    assert!(!hop("http://127.0.0.1/jwks"));
}

/// An `https://localhost` server with a leaf signed by `issuer`, answering
/// `app`. Returns its base URL.
async fn https_server_with(
    issuer: &rcgen::Issuer<'static, rcgen::KeyPair>,
    app: axum::Router,
) -> String {
    use rcgen::{CertificateParams, KeyPair};
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf_params = CertificateParams::new(vec!["localhost".to_owned()]).expect("leaf");
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let leaf = leaf_params.signed_by(&leaf_key, issuer).expect("signed");
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        leaf.pem().into_bytes(),
        leaf_key.serialize_pem().into_bytes(),
    )
    .await
    .expect("tls");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("non-blocking");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, tls)
            .expect("listener")
            .serve(app.into_make_service())
            .await;
    });
    format!("https://localhost:{port}")
}

/// A test CA for the `https://localhost` servers: its PEM and its issuer.
fn oidc_pin_ca() -> (String, rcgen::Issuer<'static, rcgen::KeyPair>) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let ca_key = KeyPair::generate().expect("CA key");
    let mut ca_params = CertificateParams::new(Vec::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "oidc-pin CA");
    let ca = ca_params.clone().self_signed(&ca_key).expect("CA");
    (ca.pem(), Issuer::new(ca_params, ca_key))
}

/// A JWKS cache whose client carries the production redirect policy and
/// trusts only the test CA; a loopback http fetch follows no redirect at all,
/// so the remote rule is reachable only over HTTPS.
fn pinned_cache(ca_pem: &str) -> JwksCache {
    let client = reqwest::Client::builder()
        .redirect(remote_redirect_policy())
        .add_root_certificate(reqwest::Certificate::from_pem(ca_pem.as_bytes()).expect("ca"))
        .no_proxy()
        .build()
        .expect("client");
    JwksCache::with_http_client(client)
}

/// The fetch failed because the redirect policy refused a hop, not because a
/// server was unreachable or TLS failed.
fn refused_redirect<T>(result: &Result<T, OidcError>) -> bool {
    matches!(result, Err(OidcError::HttpError(e)) if e.is_redirect())
}

/// MIK-8281 OIDCPIN.1: a discovery URL that redirects to a different origin
/// is refused, and that origin is never asked for anything. Driven through
/// the production redirect policy, with the test CA trusted, because a
/// loopback http fetch follows no redirect at all.
#[tokio::test]
async fn a_discovery_redirected_off_origin_is_refused() {
    use std::sync::{Arc, atomic::AtomicUsize, atomic::Ordering};
    let (ca_pem, ca_issuer) = oidc_pin_ca();

    // The other origin: a discovery document that would pass validation for
    // the issuer, naming keys on itself. It counts every request.
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let issuer_slot: Arc<std::sync::OnceLock<String>> = Arc::default();
    let named = Arc::clone(&issuer_slot);
    let other = https_server_with(
        &ca_issuer,
        axum::Router::new().fallback(move |uri: axum::http::Uri| {
            let counter = Arc::clone(&counter);
            let named = Arc::clone(&named);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                let issuer = named.get().cloned().unwrap_or_default();
                axum::Json(serde_json::json!({
                    "issuer": issuer,
                    "jwks_uri": format!("https://localhost{}", uri.path()),
                }))
            }
        }),
    )
    .await;
    // The configured issuer: its discovery path redirects to the other origin.
    let target = format!("{other}/.well-known/openid-configuration");
    let issuer = https_server_with(
        &ca_issuer,
        axum::Router::new().route(
            "/.well-known/openid-configuration",
            axum::routing::get(move || {
                let target = target.clone();
                async move { axum::response::Redirect::temporary(&target) }
            }),
        ),
    )
    .await;
    issuer_slot.set(issuer.clone()).expect("set once");

    let result = pinned_cache(&ca_pem)
        .resolve_jwks_uri(
            &issuer,
            &format!("{issuer}/.well-known/openid-configuration"),
        )
        .await;
    assert!(
        refused_redirect(&result),
        "not refused by the redirect policy: {result:?}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the other origin was requested"
    );
}

/// MIK-8281 OIDCPIN.2's discovery half: a discovery redirect on the issuer's
/// own origin is still followed, and the document it reaches is used.
#[tokio::test]
async fn a_discovery_redirected_on_its_own_origin_is_followed() {
    use std::sync::Arc;
    let (ca_pem, ca_issuer) = oidc_pin_ca();
    let issuer_slot: Arc<std::sync::OnceLock<String>> = Arc::default();
    let named = Arc::clone(&issuer_slot);
    let issuer = https_server_with(
        &ca_issuer,
        axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(|| async { axum::response::Redirect::temporary("/moved") }),
            )
            .route(
                "/moved",
                axum::routing::get(move || {
                    let issuer = named.get().cloned().unwrap_or_default();
                    async move {
                        axum::Json(serde_json::json!({
                            "issuer": issuer,
                            "jwks_uri": format!("{issuer}/keys"),
                        }))
                    }
                }),
            ),
    )
    .await;
    issuer_slot.set(issuer.clone()).expect("set once");

    let jwks_uri = pinned_cache(&ca_pem)
        .resolve_jwks_uri(
            &issuer,
            &format!("{issuer}/.well-known/openid-configuration"),
        )
        .await
        .expect("a same-origin discovery redirect is followed");
    assert_eq!(jwks_uri, format!("{issuer}/keys"));
}

/// MIK-8281 OIDCPIN.2: a JWKS fetch follows a redirect on its own origin and
/// refuses one off it, never asking the other origin. An explicit `jwks_uri`
/// and a discovered one reach the network through the same `get_or_fetch`.
#[tokio::test]
async fn a_jwks_redirect_is_followed_only_on_its_own_origin() {
    use std::sync::{Arc, atomic::AtomicUsize, atomic::Ordering};
    let (ca_pem, ca_issuer) = oidc_pin_ca();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    let other = https_server_with(
        &ca_issuer,
        axum::Router::new().fallback(move || {
            let counter = Arc::clone(&counter);
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                axum::Json(serde_json::json!({"keys": []}))
            }
        }),
    )
    .await;
    let off = format!("{other}/jwks");
    let idp = https_server_with(
        &ca_issuer,
        axum::Router::new()
            .route(
                "/moved",
                axum::routing::get(|| async { axum::response::Redirect::temporary("/keys") }),
            )
            .route(
                "/keys",
                axum::routing::get(|| async { axum::Json(serde_json::json!({"keys": []})) }),
            )
            .route(
                "/away",
                axum::routing::get(move || {
                    let off = off.clone();
                    async move { axum::response::Redirect::temporary(&off) }
                }),
            ),
    )
    .await;
    let cache = pinned_cache(&ca_pem);

    let same = cache
        .get_or_fetch(&idp, &format!("{idp}/moved"), true)
        .await;
    assert!(same.is_ok(), "a same-origin redirect was refused: {same:?}");
    let away = cache.get_or_fetch(&idp, &format!("{idp}/away"), true).await;
    assert!(
        refused_redirect(&away),
        "not refused by the redirect policy: {away:?}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "the other origin was requested"
    );
}
