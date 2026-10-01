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
/// with a redirect to `/jwks` over plain http.
async fn loopback_jwks_server() -> std::net::SocketAddr {
    use axum::{Router, response::Redirect, routing::get};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = Router::new()
        .route(
            "/jwks",
            get(|| async { axum::Json(serde_json::json!({"keys": []})) }),
        )
        .route(
            "/hop",
            get(move || async move { Redirect::temporary(&format!("http://{addr}/jwks")) }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    addr
}

// The production client honours the loopback carve-out the config allows.
#[tokio::test]
async fn production_client_fetches_loopback_jwks() {
    let addr = loopback_jwks_server().await;
    let jwks = JwksCache::new()
        .get_or_fetch("http://127.0.0.1", &format!("http://{addr}/jwks"), false)
        .await
        .expect("loopback http is allowed");
    assert!(jwks.keys.is_empty());
}

// Every fetch is checked where it happens, so no caller can skip it, and a
// redirect may only move to https.
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

    let addr = loopback_jwks_server().await;
    let err = cache
        .get_or_fetch("http://127.0.0.1", &format!("http://{addr}/hop"), true)
        .await
        .expect_err("a redirect hop must be https");
    assert!(!err.to_string().is_empty());
}
