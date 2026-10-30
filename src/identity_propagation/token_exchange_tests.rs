// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use super::*;

fn identity(subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.to_string(),
        email: format!("{subject}@corp"),
        name: None,
        groups: vec!["eng".to_string()],
        issuer: "https://idp".to_string(),
    }
}

fn backend(endpoint: Option<&str>) -> BackendDescriptor {
    BackendDescriptor {
        id: "mail".to_string(),
        audience: "https://mail.internal".to_string(),
        token_exchange_endpoint: endpoint.map(str::to_string),
        token_exchange_scope: Some("mail.read".to_string()),
    }
}

fn strategy() -> TokenExchangeStrategy {
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    TokenExchangeStrategy::new(key, 300)
}

// L2 (MIK-6729 review): a hostile/compromised STS returning `expires_in`
// at `i64::MAX` must not panic (debug builds overflow-check `now + ttl`)
// or silently wrap to an instantly-expired credential (release builds).
// MIK-8207: nor is it trusted for centuries; an `expires_in` above the
// 100-year bound is a malformed answer and the exchange is refused. A
// real HTTP round trip against a minimal in-process server standing in
// for the hostile STS.
#[tokio::test]
async fn hostile_expires_in_i64_max_is_refused() {
    use axum::{Json, Router, routing::post};
    use tokio::net::TcpListener;

    async fn hostile_token_handler() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "access_token": "hostile-token",
            "expires_in": i64::MAX,
        }))
    }

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let app = Router::new().route("/token", post(hostile_token_handler));
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("in-process hostile-STS test server");
    });

    let s = TokenExchangeStrategy::with_http_client(
        Arc::new(GatewayKeyPair::generate().expect("keygen")),
        300,
        reqwest::Client::new(),
    );
    let endpoint = format!("http://{addr}/token");

    let refused = s
        .propagate(&identity("alice"), &backend(Some(&endpoint)))
        .await
        .map(|cred| cred.expires_at)
        .expect_err("an expires_in above 100 years is refused, never trusted");
    assert!(refused.to_string().contains("expires_in"), "{refused}");

    server.abort();
}

// IDP.2 — no endpoint configured must refuse, never fall through to a
// static credential.
#[tokio::test]
async fn missing_endpoint_is_refused() {
    let s = strategy();
    let err = s
        .propagate(&identity("alice"), &backend(None))
        .await
        .expect_err("missing endpoint must refuse");
    assert!(matches!(err, PropagationError::Misconfigured(_)));
}

// IDP.3 — empty audience is refused before any network call is attempted.
#[tokio::test]
async fn empty_audience_is_refused() {
    let s = strategy();
    let mut bad = backend(Some("https://sts.internal/token"));
    bad.audience = "  ".to_string();
    let err = s
        .propagate(&identity("alice"), &bad)
        .await
        .expect_err("empty audience must refuse");
    assert!(matches!(err, PropagationError::Misconfigured(_)));
}

// A request to an unreachable endpoint must refuse (fail-closed), not
// panic or silently downgrade.
#[tokio::test]
async fn unreachable_endpoint_is_refused() {
    let s = strategy();
    // Port 0 host is never reachable / instantly refused by the OS.
    let bad = backend(Some("https://127.0.0.1:0/token"));
    let err = s
        .propagate(&identity("alice"), &bad)
        .await
        .expect_err("unreachable endpoint must refuse");
    assert!(matches!(err, PropagationError::Refuse(_)));
}

#[test]
fn client_assertion_carries_gateway_identity_and_endpoint_audience() {
    let s = strategy();
    let jwt = s
        .mint_client_assertion("https://sts.internal/token")
        .expect("client assertion must mint");
    let payload = jwt.split('.').nth(1).expect("jwt has a payload");
    let bytes = URL_SAFE_NO_PAD.decode(payload).expect("base64url");
    let claims: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(claims["iss"], CLIENT_ID);
    assert_eq!(claims["sub"], CLIENT_ID);
    assert_eq!(claims["aud"], "https://sts.internal/token");
    assert!(claims["jti"].as_str().is_some_and(|j| !j.is_empty()));
}

// S3 (MIK-6729 review): an expired cache entry must not survive a reap,
// and reaping preserves still-valid entries. `store` runs this reap when the
// cache reaches MAX_CACHE_ENTRIES, bounding growth from one-shot subjects.
#[test]
fn reap_drops_expired_entries_only() {
    let s = strategy();
    let now = SignedAssertionStrategy::now_secs().unwrap();
    s.cache.insert(
        "live".to_string(),
        CachedExchange {
            synthetic_expiry: false,
            access_token: "a".to_string(),
            expires_at: now + 100,
            scopes: vec![],
        },
    );
    s.cache.insert(
        "dead".to_string(),
        CachedExchange {
            synthetic_expiry: false,
            access_token: "b".to_string(),
            expires_at: now - 1,
            scopes: vec![],
        },
    );

    s.reap_expired();

    assert!(
        s.cache.contains_key("live"),
        "valid entry must survive reap"
    );
    assert!(
        !s.cache.contains_key("dead"),
        "expired entry must not survive reap"
    );
}

// M1 (MIK-6729 review): the exchanged-token cache key must fold in
// `token_exchange_endpoint` and `scope`, not just `(subject, audience)` —
// two backends sharing an audience but differing in endpoint or scope
// must never collide on the same cached token (credential confusion:
// one backend could be served a token minted for another's endpoint/
// scope, over- or under-privileging it).
#[test]
fn exchange_cache_key_isolates_endpoint_and_scope() {
    let base = exchange_cache_key(
        "alice",
        "https://mail.internal",
        "https://sts-a/token",
        "read",
    );
    let diff_endpoint = exchange_cache_key(
        "alice",
        "https://mail.internal",
        "https://sts-b/token",
        "read",
    );
    let diff_scope = exchange_cache_key(
        "alice",
        "https://mail.internal",
        "https://sts-a/token",
        "write",
    );
    let same_again = exchange_cache_key(
        "alice",
        "https://mail.internal",
        "https://sts-a/token",
        "read",
    );

    assert_ne!(
        base, diff_endpoint,
        "same subject+audience but different endpoint must not collide"
    );
    assert_ne!(
        base, diff_scope,
        "same subject+audience but different scope must not collide"
    );
    assert_eq!(
        base, same_again,
        "identical (subject, audience, endpoint, scope) must key identically"
    );
}

// M1 (MIK-6729 review) at the `cached()` lookup seam: a token cached under
// one (endpoint, scope) tuple must not be returned as a hit for a
// different (endpoint, scope) tuple sharing the same subject+audience.
#[test]
fn cached_lookup_misses_across_distinct_endpoint_or_scope() {
    let s = strategy();
    let now = SignedAssertionStrategy::now_secs().unwrap();
    let key_a = exchange_cache_key(
        "alice",
        "https://mail.internal",
        "https://sts-a/token",
        "read",
    );
    s.cache.insert(
        key_a.clone(),
        CachedExchange {
            synthetic_expiry: false,
            access_token: "a-token".to_string(),
            expires_at: now + 300,
            scopes: vec!["read".to_string()],
        },
    );

    assert!(s.cached(&key_a).is_some(), "exact key must hit");

    let key_b = exchange_cache_key(
        "alice",
        "https://mail.internal",
        "https://sts-b/token",
        "read",
    );
    assert!(
        s.cached(&key_b).is_none(),
        "a different endpoint must never reuse another endpoint's cached token"
    );

    let key_c = exchange_cache_key(
        "alice",
        "https://mail.internal",
        "https://sts-a/token",
        "write",
    );
    assert!(
        s.cached(&key_c).is_none(),
        "a different scope must never reuse another scope's cached token"
    );
}

// ------------------------------------------------------------------
// C4 — MIK-7334.CATALOGUE.1 revocation conjunct, token-exchange half.
//
// WHY IT LIVES HERE AND NOT IN `src/backend/slot_eviction_tests.rs`.
// `exchange_cache_key` is a private `fn` in this module, so the widened
// key is unreachable from `src/backend/`. The design asks the cell to seed
// its slot by driving `TokenExchangeStrategy::propagate` against a stubbed
// exchange endpoint and taking `credential.cache_binding` — but this repo
// has no security-token-service mock: `propagate` posts to a live
// `token_exchange_endpoint` over HTTP and nothing in the crate stands one
// up. Calling the production `exchange_cache_key` directly discharges the
// design's ACTUAL objection to the first draft — a handwritten widened
// string cannot detect a production key-format change that leaves the
// fixture untouched — at a fraction of the cost. Recorded as a deliberate
// downgrade, not a silent one.
// ------------------------------------------------------------------

use crate::identity_grants::GrantSubject;

// C4a — goes red when token-exchange slots are missed. Kills exact
// subject+audience matching, which no-ops on exactly the backends where a
// revocation matters most: on this path the POOL KEY ITSELF is the widened
// string, not PATH A's binding.
#[test]
fn c4a_the_subject_prefix_matches_the_widened_exchange_key() {
    let subject_key = "oidc:11:https://idp:5:alice";
    let prefix = crate::identity_propagation::identity_binding_prefix(&GrantSubject::new(
        "https://idp".to_string(),
        "alice".to_string(),
        None,
    ))
    .expect("C4a premise: an issuer-shaped subject yields a prefix");

    // The PRODUCTION widening, so a key-format change goes red here.
    let widened = exchange_cache_key(
        subject_key,
        "https://mail.internal",
        "https://sts-a/token",
        "read",
    );
    assert!(
        widened.starts_with(&prefix),
        "C4a: the prefix must match the WIDENED exchange key; exact \
             subject+audience matching silently no-ops on this path"
    );
}

#[tokio::test]
async fn exchange_does_not_follow_a_307_redirect() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let second_hits = Arc::new(AtomicUsize::new(0));
    let second_counter = Arc::clone(&second_hits);
    let app2 = axum::Router::new().route(
        "/token",
        axum::routing::post(move |_body: axum::body::Bytes| {
            let second_counter = Arc::clone(&second_counter);
            async move {
                second_counter.fetch_add(1, Ordering::SeqCst);
                axum::Json(serde_json::json!({
                    "access_token": "should-not-be-followed",
                    "expires_in": 300,
                }))
            }
        }),
    );
    let listener2 = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        tokio::net::TcpListener::bind("127.0.0.1:0"),
    )
    .await
    .expect("bounded")
    .expect("bind second");
    let port2 = listener2.local_addr().expect("addr second").port();
    tokio::spawn(async move { axum::serve(listener2, app2).await });

    let bodies: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let bodies_route = Arc::clone(&bodies);
    let target2 = format!("http://127.0.0.1:{port2}/token");
    let app1 = axum::Router::new().route(
        "/token",
        axum::routing::post(move |body: axum::body::Bytes| {
            let bodies = Arc::clone(&bodies_route);
            let target = target2.clone();
            async move {
                bodies
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(String::from_utf8_lossy(&body).to_string());
                (
                    axum::http::StatusCode::TEMPORARY_REDIRECT,
                    [(axum::http::header::LOCATION, target)],
                )
            }
        }),
    );
    let listener1 = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        tokio::net::TcpListener::bind("127.0.0.1:0"),
    )
    .await
    .expect("bounded")
    .expect("bind first");
    let port1 = listener1.local_addr().expect("addr first").port();
    tokio::spawn(async move { axum::serve(listener1, app1).await });

    let endpoint1 = format!("http://127.0.0.1:{port1}/token");
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(super::token_exchange_redirect_policy())
        .build()
        .expect("client");
    let strategy = TokenExchangeStrategy::with_http_client(key, 300, http);
    let outcome = tokio::time::timeout(
        crate::test_wait::HANG_BOUND,
        strategy.exchange(
            &endpoint1,
            "synthetic-subject-token-not-real",
            &backend(Some(&endpoint1)),
        ),
    )
    .await
    .expect("bounded");
    let err = outcome.expect_err("a 307 must not be followed");
    let text = err.to_string();
    assert!(text.contains("307"), "must name the status, got: {text}");
    assert!(
        text.contains("redirect"),
        "must name the redirect, got: {text}"
    );
    let seen = bodies
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(seen.len(), 1, "listener 1 sees the POST once");
    assert!(
        seen[0].contains("subject_token"),
        "the POST carries the exchange body, got: {}",
        seen[0]
    );
    drop(seen);
    assert_eq!(
        second_hits.load(Ordering::SeqCst),
        0,
        "listener 2 must see no request"
    );
}

#[test]
fn default_http_client_takes_the_token_exchange_redirect_policy() {
    let src = include_str!("token_exchange.rs");
    let lines: Vec<&str> = src.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.contains("fn default_http_client"));
    assert!(start.is_some(), "fn default_http_client must exist");
    let start: usize = start.unwrap_or_default();
    let rest = &lines[start..];
    let end = rest.iter().position(|line| *line == "}");
    assert!(end.is_some(), "fn default_http_client must end with `}}`");
    let end: usize = end.unwrap_or_default();
    let body = rest[..=end].join("\n");
    assert!(
        body.contains(".redirect(token_exchange_redirect_policy())"),
        "the default client must take the token-exchange redirect policy, got:\n{body}"
    );
}
