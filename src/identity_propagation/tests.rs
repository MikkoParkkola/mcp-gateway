// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Unit tests for `identity_propagation`, moved out of `mod.rs` unchanged.

use super::*;

/// Decode a JWT's payload claims WITHOUT signature verification (the backend
/// verifies the signature against the gateway JWKS; the test only asserts
/// the claims we minted). Avoids coupling the test to a `DecodingKey` whose
/// format must match ES256.
fn decode_claims(token: &str) -> serde_json::Value {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let payload = token.split('.').nth(1).expect("jwt has a payload segment");
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .expect("payload is base64url");
    serde_json::from_slice(&bytes).expect("payload is json")
}

// IDP.4 (MIK-6728 review) — Debug output MUST NOT leak the token. The
// header value carries a live bearer assertion; Debug shows names + a
// <redacted> marker only.
#[tokio::test]
async fn debug_redacts_the_token() {
    let s = strategy();
    let cred = s
        .propagate(&identity("dave", "https://idp"), &backend())
        .await
        .unwrap();
    let token = cred.headers[0]
        .1
        .strip_prefix("Bearer ")
        .unwrap()
        .to_string();
    assert!(!token.is_empty());
    let dbg = format!("{cred:?}");
    assert!(
        !dbg.contains(&token),
        "Debug must not contain the raw token"
    );
    assert!(dbg.contains("<redacted>"), "Debug must mark redaction");
    assert!(dbg.contains("Authorization"), "header names may show");
}

fn identity(subject: &str, issuer: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.to_string(),
        email: format!("{subject}@corp"),
        name: None,
        groups: vec!["eng".to_string()],
        issuer: issuer.to_string(),
    }
}

fn strategy() -> SignedAssertionStrategy {
    let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
    SignedAssertionStrategy::new(key, 300)
}

fn backend() -> BackendDescriptor {
    BackendDescriptor {
        id: "memory".to_string(),
        audience: "https://memory.internal".to_string(),
        ..Default::default()
    }
}

// IDP.1 — a call from user U yields a credential scoped to U: a Bearer
// assertion whose verified claims carry U's subject + the backend audience.
#[tokio::test]
async fn signed_assertion_carries_user_identity_and_audience() {
    let s = strategy();
    let id = identity("alice", "https://idp");
    let cred = s.propagate(&id, &backend()).await.expect("propagate ok");

    assert_eq!(cred.headers.len(), 1);
    let (h, v) = &cred.headers[0];
    assert_eq!(h, "Authorization");
    let token = v.strip_prefix("Bearer ").expect("bearer prefix");

    // Decode WITHOUT signature verification just to assert the claims we
    // minted. The backend is responsible for verifying the ES256 signature
    // against the gateway JWKS; here we only prove the payload carries the
    // caller's identity + the backend audience. We parse the payload
    // segment directly rather than via jsonwebtoken::decode, because a
    // DecodingKey must format-match the ES256 algorithm even when signature
    // validation is disabled (an HMAC key would fail with InvalidKeyFormat).
    let data_claims = decode_claims(token);
    assert_eq!(data_claims["sub"], "alice");
    assert_eq!(data_claims["aud"], "https://memory.internal");
    assert_eq!(data_claims["tenant"], "https://idp");
    assert_eq!(data_claims["iss"], "mcp-gateway");
    assert_eq!(cred.audience, "https://memory.internal");
    assert_eq!(cred.subject_key, id.stable_actor_id());
}

// IDP.6 — credential hygiene: exp/nbf/jti present, short TTL bounded.
#[tokio::test]
async fn signed_assertion_has_hygiene_fields() {
    let s = strategy();
    let cred = s
        .propagate(&identity("bob", "https://idp"), &backend())
        .await
        .unwrap();
    let token = cred.headers[0].1.strip_prefix("Bearer ").unwrap();
    // Parse the payload directly (see decode_claims rationale above).
    let claims = decode_claims(token);
    let exp = claims["exp"].as_i64().unwrap();
    let nbf = claims["nbf"].as_i64().unwrap();
    assert!(exp > nbf, "exp must be after nbf");
    assert!(exp - nbf <= 3600, "TTL bounded to <=1h");
    assert!(claims["jti"].as_str().is_some_and(|j| !j.is_empty()));
}

// IDP.6 — TTL is clamped to a short bound even if misconfigured huge/zero.
#[tokio::test]
async fn ttl_is_clamped() {
    let key = Arc::new(GatewayKeyPair::generate().unwrap());
    let huge = SignedAssertionStrategy::new(Arc::clone(&key), 999_999);
    let cred = huge
        .propagate(&identity("c", "https://idp"), &backend())
        .await
        .unwrap();
    assert!(cred.expires_at - SignedAssertionStrategy::now_secs().unwrap() <= 3600);
}

// IDP.3 — cache_binding distinguishes users AND audiences, collision-safe.
#[test]
fn cache_binding_isolates_users_and_audiences() {
    let a = cache_binding("oidc:11:https://idp:1:a", "https://mem");
    let b = cache_binding("oidc:11:https://idp:1:b", "https://mem");
    let c = cache_binding("oidc:11:https://idp:1:a", "https://mail");
    assert_ne!(a, b, "different users must not share a binding");
    assert_ne!(a, c, "different audiences must not share a binding");
}

// IDP.3 — the assertion refuses an empty audience.
#[tokio::test]
async fn empty_audience_is_refused() {
    let s = strategy();
    let bad = BackendDescriptor {
        id: "x".to_string(),
        audience: "  ".to_string(),
        ..Default::default()
    };
    assert!(matches!(
        s.propagate(&identity("a", "https://idp"), &bad).await,
        Err(PropagationError::Misconfigured(_))
    ));
}

// IDP.7 / IDP.2 — config validation fails closed.
#[test]
fn config_validation_is_fail_closed() {
    // Empty audience rejected.
    let cfg = IdentityPropagationConfig {
        strategy: PropagationStrategyKind::SignedAssertion,
        audience: String::new(),
        required: true,
        session_mode: SessionMode::Stateless,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    };
    assert!(cfg.validate().is_err());

    // Vault is implemented. Structural validation accepts its configuration;
    // missing account authority must still fail at the runtime custody boundary.
    let cfg = IdentityPropagationConfig {
        strategy: PropagationStrategyKind::Vault,
        audience: "https://mail".to_string(),
        required: true,
        session_mode: SessionMode::PerUser,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    };
    assert!(cfg.validate().is_ok());

    // A required backend on strategy token_exchange with no
    // token_exchange_endpoint is rejected — the endpoint check runs
    // unconditionally, not only for `required` backends (MIK-6729).
    let cfg = IdentityPropagationConfig {
        strategy: PropagationStrategyKind::TokenExchange,
        audience: "https://mail".to_string(),
        required: true,
        session_mode: SessionMode::PerUser,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    };
    assert!(cfg.validate().is_err());

    // A properly-configured token_exchange backend passes (MIK-6729).
    let cfg = IdentityPropagationConfig {
        strategy: PropagationStrategyKind::TokenExchange,
        audience: "https://mail".to_string(),
        required: true,
        session_mode: SessionMode::PerUser,
        token_exchange_endpoint: Some("https://idp.internal/token".to_string()),
        token_exchange_scope: Some("mail.read".to_string()),
    };
    assert!(cfg.validate().is_ok());

    // A valid signed-assertion config passes.
    let cfg = IdentityPropagationConfig {
        strategy: PropagationStrategyKind::SignedAssertion,
        audience: "https://mem".to_string(),
        required: true,
        session_mode: SessionMode::Stateless,
        token_exchange_endpoint: None,
        token_exchange_scope: None,
    };
    assert!(cfg.validate().is_ok());
}

// MIK-6710 — a `required` backend on a transport that cannot carry
// per-request headers (stdio, websocket) must be refused, not silently
// downgraded to an unauthenticated dispatch.
#[test]
fn required_backend_on_incapable_transport_is_refused() {
    let err = ensure_transport_carries_identity_headers(true, false)
        .expect_err("required + incapable transport must refuse");
    assert!(err.contains("cannot carry"), "error: {err}");
    assert!(err.contains("MIK-6710"), "error: {err}");
}

// A `required` backend on a header-capable (HTTP) transport is unaffected.
#[test]
fn required_backend_on_capable_transport_proceeds() {
    assert!(ensure_transport_carries_identity_headers(true, true).is_ok());
}

// A non-required backend proceeds regardless of transport capability —
// best-effort, matching the static-credential fallback used elsewhere in
// this module for a non-required backend with no identity/strategy.
#[test]
fn non_required_backend_ignores_transport_capability() {
    assert!(ensure_transport_carries_identity_headers(false, false).is_ok());
    assert!(ensure_transport_carries_identity_headers(false, true).is_ok());
}

// ------------------------------------------------------------------
// MIK-7334.CATALOGUE.1 revocation conjunct — the prefix cells.
//
// They live HERE rather than in `src/backend/slot_eviction_tests.rs`
// because `cache_binding` is a private `fn` in this module, and asserting
// against it from outside would need a visibility widening nobody asked
// for. `identity_binding_prefix` is the production helper under test; it is
// an unimplemented stub returning `None`, so every cell below is red.
// ------------------------------------------------------------------

use crate::identity_grants::GrantSubject;

/// The subject key a caller's slot is really keyed on, from the production
/// formula (`VerifiedIdentity::stable_actor_id`).
fn subject_key(issuer: &str, subject: &str) -> String {
    identity(subject, issuer).stable_actor_id()
}

/// The grant row an operator stores, built by driving the PRODUCTION
/// constructor. C10a/C10b exist because its normalisation and
/// `stable_actor_id` disagree.
///
/// IT CALLS PRODUCTION RATHER THAN MIRRORING IT. An earlier draft
/// reimplemented `grant_subject_from_verified_identity`'s trim-then-take-512
/// here, which made these cells structurally blind to the very fix they
/// exist to demand: a reimplementation reproduces whichever side its author
/// had in mind, so it can never observe the two sides diverging.
fn oidc_grant_subject(issuer: &str, subject: &str) -> GrantSubject {
    crate::gateway::grant_subject_from_verified_identity(&identity(subject, issuer))
        .expect("a verified identity always yields a grant subject")
}

// C7 — the matcher cell. Goes red when the prefix over-matches or
// under-matches: `contains` instead of `starts_with`, a dropped trailing
// separator, or a forgotten length prefix.
//
// THE FIRST DRAFT OF THIS CELL WAS VACUOUS AND REVIEW CAUGHT IT. On
// ordinary fixtures a full `idp:{n}:{S}:` prefix occurs only at offset 0,
// where `contains` and `starts_with` agree — so the cell could not go red
// against the matcher its own row claims to kill. The fixture therefore
// PLANTS the collision: identity Y is given an audience whose bytes carry
// identity X's COMPLETE prefix at a nonzero offset. Reachable by
// configuration, not contrived — the audience is an operator-set string.
#[test]
fn c7_the_prefix_matches_by_starts_with_and_never_by_containment() {
    let issuer = "https://idp";
    let x_key = subject_key(issuer, "xyz");
    let prefix = identity_binding_prefix(&oidc_grant_subject(issuer, "xyz"))
        .expect("C7 premise: an issuer-shaped subject yields a prefix");

    // Direction 1 — it matches X's own binding for EVERY audience, and
    // every token-exchange widening of those keys (which append further
    // length-prefixed segments to the right).
    for audience in ["https://mail", "https://ledger", ""] {
        let binding = cache_binding(&x_key, audience);
        assert!(
            binding.starts_with(&prefix),
            "C7: X's prefix must match X's binding for audience {audience:?}"
        );
        let widened = format!("{binding}:4:sts1:4:read");
        assert!(
            widened.starts_with(&prefix),
            "C7: X's prefix must match the token-exchange widening too"
        );
    }

    // Direction 2 — THE PLANTED COLLISION. Y's audience contains X's
    // complete prefix at a nonzero offset. `contains` evicts Y here;
    // `starts_with` does not.
    let y_key = subject_key(issuer, "someone-else");
    let poisoned_audience = format!("https://h/{prefix}junk");
    let y_binding = cache_binding(&y_key, &poisoned_audience);
    assert!(
        y_binding.contains(&prefix),
        "C7 premise: the fixture must actually plant the collision, \
         otherwise this cell cannot discriminate `contains` from \
         `starts_with` and passes vacuously"
    );
    assert!(
        !y_binding.starts_with(&prefix),
        "C7: X's revocation must not reach Y through a mid-string match"
    );
}

// C8 — a guard, not coverage. Goes red when a non-issuer authority
// silently evicts something: reconstructing a prefix for an `mtls` /
// `agent_oauth` / `trusted_header` grant and matching by accident.
//
// GREEN AGAINST THE STUB, which returns `None` for everything. Recorded as
// such: it asserts exactly the stub's behaviour and only starts
// discriminating once C7/C10 force the `Some` arm to exist.
#[test]
fn c8_a_non_issuer_authority_yields_no_prefix_at_all() {
    for authority in ["mtls", "agent_oauth", "trusted_header"] {
        let subject = GrantSubject::new(authority.to_string(), "alice".to_string(), None);
        assert!(
            identity_binding_prefix(&subject).is_none(),
            "C8: authority {authority:?} must SKIP, never fall through to a match"
        );
    }
}

// C10a — §E1.1, and red TODAY against live behaviour rather than absence.
//
// Goes red when a subject with surrounding whitespace is never evicted.
// `grant_subject_from_verified_identity` routes the subject through
// `trimmed_non_empty` while `stable_actor_id` length-prefixes the RAW
// bytes, so the grant stores one string and the binding carries another:
// the reconstructed prefix matches nothing, eviction returns 0, and the
// reload reports success. The criterion goes unmet for those callers,
// silently.
#[test]
fn c10a_a_subject_with_surrounding_whitespace_is_still_evictable() {
    let issuer = "https://idp";
    let raw = " alice ";
    // The binding the request path really builds, from the RAW claim.
    let binding = cache_binding(&subject_key(issuer, raw), "https://mail");
    // The prefix the control path reconstructs, from the STORED grant row.
    let prefix = identity_binding_prefix(&oidc_grant_subject(issuer, raw))
        .expect("C10a premise: an issuer-shaped subject yields a prefix");

    assert!(
        binding.starts_with(&prefix),
        "C10a: a whitespace-bearing subject's slot must be reachable by \
         its own grant's prefix; trimming at grant construction strands it"
    );
}

// C10b — the other half of §E1.1, and a DISTINCT cell: a length cutoff and
// a trim fail on different inputs.
//
// Goes red when a subject longer than 512 characters is never evicted.
// `.chars().take(512)` truncates by CHARACTERS while `stable_actor_id`
// length-prefixes by `.len()`, which is BYTES — so a multi-byte subject
// diverges on the length prefix as well as on the content, and the
// mismatch is not confined to the obvious over-limit case.
#[test]
fn c10b_a_subject_over_the_length_bound_is_still_evictable() {
    let issuer = "https://idp";
    for raw in [
        "a".repeat(600),
        // Multi-byte: 600 chars, 1800 bytes. The char-vs-byte disagreement
        // is why this input is here and not folded into the ASCII case.
        "ä".repeat(600),
    ] {
        let binding = cache_binding(&subject_key(issuer, &raw), "https://mail");
        let prefix = identity_binding_prefix(&oidc_grant_subject(issuer, &raw))
            .expect("C10b premise: an issuer-shaped subject yields a prefix");
        assert!(
            binding.starts_with(&prefix),
            "C10b: a {}-byte subject's slot must be reachable by its own \
             grant's prefix; the 512-char cutoff strands it",
            raw.len()
        );
    }
}
