// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows for the token store.

#![allow(
    clippy::disallowed_methods,
    reason = "test code reads the host clock (the clock-before-1970 refusal row below)"
)]
use super::*;
use crate::key_server::oidc::VerifiedIdentity;

fn make_identity(subject: &str, email: &str) -> VerifiedIdentity {
    VerifiedIdentity::for_test(
        subject.to_string(),
        email.to_string(),
        None,
        Vec::new(),
        "https://accounts.google.com".to_string(),
    )
}

/// Put `token` straight into the active indices, past the reservation
/// protocol: these rows exercise reads, revocation and reaping over
/// tokens (expired ones too) the protocol would refuse to activate.
fn seed(store: &InMemoryTokenStore, token: TemporaryToken) {
    let _pending = store.pending();
    store.by_jti.insert(token.jti.clone(), token.token.clone());
    store.by_bearer.insert(token.token.clone(), token);
}

fn make_token(subject: &str, email: &str, exp_offset_secs: i64) -> TemporaryToken {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    #[allow(clippy::cast_sign_loss)]
    let exp = if exp_offset_secs >= 0 {
        now + exp_offset_secs as u64
    } else {
        now.saturating_sub((-exp_offset_secs) as u64)
    };

    TemporaryToken {
        jti: InMemoryTokenStore::generate_jti(),
        token: InMemoryTokenStore::generate_bearer(),
        identity: make_identity(subject, email),
        scopes: TokenScopes {
            backends: vec!["tavily".to_string()],
            tools: Vec::new(),
            rate_limit: 100,
        },
        iat: now,
        exp,
        client_ip: None,
    }
}

#[test]
fn debug_output_redacts_bearer_value() {
    // CWE-532: {:?} must never leak the live bearer.
    let token = make_token("user-1", "u1@test.local", 3600);
    let raw = token.token.clone();
    let dbg = format!("{token:?}");
    assert!(!dbg.contains(&raw), "Debug leaked the bearer value: {dbg}");
    assert!(
        dbg.contains("<redacted>"),
        "expected redaction marker: {dbg}"
    );
    assert!(dbg.contains(&token.jti), "jti stays visible for revocation");
}

#[tokio::test]
async fn insert_and_get_valid_token() {
    // GIVEN: a token store with one valid token
    let store = InMemoryTokenStore::new(5, 3600);
    let token = make_token("sub123", "alice@company.com", 3600);
    let bearer = token.token.clone();

    // WHEN: we insert then look it up by bearer
    seed(&store, token);
    let found = store.get(&bearer).await;

    // THEN: the token is returned
    assert!(found.is_some());
    assert_eq!(found.unwrap().identity.email(), "alice@company.com");
}

#[tokio::test]
async fn get_returns_none_for_unknown_token() {
    // GIVEN: an empty token store
    let store = InMemoryTokenStore::new(5, 3600);

    // WHEN: we look up a non-existent bearer
    let found = store.get("mcpgw_nonexistent").await;

    // THEN: None is returned
    assert!(found.is_none());
}

#[tokio::test]
async fn get_lazy_evicts_expired_token() {
    // GIVEN: a store with an already-expired token (exp = 1 second ago)
    let store = InMemoryTokenStore::new(5, 3600);
    let token = make_token("sub123", "alice@company.com", -1);
    let bearer = token.token.clone();

    seed(&store, token);

    // WHEN: we try to retrieve it
    let found = store.get(&bearer).await;

    // THEN: it is evicted and None is returned
    assert!(found.is_none());
    // Both indices cleaned up
    assert_eq!(store.by_bearer.len(), 0);
    assert_eq!(store.by_jti.len(), 0);
}

#[tokio::test]
async fn revoke_by_jti_removes_token() {
    // GIVEN: a store with one valid token
    let store = InMemoryTokenStore::new(5, 3600);
    let token = make_token("sub123", "alice@company.com", 3600);
    let jti = token.jti.clone();
    let bearer = token.token.clone();
    seed(&store, token);

    // WHEN: we revoke by JTI
    let removed = store.revoke_by_jti(&jti).await;

    // THEN: returns true and token is gone
    assert!(removed);
    assert!(store.get(&bearer).await.is_none());
    assert_eq!(store.by_jti.len(), 0);
}

#[tokio::test]
async fn revoke_by_jti_returns_false_for_unknown() {
    // GIVEN: empty store
    let store = InMemoryTokenStore::new(5, 3600);

    // WHEN: revoke non-existent JTI
    let removed = store.revoke_by_jti("nonexistent-jti").await;

    // THEN: returns false
    assert!(!removed);
}

#[tokio::test]
async fn revoke_by_subject_removes_all_tokens() {
    // GIVEN: two tokens for alice, one for bob
    let store = InMemoryTokenStore::new(5, 3600);
    let t1 = make_token("alice-sub", "alice@company.com", 3600);
    let t2 = make_token("alice-sub", "alice@company.com", 3600);
    let t3 = make_token("bob-sub", "bob@company.com", 3600);

    seed(&store, t1);
    seed(&store, t2);
    seed(&store, t3);

    // WHEN: revoke all for alice
    let count = store
        .revoke_by_subject("https://accounts.google.com", "alice-sub")
        .await;

    // THEN: 2 removed, bob's token untouched
    assert_eq!(count, 2);
    assert_eq!(store.by_bearer.len(), 1); // bob's token remains
}

#[tokio::test]
async fn count_for_subject_counts_active_tokens() {
    // GIVEN: two valid + one expired token for the same subject
    let store = InMemoryTokenStore::new(5, 3600);
    let t1 = make_token("alice-sub", "alice@company.com", 3600);
    let t2 = make_token("alice-sub", "alice@company.com", 3600);
    let t_expired = make_token("alice-sub", "alice@company.com", -1);

    seed(&store, t1);
    seed(&store, t2);
    seed(&store, t_expired);

    // WHEN: count active tokens for alice
    let count = store
        .count_for_subject("https://accounts.google.com", "alice-sub")
        .await;

    // THEN: only 2 active tokens (expired one not counted)
    assert_eq!(count, 2);
}

#[tokio::test]
async fn revoke_and_count_are_scoped_to_issuer() {
    // GIVEN: sub "123" at two issuers
    let store = InMemoryTokenStore::new(5, 3600);
    let at_a = make_token("123", "", 3600);
    let mut at_b = make_token("123", "", 3600);
    at_b.identity = at_b.identity.clone().with_issuer("https://idp-b.example");
    let bearer_b = at_b.token.clone();
    seed(&store, at_a);
    seed(&store, at_b);

    // THEN: each issuer counts and revokes only its own identity
    assert_eq!(
        store
            .count_for_subject("https://idp-b.example", "123")
            .await,
        1
    );
    assert_eq!(
        store
            .revoke_by_subject("https://accounts.google.com", "123")
            .await,
        1
    );
    assert!(store.get(&bearer_b).await.is_some());
}

#[tokio::test]
async fn reap_expired_removes_only_expired() {
    // GIVEN: one valid + two expired tokens
    let store = InMemoryTokenStore::new(5, 3600);
    let valid = make_token("sub1", "alice@company.com", 3600);
    let expired1 = make_token("sub2", "bob@company.com", -1);
    let expired2 = make_token("sub3", "carol@company.com", -10);

    seed(&store, valid);
    seed(&store, expired1);
    seed(&store, expired2);

    // WHEN: reap expired
    let reaped = store.reap_expired().await;

    // THEN: 2 removed, 1 remains
    assert_eq!(reaped, 2);
    assert_eq!(store.by_bearer.len(), 1);
}

#[tokio::test]
async fn generate_bearer_has_correct_prefix() {
    // GIVEN/WHEN: generate a bearer token
    let bearer = InMemoryTokenStore::generate_bearer();

    // THEN: it starts with the required prefix
    assert!(bearer.starts_with("mcpgw_"));
    // And has 256 bits of entropy (32 bytes = 43 base64url chars)
    assert!(bearer.len() > 40);
}

#[test]
fn is_expired_returns_true_for_past_exp() {
    // GIVEN: token with exp in the past
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = TemporaryToken {
        jti: "test".to_string(),
        token: "mcpgw_test".to_string(),
        identity: make_identity("sub", "test@example.com"),
        scopes: TokenScopes::default(),
        iat: now - 7200,
        exp: now - 1,
        client_ip: None,
    };

    // THEN: is_expired returns true
    assert!(token.is_expired(now));
}

#[test]
fn is_expired_returns_false_for_future_exp() {
    // GIVEN: token with exp in the future
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = TemporaryToken {
        jti: "test".to_string(),
        token: "mcpgw_test".to_string(),
        identity: make_identity("sub", "test@example.com"),
        scopes: TokenScopes::default(),
        iat: now,
        exp: now + 3600,
        client_ip: None,
    };

    // THEN: is_expired returns false
    assert!(!token.is_expired(now));
}

/// A clock that reads before 1970 refuses a bearer token the
/// real clock still admits; it never reads an expiry as still ahead.
#[tokio::test(flavor = "current_thread")]
async fn a_clock_before_the_epoch_refuses_a_live_bearer_token() {
    let store = InMemoryTokenStore::new(5, 3600);
    let token = make_token("sub", "alice@company.com", 3600);
    let bearer = token.token.clone();
    seed(&store, token);
    assert!(
        store.get(&bearer).await.is_some(),
        "control: live on the real clock"
    );

    {
        let _clock = crate::clock::test_clock::before_epoch();
        assert!(
            store.get(&bearer).await.is_none(),
            "an unreadable clock admitted a bearer token"
        );
        assert_eq!(
            store.reap_expired().await,
            0,
            "an unreadable clock reaped a token"
        );
    }
    assert!(
        store.get(&bearer).await.is_some(),
        "a refusal on an unreadable clock deleted the token for good"
    );
}
