// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};

const SECRET: &[u8] = b"fixture-adapter-signing-secret-123456789";

fn runtime(installation: &str) -> AdapterRuntime {
    AdapterRuntime {
        installation_id: installation.to_string(),
        header: "x-openwebui-assertion".to_string(),
        issuer: "open-webui".to_string(),
        allowed_api_key_names: vec!["owui".to_string()],
        max_lifetime_seconds: 300,
        clock_skew_seconds: 30,
        secret: SECRET.to_vec(),
    }
}

fn claims(subject: &str) -> Value {
    let now = now_seconds().expect("the test host clock reads after 1970");
    json!({"iss":"open-webui", "sub":subject, "iat":now, "exp":now+120,
        "email":"untrusted@example.invalid", "roles":["admin"], "groups":["admin"]})
}

fn token(claims: &Value, algorithm: Algorithm, secret: &[u8]) -> String {
    encode(
        &Header::new(algorithm),
        claims,
        &EncodingKey::from_secret(secret),
    )
    .unwrap()
}

/// MIK-8286 R6 (pin): an assertion whose subject is empty names no one
/// and is refused (the adapter answers 403 through `refuse`), now through
/// `VerifiedIdentity::checked` rather than a check of its own. Mutant:
/// the emptiness test in `names_someone` removed.
#[test]
fn an_assertion_naming_no_one_is_refused() {
    let key = DecodingKey::from_secret(SECRET);
    let nameless = token(&claims(""), Algorithm::HS256, SECRET);
    assert!(matches!(
        verify(&runtime("desk"), &key, &nameless),
        Err(Refusal::Invalid("empty subject"))
    ));
}

#[test]
fn identities_are_namespaced_and_profile_claims_are_discarded() {
    let key = DecodingKey::from_secret(SECRET);
    let alice = token(&claims("alice"), Algorithm::HS256, SECRET);
    let bob = token(&claims("bob"), Algorithm::HS256, SECRET);
    let a = verify(&runtime("desk"), &key, &alice).unwrap_or_else(|_| panic!("valid Alice"));
    let b = verify(&runtime("desk"), &key, &bob).unwrap_or_else(|_| panic!("valid Bob"));
    let other =
        verify(&runtime("laptop"), &key, &alice).unwrap_or_else(|_| panic!("valid installation"));
    assert_ne!(a.stable_actor_id(), b.stable_actor_id());
    assert_ne!(a.stable_actor_id(), other.stable_actor_id());
    assert_eq!(a.subject, "alice");
    assert!(a.email.is_empty());
    assert!(a.name.is_none());
    assert!(a.groups.is_empty());
    assert_ne!(a.issuer, "open-webui");
}

fn trusted(installation: &str, secret: &[u8]) -> Trusted {
    let mut runtime = runtime(installation);
    runtime.secret = secret.to_vec();
    Trusted {
        decoding_key: DecodingKey::from_secret(secret),
        runtime,
    }
}

/// Installations sharing a header are resolved by SIGNATURE, and exactly
/// one of them must succeed.
#[test]
fn shared_header_resolves_to_exactly_one_installation() {
    const OTHER: &[u8] = b"fixture-second-installation-secret-987654321";
    let candidates = vec![trusted("desk", SECRET), trusted("laptop", OTHER)];
    let desk = token(&claims("alice"), Algorithm::HS256, SECRET);
    let laptop = token(&claims("alice"), Algorithm::HS256, OTHER);

    let (first, _) =
        resolve_identity(&candidates, "owui", &desk).unwrap_or_else(|_| panic!("desk assertion"));
    let (second, _) = resolve_identity(&candidates, "owui", &laptop)
        .unwrap_or_else(|_| panic!("laptop assertion"));
    // Order-independent: the second installation is reachable even though
    // it is not the first candidate tried.
    assert_ne!(first.stable_actor_id(), second.stable_actor_id());
    assert_eq!(first.subject, second.subject);

    // Signed by neither, and presented by an API key neither installation
    // lists: both are refusals, not a fallback to some other installation.
    assert!(
        resolve_identity(
            &candidates,
            "owui",
            &token(&claims("alice"), Algorithm::HS256, b"unconfigured-secret")
        )
        .is_err()
    );
    assert!(resolve_identity(&candidates, "unlisted", &desk).is_err());

    // Two installations that both verify the same assertion give two
    // answers to "who is this", so the assertion is refused outright.
    let ambiguous = vec![trusted("desk", SECRET), trusted("laptop", SECRET)];
    assert!(resolve_identity(&ambiguous, "owui", &desk).is_err());
}

#[test]
fn invalid_signatures_algorithms_and_claims_are_refused() {
    let runtime = runtime("desk");
    let key = DecodingKey::from_secret(SECRET);
    assert!(
        verify(
            &runtime,
            &key,
            &token(&claims("alice"), Algorithm::HS256, b"wrong-key")
        )
        .is_err()
    );
    assert!(
        verify(
            &runtime,
            &key,
            &token(&claims("alice"), Algorithm::HS384, SECRET)
        )
        .is_err()
    );
    for field in ["sub", "iat", "exp", "iss"] {
        let mut value = claims("alice");
        value.as_object_mut().unwrap().remove(field);
        assert!(
            verify(&runtime, &key, &token(&value, Algorithm::HS256, SECRET)).is_err(),
            "missing {field}"
        );
    }
    let now = now_seconds().expect("the test host clock reads after 1970");
    for (field, value) in [
        ("sub", json!("")),
        ("iss", json!("attacker")),
        ("exp", json!(now - 60)),
        ("exp", json!(now + 3600)),
        ("iat", json!(now + 60)),
        ("iat", json!(i64::MIN)),
    ] {
        let mut invalid = claims("alice");
        invalid[field] = value;
        assert!(
            verify(&runtime, &key, &token(&invalid, Algorithm::HS256, SECRET)).is_err(),
            "invalid {field}"
        );
    }
}

/// Capture a receipt through the real signed [`verify_assertion`] path,
/// for [`AdapterAssertion::verified_for_test`]. Only the receipt of an
/// accepted assertion is returned; the raw token never leaves this helper.
pub(super) fn verified_receipt(
    issued_at: i64,
    expires_at: i64,
    skew: u64,
) -> Option<AdapterAssertion> {
    let mut adapter = runtime("desk");
    adapter.clock_skew_seconds = skew;
    let signed = token(
        &json!({"iss":"open-webui", "sub":"alice", "iat":issued_at, "exp":expires_at}),
        Algorithm::HS256,
        SECRET,
    );
    let key = DecodingKey::from_secret(SECRET);
    verify_assertion(&adapter, &key, &signed)
        .ok()
        .map(|(_, receipt)| receipt)
}

/// D11 (MIK-8350): a held assertion must recheck future issuance, so a
/// clock rolled back past `iat - skew` kills it exactly where fresh
/// verification of the same token starts refusing it.
#[test]
fn held_adapter_assertion_rechecks_future_issuance_after_clock_rollback() {
    let mut adapter = runtime("desk");
    adapter.clock_skew_seconds = 30;
    let key = DecodingKey::from_secret(SECRET);
    let signed = token(
        &json!({"iss":"open-webui", "sub":"alice", "iat":1_000_000, "exp":1_000_120}),
        Algorithm::HS256,
        SECRET,
    );
    let forged = token(
        &json!({"iss":"open-webui", "sub":"alice", "iat":1_000_000, "exp":1_000_120}),
        Algorithm::HS256,
        b"wrong-key",
    );

    let guard = crate::clock::test_clock::at_secs(1_000_000);
    assert!(verify_assertion(&adapter, &key, &forged).is_err());
    let (identity, held) = verify_assertion(&adapter, &key, &signed)
        .unwrap_or_else(|_| panic!("valid Alice at issuance"));
    assert_eq!(identity.subject, "alice");
    assert_ne!(identity.issuer, "open-webui");
    assert_eq!(held.expires_at, 1_000_120);
    assert_eq!(held.skew, 30);
    assert!(held.live());
    drop(guard);

    let guard = crate::clock::test_clock::at_secs(999_970);
    assert!(held.live(), "inclusive iat-minus-skew boundary stays live");
    assert!(
        verify_assertion(&adapter, &key, &signed).is_ok(),
        "fresh verification succeeds at the inclusive boundary"
    );
    drop(guard);

    let guard = crate::clock::test_clock::at_secs(999_969);
    assert!(
        matches!(
            verify_assertion(&adapter, &key, &signed),
            Err(Refusal::Invalid("issued in the future"))
        ),
        "fresh verification refuses the rolled-back token"
    );
    std::assert!(
        !held.live(),
        "own D11: held assertion must recheck future issuance after clock rollback"
    );
    drop(guard);
}

/// The inclusive side of the future-issuance boundary: at `iat - skew`
/// the held assertion is live and fresh verification still succeeds,
/// while one second earlier fresh verification refuses the token.
#[test]
fn adapter_future_issuance_boundary_matches_fresh_verification() {
    let mut adapter = runtime("desk");
    adapter.clock_skew_seconds = 30;
    let key = DecodingKey::from_secret(SECRET);
    let signed = token(
        &json!({"iss":"open-webui", "sub":"alice", "iat":1_000_000, "exp":1_000_120}),
        Algorithm::HS256,
        SECRET,
    );

    let guard = crate::clock::test_clock::at_secs(1_000_000);
    let held = AdapterAssertion::verified_for_test(1_000_000, 1_000_120, 30)
        .unwrap_or_else(|| panic!("genuine capture at issuance"));
    assert!(held.live());
    assert!(verify_assertion(&adapter, &key, &signed).is_ok());
    drop(guard);

    let guard = crate::clock::test_clock::at_secs(999_970);
    assert!(held.live());
    assert!(verify_assertion(&adapter, &key, &signed).is_ok());
    drop(guard);

    let guard = crate::clock::test_clock::at_secs(999_969);
    assert!(matches!(
        verify_assertion(&adapter, &key, &signed),
        Err(Refusal::Invalid("issued in the future"))
    ));
    drop(guard);
}

/// Expiry is inclusive at `exp + skew` and dead one second later, for
/// the held assertion and for fresh verification alike.
#[test]
fn adapter_expiry_boundary_matches_fresh_verification() {
    let mut adapter = runtime("desk");
    adapter.clock_skew_seconds = 30;
    let key = DecodingKey::from_secret(SECRET);
    let signed = token(
        &json!({"iss":"open-webui", "sub":"alice", "iat":1_000_000, "exp":1_000_120}),
        Algorithm::HS256,
        SECRET,
    );

    let guard = crate::clock::test_clock::at_secs(1_000_000);
    let (_, held) = verify_assertion(&adapter, &key, &signed)
        .unwrap_or_else(|_| panic!("valid Alice at issuance"));
    assert!(held.live());
    drop(guard);

    let guard = crate::clock::test_clock::at_secs(1_000_150);
    assert!(held.live(), "exp plus skew is still live");
    assert!(verify_assertion(&adapter, &key, &signed).is_ok());
    drop(guard);

    let guard = crate::clock::test_clock::at_secs(1_000_151);
    assert!(!held.live(), "one second past exp plus skew is dead");
    assert!(matches!(
        verify_assertion(&adapter, &key, &signed),
        Err(Refusal::Invalid("signature or claim validation failed"))
    ));
    drop(guard);
}

/// A coherent negative `iat` keeps its signed meaning: issued before
/// the epoch, expiring after it, it is admitted and held live.
#[test]
fn adapter_coherent_negative_issuance_remains_admitted() {
    let mut adapter = runtime("desk");
    adapter.clock_skew_seconds = 30;
    let key = DecodingKey::from_secret(SECRET);
    let signed = token(
        &json!({"iss":"open-webui", "sub":"alice", "iat":-5, "exp":100}),
        Algorithm::HS256,
        SECRET,
    );

    let guard = crate::clock::test_clock::at_secs(10);
    let (identity, held) = verify_assertion(&adapter, &key, &signed)
        .unwrap_or_else(|_| panic!("coherent negative issuance admitted"));
    assert_eq!(identity.subject, "alice");
    assert_eq!(held.expires_at, 100);
    assert_eq!(held.skew, 30);
    assert!(held.live());
    assert!(AdapterAssertion::verified_for_test(-5, 100, 30).is_some());
    drop(guard);
}

/// A clock that reads before the epoch answers not-live and refuses
/// fresh verification; it never falls back to reading the time as zero.
#[test]
fn adapter_unreadable_clock_is_not_live() {
    let mut adapter = runtime("desk");
    adapter.clock_skew_seconds = 30;
    let key = DecodingKey::from_secret(SECRET);
    let signed = token(
        &json!({"iss":"open-webui", "sub":"alice", "iat":1_000_000, "exp":1_000_120}),
        Algorithm::HS256,
        SECRET,
    );

    let guard = crate::clock::test_clock::at_secs(1_000_000);
    let held = AdapterAssertion::verified_for_test(1_000_000, 1_000_120, 30)
        .unwrap_or_else(|| panic!("genuine capture at issuance"));
    assert!(held.live());
    drop(guard);

    let guard = crate::clock::test_clock::before_epoch();
    assert!(!held.live());
    assert!(verify_assertion(&adapter, &key, &signed).is_err());
    drop(guard);
}

/// A configured skew outside the signed range is refused by fresh
/// verification. The token is otherwise coherent and unexpired at the
/// reading clock, and `exp + skew` does not overflow for `exp` zero, so
/// verification reaches the original conversion branch that refuses it.
#[test]
fn adapter_out_of_range_skew_is_refused() {
    let mut adapter = runtime("desk");
    adapter.clock_skew_seconds = u64::MAX;
    let key = DecodingKey::from_secret(SECRET);
    let signed = token(
        &json!({"iss":"open-webui", "sub":"alice", "iat":-10, "exp":0}),
        Algorithm::HS256,
        SECRET,
    );

    let guard = crate::clock::test_clock::at_secs(10);
    assert!(matches!(
        verify_assertion(&adapter, &key, &signed),
        Err(Refusal::Invalid("configured clock skew out of range"))
    ));
    assert!(AdapterAssertion::verified_for_test(-10, 0, u64::MAX).is_none());
    drop(guard);
}
