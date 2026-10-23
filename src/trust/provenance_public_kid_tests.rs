// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8398 kid tests: D4 and kid-charset rows.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::tests::{
    ATTESTATION_ID, KID_ONE, SEED_ONE, SEED_TWO, assert_value_free, jwk_for, overlay_with,
    seed_b64, x_of,
};
use super::*;

#[test]
fn a_seed_without_a_kid_is_refused() {
    assert!(
        std::env::var(PROVENANCE_SEED_ENV).is_err(),
        "an inherited seed would be silently used"
    );
    assert!(
        std::env::var(PROVENANCE_KEY_ID_ENV).is_err(),
        "an inherited kid would be silently used"
    );
    let encoded = seed_b64(&SEED_ONE);
    let (_dir, env) = overlay_with(&[(PROVENANCE_SEED_ENV, encoded.as_str())]);
    let error = resolve_public_signer(&env, ATTESTATION_ID).expect_err("a missing kid is refused");
    assert_value_free(&error, &SEED_ONE);
    let (_dir, env) = overlay_with(&[
        (PROVENANCE_SEED_ENV, encoded.as_str()),
        (PROVENANCE_KEY_ID_ENV, "\"  \""),
    ]);
    assert_eq!(
        env.resolve(PROVENANCE_KEY_ID_ENV).as_deref(),
        Some("  "),
        "the env file must transport the kid under test"
    );
    let error = resolve_public_signer(&env, ATTESTATION_ID).expect_err("a blank kid is refused");
    assert_value_free(&error, &SEED_ONE);
}

#[test]
fn an_overlong_kid_is_refused() {
    let encoded = seed_b64(&SEED_ONE);
    let long = "k".repeat(65);
    let (_dir, env) = overlay_with(&[
        (PROVENANCE_SEED_ENV, encoded.as_str()),
        (PROVENANCE_KEY_ID_ENV, long.as_str()),
    ]);
    let error = resolve_public_signer(&env, ATTESTATION_ID).expect_err("a 65-byte kid is refused");
    assert_value_free(&error, &SEED_ONE);
}

/// MIK-8398 D4: a kid is 1-64 bytes of `0x21..=0x7E`. Anything else is
/// refused by the resolver (value-free) and by the trust set as `MalformedKid`.
#[test]
fn d4_malformed_kid_with_space_is_refused() {
    let encoded = seed_b64(&SEED_ONE);
    let written = "\"prov test\"";
    let resolved = "prov test";
    let (_dir, env) = overlay_with(&[
        (PROVENANCE_SEED_ENV, encoded.as_str()),
        (PROVENANCE_KEY_ID_ENV, written),
    ]);
    assert_eq!(
        env.resolve(PROVENANCE_KEY_ID_ENV).as_deref(),
        Some(resolved),
        "the env file must transport the kid under test"
    );
    let result = resolve_public_signer(&env, ATTESTATION_ID);
    assert!(result.is_err(), "a malformed kid {resolved:?} is refused");
    let err = result.expect_err("just asserted");
    assert_value_free(&err, &SEED_ONE);

    let x = URL_SAFE_NO_PAD.encode([7u8; 32]);
    let kid_json = serde_json::to_string(resolved).expect("a kid serializes");
    let text = format!("{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":{kid_json},\"x\":\"{x}\"}}");
    let trust = TrustSet::from_json(&text);
    let Err(refusal) = trust else {
        panic!("the trust set must refuse {resolved:?} as MalformedKid");
    };
    assert_eq!(
        refusal,
        TrustSetRefusal::MalformedKid,
        "the trust set must refuse {resolved:?} as MalformedKid"
    );
}

/// MIK-8398 D4: a kid is 1-64 bytes of `0x21..=0x7E`. Anything else is
/// refused by the resolver (value-free) and by the trust set as `MalformedKid`.
#[test]
fn d4_malformed_kid_with_newline_is_refused() {
    let encoded = seed_b64(&SEED_ONE);
    let written = "\"prov\\ntest\"";
    let resolved = "prov\ntest";
    let (_dir, env) = overlay_with(&[
        (PROVENANCE_SEED_ENV, encoded.as_str()),
        (PROVENANCE_KEY_ID_ENV, written),
    ]);
    assert_eq!(
        env.resolve(PROVENANCE_KEY_ID_ENV).as_deref(),
        Some(resolved),
        "the env file must transport the kid under test"
    );
    let result = resolve_public_signer(&env, ATTESTATION_ID);
    assert!(result.is_err(), "a malformed kid {resolved:?} is refused");
    let err = result.expect_err("just asserted");
    assert_value_free(&err, &SEED_ONE);
    let display = err.to_string();
    let debug = format!("{err:?}");
    assert!(
        !display.contains(resolved),
        "the error leaks the raw kid: {display}"
    );
    assert!(
        !debug.contains(resolved),
        "the error leaks the raw kid: {debug}"
    );

    let x = URL_SAFE_NO_PAD.encode([7u8; 32]);
    let kid_json = serde_json::to_string(resolved).expect("a kid serializes");
    let text = format!("{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":{kid_json},\"x\":\"{x}\"}}");
    let trust = TrustSet::from_json(&text);
    let Err(refusal) = trust else {
        panic!("the trust set must refuse {resolved:?} as MalformedKid");
    };
    assert_eq!(
        refusal,
        TrustSetRefusal::MalformedKid,
        "the trust set must refuse {resolved:?} as MalformedKid"
    );
    let debug = format!("{refusal:?}");
    assert!(
        !debug.contains(resolved),
        "the trust error leaks the raw kid: {debug}"
    );
}

/// MIK-8398 D4: a kid is 1-64 bytes of `0x21..=0x7E`. Anything else is
/// refused by the resolver (value-free) and by the trust set as `MalformedKid`.
#[test]
fn d4_malformed_kid_with_non_ascii_is_refused() {
    let encoded = seed_b64(&SEED_ONE);
    let written = "\"prov-✓\"";
    let resolved = "prov-✓";
    let (_dir, env) = overlay_with(&[
        (PROVENANCE_SEED_ENV, encoded.as_str()),
        (PROVENANCE_KEY_ID_ENV, written),
    ]);
    assert_eq!(
        env.resolve(PROVENANCE_KEY_ID_ENV).as_deref(),
        Some(resolved),
        "the env file must transport the kid under test"
    );
    let result = resolve_public_signer(&env, ATTESTATION_ID);
    assert!(result.is_err(), "a malformed kid {resolved:?} is refused");
    let err = result.expect_err("just asserted");
    assert_value_free(&err, &SEED_ONE);

    let x = URL_SAFE_NO_PAD.encode([7u8; 32]);
    let kid_json = serde_json::to_string(resolved).expect("a kid serializes");
    let text = format!("{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":{kid_json},\"x\":\"{x}\"}}");
    let trust = TrustSet::from_json(&text);
    let Err(refusal) = trust else {
        panic!("the trust set must refuse {resolved:?} as MalformedKid");
    };
    assert_eq!(
        refusal,
        TrustSetRefusal::MalformedKid,
        "the trust set must refuse {resolved:?} as MalformedKid"
    );
}

/// MIK-8398 D4: a kid is 1-64 bytes of `0x21..=0x7E`. Anything else is
/// refused by the resolver (value-free) and by the trust set as `MalformedKid`.
#[test]
fn d4_malformed_kid_with_65_bytes_is_refused() {
    let encoded = seed_b64(&SEED_ONE);
    let long = "k".repeat(65);
    let long_quoted = format!("\"{long}\"");
    let written = long_quoted.as_str();
    let resolved = long.as_str();
    let (_dir, env) = overlay_with(&[
        (PROVENANCE_SEED_ENV, encoded.as_str()),
        (PROVENANCE_KEY_ID_ENV, written),
    ]);
    assert_eq!(
        env.resolve(PROVENANCE_KEY_ID_ENV).as_deref(),
        Some(resolved),
        "the env file must transport the kid under test"
    );
    let result = resolve_public_signer(&env, ATTESTATION_ID);
    assert!(result.is_err(), "a malformed kid {resolved:?} is refused");
    let err = result.expect_err("just asserted");
    assert_value_free(&err, &SEED_ONE);

    let x = URL_SAFE_NO_PAD.encode([7u8; 32]);
    let kid_json = serde_json::to_string(resolved).expect("a kid serializes");
    let text = format!("{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":{kid_json},\"x\":\"{x}\"}}");
    let trust = TrustSet::from_json(&text);
    let Err(refusal) = trust else {
        panic!("the trust set must refuse {resolved:?} as MalformedKid");
    };
    assert_eq!(
        refusal,
        TrustSetRefusal::MalformedKid,
        "the trust set must refuse {resolved:?} as MalformedKid"
    );
}

#[test]
fn d4_a_64_byte_tilde_kid_is_accepted() {
    let kid = "~".repeat(64);
    let encoded = seed_b64(&SEED_ONE);
    let (_dir, env) = overlay_with(&[
        (PROVENANCE_SEED_ENV, encoded.as_str()),
        (PROVENANCE_KEY_ID_ENV, kid.as_str()),
    ]);
    let signer = resolve_public_signer(&env, ATTESTATION_ID).expect("a 64-byte kid resolves");
    assert_eq!(
        signer.as_ref().map(super::ProvenancePublicSigner::kid),
        Some(kid.as_str()),
        "a 64-byte kid yields a signer"
    );

    let x = URL_SAFE_NO_PAD.encode([7u8; 32]);
    let text = format!("{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"{kid}\",\"x\":\"{x}\"}}");
    assert!(TrustSet::from_json(&text).is_ok(), "a 64-byte kid loads");
}

#[test]
fn a_kid_colliding_with_attestation_is_refused() {
    let encoded = seed_b64(&SEED_ONE);
    for kid in ["gateway", "bnaut/gateway"] {
        let (_dir, env) = overlay_with(&[
            (PROVENANCE_SEED_ENV, encoded.as_str()),
            (PROVENANCE_KEY_ID_ENV, kid),
        ]);
        let error =
            resolve_public_signer(&env, "gateway").expect_err("an attestation kid is refused");
        assert_value_free(&error, &SEED_ONE);
    }
}

#[test]
fn a_duplicate_kid_is_refused() {
    let text = format!(
        "{{\"keys\":[{},{}]}}",
        jwk_for(&SEED_ONE, KID_ONE),
        jwk_for(&SEED_TWO, KID_ONE)
    );
    assert!(matches!(
        TrustSet::from_json(&text),
        Err(TrustSetRefusal::DuplicateKid)
    ));
}

#[test]
fn a_missing_kid_is_refused() {
    let text = format!(
        "{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{}\"}}",
        x_of(&SEED_ONE)
    );
    assert!(matches!(
        TrustSet::from_json(&text),
        Err(TrustSetRefusal::MissingKid)
    ));
}

/// With both a seed of the wrong length and a malformed key id, the key id
/// refusal is the one reported (57b74df7b moved the length check into the
/// key constructor, after the key id checks), still value-free.
#[test]
fn a_bad_kid_is_reported_before_a_bad_seed_length() {
    let seed = vec![7u8; 31];
    let encoded = seed_b64(&seed);
    let (_dir, env) = overlay_with(&[
        (PROVENANCE_SEED_ENV, encoded.as_str()),
        (PROVENANCE_KEY_ID_ENV, "\"has space\""),
    ]);
    assert_eq!(
        env.resolve(PROVENANCE_KEY_ID_ENV).as_deref(),
        Some("has space"),
        "the env file must transport the kid under test"
    );
    let error = resolve_public_signer(&env, ATTESTATION_ID).expect_err("both are refused");
    assert_eq!(
        error.to_string(),
        format!(
            "Configuration validation error: {PROVENANCE_KEY_ID_ENV} must be 1-64 bytes of 0x21..=0x7E"
        ),
        "the key id refusal wins"
    );
    assert_value_free(&error, &seed);
}
