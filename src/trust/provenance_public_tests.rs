// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8398 red-phase tests: the A0 fixture writer/checker plus rows B1-B8.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use sha2::Digest as _;

use super::*;
use crate::attestation::{
    AttestationValidator, BnautAttestationSigner, RESULT_PROVENANCE_DOMAIN_INFO,
};
use crate::config::EnvOverlay;
use crate::trust::{CacheOutcome, RuntimeProvenanceReceipt, SignedResultProvenance};

const SEED_ONE: [u8; 32] = [7u8; 32];
const SEED_TWO: [u8; 32] = [9u8; 32];
const KID_ONE: &str = "prov-test-1";
const KID_TWO: &str = "prov-test-2";
const DOMAIN_TAG: &[u8] = b"mcp-gateway-provenance-ed25519-v1\0";
const ATTESTATION_ID: &str = "bnaut/gateway";
const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/mik_8398");

fn sample() -> RuntimeProvenanceReceipt {
    RuntimeProvenanceReceipt::observed(
        "github",
        "search_issues",
        "2026-07-13T10:15:30Z",
        CacheOutcome::Miss,
        true,
    )
}

/// Every optional field populated, `row_count` at `u64::MAX`.
fn wide_sample() -> RuntimeProvenanceReceipt {
    sample()
        .with_auth_context_ref("sha256:wide-test-context")
        .with_row_count(u64::MAX)
        .with_call_id("gw-wide-test")
}

fn hmac() -> BnautAttestationSigner {
    BnautAttestationSigner::new(b"hmac-test-key".to_vec(), "gateway")
        .derive_domain(RESULT_PROVENANCE_DOMAIN_INFO)
}

fn result_json() -> serde_json::Value {
    serde_json::json!({"content": [{"type": "text", "text": "ok"}]})
}

fn receipt_json() -> serde_json::Value {
    serde_json::to_value(sample()).expect("receipt serializes")
}

fn signer_one() -> ProvenancePublicSigner {
    ProvenancePublicSigner::from_seed_for_test(SEED_ONE, KID_ONE)
}

fn signer_two() -> ProvenancePublicSigner {
    ProvenancePublicSigner::from_seed_for_test(SEED_TWO, KID_TWO)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("a String never fails a write");
    }
    out
}

fn seed_b64(seed: &[u8]) -> String {
    STANDARD.encode(seed)
}

fn write_private(path: &std::path::Path, contents: &[u8]) {
    std::fs::write(path, contents).expect("file writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("file is owner-only");
    }
}

fn overlay_with(vars: &[(&str, &str)]) -> (tempfile::TempDir, EnvOverlay) {
    let dir = tempfile::tempdir().expect("temporary dir");
    let mut text = String::new();
    for (key, value) in vars {
        text.push_str(key);
        text.push('=');
        text.push_str(value);
        text.push('\n');
    }
    let path = dir.path().join("prov.env");
    write_private(&path, text.as_bytes());
    (dir, EnvOverlay::from_paths(&[path]))
}

fn assert_value_free(error: &crate::Error, seed: &[u8]) {
    let display = error.to_string();
    let debug = format!("{error:?}");
    let encoded = seed_b64(seed);
    let rendered = hex(seed);
    let supplied = String::from_utf8_lossy(seed);
    for text in [&display, &debug] {
        assert!(!text.contains(encoded.as_str()), "error leaks the seed: {text}");
        assert!(!text.contains(rendered.as_str()), "error leaks the seed: {text}");
        assert!(
            !text.contains(supplied.as_ref()),
            "error leaks the supplied seed text: {text}"
        );
    }
}

fn trust_of(signer: &ProvenancePublicSigner) -> TrustSet {
    let jwk = signer.public_jwk();
    assert_eq!(
        jwk.get("kty").and_then(serde_json::Value::as_str),
        Some("OKP"),
        "the test signer's JWK must read as OKP: {jwk}"
    );
    let text = serde_json::to_string(&jwk).expect("JWK serializes");
    TrustSet::from_json(&text).expect("trust set builds")
}

fn signed_prov(result: Option<&serde_json::Value>) -> serde_json::Value {
    let signer = signer_one();
    let signed = sample().sign(&hmac());
    provenance_value(&signed, Some((&signer, result)))
}

fn payload_of(prov: &serde_json::Value) -> Vec<u8> {
    let payload = prov["public_signature"]["payload"]
        .as_str()
        .expect("a payload member");
    URL_SAFE_NO_PAD.decode(payload).expect("payload decodes")
}

fn payload_json_of(prov: &serde_json::Value) -> serde_json::Value {
    serde_json::from_slice(&payload_of(prov)).expect("payload parses")
}

/// Re-sign hand-built payload bytes with the first test key over the domain tag.
fn resign(payload: &[u8]) -> String {
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&SEED_ONE).expect("seed");
    let mut message = DOMAIN_TAG.to_vec();
    message.extend_from_slice(payload);
    URL_SAFE_NO_PAD.encode(key_pair.sign(&message).as_ref())
}

fn prov_with_payload(payload: &[u8]) -> serde_json::Value {
    let mut prov = serde_json::to_value(sample().sign(&hmac())).expect("signed serializes");
    prov["public_signature"] = serde_json::json!({
        "payload": URL_SAFE_NO_PAD.encode(payload),
        "sig": resign(payload),
    });
    prov
}

/// The `x` of `seed`: the real public key, without touching the skeleton's
/// `public_jwk` (Null until implemented).
fn x_of(seed: &[u8; 32]) -> String {
    let key_pair = Ed25519KeyPair::from_seed_unchecked(seed).expect("a seed loads");
    URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref())
}

/// A JWK text for `seed`/`kid`, built from literals plus the seed's real key.
fn jwk_for(seed: &[u8; 32], kid: &str) -> String {
    format!(
        "{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"{kid}\",\"x\":\"{}\"}}",
        x_of(seed)
    )
}

#[test]
fn a0_fixtures_match_the_committed_bytes() {
    let signer = signer_one();
    let signed = sample().sign(&hmac());
    let result = result_json();
    let unbound = serde_json::json!({"n": 9_007_199_254_740_992u64});
    let other = ProvenancePublicSigner::from_seed_for_test(SEED_TWO, KID_ONE);
    let fixtures = [
        ("jwk.json", signer.public_jwk()),
        ("result.json", result.clone()),
        ("provenance.json", provenance_value(&signed, Some((&signer, Some(&result))))),
        ("provenance_unbound.json", provenance_value(&signed, Some((&signer, Some(&unbound))))),
        ("jwk_other.json", other.public_jwk()),
        (
            "provenance_wide.json",
            provenance_value(&wide_sample().sign(&hmac()), Some((&signer, Some(&result)))),
        ),
    ];
    let update = std::env::var("UPDATE_GOLDEN").is_ok();
    for (name, value) in fixtures {
        let fresh = serde_json::to_vec_pretty(&value).expect("fixture serializes");
        let path = format!("{FIXTURE_DIR}/{name}");
        if update {
            std::fs::create_dir_all(FIXTURE_DIR).expect("fixture dir is creatable");
            std::fs::write(&path, &fresh).expect("fixture is writable");
        }
        let committed = std::fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "fixture {name} missing at {path}: {error}. Bless it with UPDATE_GOLDEN=1 on the implemented tree, then review the blessed bytes."
            )
        });
        assert_eq!(committed, fresh, "fixture {name} differs from the committed bytes");
    }
}

#[test]
fn an_absent_seed_resolves_to_no_signer() {
    assert!(std::env::var(PROVENANCE_SEED_ENV).is_err(), "an inherited seed would be silently used");
    assert!(std::env::var(PROVENANCE_KEY_ID_ENV).is_err(), "an inherited kid would be silently used");
    let resolved = resolve_public_signer(&EnvOverlay::none(), ATTESTATION_ID)
        .expect("absent is not an error");
    assert!(resolved.is_none());
}

#[test]
fn a_blank_seed_resolves_to_no_signer() {
    for blank in ["", "   "] {
        let (_dir, env) = overlay_with(&[
            (PROVENANCE_SEED_ENV, blank),
            (PROVENANCE_KEY_ID_ENV, KID_ONE),
        ]);
        let resolved = resolve_public_signer(&env, ATTESTATION_ID).expect("blank is not an error");
        assert!(resolved.is_none(), "blank seed {blank:?} must resolve to None");
    }
}

#[test]
fn a_short_or_long_seed_is_refused() {
    for seed in [vec![7u8; 31], vec![7u8; 33]] {
        let encoded = seed_b64(&seed);
        let (_dir, env) = overlay_with(&[
            (PROVENANCE_SEED_ENV, encoded.as_str()),
            (PROVENANCE_KEY_ID_ENV, KID_ONE),
        ]);
        let error = resolve_public_signer(&env, ATTESTATION_ID).expect_err("length is refused");
        assert_value_free(&error, &seed);
    }
}

#[test]
fn a_non_base64_seed_is_refused() {
    let encoded = "!!!not-base64!!!".to_owned();
    let (_dir, env) = overlay_with(&[
        (PROVENANCE_SEED_ENV, encoded.as_str()),
        (PROVENANCE_KEY_ID_ENV, KID_ONE),
    ]);
    let error = resolve_public_signer(&env, ATTESTATION_ID).expect_err("non-base64 is refused");
    assert_value_free(&error, encoded.as_bytes());
}

#[test]
fn a_seed_without_a_kid_is_refused() {
    assert!(std::env::var(PROVENANCE_SEED_ENV).is_err(), "an inherited seed would be silently used");
    assert!(std::env::var(PROVENANCE_KEY_ID_ENV).is_err(), "an inherited kid would be silently used");
    let encoded = seed_b64(&SEED_ONE);
    let (_dir, env) = overlay_with(&[(PROVENANCE_SEED_ENV, encoded.as_str())]);
    let error = resolve_public_signer(&env, ATTESTATION_ID).expect_err("a missing kid is refused");
    assert_value_free(&error, &SEED_ONE);
    let (_dir, env) = overlay_with(&[
        (PROVENANCE_SEED_ENV, encoded.as_str()),
        (PROVENANCE_KEY_ID_ENV, "  "),
    ]);
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
/// refused by the resolver (value-free) and by the trust set as MalformedKid.
#[test]
fn d4_malformed_kids_are_refused() {
    let encoded = seed_b64(&SEED_ONE);
    let long = "k".repeat(65);
    for (written, resolved) in [
        ("prov test", "prov test"),
        ("\"prov\\ntest\"", "prov\ntest"),
        ("prov-✓", "prov-✓"),
        (long.as_str(), long.as_str()),
    ] {
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
        assert_value_free(&result.expect_err("just asserted"), &SEED_ONE);

        let x = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let kid_json = serde_json::to_string(resolved).expect("a kid serializes");
        let text =
            format!("{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":{kid_json},\"x\":\"{x}\"}}");
        assert!(
            matches!(TrustSet::from_json(&text), Err(TrustSetRefusal::MalformedKid)),
            "the trust set must refuse {resolved:?} as MalformedKid"
        );
    }
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
fn a_valid_seed_and_kid_resolve() {
    let encoded = seed_b64(&SEED_ONE);
    let (_dir, env) = overlay_with(&[
        (PROVENANCE_SEED_ENV, encoded.as_str()),
        (PROVENANCE_KEY_ID_ENV, KID_ONE),
    ]);
    let signer = resolve_public_signer(&env, ATTESTATION_ID)
        .expect("valid config resolves")
        .expect("valid config yields a signer");
    assert_eq!(signer.kid(), KID_ONE);
}

#[test]
fn signer_debug_prints_only_the_kid() {
    let rendered = format!("{:?}", signer_one());
    let encoded = seed_b64(&SEED_ONE);
    let digest = hex(&SEED_ONE);
    assert!(rendered.contains(KID_ONE), "debug names the kid: {rendered}");
    assert!(!rendered.contains(encoded.as_str()), "debug leaks the seed: {rendered}");
    assert!(!rendered.contains(digest.as_str()), "debug leaks the seed: {rendered}");
}

#[test]
fn the_thumbprint_is_the_rfc7638_hash() {
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&SEED_ONE).expect("seed");
    let x = URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref());
    let message = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    let expected = URL_SAFE_NO_PAD.encode(sha2::Sha256::digest(message.as_bytes()));
    assert_eq!(signer_one().jwk_thumbprint(), expected);
}

#[test]
fn bound_with_the_same_result() {
    let result = result_json();
    let prov = signed_prov(Some(&result));
    let trust = trust_of(&signer_one());
    let verified = verify_public(&prov, &trust, Some(&result)).expect("bound verifies");
    assert_eq!(verified.status, VerifyStatus::Bound);
    assert_eq!(verified.kid, KID_ONE);
    assert_eq!(verified.receipt, sample());
}

#[test]
fn mismatch_with_another_result() {
    let result = result_json();
    let other = serde_json::json!({"content": [{"type": "text", "text": "other"}]});
    let prov = signed_prov(Some(&result));
    let trust = trust_of(&signer_one());
    assert_eq!(
        verify_public(&prov, &trust, Some(&other)),
        Err(VerifyRefusal::ResultMismatch)
    );
}

#[test]
fn bound_receipt_with_an_unhashable_offer_is_unhashable() {
    let result = result_json();
    let prov = signed_prov(Some(&result));
    let trust = trust_of(&signer_one());
    let array = serde_json::json!([1, 2]);
    assert_eq!(
        verify_public(&prov, &trust, Some(&array)),
        Err(VerifyRefusal::ResultUnhashable)
    );
}

#[test]
fn signature_only_without_a_result() {
    let result = result_json();
    let prov = signed_prov(Some(&result));
    let trust = trust_of(&signer_one());
    let verified = verify_public(&prov, &trust, None).expect("the signature alone verifies");
    assert_eq!(verified.status, VerifyStatus::SignatureOnly);
    assert_eq!(verified.kid, KID_ONE);
}

#[test]
fn unbound_when_signed_without_a_result() {
    let prov = signed_prov(None);
    let trust = trust_of(&signer_one());
    let result = result_json();
    for offered in [Some(&result), None] {
        let verified =
            verify_public(&prov, &trust, offered).expect("an undigested receipt verifies");
        assert_eq!(verified.status, VerifyStatus::Unbound);
    }
    let payload = payload_json_of(&prov);
    assert!(payload.get("result_sha256").is_some(), "the member is present");
    assert!(payload["result_sha256"].is_null(), "and its value is null");
}

#[test]
fn unbound_for_an_unsafe_integer() {
    let unhashable = serde_json::json!({"n": 9_007_199_254_740_992u64});
    let prov = signed_prov(Some(&unhashable));
    assert!(payload_json_of(&prov).get("result_sha256").is_some(), "the member is present");
    assert!(payload_json_of(&prov)["result_sha256"].is_null(), "2^53 digests to null");
    let trust = trust_of(&signer_one());
    let verified = verify_public(&prov, &trust, Some(&unhashable)).expect("unbound verifies");
    assert_eq!(verified.status, VerifyStatus::Unbound);
}

#[test]
fn bound_for_safe_numbers() {
    for safe in [
        serde_json::json!({"n": 9_007_199_254_740_991u64}),
        serde_json::json!({"x": 1.5}),
    ] {
        let prov = signed_prov(Some(&safe));
        let trust = trust_of(&signer_one());
        let verified = verify_public(&prov, &trust, Some(&safe)).expect("a safe number binds");
        assert_eq!(verified.status, VerifyStatus::Bound);
    }
}

#[test]
fn unbound_for_a_non_object_result() {
    let array = serde_json::json!([1, 2]);
    let prov = signed_prov(Some(&array));
    assert!(payload_json_of(&prov).get("result_sha256").is_some(), "the member is present");
    assert!(payload_json_of(&prov)["result_sha256"].is_null());
    let trust = trust_of(&signer_one());
    let verified = verify_public(&prov, &trust, Some(&array)).expect("unbound verifies");
    assert_eq!(verified.status, VerifyStatus::Unbound);
}

#[test]
fn unknown_kid_is_refused() {
    let result = result_json();
    let prov = signed_prov(Some(&result));
    let trust = trust_of(&signer_two());
    assert_eq!(verify_public(&prov, &trust, Some(&result)), Err(VerifyRefusal::UnknownKid));
}

#[test]
fn a_flipped_signature_byte_is_refused() {
    let result = result_json();
    let mut prov = signed_prov(Some(&result));
    let mut sig = URL_SAFE_NO_PAD
        .decode(prov["public_signature"]["sig"].as_str().expect("a sig member"))
        .expect("sig decodes");
    sig[0] ^= 0x01;
    prov["public_signature"]["sig"] = serde_json::Value::from(URL_SAFE_NO_PAD.encode(&sig));
    let trust = trust_of(&signer_one());
    assert_eq!(verify_public(&prov, &trust, Some(&result)), Err(VerifyRefusal::BadSignature));
}

#[test]
fn a_short_or_padded_signature_is_bad_encoding() {
    let result = result_json();
    let short = URL_SAFE_NO_PAD.encode(vec![0u8; 63]);
    let prov = signed_prov(Some(&result));
    let padded = format!("{}=", prov["public_signature"]["sig"].as_str().expect("a sig member"));
    for sig in [short, padded] {
        let mut tampered = prov.clone();
        tampered["public_signature"]["sig"] = serde_json::Value::from(sig);
        let trust = trust_of(&signer_one());
        assert_eq!(
            verify_public(&tampered, &trust, Some(&result)),
            Err(VerifyRefusal::BadEncoding)
        );
    }
}

#[test]
fn an_edited_outer_receipt_mismatches() {
    let result = result_json();
    let mut prov = signed_prov(Some(&result));
    prov["receipt"]["tool"] = serde_json::json!("other_tool");
    let trust = trust_of(&signer_one());
    assert_eq!(
        verify_public(&prov, &trust, Some(&result)),
        Err(VerifyRefusal::OuterReceiptMismatch)
    );
}

#[test]
fn an_outer_only_extra_member_mismatches() {
    let result = result_json();
    let mut prov = signed_prov(Some(&result));
    prov["receipt"]["extra_outer_only"] = serde_json::json!("forged");
    let trust = trust_of(&signer_one());
    assert_eq!(
        verify_public(&prov, &trust, Some(&result)),
        Err(VerifyRefusal::OuterReceiptMismatch)
    );
}

fn profile_payload(v: u64, alg: &str) -> Vec<u8> {
    let payload = serde_json::json!({
        "v": v,
        "alg": alg,
        "kid": KID_ONE,
        "receipt": receipt_json(),
        "result_sha256": null,
    });
    serde_json::to_vec(&payload).expect("payload serializes")
}

#[test]
fn a_wrong_version_or_algorithm_is_a_bad_profile() {
    for payload in [profile_payload(2, "EdDSA"), profile_payload(1, "HS256")] {
        let prov = prov_with_payload(&payload);
        let trust = trust_of(&signer_one());
        assert_eq!(verify_public(&prov, &trust, None), Err(VerifyRefusal::BadProfile));
    }
}

#[test]
fn a_duplicate_payload_member_is_refused() {
    let clean = serde_json::to_string(&serde_json::json!({
        "v": 1,
        "alg": "EdDSA",
        "kid": KID_ONE,
        "receipt": receipt_json(),
        "result_sha256": null,
    }))
    .expect("payload serializes");
    let once = format!("\"kid\":\"{KID_ONE}\"");
    let twice = format!("{once},{once}");
    let text = clean.replacen(once.as_str(), &twice, 1);
    let prov = prov_with_payload(text.as_bytes());
    let trust = trust_of(&signer_one());
    assert_eq!(verify_public(&prov, &trust, None), Err(VerifyRefusal::DuplicateMember));
}

#[test]
fn a_duplicate_member_inside_receipt_is_refused() {
    let receipt_text = serde_json::to_string(&receipt_json()).expect("receipt serializes");
    let once = "\"tool\":\"search_issues\"";
    let text = format!(
        "{{\"v\":1,\"alg\":\"EdDSA\",\"kid\":\"{KID_ONE}\",\"receipt\":{},\"result_sha256\":null}}",
        receipt_text.replacen(once, &format!("{once},{once}"), 1)
    );
    let prov = prov_with_payload(text.as_bytes());
    let trust = trust_of(&signer_one());
    assert_eq!(verify_public(&prov, &trust, None), Err(VerifyRefusal::DuplicateMember));
}

#[test]
fn a_signature_without_the_domain_tag_is_bad_signature() {
    let payload = serde_json::to_vec(&serde_json::json!({
        "v": 1,
        "alg": "EdDSA",
        "kid": KID_ONE,
        "receipt": receipt_json(),
        "result_sha256": null,
    }))
    .expect("payload serializes");
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&SEED_ONE).expect("a seed loads");
    let sig = URL_SAFE_NO_PAD.encode(key_pair.sign(&payload).as_ref());
    let mut prov = serde_json::to_value(sample().sign(&hmac())).expect("signed serializes");
    prov["public_signature"] = serde_json::json!({
        "payload": URL_SAFE_NO_PAD.encode(&payload),
        "sig": sig,
    });
    let trust = trust_of(&signer_one());
    assert_eq!(verify_public(&prov, &trust, None), Err(VerifyRefusal::BadSignature));
}

#[test]
fn a_non_canonical_payload_verifies_verbatim() {
    let text = format!(
        "{{ \"kid\" : \"{KID_ONE}\" , \"v\" : 1 , \"alg\" : \"EdDSA\" , \"receipt\" : {} , \"result_sha256\" : null }}",
        serde_json::to_string(&receipt_json()).expect("receipt serializes")
    );
    let prov = prov_with_payload(text.as_bytes());
    let trust = trust_of(&signer_one());
    let verified = verify_public(&prov, &trust, None).expect("non-canonical verifies");
    assert_eq!(verified.status, VerifyStatus::Unbound);
    assert_eq!(verified.receipt, sample());
    assert_eq!(payload_of(&prov), text.as_bytes());
}

#[test]
fn a_plain_signature_has_no_public_part() {
    let plain = serde_json::to_value(sample().sign(&hmac())).expect("signed serializes");
    let trust = TrustSet { keys: BTreeMap::new() };
    assert_eq!(
        verify_public(&plain, &trust, Some(&result_json())),
        Err(VerifyRefusal::NoPublicSignature)
    );
}

#[test]
fn a_single_jwk_is_a_trust_set() {
    assert!(TrustSet::from_json(&jwk_for(&SEED_ONE, KID_ONE)).is_ok());
}

#[test]
fn a_jwks_selects_by_kid() {
    let text = format!(
        "{{\"keys\":[{},{}]}}",
        jwk_for(&SEED_ONE, KID_ONE),
        jwk_for(&SEED_TWO, KID_TWO)
    );
    let trust = TrustSet::from_json(&text).expect("two keys load");
    let result = result_json();
    let one = signer_one();
    let two = signer_two();
    for (signer, kid) in [(&one, KID_ONE), (&two, KID_TWO)] {
        let signed = sample().sign(&hmac());
        let prov = provenance_value(&signed, Some((signer, Some(&result))));
        let verified = verify_public(&prov, &trust, Some(&result)).expect("selected key verifies");
        assert_eq!(verified.kid, kid);
    }
}

#[test]
fn a_duplicate_kid_is_refused() {
    let text = format!(
        "{{\"keys\":[{},{}]}}",
        jwk_for(&SEED_ONE, KID_ONE),
        jwk_for(&SEED_TWO, KID_ONE)
    );
    assert!(matches!(TrustSet::from_json(&text), Err(TrustSetRefusal::DuplicateKid)));
}

#[test]
fn a_non_edwards_key_is_refused() {
    let x = x_of(&SEED_ONE);
    for text in [
        format!("{{\"kty\":\"EC\",\"crv\":\"Ed25519\",\"kid\":\"{KID_ONE}\",\"x\":\"{x}\"}}"),
        format!("{{\"kty\":\"OKP\",\"crv\":\"X25519\",\"kid\":\"{KID_ONE}\",\"x\":\"{x}\"}}"),
    ] {
        assert!(
            matches!(TrustSet::from_json(&text), Err(TrustSetRefusal::NotEd25519)),
            "not-Ed25519 must refuse: {text}"
        );
    }
}

#[test]
fn a_short_x_is_refused() {
    let x = URL_SAFE_NO_PAD.encode([0u8; 31]);
    let text = format!("{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"{KID_ONE}\",\"x\":\"{x}\"}}");
    assert!(matches!(TrustSet::from_json(&text), Err(TrustSetRefusal::BadX)));
}

#[test]
fn a_private_member_is_refused() {
    let text = format!(
        "{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"{KID_ONE}\",\"x\":\"{}\",\"d\":\"secret\"}}",
        x_of(&SEED_ONE)
    );
    assert!(matches!(TrustSet::from_json(&text), Err(TrustSetRefusal::PrivateMember)));
}

#[test]
fn a_missing_kid_is_refused() {
    let text = format!("{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{}\"}}", x_of(&SEED_ONE));
    assert!(matches!(TrustSet::from_json(&text), Err(TrustSetRefusal::MissingKid)));
}

#[test]
fn unsigned_stamping_is_byte_identical_and_field_pinned() {
    const RECEIPT: &str = concat!(
        "{\"subject_kind\":\"runtime\",",
        "\"backend_id\":\"github\",",
        "\"tool\":\"search_issues\",",
        "\"observed_at\":\"2026-07-13T10:15:30Z\",",
        "\"cache\":\"miss\",",
        "\"backend_ok\":true,",
        "\"evidence_kind\":\"observed\"}"
    );
    let signed = sample().sign(&hmac());
    let plain = serde_json::to_value(&signed).expect("signed serializes");
    let stamped = provenance_value(&signed, None);
    assert_eq!(stamped, plain);
    assert!(stamped.get("public_signature").is_none());
    let text = serde_json::to_string(&signed).expect("signed serializes");
    let mut expected = String::from("{\"receipt\":");
    expected.push_str(RECEIPT);
    expected.push_str(",\"key_id\":\"bnaut/gateway\",\"algorithm\":\"HS256\",\"signature\":\"");
    expected.push_str(&signed.signature);
    expected.push_str("\"}");
    assert_eq!(text, expected);
}

#[test]
fn dual_signing_keeps_the_hmac_seal() {
    let signed = sample().sign(&hmac());
    let plain = serde_json::to_value(&signed).expect("signed serializes");
    let result = result_json();
    let signer = signer_one();
    let stamped = provenance_value(&signed, Some((&signer, Some(&result))));
    for member in ["receipt", "key_id", "algorithm", "signature"] {
        assert_eq!(stamped[member], plain[member], "{member} is unchanged");
    }
    assert!(stamped.get("public_signature").is_some(), "the public part is added");
    let back: SignedResultProvenance =
        serde_json::from_value(stamped).expect("the stamped value still reads");
    let validator = AttestationValidator::new(BnautAttestationSigner::new(
        b"hmac-test-key".to_vec(),
        "gateway",
    ));
    assert!(validator.verify_result_provenance(&back));
}

#[test]
fn a_wide_receipt_with_u64_max_row_count_verifies() {
    let signed = wide_sample().sign(&hmac());
    let result = result_json();
    let signer = signer_one();
    let prov = provenance_value(&signed, Some((&signer, Some(&result))));
    let trust = trust_of(&signer);
    let payload_text = String::from_utf8(payload_of(&prov)).expect("payload is UTF-8");
    assert!(
        payload_text.contains("18446744073709551615"),
        "the payload must carry u64::MAX exactly: {payload_text}"
    );
    let verified = verify_public(&prov, &trust, Some(&result)).expect("a wide receipt verifies");
    assert_eq!(verified.status, VerifyStatus::Bound);
    assert_eq!(verified.receipt, wide_sample());
}
