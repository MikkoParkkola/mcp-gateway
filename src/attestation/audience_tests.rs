// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7795: an attestation token is bound to the destination it was minted
//! for. A validator accepts only its own audience, an empty audience on either
//! side matches nothing, and two gateways that share a signing key do not
//! accept each other's tokens.

use chrono::Utc;
use uuid::Uuid;

use super::wiring::{ATTESTATION_AUDIENCE_ENV, resolve_attestation_wiring};
use super::{
    AttestationRejection, AttestationToken, AttestationValidator, BnautAttestationSigner,
    TokenClaims, TokenRequest,
};

const KEY: &[u8] = b"audience-test-key";

fn signer(audience: Option<&str>) -> BnautAttestationSigner {
    let signer = BnautAttestationSigner::new(KEY.to_vec(), "aud");
    match audience {
        Some(audience) => signer.with_audience(audience),
        None => signer,
    }
}

fn token_for(audience: Option<&str>) -> AttestationToken {
    signer(audience).issue(
        &TokenRequest {
            agent_identity: "agent".to_string(),
            task_uuid: Uuid::new_v4(),
            capabilities: vec!["read".to_string()],
        },
        Utc::now(),
        crate::duration_bound::delta!(minutes, 5),
    )
}

fn check(
    validator: &AttestationValidator,
    token: &AttestationToken,
) -> Result<TokenClaims, AttestationRejection> {
    validator.validate_boundary_call(Some(token.encoded()), "test", None, Utc::now())
}

fn validator_for(audience: Option<&str>) -> AttestationValidator {
    AttestationValidator::new(signer(audience))
}

/// Mutant: `issue` mints no audience, so the claim binds nothing.
#[test]
fn issue_stamps_the_signers_audience() {
    assert_eq!(token_for(Some("gateway-a")).claims().audience, "gateway-a");
}

/// Mutant: the comparison is dropped or inverted.
#[test]
fn a_token_is_accepted_only_by_its_own_audience() {
    let token = token_for(Some("gateway-a"));

    assert!(check(&validator_for(Some("gateway-a")), &token).is_ok());
    assert_eq!(
        check(&validator_for(Some("gateway-b")), &token),
        Err(AttestationRejection::AudienceMismatch {
            expected: "gateway-b".to_string(),
            presented: "gateway-a".to_string(),
        }),
        "the same key and another audience is the replay to refuse"
    );
}

/// Mutant: the empty guard is removed, so two unconfigured sides match.
#[test]
fn an_empty_audience_on_either_side_matches_nothing() {
    for (minted_for, accepted_by) in [
        (None, None),
        (None, Some("gateway-a")),
        (Some("gateway-a"), None),
    ] {
        let verdict = check(&validator_for(accepted_by), &token_for(minted_for));
        assert!(
            matches!(verdict, Err(AttestationRejection::AudienceMismatch { .. })),
            "minted for {minted_for:?}, accepted by {accepted_by:?}: {verdict:?}"
        );
    }
}

/// The claim is required: a token without it is malformed, not unbound.
#[test]
fn a_token_without_an_audience_claim_is_malformed() {
    let signer = signer(Some("gateway-a"));
    let genuine = token_for(Some("gateway-a"));
    let mut claims = serde_json::to_value(genuine.claims()).expect("claims serialize");
    claims
        .as_object_mut()
        .expect("an object")
        .remove("audience");
    let payload = serde_json::to_vec(&claims).expect("payload");
    let signature = signer.sign_bytes(&payload);
    let token = AttestationToken::from_parts(genuine.claims().clone(), &payload, &signature);

    assert!(matches!(
        check(&validator_for(Some("gateway-a")), &token),
        Err(AttestationRejection::MalformedToken { .. })
    ));
}

/// Mutant: rotation stamps the signer's audience instead of carrying the
/// predecessor's, so rotating a foreign token relabels it as local.
#[test]
fn rotation_keeps_the_destination_of_the_token_it_replaces() {
    let local = validator_for(Some("gateway-a"));
    let own = token_for(Some("gateway-a"));
    let rotated = local.rotate(
        own.claims(),
        Utc::now(),
        crate::duration_bound::delta!(minutes, 5),
    );
    assert_eq!(rotated.claims().audience, "gateway-a");
    assert!(check(&local, &rotated).is_ok());

    let foreign = token_for(Some("gateway-b"));
    let laundered = local.rotate(
        foreign.claims(),
        Utc::now(),
        crate::duration_bound::delta!(minutes, 5),
    );
    assert_eq!(laundered.claims().audience, "gateway-b");
    assert!(
        matches!(
            check(&local, &laundered),
            Err(AttestationRejection::AudienceMismatch { .. })
        ),
        "rotation must not make a foreign token local"
    );
}

/// Mutant: `enforce` stops requiring an audience, so an enforcing gateway
/// would refuse every token with no startup error saying why.
#[test]
fn enforce_needs_an_audience_and_observe_without_one_rejects_every_token() {
    for blank in [None, Some(""), Some("   ")] {
        let Err(err) = resolve_attestation_wiring(Some("enforce"), Some(b"k"), None, blank) else {
            panic!("enforce without an audience {blank:?} must fail startup");
        };
        assert!(err.contains(ATTESTATION_AUDIENCE_ENV), "{err}");
    }

    let (validator, _) = resolve_attestation_wiring(Some("observe"), Some(KEY), None, None)
        .expect("observe starts without an audience")
        .expect("observe attaches a validator");
    assert!(matches!(
        check(&validator, &token_for(Some("gateway-a"))),
        Err(AttestationRejection::AudienceMismatch { .. })
    ));
}

/// Mutant: the wiring drops the configured audience or keeps its whitespace.
#[test]
fn the_configured_audience_is_trimmed_and_reaches_the_validator() {
    let (validator, _) =
        resolve_attestation_wiring(Some("enforce"), Some(KEY), None, Some("  gateway-a  "))
            .expect("enforce with an audience starts")
            .expect("enforce attaches a validator");

    assert!(check(&validator, &token_for(Some("gateway-a"))).is_ok());
    assert!(check(&validator, &token_for(Some("gateway-b"))).is_err());
}
