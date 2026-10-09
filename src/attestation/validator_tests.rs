// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;
use crate::attestation::signer::TokenRequest;
use uuid::Uuid;

fn validator() -> AttestationValidator {
    AttestationValidator::with_settings(
        BnautAttestationSigner::new(b"validator-test-key".to_vec(), "unit")
            .with_audience("test-gateway"),
        8,
        crate::duration_bound::delta!(seconds, 30),
    )
}

fn sample_receipt() -> crate::trust::RuntimeProvenanceReceipt {
    crate::trust::RuntimeProvenanceReceipt::observed(
        "github",
        "search_issues",
        "2026-07-13T10:15:30Z",
        crate::trust::CacheOutcome::Miss,
        true,
    )
}

/// A receipt-domain signer sharing the validator's raw key material —
/// mirrors how `resolve_provenance_signer` (`gateway/server/provenance_signer.rs`) derives
/// the live receipt signer from the same configured key (MIK-6909 item 2).
fn twin_receipt_signer() -> BnautAttestationSigner {
    BnautAttestationSigner::new(b"validator-test-key".to_vec(), "unit")
        .with_audience("test-gateway")
        .derive_domain(super::super::signer::RESULT_PROVENANCE_DOMAIN_INFO)
}

#[test]
fn result_provenance_round_trips_sign_then_verify() {
    let v = validator();
    let signed = sample_receipt().sign(&twin_receipt_signer());
    assert_eq!(signed.algorithm, crate::attestation::SIGNING_ALGORITHM);
    assert_eq!(signed.key_id, "bnaut/unit");
    assert!(v.verify_result_provenance(&signed));
}

#[test]
fn tampered_receipt_fails_verification() {
    let v = validator();
    let mut signed = sample_receipt().sign(&twin_receipt_signer());
    // Flip a fact after signing — the HMAC must no longer match.
    signed.receipt.backend_ok = Some(false);
    assert!(!v.verify_result_provenance(&signed));
}

#[test]
fn wrong_key_fails_verification() {
    let v = validator();
    let other = BnautAttestationSigner::new(b"a-different-key".to_vec(), "unit")
        .with_audience("test-gateway")
        .derive_domain(super::super::signer::RESULT_PROVENANCE_DOMAIN_INFO);
    let signed = sample_receipt().sign(&other);
    assert!(!v.verify_result_provenance(&signed));
}

#[test]
fn raw_key_signature_does_not_verify_as_a_receipt() {
    // MIK-6909 item 2: signing with the raw (token-domain) key — the
    // pre-hardening behavior — must NOT verify against the validator's
    // HKDF-derived receipt domain. Proves the receipt channel no longer
    // accepts token-domain signatures.
    let v = validator();
    let raw = BnautAttestationSigner::new(b"validator-test-key".to_vec(), "unit")
        .with_audience("test-gateway");
    let signed = sample_receipt().sign(&raw);
    assert!(!v.verify_result_provenance(&signed));
}

#[test]
fn malformed_signature_encoding_fails_verification() {
    let v = validator();
    let twin = BnautAttestationSigner::new(b"validator-test-key".to_vec(), "unit")
        .with_audience("test-gateway");
    let mut signed = sample_receipt().sign(&twin);
    signed.signature = "not valid base64url!!".to_string();
    assert!(!v.verify_result_provenance(&signed));
}

fn issue(now: DateTime<Utc>) -> AttestationToken {
    // Twin signer sharing the validator's key material.
    let signer = BnautAttestationSigner::new(b"validator-test-key".to_vec(), "unit")
        .with_audience("test-gateway");
    signer.issue(
        &TokenRequest {
            agent_identity: "agent".to_string(),
            task_uuid: Uuid::new_v4(),
            capabilities: vec!["cap".to_string()],
        },
        now,
        crate::duration_bound::delta!(minutes, 10),
    )
}

#[test]
fn valid_token_passes_and_counts() {
    let v = validator();
    let now = Utc::now();
    let token = issue(now);
    let claims = v
        .validate_boundary_call(Some(token.encoded()), "test", None, now)
        .unwrap();
    assert_eq!(claims.agent_identity, "agent");
    assert_eq!(v.validations_total(), 1);
    assert_eq!(v.rejections_total(), 0);
    assert!(v.audit().is_empty());
}

#[test]
fn missing_token_rejected_and_audited() {
    let v = validator();
    let err = v
        .validate_boundary_call(None, "boot", None, Utc::now())
        .unwrap_err();
    assert_eq!(err, AttestationRejection::MissingToken);
    assert_eq!(v.rejections_total(), 1);
    let records = v.audit().snapshot();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].boundary, "boot");
}

#[test]
fn mik_5223_caps_1_rejects_token_lacking_required_capability() {
    // MIK-5223.CAPS.1 — fail-closed: an authentic, unexpired token whose
    // capability allow-list does NOT include the requested action is
    // rejected. Authenticity alone must not authorize an out-of-scope call.
    let v = validator();
    let now = Utc::now();
    let token = issue(now); // minted with capabilities = ["cap"]

    // Requesting an action the token was not scoped for → rejected.
    let err = v
        .validate_boundary_call(Some(token.encoded()), "gateway_invoke", Some("write"), now)
        .unwrap_err();
    assert!(
        matches!(err, AttestationRejection::CapabilityNotGranted { .. }),
        "expected CapabilityNotGranted, got: {err:?}"
    );
    assert_eq!(v.rejections_total(), 1);

    // The same token IS admitted for the capability it actually holds.
    let granted = v
        .validate_boundary_call(Some(token.encoded()), "gateway_invoke", Some("cap"), now)
        .unwrap();
    assert_eq!(granted.agent_identity, "agent");

    // A capability-agnostic boundary (None, e.g. sandbox_boot) still passes.
    v.validate_boundary_call(Some(token.encoded()), "boot", None, now)
        .unwrap();
}

#[test]
fn wildcard_capability_grants_any_action() {
    // A token holding the "*" wildcard authorizes any requested action.
    let signer = BnautAttestationSigner::new(b"validator-test-key".to_vec(), "unit")
        .with_audience("test-gateway");
    let now = Utc::now();
    let token = signer.issue(
        &TokenRequest {
            agent_identity: "agent".to_string(),
            task_uuid: Uuid::new_v4(),
            capabilities: vec!["*".to_string()],
        },
        now,
        crate::duration_bound::delta!(minutes, 10),
    );
    let v = validator();
    v.validate_boundary_call(Some(token.encoded()), "gateway_invoke", Some("write"), now)
        .unwrap();
}

#[test]
fn expired_token_rejected() {
    let v = validator();
    let issued = Utc::now();
    let token = issue(issued);
    let later = issued + crate::duration_bound::delta!(minutes, 11);
    let err = v
        .validate_boundary_call(Some(token.encoded()), "call", None, later)
        .unwrap_err();
    assert!(matches!(err, AttestationRejection::Expired { .. }));
}

#[test]
fn ring_buffer_evicts_oldest_at_capacity() {
    let buffer = AuditRingBuffer::new(2);
    for i in 0..3 {
        buffer.push(AttestationAuditRecord {
            seq: 0,
            timestamp: String::new(),
            boundary: format!("b{i}"),
            token_id: None,
            agent_identity: None,
            rejection: AttestationRejection::MissingToken,
            detection_micros: 0,
        });
    }
    let records = buffer.snapshot();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].boundary, "b1");
    assert_eq!(records[1].boundary, "b2");
    assert_eq!(buffer.total_pushed(), 3);
}

#[test]
fn checkpoint_round_trips_rotation_state() {
    let v = validator();
    let now = Utc::now();
    let token = issue(now);
    let _successor = v.rotate(
        token.claims(),
        now,
        crate::duration_bound::delta!(minutes, 10),
    );
    let checkpoint = v.checkpoint();
    assert_eq!(checkpoint.retiring.len(), 1);
    assert_eq!(checkpoint.retiring[0].token_id, token.claims().token_id);

    let fresh = validator();
    fresh.restore(&checkpoint);
    assert_eq!(fresh.checkpoint(), checkpoint);
}

#[test]
fn restore_drops_unparseable_timestamps() {
    let v = validator();
    v.restore(&RotationCheckpoint {
        retiring: vec![RetiringToken {
            token_id: "t".to_string(),
            reject_after: "not-a-time".to_string(),
        }],
    });
    assert!(v.checkpoint().retiring.is_empty());
}
