// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Dual signing and the wide receipt.

use super::*;

#[test]
fn dual_signing_keeps_the_hmac_seal() {
    let signed = sample().sign(&hmac());
    let plain = serde_json::to_value(&signed).expect("signed serializes");
    let result = result_json();
    let key = signer_one();
    let stamped = provenance_value(&signed, Some((&key, Some(&result))));
    for member in ["receipt", "key_id", "algorithm", "signature"] {
        assert_eq!(stamped[member], plain[member], "{member} is unchanged");
    }
    assert!(
        stamped.get("public_signature").is_some(),
        "the public part is added"
    );
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
    let stamped = wide_sample().sign(&hmac());
    let result = result_json();
    let signer = signer_one();
    let prov = provenance_value(&stamped, Some((&signer, Some(&result))));
    let trust = trust_of(&signer);
    let verified = verify_public(&prov, &trust, Some(&result)).expect("a wide receipt verifies");
    assert_eq!(verified.status, VerifyStatus::Bound);
    assert_eq!(verified.receipt, wide_sample());
    let payload_text = String::from_utf8(payload_of(&prov)).expect("payload is UTF-8");
    assert!(
        payload_text.contains("18446744073709551615"),
        "the payload must carry u64::MAX exactly: {payload_text}"
    );
}
