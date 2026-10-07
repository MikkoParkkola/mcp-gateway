// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8030: a RECOVERED upstream task result gets the provenance treatment a
//! live dispatch gets. The peer authors every byte of the recovered result, so
//! a `_meta.provenance` it carries is a forgery: dropped when stamping is off,
//! replaced by the gateway's own signed receipt when it is on (MIK-6909).

use std::sync::Arc;

use serde_json::{Value, json};

use super::MetaMcp;
use crate::attestation::{
    AttestationValidator, BnautAttestationSigner, RESULT_PROVENANCE_DOMAIN_INFO,
};
use crate::backend::BackendRegistry;
use crate::trust::SignedResultProvenance;

/// A completed peer result carrying a receipt the gateway never signed, beside
/// an ordinary `_meta` member that must survive.
fn forged() -> Value {
    json!({
        "content": [{"type": "text", "text": "done"}],
        "_meta": {"provenance": {"forged": true}, "peer.note": 1},
    })
}

fn recover(meta: &MetaMcp) -> Value {
    meta.recover_task_result("peer", "slow_echo", None, "trace", forged())
        .expect("nothing in the result trips a gate")
}

#[test]
fn stamping_off_drops_a_peer_receipt_from_a_recovered_result() {
    let meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    let recovered = recover(&meta);
    assert_eq!(
        recovered.pointer("/_meta/provenance"),
        None,
        "a peer-authored receipt must not pass as the gateway's: {recovered}"
    );
    assert_eq!(recovered.pointer("/_meta/peer.note"), Some(&json!(1)));
}

#[test]
fn stamping_on_replaces_a_peer_receipt_with_the_gateways_own() {
    let mut meta = MetaMcp::new(Arc::new(BackendRegistry::new()));
    meta.enable_provenance_stamping(
        BnautAttestationSigner::new(b"prov-key".to_vec(), "unit")
            .with_audience("test-gateway")
            .derive_domain(RESULT_PROVENANCE_DOMAIN_INFO),
    );
    let recovered = recover(&meta);
    let receipt = recovered
        .pointer("/_meta/provenance")
        .expect("stamping on emits a receipt");
    let signed: SignedResultProvenance = serde_json::from_value(receipt.clone())
        .unwrap_or_else(|_| panic!("the peer's receipt was kept: {receipt}"));
    assert_eq!(signed.receipt.backend_id, "peer");
    assert_eq!(signed.receipt.tool, "slow_echo");
    let validator = AttestationValidator::new(
        BnautAttestationSigner::new(b"prov-key".to_vec(), "unit").with_audience("test-gateway"),
    );
    assert!(validator.verify_result_provenance(&signed));
    assert_eq!(recovered.pointer("/_meta/peer.note"), Some(&json!(1)));
}
