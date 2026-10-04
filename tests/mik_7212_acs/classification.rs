// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use mcp_gateway::protocol::meta::{RequestShape, classify_request};
use serde_json::json;

fn modern_meta() -> serde_json::Value {
    json!({"_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    }})
}

#[test]
fn a_modern_version_header_without_body_metadata_is_malformed() {
    // The bypass: upstream routes on the header, the gateway classifies on
    // the body, and the two disagree about which protocol this even is.
    // Answering Legacy here skips the feature gate and every mirrored-header
    // check behind it.
    let shape = classify_request(Some(&json!({})), Some("2026-07-28"));
    assert!(
        matches!(shape, RequestShape::Malformed { .. }),
        "a header declaring 2026-07-28 with no body metadata must be refused, got {shape:?}"
    );
}

#[test]
fn an_unserved_2026_version_header_without_body_metadata_is_malformed() {
    // Adversarial review, 2026-08-30, confirmed at source: the router skips
    // session minting on `declares_modern_era` (any `2026-*`) while the
    // classifier read the narrower `MODERN_VERSIONS`. A revision this build
    // does not serve therefore got no session AND the legacy path — the
    // legacy destructive-confirmation policy, with an empty session id,
    // never reaching the -32022 unsupported-version refusal. Two predicates
    // deciding one question is the defect; the answer is one predicate.
    let shape = classify_request(Some(&json!({})), Some("2026-11-25"));
    assert!(
        matches!(shape, RequestShape::Malformed { .. }),
        "a header declaring an unserved 2026 revision with no body metadata \
         must be refused, not treated as legacy, got {shape:?}"
    );
}

#[test]
fn a_legacy_version_header_is_not_a_modern_declaration() {
    // 2025 defines this header too. Treating its mere presence as a modern
    // declaration would refuse every conforming 2025 client — the likelier
    // and more damaging mistake.
    let shape = classify_request(Some(&json!({})), Some("2025-11-25"));
    assert!(
        matches!(shape, RequestShape::Legacy),
        "a 2025 client sending its own version header must stay legacy, got {shape:?}"
    );
}

#[test]
fn a_modern_header_agreeing_with_modern_body_classifies_modern() {
    let shape = classify_request(Some(&modern_meta()), Some("2026-07-28"));
    assert!(matches!(shape, RequestShape::Modern(_)), "got {shape:?}");
}

#[test]
fn body_metadata_alone_still_classifies_modern() {
    // No header at all: the body remains a sufficient declaration.
    let shape = classify_request(Some(&modern_meta()), None);
    assert!(matches!(shape, RequestShape::Modern(_)), "got {shape:?}");
}

#[test]
fn capabilities_present_but_not_an_object_is_malformed() {
    // Presence satisfied the required-field check while the value was
    // unusable, so an invalid declaration reached dispatch looking valid.
    for bad in [json!(null), json!(7), json!("caps"), json!([])] {
        let params = json!({"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": bad
        }});
        let shape = classify_request(Some(&params), None);
        assert!(
            matches!(shape, RequestShape::Malformed { .. }),
            "clientCapabilities {bad} must be refused, got {shape:?}"
        );
    }
}

#[test]
fn a_modern_only_optional_key_declares_the_era() {
    // clientInfo and logLevel are 2026 keys. A request carrying one and
    // omitting the required pair has declared an era and failed to complete
    // the declaration, which is malformed rather than legacy.
    for key in [
        "io.modelcontextprotocol/clientInfo",
        "io.modelcontextprotocol/logLevel",
    ] {
        let params = json!({"_meta": { key: {"name": "x"} }});
        let shape = classify_request(Some(&params), None);
        assert!(
            matches!(shape, RequestShape::Malformed { .. }),
            "{key} alone must be malformed, got {shape:?}"
        );
    }
}

#[test]
fn an_unrelated_meta_key_is_still_legacy() {
    // A 2025 client sending a trace context has declared nothing.
    let params = json!({"_meta": {"traceparent": "00-abc-def-01"}});
    assert!(matches!(
        classify_request(Some(&params), None),
        RequestShape::Legacy
    ));
}
