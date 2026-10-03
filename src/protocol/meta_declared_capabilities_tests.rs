use super::{Declared, RequestShape, classify_request};
use serde_json::json;

fn modern_params(caps: &serde_json::Value) -> serde_json::Value {
    json!({"_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": caps
    }})
}

#[test]
fn a_modern_request_carries_the_names_it_declared() {
    let shape = classify_request(
        Some(&modern_params(&json!({"elicitation": {}}))),
        Some("2026-07-28"),
    );
    assert!(
        matches!(shape, RequestShape::Modern(_)),
        "fixture must be modern"
    );
    assert!(shape.declared_capabilities().has("elicitation"));
}

#[test]
fn declaring_nothing_carries_no_names() {
    let shape = classify_request(Some(&modern_params(&json!({}))), Some("2026-07-28"));
    assert!(
        matches!(shape, RequestShape::Modern(_)),
        "fixture must be modern"
    );
    assert_eq!(shape.declared_capabilities(), Declared::NONE);
}

#[test]
fn a_neighbouring_capability_is_carried_under_its_own_name() {
    // The names must stay distinguishable: collapsing them to one bit is
    // what MRTR.9's per-method refusal cannot be built on.
    for cap in ["sampling", "roots"] {
        let shape = classify_request(Some(&modern_params(&json!({cap: {}}))), Some("2026-07-28"));
        assert!(shape.declared_capabilities().has(cap), "{cap}");
    }
}

#[test]
fn a_shape_that_failed_to_classify_declares_nothing() {
    // The doc comment names this an empty case, so something has to hold it
    // there. Production does not reach it today -- the handler returns on a
    // failed classification before the field is read -- which is exactly why
    // a mutant returning a non-empty slice would otherwise go unnoticed.
    let shape = RequestShape::Malformed {
        missing: vec!["protocolVersion"],
    };
    assert_eq!(shape.declared_capabilities(), Declared::NONE);
}

#[test]
fn a_legacy_request_declares_nothing() {
    let shape = classify_request(Some(&json!({})), Some("2025-11-25"));
    assert!(
        matches!(shape, RequestShape::Legacy),
        "fixture must be legacy"
    );
    assert_eq!(shape.declared_capabilities(), Declared::NONE);
}

#[test]
fn cache_revision_for_modern_is_the_validated_body_version() {
    let params = modern_params(&json!({}));
    let shape = classify_request(Some(&params), Some("2026-07-28"));
    assert_eq!(
        super::cache_protocol_revision(&shape, Some("2026-07-28"), None),
        Some("2026-07-28")
    );
}

#[test]
fn cache_revision_for_legacy_is_the_header_not_a_log_token() {
    let params = json!({});
    let shape = classify_request(Some(&params), Some("2025-11-25"));
    assert_eq!(
        super::cache_protocol_revision(&shape, Some("2025-11-25"), None),
        Some("2025-11-25")
    );
}

#[test]
fn cache_revision_for_malformed_is_none() {
    let shape = RequestShape::Malformed {
        missing: vec!["protocolVersion"],
    };
    assert_eq!(
        super::cache_protocol_revision(&shape, Some("2026-07-28"), None),
        None
    );
}

#[test]
fn cache_revision_legacy_rejects_the_modern_sentinel() {
    let params = json!({});
    let shape = classify_request(Some(&params), None);
    assert!(matches!(shape, RequestShape::Legacy));
    assert_eq!(
        super::cache_protocol_revision(&shape, Some("2026-07-28"), None),
        None,
        "the duplicate-header sentinel is a classification trick, not a served revision"
    );
}

#[test]
fn cache_revision_legacy_rejects_unsupported_and_log_tokens() {
    let params = json!({});
    let shape = classify_request(Some(&params), None);
    for bogus in ["not-a-revision", "absent", "none", " ABSENT "] {
        assert_eq!(
            super::cache_protocol_revision(&shape, Some(bogus), None),
            None,
            "{bogus}"
        );
    }
}

#[test]
fn cache_revision_legacy_accepts_a_supported_session_handshake() {
    let params = json!({});
    let shape = classify_request(Some(&params), None);
    assert_eq!(
        super::cache_protocol_revision(&shape, None, Some("2025-06-18")),
        Some("2025-06-18")
    );
}

/// A `tools/call` body cannot choose the revision bucket. `protocolVersion`
/// is not a field of that request, so a header-less caller that adds one
/// would otherwise select where its response is stored and read from.
#[test]
fn cache_revision_legacy_ignores_a_body_protocol_version() {
    let params = json!({"protocolVersion": "2025-03-26"});
    let shape = classify_request(Some(&params), None);
    assert!(matches!(shape, RequestShape::Legacy), "fixture is legacy");
    assert_eq!(
        super::cache_protocol_revision(&shape, None, None),
        None,
        "an arbitrary body field is not evidence of the revision served"
    );
    assert_eq!(
        super::cache_protocol_revision(&shape, None, Some("2025-11-25")),
        Some("2025-11-25"),
        "the handshake the gateway answered still decides, not the body"
    );
}

/// Whitespace is not normalised away: `negotiate_version` compares
/// spellings exactly, so a padded value names no bucket at all.
#[test]
fn cache_revision_rejects_whitespace_padded_spellings() {
    let params = json!({});
    let shape = classify_request(Some(&params), None);
    for padded in [" 2025-11-25", "2025-11-25 ", "\t2025-06-18\n"] {
        assert_eq!(
            super::cache_protocol_revision(&shape, Some(padded), None),
            None,
            "header: {padded:?}"
        );
        assert_eq!(
            super::cache_protocol_revision(&shape, None, Some(padded)),
            None,
            "session: {padded:?}"
        );
    }
}

/// The two eras are one accepted set for the cache layers, and `2026-07-28`
/// is deliberately absent from `SUPPORTED_VERSIONS` — a helper built on
/// that constant alone accepts no modern revision at all.
#[test]
fn served_revision_spans_both_eras_and_matches_exactly() {
    for legacy in crate::protocol::SUPPORTED_VERSIONS {
        assert_eq!(super::served_revision(legacy), Some(*legacy), "{legacy}");
    }
    for modern in super::MODERN_VERSIONS {
        assert_eq!(super::served_revision(modern), Some(*modern), "{modern}");
    }
    for bogus in ["", " 2026-07-28", "2026-07-28 ", "not-a-revision"] {
        assert_eq!(super::served_revision(bogus), None, "{bogus:?}");
    }
}
