//! MIK-7214.HEADER.7/.8 — `x-mcp-header` schema validation.
//!
//! HEADER.7 names six constraints; each has a case here. HEADER.8 requires a
//! violating tool to be excluded from `tools/list`.

use mcp_gateway::protocol::param_headers::{MirrorViolation, SAFE_INTEGER_MAX, mirrored_params};
use serde_json::json;

fn schema_with(
    property: &str,
    ty: &str,
    header: impl Into<serde_json::Value>,
) -> serde_json::Value {
    let header = header.into();
    json!({
        "type": "object",
        "properties": { property: { "type": ty, "x-mcp-header": header } }
    })
}

#[test]
fn valid_annotation_yields_prefixed_header_name() {
    // GIVEN a string property annotated with a well-formed header name
    let schema = schema_with("tenant", "string", json!("Tenant-Id"));
    // WHEN the schema is validated
    let mirrored = mirrored_params(&schema).expect("well-formed annotation must validate");
    // THEN the outbound name carries the mandatory prefix
    assert_eq!(mirrored.len(), 1);
    assert_eq!(mirrored[0].property, "tenant");
    assert_eq!(mirrored[0].header_name, "Mcp-Param-Tenant-Id");
}

#[test]
fn schema_without_annotation_yields_no_mirrors() {
    let schema = json!({"type": "object", "properties": {"q": {"type": "string"}}});
    assert!(
        mirrored_params(&schema)
            .expect("plain schema is valid")
            .is_empty()
    );
}

#[test]
fn empty_header_name_is_rejected() {
    let schema = schema_with("tenant", "string", json!(""));
    assert_eq!(mirrored_params(&schema), Err(MirrorViolation::Empty));
}

#[test]
fn non_token_header_name_is_rejected() {
    // GIVEN a name carrying a separator that RFC 9110 5.1 forbids in a token
    let schema = schema_with("tenant", "string", json!("Tenant Id"));
    assert_eq!(mirrored_params(&schema), Err(MirrorViolation::NotToken));
}

#[test]
fn header_name_with_crlf_is_rejected_as_control() {
    // GIVEN a name attempting header injection
    let schema = schema_with("tenant", "string", json!("Tenant\r\nX-Injected: 1"));
    // THEN it is refused as a control character, before token analysis
    assert_eq!(mirrored_params(&schema), Err(MirrorViolation::Control));
}

#[test]
fn case_insensitively_duplicate_names_are_rejected() {
    let schema = json!({
        "type": "object",
        "properties": {
            "a": {"type": "string", "x-mcp-header": "Tenant"},
            "b": {"type": "string", "x-mcp-header": "tenant"}
        }
    });
    assert_eq!(mirrored_params(&schema), Err(MirrorViolation::Duplicate));
}

#[test]
fn number_typed_property_is_rejected() {
    // GIVEN `number`, which the spec excludes because a double has no lossless
    // header rendering
    let schema = schema_with("ratio", "number", json!("Ratio"));
    assert_eq!(
        mirrored_params(&schema),
        Err(MirrorViolation::UnsupportedType)
    );
}

#[test]
fn integer_string_and_boolean_types_are_all_accepted() {
    for ty in ["integer", "string", "boolean"] {
        let schema = schema_with("p", ty, json!("P"));
        assert_eq!(
            mirrored_params(&schema).map(|m| m.len()),
            Ok(1),
            "type {ty} must be mirrorable"
        );
    }
}

#[test]
fn integer_property_declaring_an_unsafe_bound_is_rejected() {
    // GIVEN an integer property whose declared maximum exceeds 2^53-1
    let schema = json!({
        "type": "object",
        "properties": {
            "seq": {
                "type": "integer",
                "maximum": 9_223_372_036_854_775_807i64,
                "x-mcp-header": "Seq"
            }
        }
    });
    // THEN the tool is excludable at schema time, not merely omitted per call
    assert_eq!(
        mirrored_params(&schema),
        Err(MirrorViolation::IntegerOutOfRange)
    );
}

#[test]
fn integer_property_declaring_safe_bounds_is_accepted() {
    let schema = json!({
        "type": "object",
        "properties": {
            "seq": {
                "type": "integer",
                "minimum": 0,
                "maximum": SAFE_INTEGER_MAX,
                "x-mcp-header": "Seq"
            }
        }
    });
    assert_eq!(mirrored_params(&schema).map(|m| m.len()), Ok(1));
}

#[test]
fn integer_property_without_declared_bounds_stays_listed() {
    // GIVEN no declared bound, there is nothing to exclude on; the per-call
    // omission in `header_value_for` carries the constraint instead
    let schema = schema_with("seq", "integer", "Seq");
    assert_eq!(mirrored_params(&schema).map(|m| m.len()), Ok(1));
}

#[test]
fn non_string_annotation_value_is_rejected() {
    // GIVEN an annotation that is a number rather than a header name
    let schema = schema_with("tenant", "string", json!(123));
    assert_eq!(mirrored_params(&schema), Err(MirrorViolation::NotAString));
}

#[test]
fn integer_property_declaring_an_unsafe_const_is_rejected() {
    let schema = json!({
        "type": "object",
        "properties": {
            "seq": {"type": "integer", "const": SAFE_INTEGER_MAX + 1, "x-mcp-header": "Seq"}
        }
    });
    assert_eq!(
        mirrored_params(&schema),
        Err(MirrorViolation::IntegerOutOfRange)
    );
}

#[test]
fn integer_property_enumerating_an_unsafe_member_is_rejected() {
    // GIVEN an enum whose last member leaves the safe range
    let schema = json!({
        "type": "object",
        "properties": {
            "seq": {"type": "integer", "enum": [1, SAFE_INTEGER_MAX + 1], "x-mcp-header": "Seq"}
        }
    });
    assert_eq!(
        mirrored_params(&schema),
        Err(MirrorViolation::IntegerOutOfRange)
    );
}

#[test]
fn integer_property_bounded_at_i64_min_is_rejected_without_overflow() {
    // GIVEN the one value `abs()` cannot negate; the range test must still
    // answer, and answer "unsafe"
    let schema = json!({
        "type": "object",
        "properties": {
            "seq": {"type": "integer", "minimum": i64::MIN, "x-mcp-header": "Seq"}
        }
    });
    assert_eq!(
        mirrored_params(&schema),
        Err(MirrorViolation::IntegerOutOfRange)
    );
}
