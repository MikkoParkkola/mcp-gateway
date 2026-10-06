// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7818: an object schema may say which parameters must be given together
//! (`anyOf`) or exclusively (`oneOf`), as lists of `required` names. The
//! validator refuses a call that satisfies none, or (`oneOf`) more than one.
//! MIK-7943: a null a property's `type` admits counts as given, in `required`
//! and in a branch, and is checked and forwarded like any value.

use super::*;
use serde_json::json;

fn purge_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "zone": { "type": "string" },
            "everything": { "type": "boolean" },
            "files": { "type": "array", "items": { "type": "string" } }
        },
        "required": ["zone"],
        "oneOf": [
            { "required": ["everything"], "properties": { "everything": { "const": true } } },
            { "required": ["files"] }
        ]
    })
}

#[test]
fn one_of_refuses_neither_selector() {
    let verdict = validate_arguments(&json!({ "zone": "z" }), &purge_schema());
    assert!(!verdict.is_valid());
    let text = verdict.format_error(&purge_schema());
    assert!(text.contains("exactly one of"), "{text}");
    assert!(
        text.contains("everything") && text.contains("files"),
        "{text}"
    );
}

#[test]
fn one_of_refuses_both_selectors() {
    let args = json!({ "zone": "z", "everything": true, "files": ["https://a"] });
    assert!(!validate_arguments(&args, &purge_schema()).is_valid());
}

#[test]
fn one_of_accepts_either_selector_alone() {
    for args in [
        json!({ "zone": "z", "everything": true }),
        json!({ "zone": "z", "files": ["https://a"] }),
        // `everything: false` selects nothing, so `files` is the one selector.
        json!({ "zone": "z", "everything": false, "files": ["https://a"] }),
    ] {
        let verdict = validate_arguments(&args, &purge_schema());
        assert!(verdict.is_valid(), "{args}: {:?}", verdict.violations);
    }
}

#[test]
fn one_of_refuses_a_selector_that_selects_nothing() {
    let args = json!({ "zone": "z", "everything": false });
    assert!(!validate_arguments(&args, &purge_schema()).is_valid());
}

fn update_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "id": { "type": "string" },
            "name": { "type": "string" },
            "ttl": { "type": "integer" }
        },
        "required": ["id"],
        "anyOf": [ { "required": ["name"] }, { "required": ["ttl"] } ]
    })
}

#[test]
fn any_of_refuses_a_call_with_none_of_the_fields() {
    let verdict = validate_arguments(&json!({ "id": "i" }), &update_schema());
    assert!(!verdict.is_valid());
    let text = verdict.format_error(&update_schema());
    assert!(text.contains("at least one of"), "{text}");
    // A null is not a value.
    assert!(!validate_arguments(&json!({ "id": "i", "name": null }), &update_schema()).is_valid());
}

#[test]
fn any_of_accepts_one_or_several() {
    for args in [
        json!({ "id": "i", "name": "n" }),
        json!({ "id": "i", "ttl": 60 }),
        json!({ "id": "i", "name": "n", "ttl": 60 }),
    ] {
        assert!(
            validate_arguments(&args, &update_schema()).is_valid(),
            "{args}"
        );
    }
}

#[test]
fn a_schema_without_alternatives_is_unchanged() {
    let schema = json!({
        "type": "object",
        "properties": { "a": { "type": "string" } }
    });
    assert!(validate_arguments(&json!({}), &schema).is_valid());
}

/// The alternatives are judged on the values as forwarded: `"true"` for a
/// boolean is coerced to `true` before the pin is compared.
#[test]
fn one_of_compares_the_coerced_value_not_the_typed_one() {
    let mut schema = purge_schema();
    schema["properties"]["everything"] = json!({ "type": "boolean", "description": "d" });
    let result = validate_arguments(&json!({ "zone": "z", "everything": "true" }), &schema);
    assert!(result.is_valid(), "{:?}", result.violations);
    assert_eq!(result.coerced["everything"], json!(true));
    let off = validate_arguments(&json!({ "zone": "z", "everything": "false" }), &schema);
    assert!(!off.is_valid(), "a string false selects nothing");
}

/// A branch the reader does not understand leaves the whole list alone: it must
/// not count as always satisfied and make a valid call look ambiguous.
#[test]
fn a_list_with_an_unsupported_branch_is_left_alone() {
    let schema = json!({
        "type": "object",
        "properties": { "kind": { "type": "string" }, "a": { "type": "string" } },
        "oneOf": [
            { "properties": { "kind": { "enum": ["x", "y"] } } },
            { "required": ["a"] }
        ]
    });
    assert!(validate_arguments(&json!({ "kind": "x", "a": "1" }), &schema).is_valid());
}

/// The schema a client is shown has no root combinator; the one that is
/// enforced still has.
#[test]
fn the_advertised_schema_has_no_root_combinators_and_the_enforced_one_keeps_them() {
    let shown = advertised_input_schema(&purge_schema());
    for keyword in ["oneOf", "anyOf", "allOf"] {
        assert!(
            shown.get(keyword).is_none(),
            "{keyword} advertised: {shown}"
        );
    }
    assert_eq!(shown["required"], json!(["zone"]));
    assert!(purge_schema().get("oneOf").is_some());
    // Nested combinators are not the root's business.
    let nested = advertised_input_schema(
        &json!({ "type": "object", "properties": { "p": { "oneOf": [{ "type": "string" }] } } }),
    );
    assert!(nested["properties"]["p"].get("oneOf").is_some());
}

/// A root combinator the gateway does not enforce stays listed: hiding it
/// would leave the constraint checked by neither the client nor the gateway.
#[test]
fn an_unenforced_root_combinator_stays_in_the_advertised_schema() {
    let schema = json!({
        "type": "object",
        "properties": { "a": { "type": "string" }, "b": { "type": "string" } },
        "anyOf": [{ "required": ["a"] }, { "type": "object" }],
        "oneOf": [{ "required": ["a"] }, { "required": ["b"] }],
        "allOf": [{ "required": ["a"] }]
    });
    let shown = advertised_input_schema(&schema);
    assert_eq!(shown["anyOf"], schema["anyOf"], "unread branch: {shown}");
    assert_eq!(
        shown["allOf"], schema["allOf"],
        "allOf is never enforced: {shown}"
    );
    assert!(
        shown.get("oneOf").is_none(),
        "enforced list advertised: {shown}"
    );
    // Without root `properties` the validator reads nothing, so nothing is
    // enforced and the list stays listed.
    let bare = json!({ "type": "object", "anyOf": [{ "required": ["a"] }] });
    assert_eq!(advertised_input_schema(&bare), bare);
}

/// A type error is the whole answer: the alternatives are not judged on a
/// value that failed coercion, so the caller sees one violation, not a second
/// "no alternative" message caused by the first.
#[test]
fn a_type_error_is_reported_alone() {
    let verdict = validate_arguments(
        &json!({ "zone": "z", "everything": "not-a-bool" }),
        &purge_schema(),
    );
    let params: Vec<&str> = verdict
        .violations
        .iter()
        .map(|v| v.param.as_str())
        .collect();
    assert_eq!(params, ["everything"], "{:?}", verdict.violations);
}

/// MIK-7943 finding 6: a required property whose type admits null accepts a
/// present null; it must still be present, and a non-null type still refuses.
#[test]
fn a_required_nullable_union_property_accepts_a_present_null() {
    let schema = json!({
        "type": "object",
        "properties": { "cursor": { "type": ["string", "null"] } },
        "required": ["cursor"]
    });
    let result = validate_arguments(&json!({ "cursor": null }), &schema);
    assert!(result.is_valid(), "{:?}", result.violations);
    assert!(
        !validate_arguments(&json!({}), &schema).is_valid(),
        "still required"
    );
    let strict = json!({
        "type": "object",
        "properties": { "cursor": { "type": "string" } },
        "required": ["cursor"]
    });
    assert!(!validate_arguments(&json!({ "cursor": null }), &strict).is_valid());
}

/// A null the `type` admits is a value: an `enum` without null refuses it,
/// and an accepted one is forwarded, not dropped.
#[test]
fn an_admitted_null_is_checked_and_forwarded() {
    let schema = json!({
        "type": "object",
        "properties": {
            "cursor": { "type": ["string", "null"] },
            "mode": { "type": ["string", "null"], "enum": ["a", "b"] }
        },
        "required": ["cursor"]
    });
    let result = validate_arguments(&json!({ "cursor": null }), &schema);
    assert!(result.is_valid(), "{:?}", result.violations);
    assert_eq!(result.coerced, json!({ "cursor": null }), "forwarded");
    let refused = validate_arguments(&json!({ "cursor": "c", "mode": null }), &schema);
    assert!(!refused.is_valid(), "null is not in the enum");
}

/// An `anyOf` branch that requires a nullable property holds when it is null.
#[test]
fn an_any_of_branch_counts_an_admitted_null_as_present() {
    let schema = json!({
        "type": "object",
        "properties": {
            "cursor": { "type": ["string", "null"] },
            "page": { "type": "integer" }
        },
        "anyOf": [{ "required": ["cursor"] }, { "required": ["page"] }]
    });
    let result = validate_arguments(&json!({ "cursor": null }), &schema);
    assert!(result.is_valid(), "{:?}", result.violations);
}
