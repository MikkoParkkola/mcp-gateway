// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7818: an object schema may say which parameters must be given together
//! (`anyOf`) or exclusively (`oneOf`), as lists of `required` names. The
//! validator refuses a call that satisfies none, or (`oneOf`) more than one.

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
