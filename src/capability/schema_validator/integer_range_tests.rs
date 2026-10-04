// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7905: a whole number under `type: integer` becomes an `i64` only inside
//! that range; outside it is kept as sent, never clamped.

use super::*;
use serde_json::json;

#[allow(clippy::needless_pass_by_value)]
fn schema_with_props(props: serde_json::Value, required: &[&str]) -> serde_json::Value {
    json!({ "type": "object", "properties": props, "required": required })
}

/// MIK-7905: a whole number outside the `i64` range under a plain integer type
/// is kept as sent, never clamped to `i64::MAX` or `i64::MIN`. Inside the range
/// a whole float still becomes an integer; -2^63 is `i64::MIN` exactly.
#[test]
fn a_whole_number_beyond_i64_is_kept_not_clamped() {
    let schema = schema_with_props(json!({ "n": { "type": "integer" } }), &[]);
    for sent in [
        json!(1e20),
        json!(-1e20),
        json!(9_223_372_036_854_775_808.0),
    ] {
        let result = validate_arguments(&json!({ "n": sent }), &schema);
        assert!(result.is_valid(), "{sent}: {:?}", result.violations);
        assert_eq!(result.coerced["n"], sent);
    }
    for (sent, integer) in [
        (json!(-9_223_372_036_854_775_808.0), json!(i64::MIN)),
        (json!(3.0), json!(3)),
    ] {
        let result = validate_arguments(&json!({ "n": sent }), &schema);
        assert!(result.is_valid(), "{sent}: {:?}", result.violations);
        assert_eq!(result.coerced["n"], integer, "{sent}");
    }
}

/// MIK-7905 with MIK-7818: a `oneOf` alternative is judged on the forwarded
/// (coerced) value, so a whole number beyond `i64` pinned by `const` matches
/// only because it is kept, not clamped to `i64::MAX`.
#[test]
fn a_whole_number_beyond_i64_in_a_one_of_alternative_is_kept() {
    let schema = json!({
        "type": "object",
        "properties": { "n": { "type": "integer" }, "m": { "type": "string" } },
        "oneOf": [
            { "required": ["n"], "properties": { "n": { "const": 1e20 } } },
            { "required": ["m"] }
        ]
    });
    let result = validate_arguments(&json!({ "n": 1e20 }), &schema);
    assert!(result.is_valid(), "{:?}", result.violations);
    assert_eq!(result.coerced["n"], json!(1e20));
}
