// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7954: an injected secret that reads as a short JSON number or as a
//! literal `true`, `false` or `null` is redacted where the result holds a value
//! equal to it by exact JSON equality, and nowhere else.

use serde_json::{Value, json};

use super::redact_value;

#[test]
fn a_short_number_secret_is_redacted_on_exact_equality() {
    let mut value: Value = serde_json::from_str(
        r#"{"a": 7, "b": 42, "c": -5, "d": 1.5, "near": 70, "other": 1234, "list": [7, 8]}"#,
    )
    .unwrap();
    let secrets = ["7", "42", "-5", "1.5"].map(str::to_owned);
    redact_value(&mut value, &secrets);
    for key in ["a", "b", "c", "d"] {
        assert_eq!(value[key], "[redacted]", "{key}: {value}");
    }
    assert_eq!(value["list"][0], "[redacted]", "{value}");
    assert_eq!(value["list"][1], 8, "{value}");
    assert_eq!(value["near"], 70, "a number containing it is untouched");
    assert_eq!(value["other"], 1234, "{value}");
}

#[test]
fn a_literal_secret_is_redacted_where_the_result_equals_it() {
    let mut value = json!({"t": true, "f": false, "n": null, "s": "keep", "deep": [null, true]});
    redact_value(&mut value, &["true".to_owned(), "null".to_owned()]);
    assert_eq!(value["t"], "[redacted]", "{value}");
    assert_eq!(value["n"], "[redacted]", "{value}");
    assert_eq!(
        value["deep"],
        json!(["[redacted]", "[redacted]"]),
        "{value}"
    );
    assert_eq!(value["f"], false, "{value}");
    assert_eq!(value["s"], "keep", "{value}");

    let mut value = json!({"f": false, "t": true});
    redact_value(&mut value, &["false".to_owned()]);
    assert_eq!(value["f"], "[redacted]", "{value}");
    assert_eq!(value["t"], true, "{value}");
}

/// Text that is not a JSON scalar ("007", "TRUE") is not taken for one.
#[test]
fn a_short_secret_that_is_not_json_matches_no_scalar() {
    let mut value = json!({"n": 7, "t": true});
    redact_value(&mut value, &["007".to_owned(), "TRUE".to_owned()]);
    assert_eq!(value, json!({"n": 7, "t": true}));
}

/// An integer-valued form is judged by its significant digits: zeros leading
/// the fraction, or a zero coefficient under a large exponent, still match.
#[test]
fn integer_forms_with_fraction_zeros_or_a_zero_coefficient_match() {
    let mut value: Value = serde_json::from_str(
        r#"{"big": 1000000000000000000, "near": 999999999999999999, "zero": 0, "one": 1}"#,
    )
    .unwrap();
    let secrets = ["0.00000000000000000000000000001e47", "0e99"].map(str::to_owned);
    redact_value(&mut value, &secrets);
    assert_eq!(value["big"], "[redacted]", "{value}");
    assert_eq!(value["zero"], "[redacted]", "{value}");
    assert_eq!(value["near"], 999_999_999_999_999_999_u64, "{value}");
    assert_eq!(value["one"], 1, "{value}");
}

/// What `serde_json` accepts as a number is matched as one: whitespace around
/// the text, and a zero coefficient under an exponent past i64.
#[test]
fn padded_and_overflowing_zero_forms_match_their_integer() {
    let mut value: Value =
        serde_json::from_str(r#"{"a": 12345, "near": 12346, "zero": 0, "one": 1}"#).unwrap();
    let secrets = ["12345.0\n", "0e9223372036854775808"].map(str::to_owned);
    redact_value(&mut value, &secrets);
    assert_eq!(value["a"], "[redacted]", "{value}");
    assert_eq!(value["zero"], "[redacted]", "{value}");
    assert_eq!(value["near"], 12346, "{value}");
    assert_eq!(value["one"], 1, "{value}");
}

/// Below the floor a number secret matches by JSON equality alone: "1e5" is
/// the float 1e5, so the integer 100000 stays.
#[test]
fn a_short_exponent_secret_leaves_the_equal_integer() {
    let mut value: Value = serde_json::from_str(r#"{"f": 1e5, "i": 100000}"#).unwrap();
    redact_value(&mut value, &["1e5".to_owned()]);
    assert_eq!(value["f"], "[redacted]", "{value}");
    assert_eq!(value["i"], 100_000, "{value}");
}

/// A number secret with a fraction names no integer: "12345.5" redacts the
/// float 12345.5 and leaves the integer 12345 its digits start with.
#[test]
fn a_fractional_secret_leaves_the_integer_it_truncates_to() {
    let mut value: Value = serde_json::from_str(r#"{"f": 12345.5, "i": 12345}"#).unwrap();
    redact_value(&mut value, &["12345.5".to_owned()]);
    assert_eq!(value["f"], "[redacted]", "{value}");
    assert_eq!(value["i"], 12345, "{value}");
}
