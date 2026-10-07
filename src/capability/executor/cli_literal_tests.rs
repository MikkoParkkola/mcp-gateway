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

/// Text that is not a JSON scalar ("TRUE") is not taken for one. "007" is not
/// JSON either, but it names the number 7 by value, so it redacts it at any
/// length (MIK-8065 ruling: a leak is worse than blanking an equal number,
/// #3238 already blanks it for the literal `7`, and the 4-byte floor was meant
/// for caller values, which never reach this function).
#[test]
fn a_secret_that_is_not_json_matches_no_scalar_but_its_number_value() {
    let mut value = json!({"n": 7, "t": true});
    redact_value(&mut value, &["007".to_owned(), "TRUE".to_owned()]);
    assert_eq!(value, json!({"n": "[redacted]", "t": true}));
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

/// A short exponent secret matches by value too: "1e5" redacts the float 1e5
/// and the equal integer 100000 (MIK-8065 ruling, as above).
#[test]
fn a_short_exponent_secret_redacts_the_equal_integer() {
    let mut value: Value = serde_json::from_str(r#"{"f": 1e5, "i": 100000}"#).unwrap();
    redact_value(&mut value, &["1e5".to_owned()]);
    assert_eq!(value["f"], "[redacted]", "{value}");
    assert_eq!(value["i"], "[redacted]", "{value}");
}

/// `MIK-8065.NUM.1`/`NUM.2`: a credential of 1-3 bytes in a number form that is
/// not a JSON literal is redacted from a result number equal to it, and never
/// from one whose digits merely hold it. Mutant: the length floor restored.
#[test]
fn a_short_credential_in_another_number_form_is_redacted_by_value() {
    let mut value: Value =
        serde_json::from_str(r#"{"n": 12, "f": 12.0, "held": 912, "near": 13}"#).unwrap();
    redact_value(&mut value, &["012".to_owned()]);
    assert_eq!(value["n"], "[redacted]", "{value}");
    assert_eq!(value["f"], "[redacted]", "{value}");
    assert_eq!(value["held"], 912, "{value}");
    assert_eq!(value["near"], 13, "{value}");

    let mut value = json!({"n": 12, "neg": -12});
    redact_value(&mut value, &["+12".to_owned()]);
    assert_eq!(value, json!({"n": "[redacted]", "neg": "[redacted]"}));

    let mut value: Value = serde_json::from_str(r#"{"i": 100, "f": 100.0, "k": 1000}"#).unwrap();
    redact_value(&mut value, &["1e2".to_owned()]);
    assert_eq!(value["i"], "[redacted]", "{value}");
    assert_eq!(value["f"], "[redacted]", "{value}");
    assert_eq!(value["k"], 1000, "{value}");
}

/// `MIK-8065.NUM.4`: a credential with no digit before its exponent names no
/// number, so it never blanks a zero. Mutant: the coefficient check removed.
#[test]
fn a_credential_with_no_digit_leaves_every_zero() {
    for secret in ["e123", "-e10", "    ", "+", "e2", "-.e5"] {
        let mut value: Value = serde_json::from_str(r#"{"z": 0, "zf": 0.0, "one": 1}"#).unwrap();
        redact_value(&mut value, &[secret.to_owned()]);
        assert_eq!(value["z"], 0, "{secret:?}: {value}");
        assert_eq!(value["one"], 1, "{secret:?}: {value}");
        assert!(value["zf"].is_number(), "{secret:?}: {value}");
    }
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

/// Integer-valued needles in decimal or exponent form, against results the
/// child prints as integers: compared exactly, so an integer one past f64
/// precision is never taken for the needle. Crossed with sign and leading
/// zeros, both exponent letters, and an independent result sign.
#[test]
fn integer_valued_number_forms_match_integers_exactly() {
    // (needle body, own integer, adjacent integer)
    let shapes = [
        ("12345.0", "12345", "12346"),
        ("1.2345e4", "12345", "12346"),
        ("1.2345E4", "12345", "12346"),
        ("123450e-1", "12345", "12346"),
        ("9007199254740992.0", "9007199254740992", "9007199254740993"),
        ("9007199254740993.0", "9007199254740993", "9007199254740992"),
        (
            "9.007199254740993e15",
            "9007199254740993",
            "9007199254740992",
        ),
        (
            "18446744073709551615.0",
            "18446744073709551615",
            "18446744073709551614",
        ),
    ];
    let mut failures = Vec::new();
    for sign in ["", "+", "-"] {
        for zeros in ["", "00"] {
            for result_sign in ["", "-"] {
                for (body, own, adjacent) in shapes {
                    // A u64 past i64 cannot be negative in JSON integers.
                    if result_sign == "-" && own.len() > 19 {
                        continue;
                    }
                    let needle = format!("{sign}{zeros}{body}");
                    let text = format!(
                        r#"{{"own": {result_sign}{own}, "adjacent": {result_sign}{adjacent}}}"#
                    );
                    let mut value: Value = serde_json::from_str(&text).unwrap();
                    redact_value(&mut value, std::slice::from_ref(&needle));
                    if value["own"] != "[redacted]" || value["adjacent"] == "[redacted]" {
                        failures.push(format!("{needle} vs {result_sign}{own}: {value}"));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} cases wrong:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// MIK-7954.FIX.1: a numeric secret is matched as a whole number only.
#[test]
fn a_numeric_secret_is_redacted_where_the_result_equals_it() {
    let mut value = json!({"n": 123_456, "neg": -123_456, "list": [123_456]});
    redact_value(&mut value, &["123456".to_owned()]);
    assert_eq!(value["n"], "[redacted]", "{value}");
    assert_eq!(value["neg"], "[redacted]", "{value}");
    assert_eq!(value["list"][0], "[redacted]", "{value}");
}

#[test]
fn a_number_holding_the_secret_digits_is_left_whole() {
    let mut value = json!({"a": 912_345, "b": 12_340, "c": -91_234, "d": 1_234.5});
    redact_value(&mut value, &["1234".to_owned()]);
    assert_eq!(
        value,
        json!({"a": 912_345, "b": 12_340, "c": -91_234, "d": 1_234.5}),
        "only a number equal to the secret is redacted"
    );
}

#[test]
fn a_numeric_secret_inside_a_string_is_still_redacted() {
    let mut value = json!({"s": "id-912345-x", "k": "pin=1234"});
    redact_value(&mut value, &["1234".to_owned()]);
    assert_eq!(
        value,
        json!({"s": "id-9[redacted]5-x", "k": "pin=[redacted]"}),
        "the secret goes, the text around it stays"
    );
}
