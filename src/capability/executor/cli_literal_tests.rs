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
