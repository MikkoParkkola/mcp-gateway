// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8663 T5 (DUPC-6.PR6.5): the strict payload rule, one table for every
//! reader of "the tool's value inside an MCP result". `structuredContent`
//! when present, else exactly one `content` block whose text parses as JSON,
//! else none.

use serde_json::{Value, json};

/// `(case, result, expected payload)`.
fn rows() -> Vec<(&'static str, Value, Option<Value>)> {
    let text = |t: &str| json!({"type": "text", "text": t});
    let mut rows = vec![
        (
            "1 structuredContent wins over valid text",
            json!({"structuredContent": {"a": 1}, "content": [text("{\"b\": 2}")]}),
            Some(json!({"a": 1})),
        ),
        (
            "2 one JSON text block decodes",
            json!({"content": [text("{\"b\": 2}")]}),
            Some(json!({"b": 2})),
        ),
        (
            "3 two blocks without structuredContent give none",
            json!({"content": [text("{\"b\": 2}"), text("{\"c\": 3}")]}),
            None,
        ),
        (
            "4 structuredContent beside two blocks wins",
            json!({"structuredContent": {"a": 1}, "content": [text("1"), text("2")]}),
            Some(json!({"a": 1})),
        ),
        (
            "5 a null structuredContent is present and wins",
            json!({"structuredContent": null, "content": [text("{\"b\": 2}")]}),
            Some(Value::Null),
        ),
        (
            "6 non-JSON text gives none",
            json!({"content": [text("not json")]}),
            None,
        ),
        ("7 empty content gives none", json!({"content": []}), None),
        (
            "8 content that is not an array gives none",
            json!({"content": "{\"b\": 2}"}),
            None,
        ),
        (
            "9 a block with no string text gives none",
            json!({"content": [{"type": "text", "text": 7}]}),
            None,
        ),
        ("10 a bare value gives none", json!({"b": 2}), None),
    ];
    for (label, raw, value) in [
        ("11 null text decodes", "null", Value::Null),
        ("11 false text decodes", "false", json!(false)),
        ("11 zero text decodes", "0", json!(0)),
        ("11 string text decodes", "\"s\"", json!("s")),
        ("11 array text decodes", "[1]", json!([1])),
    ] {
        rows.push((label, json!({"content": [text(raw)]}), Some(value)));
    }
    rows
}

fn check(reader: &str, read: impl Fn(&Value) -> Option<Value>) {
    let wrong: Vec<String> = rows()
        .into_iter()
        .filter_map(|(case, result, expected)| {
            let got = read(&result);
            (got != expected).then(|| format!("{case}: got {got:?}, want {expected:?}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{reader} breaks the strict rule: {wrong:#?}"
    );
}

#[test]
fn output_validation_target_follows_the_strict_rule() {
    check(
        "extract_output_validation_target",
        super::output_shape::extract_output_validation_target,
    );
}

/// RED on base: `invoke_value` reads the first of several blocks (row 3).
#[test]
fn invoke_value_follows_the_strict_rule() {
    check("invoke_value", super::audit::invoke_value);
}
