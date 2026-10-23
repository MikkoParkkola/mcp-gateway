// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Fixtures for the single-reader scan: each runs a literal source through
//! the same per-function check the crate walk uses, both sides.

use super::*;

/// The rows a source yields when it sits in `file`.
fn rows_of(file: &str, source: &str) -> Vec<String> {
    let parsed = syn::parse_file(source).expect("the fixture parses");
    let mut findings = Findings::new();
    let at = Place {
        file: file.to_string(),
        func: None,
    };
    for item in &parsed.items {
        findings.item(&at, item);
    }
    findings.rows
}

const ELSEWHERE: &str = "src/elsewhere.rs";

/// gpt r3 g3: an injected copy of `invoke_value` is a second decoder.
#[test]
fn fixture_invoke_value_copy_is_flagged() {
    let source = r#"fn copy(result: &Value) -> Option<Value> {
        result.get("structuredContent").cloned().or_else(|| {
            let text = result.pointer("/content/0/text")?.as_str()?;
            serde_json::from_str(text).ok()
        })
    }"#;
    assert_eq!(
        rows_of(ELSEWHERE, source),
        ["src/elsewhere.rs:copy: payload decoder"]
    );
}

/// tp3 grok F2: a verbatim copy of `extract_output_validation_target` (the
/// strict reader's own body) is a second decoder.
#[test]
fn fixture_strict_reader_copy_is_flagged() {
    let source = r#"fn copy(result: &Value) -> Option<Value> {
        if let Some(structured) = result.get("structuredContent") {
            return Some(structured.clone());
        }
        let content = result.get("content")?.as_array()?;
        if content.len() != 1 {
            return None;
        }
        let text = content[0].get("text")?.as_str()?;
        serde_json::from_str::<Value>(text).ok()
    }"#;
    assert_eq!(
        rows_of(ELSEWHERE, source),
        ["src/elsewhere.rs:copy: payload decoder"]
    );
}

/// gpt tp1 I1, grok tp1 I3: `application_value`'s live body is a decoder,
/// so its allowlist entry is really matched.
#[test]
fn fixture_application_value_body_is_flagged() {
    let source = r#"fn copy(mut result: Value) -> Value {
        if let Some(structured) = result.get_mut("structuredContent").map(Value::take) {
            return structured;
        }
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned()))
    }"#;
    assert_eq!(
        rows_of(ELSEWHERE, source),
        ["src/elsewhere.rs:copy: payload decoder"]
    );
}

/// The kept `delivered_value` wrapper (guard and pretty-print filter around
/// the survivor) is not a decoder: it parses nothing itself.
#[test]
fn fixture_delivered_value_wrapper_is_not_flagged() {
    let source = r#"fn delivered_value(delivered: &Value) -> Cow<'_, Value> {
        let one_block = delivered.get("structuredContent").is_none()
            && delivered.get("content").and_then(Value::as_array).is_some_and(|c| c.len() == 1);
        let text = delivered.pointer("/content/0/text").and_then(Value::as_str);
        let wrapped = (one_block.then(|| tool_result_payload(delivered)).flatten())
            .filter(|decoded| text == serde_json::to_string_pretty(decoded).ok().as_deref());
        wrapped.map_or(Cow::Borrowed(delivered), Cow::Owned)
    }"#;
    assert!(rows_of(ELSEWHERE, source).is_empty());
}

/// `apply_validated_output`'s envelope test reads both fields and parses no
/// text: not a decoder.
#[test]
fn fixture_envelope_check_is_not_flagged() {
    let source = r#"fn is_mcp_envelope(result: &Value) -> bool {
        result.as_object().is_some_and(|obj| {
            obj.get("content").is_some_and(Value::is_array) || obj.contains_key("structuredContent")
        })
    }"#;
    assert!(rows_of(ELSEWHERE, source).is_empty());
}

/// A `call_tool`-style error path reads content text and never
/// `structuredContent`: not a decoder (it is Rule B's negative half).
#[test]
fn fixture_error_text_path_is_not_flagged() {
    let source = r#"fn error_text(result: &Value) -> Vec<String> {
        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        serde_json::from_str::<Vec<String>>(text).unwrap_or_default()
    }"#;
    assert!(rows_of(ELSEWHERE, source).is_empty());
}

/// Rule A: removing a directive by its literal name outside the allowlist
/// is a second strip.
#[test]
fn fixture_literal_directive_strip_is_flagged() {
    let source = r#"fn intake(arguments: &mut Value) {
        if let Some(obj) = arguments.as_object_mut() {
            obj.remove("_full");
        }
    }"#;
    assert_eq!(
        rows_of(ELSEWHERE, source),
        ["src/elsewhere.rs:intake: strip `_full`"]
    );
}

/// Rule A: the shared strip's loop over the list names no literal.
#[test]
fn fixture_list_driven_strip_is_not_flagged() {
    let source = r#"fn execution_arguments(arguments: &mut Value) -> bool {
        if let Some(object) = arguments.as_object_mut() {
            for directive in EXECUTION_DIRECTIVES {
                object.remove(directive);
            }
        }
        false
    }"#;
    assert!(rows_of(ELSEWHERE, source).is_empty());
}

/// A method in an impl block is checked like a free function.
#[test]
fn fixture_impl_method_decoder_is_flagged() {
    let source = r#"impl Reader {
        fn read(&self, result: &Value) -> Option<Value> {
            result.get("structuredContent").cloned().or_else(|| {
                serde_json::from_str(result.pointer("/content/0/text")?.as_str()?).ok()
            })
        }
    }"#;
    assert_eq!(
        rows_of(ELSEWHERE, source),
        ["src/elsewhere.rs:read: payload decoder"]
    );
}
