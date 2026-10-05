// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The output-schema mismatch log runs before the response firewall, so it
//! names where a result broke its schema and the types involved, never a
//! value or an undeclared key: either can be a credential the backend
//! returned, which the firewall has not yet seen.

use serde_json::json;

use super::enforce_output_schema;
use crate::test_log_capture::{count, records};

const TOKEN: &str = "tok-7f3a9c-do-not-log";
const WARNING: &str = "did not match its declared output schema";

fn schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {"count": {"type": "integer"}, "name": {"type": "string"}},
        "required": ["name"],
    })
}

/// One warning per result, carrying `expected` and no trace of [`TOKEN`],
/// for the bare payload and for the same payload inside an MCP envelope.
fn assert_logged_without_token(payload: &serde_json::Value, expected: &[&str]) {
    let envelope = json!({"content": [{"type": "text", "text": payload.to_string()}]});
    for result in [payload.clone(), envelope] {
        let logs = records(|| {
            let _ = enforce_output_schema("srv", "tool", result.clone(), Some(&schema()));
        });
        assert_eq!(count(&logs, "WARN", WARNING), 1, "{logs:?}");
        let text = serde_json::to_string(&logs).unwrap();
        assert!(
            !text.contains(TOKEN),
            "a backend value reached the log: {text}"
        );
        let warning = logs
            .iter()
            .find(|r| {
                r["fields"]["message"]
                    .as_str()
                    .is_some_and(|m| m.contains(WARNING))
            })
            .unwrap();
        let mismatch = warning["fields"]["mismatch"].as_str().unwrap_or_default();
        for part in expected {
            assert!(mismatch.contains(part), "{part:?} not in {mismatch:?}");
        }
    }
}

/// A token in an integer-typed field: the path and both types, not the token.
#[test]
fn a_type_mismatch_log_names_the_path_and_types_not_the_value() {
    assert_logged_without_token(
        &json!({"name": "n", "count": TOKEN}),
        &["count: expected integer, got string"],
    );
}

/// A token as an undeclared key (with a required field missing, which the
/// validator reports in the same pass): the key is never named.
#[test]
fn an_undeclared_key_is_never_named_in_the_log() {
    assert_logged_without_token(
        &json!({TOKEN: 1}),
        &["undeclared key", "name: expected string, got missing"],
    );
}

/// MIK-7959: an array root published under `items` is validated in its
/// declared shape, as the capability route runs it, and the text content is
/// not rewritten into the wrapped shape.
#[test]
fn a_wrapped_output_root_is_validated_unwrapped_and_keeps_its_text() {
    let declared = json!({ "type": "array", "items": { "type": "string" } });
    let payload = json!(["a", "b"]);
    let text = serde_json::to_string_pretty(&payload).unwrap();
    let mut envelope = json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": crate::capability::published_output(&declared, payload.clone()),
        "isError": false,
    });

    assert!(crate::capability::unwrap_published_output(
        &declared,
        &mut envelope
    ));
    let mut validated = enforce_output_schema("caps", "listing", envelope, Some(&declared));
    crate::capability::rewrap_published_output(&mut validated);

    assert_eq!(validated["structuredContent"], json!({ "items": payload }));
    assert_eq!(validated["content"][0]["text"], json!(text));
}
