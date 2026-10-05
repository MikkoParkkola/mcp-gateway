// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7959: a capability's declared output root as MCP lets a client see it.

use serde_json::Value;

/// MCP (2025-11-25) restricts a tool's `outputSchema` root to `type: "object"`
/// and `structuredContent` to a JSON object (MIK-7959). A declared output root
/// of any other `type` (an array, a string) is carried under this key in both;
/// the text content keeps the declared shape. A root with no `type` is left as
/// declared.
const WRAPPED_OUTPUT_KEY: &str = "items";

fn output_root_is_wrapped(schema: &Value) -> bool {
    schema.get("type").is_some_and(|ty| ty != "object")
}

/// The `outputSchema` a client is shown for a declared output schema.
#[must_use]
pub(crate) fn advertised_output_schema(schema: &Value) -> Option<Value> {
    if schema.is_null() {
        return None;
    }
    Some(if output_root_is_wrapped(schema) {
        serde_json::json!({
            "type": "object",
            "properties": { WRAPPED_OUTPUT_KEY: schema },
            "required": [WRAPPED_OUTPUT_KEY],
        })
    } else {
        schema.clone()
    })
}

/// The `structuredContent` published for a result of the declared schema.
#[must_use]
pub(crate) fn published_output(schema: &Value, result: Value) -> Value {
    if output_root_is_wrapped(schema) {
        serde_json::json!({ WRAPPED_OUTPUT_KEY: result })
    } else {
        result
    }
}

/// Restore an envelope's `structuredContent` to the declared shape, so steps
/// written against the declared schema read what it describes. Returns whether
/// it was unwrapped; [`rewrap_published_output`] puts the wrapper back.
pub(crate) fn unwrap_published_output(schema: &Value, envelope: &mut Value) -> bool {
    if !output_root_is_wrapped(schema) {
        return false;
    }
    let Some(structured) = envelope.get_mut("structuredContent") else {
        return false;
    };
    let Some(inner) = structured.get_mut(WRAPPED_OUTPUT_KEY).map(Value::take) else {
        return false;
    };
    *structured = inner;
    true
}

/// Undo [`unwrap_published_output`]. The text content is left as it is.
pub(crate) fn rewrap_published_output(envelope: &mut Value) {
    if let Some(structured) = envelope.get_mut("structuredContent") {
        *structured = serde_json::json!({ WRAPPED_OUTPUT_KEY: structured.take() });
    }
}
