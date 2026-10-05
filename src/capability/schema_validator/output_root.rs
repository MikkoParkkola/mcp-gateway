// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7959: a capability's declared output root as MCP lets a client see it.

use serde_json::Value;

/// MCP (2025-11-25) restricts a tool's `outputSchema` root to `type: "object"`
/// and `structuredContent` to a JSON object (MIK-7959). A declared root that is
/// not object-shaped (an array, a string, a type list such as
/// `["object", "null"]`, or a typeless `anyOf`) is carried under this key in
/// both; the text content keeps the declared shape.
const WRAPPED_OUTPUT_KEY: &str = "items";

/// The `$id` a wrapped declared schema is given when it has none.
const DECLARED_OUTPUT_ID: &str = "urn:mcp-gateway:declared-output";

/// Object-shaped: `type: "object"`, or no `type` but `properties`, which
/// `validate_output` already refuses for anything but an object.
fn output_root_is_wrapped(schema: &Value) -> bool {
    !schema.is_null()
        && match schema.get("type") {
            Some(ty) => ty != "object",
            None => schema.get("properties").is_none(),
        }
}

/// The `outputSchema` a client is shown for a declared output schema.
#[must_use]
pub(crate) fn advertised_output_schema(schema: &Value) -> Option<Value> {
    if schema.is_null() {
        return None;
    }
    let mut shown = schema.clone();
    if !output_root_is_wrapped(schema) {
        if let Some(object) = shown.as_object_mut() {
            object
                .entry("type")
                .or_insert_with(|| Value::from("object"));
        }
        return Some(shown);
    }
    // The declared schema moves to `/properties/items`. Given an `$id`, it is
    // its own schema resource there, so its `#` and `#/...` references keep
    // resolving inside it, nested resources and instance data untouched. One
    // that already has an `$id` is a resource as declared.
    if let Some(object) = shown.as_object_mut() {
        object
            .entry("$id")
            .or_insert_with(|| Value::from(DECLARED_OUTPUT_ID));
    }
    let mut wrapper = serde_json::json!({
        "type": "object",
        "properties": { WRAPPED_OUTPUT_KEY: shown },
        "required": [WRAPPED_OUTPUT_KEY],
    });
    // The wrapper is read in the declared dialect too.
    if let (Some(dialect), Some(object)) = (schema.get("$schema"), wrapper.as_object_mut()) {
        object.insert("$schema".to_owned(), dialect.clone());
    }
    Some(wrapper)
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
