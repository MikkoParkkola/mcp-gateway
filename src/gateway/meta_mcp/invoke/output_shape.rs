// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Output-schema enforcement and the MCP-envelope helpers it shares with the
//! capability projection. Moved out of `invoke.rs` unchanged.

use serde_json::Value;

use crate::capability::validate_output;

pub(in crate::gateway::meta_mcp) fn enforce_output_schema(
    server: &str,
    tool: &str,
    result: Value,
    output_schema: Option<&Value>,
) -> Value {
    let Some(schema) = output_schema else {
        return result;
    };

    if result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return result;
    }

    // No inner payload, no validation. The schema describes the tool's output,
    // not the MCP envelope carrying it, so falling back to the envelope
    // validates the wrong document and then republishes it under
    // `structuredContent` — carrying the backend's own `requestState` past the
    // mint that exists to replace it (MIK-7212.MRTR.2a), and overwriting a
    // single plain-text item with a dump of its own wrapper.
    // `apply_capability_projection` refuses this same case as bug #167; the
    // schema path refuses it here.
    let validation_target = match extract_output_validation_target(&result) {
        Some(target) => target,
        // A bare payload is its own validation target: no envelope to unwrap,
        // and `apply_validated_output` returns the coerced value directly.
        None if !is_mcp_envelope(&result) => result.clone(),
        None => return result,
    };
    let validation = validate_output(&validation_target, schema);
    if validation.is_valid() {
        apply_validated_output(&result, validation.coerced)
    } else {
        // Output-schema mismatch is ADVISORY, not fatal, for proxied tools.
        // Upstream APIs (e.g. open-meteo, travel providers) legitimately return
        // more fields than a hand-authored capability schema declares; hard-
        // rejecting would break a working tool and surface as an opaque error in
        // clients. We log the mismatch and pass the result through, still
        // populating `structuredContent` from the actual payload so spec-
        // compliant clients (Open WebUI) receive structured output. The gateway
        // does not author these fields — it proxies them — so extra keys are not
        // a trust-boundary concern here.
        tracing::warn!(
            server,
            tool,
            mismatch = %mismatch_shape(
                validation.violations.iter().map(|v| v.param.as_str()),
                &validation_target,
                schema,
            ),
            "tool output did not match its declared output schema; passing through (advisory)"
        );
        apply_validated_output(&result, validation_target)
    }
}

/// Each violation as its path and the expected and actual JSON type, never a
/// value: this log is written before the response firewall inspects the
/// result, and a value or an undeclared key can be a credential the backend
/// returned. A key the schema does not declare is backend text, so it is
/// named only as "undeclared key".
fn mismatch_shape<'a>(
    params: impl Iterator<Item = &'a str>,
    target: &Value,
    schema: &Value,
) -> String {
    let declared = schema.get("properties").and_then(Value::as_object);
    params
        .map(|param| match declared.and_then(|props| props.get(param)) {
            Some(prop) => {
                let expected = match prop.get("type") {
                    Some(Value::String(ty)) => ty.clone(),
                    Some(other) => other.to_string(),
                    None => "any".to_owned(),
                };
                let actual = target.get(param).map_or("missing", json_type);
                format!("{param}: expected {expected}, got {actual}")
            }
            None if param.is_empty() => format!("$: got {}", json_type(target)),
            None => "undeclared key".to_owned(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn json_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(n) if n.is_f64() => "number",
        Value::Number(_) => "integer",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

pub(super) fn extract_output_validation_target(result: &Value) -> Option<Value> {
    if let Some(structured) = result.get("structuredContent") {
        return Some(structured.clone());
    }

    let content = result.get("content")?.as_array()?;
    if content.len() != 1 {
        return None;
    }
    let text = content[0].get("text")?.as_str()?;
    serde_json::from_str::<Value>(text).ok()
}

/// Whether a value is an MCP tool-result envelope rather than a bare payload.
///
/// The two are validated differently: an envelope's schema describes what it
/// CARRIES, so an envelope with nothing extractable has nothing to validate,
/// while a bare payload is its own target. [`apply_validated_output`] keys its
/// re-wrap on the same two fields, so the answer stays consistent across both.
fn is_mcp_envelope(result: &Value) -> bool {
    result.as_object().is_some_and(|obj| {
        // `content` must be an ARRAY, which is the shape
        // `extract_output_validation_target` consumes and the specification
        // requires. Keying on the bare presence of the name would classify a
        // payload that merely has a `content` field as an envelope and return
        // it unvalidated — failing the schema gate open on exactly the values
        // it exists to check.
        obj.get("content").is_some_and(Value::is_array) || obj.contains_key("structuredContent")
    })
}

pub(super) fn apply_validated_output(result: &Value, validated: Value) -> Value {
    if !is_mcp_envelope(result) {
        return validated;
    }
    let Some(obj) = result.as_object() else {
        return validated;
    };

    let mut obj = obj.clone();
    obj.insert("structuredContent".to_owned(), validated.clone());
    if let Some(content) = obj.get_mut("content").and_then(Value::as_array_mut)
        && content.len() == 1
        && let Some(text_obj) = content[0].as_object_mut()
        && text_obj.get("type").and_then(Value::as_str) == Some("text")
    {
        text_obj.insert(
            "text".to_owned(),
            Value::String(
                serde_json::to_string_pretty(&validated).unwrap_or_else(|_| validated.to_string()),
            ),
        );
    }
    Value::Object(obj)
}

#[cfg(test)]
#[path = "output_shape_tests.rs"]
mod tests;
