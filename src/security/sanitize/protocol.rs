// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The request-level parts of the one sanitize step (MIK-8154 SAN.1): the
//! protocol fields it validates without rewriting, and the walk that reaches
//! tool arguments a client sent as a JSON string.

use serde_json::Value;

use super::{sanitize_json_value, sanitize_string, validate_protocol_text};
use crate::{Error, Result};

/// Validate `id`, the `_meta` nonces and `gateway_invoke`'s argument nonce
/// before anything takes them off the request (MIK-8154 S2'), whatever its
/// backends: these fields are the gateway's. Signing capture removes the
/// argument nonce before sanitizing, so it is checked here or nowhere.
///
/// # Errors
///
/// `Error::Protocol` for the first field that fails [`validate_protocol_text`].
pub(crate) fn validate_protocol_fields(request: &Value, nonces: &[&str]) -> Result<()> {
    if let Some(Value::String(id)) = request.get("id") {
        validate_protocol_text(id)?;
    }
    let meta = request.pointer("/params/_meta");
    for field in nonces {
        if let Some(Value::String(text)) = meta.and_then(|meta| meta.get(field)) {
            validate_protocol_text(text)?;
        }
    }
    if request.pointer("/params/name").and_then(Value::as_str) == Some("gateway_invoke")
        && let Some(Value::String(nonce)) = request.pointer("/params/arguments/nonce")
    {
        validate_protocol_text(nonce)?;
    }
    Ok(())
}

/// [`sanitize_json_value`], also reaching into an `arguments` member that is a
/// string holding a JSON object (the OpenAI style every route accepts and
/// decodes after this step): it is decoded, sanitized as an object and
/// re-encoded, so an escaped NUL in it is refused and an escaped control
/// character stripped before the decode can produce it.
///
/// # Errors
///
/// `Error::Protocol` for a NUL anywhere, the encoded arguments included.
pub(super) fn sanitize_value(value: &Value) -> Result<Value> {
    match value {
        Value::Object(map) => {
            let mut sanitized = serde_json::Map::with_capacity(map.len());
            for (key, member) in map {
                let clean = match member {
                    Value::String(raw) if key == "arguments" => {
                        encoded_arguments(raw).unwrap_or_else(|| sanitize_json_value(member))?
                    }
                    _ => sanitize_value(member)?,
                };
                sanitized.insert(sanitize_string(key)?, clean);
            }
            Ok(Value::Object(sanitized))
        }
        Value::Array(items) => items
            .iter()
            .map(sanitize_value)
            .collect::<Result<Vec<_>>>()
            .map(Value::Array),
        other => sanitize_json_value(other),
    }
}

/// `raw` decoded, sanitized and re-encoded when it holds a JSON object; `None`
/// when it does not (it is then sanitized as the plain string it is).
fn encoded_arguments(raw: &str) -> Option<Result<Value>> {
    let decoded @ Value::Object(_) = serde_json::from_str::<Value>(raw).ok()? else {
        return None;
    };
    Some(sanitize_value(&decoded).and_then(|clean| {
        serde_json::to_string(&clean)
            .map(Value::String)
            .map_err(|e| Error::Protocol(format!("Invalid 'arguments' JSON string: {e}")))
    }))
}
