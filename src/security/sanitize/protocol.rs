// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The request-level parts of the one sanitize step (MIK-8154 SAN.1): the
//! protocol fields it validates without rewriting, and the walk that reaches
//! tool arguments a client sent as a JSON string.

use serde_json::Value;

use super::{sanitize_json_value, sanitize_string, validate_protocol_text};
use crate::protocol::meta::KEY_CLIENT_CAPABILITIES;
use crate::{Error, Result};

/// Validate `id`, `method`, the capability keys, the `_meta` nonces, the
/// idempotency key and `gateway_invoke`'s argument nonce
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
    // The idempotency key too: stripped, two keys could become one.
    let key = crate::protocol::mrtr::IDEMPOTENCY_KEY_META;
    for field in nonces.iter().chain(std::iter::once(&key)) {
        if let Some(Value::String(text)) = meta.and_then(|meta| meta.get(field)) {
            validate_protocol_text(text)?;
        }
    }
    // The method and the capability keys intake reads before the sanitize
    // step (session and hardened checks, muse 6 ruling (b)): refused, never
    // read dirty and later rewritten into something else.
    if let Some(Value::String(method)) = request.get("method") {
        validate_protocol_text(method)?;
    }
    let client_capabilities = meta.and_then(|meta| meta.get(KEY_CLIENT_CAPABILITIES));
    for capabilities in [request.pointer("/params/capabilities"), client_capabilities] {
        capabilities.map_or(Ok(()), validate_keys)?;
    }
    if request.pointer("/params/name").and_then(Value::as_str) == Some("gateway_invoke")
        && let Some(Value::String(nonce)) = request.pointer("/params/arguments/nonce")
    {
        validate_protocol_text(nonce)?;
    }
    Ok(())
}

/// Every object key in `value`, at any depth, passes [`validate_protocol_text`].
fn validate_keys(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => map.iter().try_for_each(|(key, member)| {
            validate_protocol_text(key)?;
            validate_keys(member)
        }),
        Value::Array(items) => items.iter().try_for_each(validate_keys),
        _ => Ok(()),
    }
}

/// [`sanitize_json_value`], also reaching into an `arguments` member that is a
/// string holding a JSON object (a client style every route accepts and
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
