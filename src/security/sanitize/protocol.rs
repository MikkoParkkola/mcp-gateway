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
pub(crate) fn validate_protocol_fields(
    request: &Value,
    nonces: &[&str],
    route: ProtocolRoute,
) -> Result<()> {
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
    // Protocol-position keys are refused when dirty, never stripped into
    // another field (an alias of `id`, `name` or the idempotency key): the
    // envelope's, `params`' own, and every key under `_meta`.
    let own_keys = |value: Option<&Value>| match value {
        Some(Value::Object(map)) => map.keys().try_for_each(|key| validate_protocol_text(key)),
        _ => Ok(()),
    };
    own_keys(Some(request))?;
    own_keys(request.get("params"))?;
    meta.map_or(Ok(()), validate_keys)?;
    let client_capabilities = meta.and_then(|meta| meta.get(KEY_CLIENT_CAPABILITIES));
    for capabilities in [request.pointer("/params/capabilities"), client_capabilities] {
        capabilities.map_or(Ok(()), validate_keys)?;
    }
    if route == ProtocolRoute::Meta
        && request.pointer("/params/name").and_then(Value::as_str) == Some("gateway_invoke")
        && let Some(Value::String(nonce)) = request.pointer("/params/arguments/nonce")
    {
        validate_protocol_text(nonce)?;
    }
    Ok(())
}

/// Which route a request came in on: on the meta routes (`/mcp`, stdio)
/// `gateway_invoke` is the gateway's own tool and its `arguments.nonce` the
/// signing nonce; on `/mcp/{name}` a backend tool of that name is the
/// backend's, and its arguments are business data.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProtocolRoute {
    Meta,
    Direct,
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

/// Where an `arguments` slot sits in the request: the call's own
/// (`params.arguments`), or one the gateway parses inside it (a meta tool's
/// inner `arguments`, a chain step's `arguments`).
#[derive(Clone, Copy)]
enum Slot {
    Call,
    Inner,
}

/// [`sanitize_json_value`] for one top-level request member, reaching into
/// the `arguments` slots the gateway decodes after this step when a client
/// sends them as a JSON string (MIK-8154 F1): there they are decoded,
/// sanitized and re-encoded, so an escaped NUL is refused before the decode
/// can produce it. Keys are matched as sanitized, so a dirty `arguments` key
/// is no way around it. No other string is decoded or re-encoded.
///
/// # Errors
///
/// `Error::Protocol` for a NUL anywhere, the encoded arguments included.
pub(super) fn sanitize_value(key: &str, value: &Value) -> Result<Value> {
    match value {
        Value::Object(params) if key == "params" => sanitize_object(params, |key, member| {
            (key == "arguments").then(|| sanitize_slot(member, Slot::Call))
        }),
        _ => sanitize_json_value(value),
    }
}

/// `map` sanitized member by member, keys first; `special` handles a member
/// itself when it returns `Some`.
fn sanitize_object(
    map: &serde_json::Map<String, Value>,
    special: impl Fn(&str, &Value) -> Option<Result<Value>>,
) -> Result<Value> {
    let mut sanitized = serde_json::Map::with_capacity(map.len());
    for (key, member) in map {
        let key = sanitize_string(key)?;
        let clean = match special(&key, member) {
            Some(handled) => handled?,
            None => sanitize_json_value(member)?,
        };
        sanitized.insert(key, clean);
    }
    Ok(Value::Object(sanitized))
}

/// An `arguments` slot: an object, or a string holding one (decoded,
/// sanitized, re-encoded); anything else is sanitized as it is.
fn sanitize_slot(value: &Value, slot: Slot) -> Result<Value> {
    if let Value::String(raw) = value
        && let Ok(Value::Object(decoded)) = serde_json::from_str::<Value>(raw)
    {
        let clean = sanitize_arguments(&decoded, slot)?;
        return serde_json::to_string(&clean)
            .map(Value::String)
            .map_err(|e| Error::Protocol(format!("Invalid 'arguments' JSON string: {e}")));
    }
    match value {
        Value::Object(map) => sanitize_arguments(map, slot),
        _ => sanitize_json_value(value),
    }
}

/// A call's arguments: its inner `arguments` and each chain step's
/// `arguments` are slots too; an inner slot holds a tool's own arguments,
/// sanitized as plain values.
fn sanitize_arguments(map: &serde_json::Map<String, Value>, slot: Slot) -> Result<Value> {
    match slot {
        Slot::Inner => sanitize_json_value(&Value::Object(map.clone())),
        Slot::Call => sanitize_object(map, |key, member| match (key, member) {
            ("arguments", _) => Some(sanitize_slot(member, Slot::Inner)),
            ("steps", Value::Array(steps)) => Some(sanitize_steps(steps)),
            _ => None,
        }),
    }
}

/// A chain's steps, each step's `arguments` an inner slot.
fn sanitize_steps(steps: &[Value]) -> Result<Value> {
    steps
        .iter()
        .map(|step| match step {
            Value::Object(map) => sanitize_object(map, |key, member| {
                (key == "arguments").then(|| sanitize_slot(member, Slot::Inner))
            }),
            other => sanitize_json_value(other),
        })
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}
