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
    // The argument nonce, read where the meta route reads it: the name as
    // dispatch routes on it (sanitized), `arguments` decoded when a client
    // sent them as a JSON string, so neither form launders a dirty nonce.
    if route == ProtocolRoute::Meta
        && let Some(Value::String(name)) = request.pointer("/params/name")
        && sanitize_string(name).is_ok_and(|name| name == "gateway_invoke")
    {
        let arguments = match request.pointer("/params/arguments") {
            Some(Value::String(raw)) => serde_json::from_str::<Value>(raw).ok(),
            other => other.cloned(),
        };
        if let Some(Value::String(nonce)) = arguments.as_ref().and_then(|a| a.get("nonce")) {
            validate_protocol_text(nonce)?;
        }
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

/// Where an `arguments` slot sits in the request: a meta tool's own (the
/// gateway parses the inner `arguments` and chain steps inside it), any other
/// tool's own (its contents are the tool's, plain values), or one the gateway
/// parses inside a meta tool's.
#[derive(Clone, Copy)]
enum Slot {
    Meta,
    Tool,
    Inner,
}

/// The meta tools whose arguments hold `arguments` the gateway decodes. Their
/// names always resolve to the gateway's own handler: surfacing refuses a
/// backend tool under any meta-tool name (`MetaMcp::with_surfaced_tools`,
/// pinned by `with_surfaced_tools_drops_all_known_meta_tool_names`), so a
/// name here is never a backend's tool on a meta route.
const META_PARSED: [&str; 3] = ["gateway_invoke", "gateway_run_playbook", "gateway_execute"];

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
pub(super) fn sanitize_value(key: &str, value: &Value, route: ProtocolRoute) -> Result<Value> {
    let Value::Object(params) = value else {
        return sanitize_json_value(value);
    };
    if key != "params" {
        return sanitize_json_value(value);
    }
    // Judged on the name as sanitized: the name dispatch will route on.
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .map(sanitize_string);
    let meta = route == ProtocolRoute::Meta
        && matches!(name, Some(Ok(name)) if META_PARSED.contains(&name.as_str()));
    let slot = if meta { Slot::Meta } else { Slot::Tool };
    sanitize_object(params, |key, member| {
        (key == "arguments").then(|| sanitize_slot(member, slot))
    })
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

/// A meta call's arguments: its inner `arguments` and each `chain` step's
/// `arguments` (`gateway_execute`, dispatched through the invoke funnel,
/// which decodes them) are slots too; an inner slot holds a tool's own arguments,
/// sanitized as plain values.
fn sanitize_arguments(map: &serde_json::Map<String, Value>, slot: Slot) -> Result<Value> {
    match slot {
        Slot::Tool | Slot::Inner => sanitize_json_value(&Value::Object(map.clone())),
        Slot::Meta => sanitize_object(map, |key, member| match (key, member) {
            ("arguments", _) => Some(sanitize_slot(member, Slot::Inner)),
            ("chain", Value::Array(steps)) => Some(sanitize_steps(steps)),
            _ => None,
        }),
    }
}

/// A `chain`'s steps, each step's `arguments` an inner slot.
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::ProtocolRoute;
    use crate::security::sanitize::sanitize_request;

    /// S9e (fixes seat gpt): a tool's own field named `arguments` holding a
    /// JSON string is the tool's business, never decoded or re-encoded: on
    /// the direct route, and for a tool that is not a parsing meta tool on
    /// the meta route. A parsing meta tool's inner slot is decoded.
    #[test]
    fn s9e_only_gateway_parsed_slots_are_decoded() {
        let opaque = "{\"b\": 1,  \"a\": 2}";
        for (route, name) in [
            (ProtocolRoute::Direct, "gateway_invoke"),
            (ProtocolRoute::Direct, "read"),
            (ProtocolRoute::Meta, "read"),
        ] {
            let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": {"arguments": opaque}}});
            let clean = sanitize_request(&request, route).expect("sanitizes");
            assert_eq!(clean["params"]["arguments"]["arguments"], opaque, "{name}");
        }
        let invoke = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "gateway_invoke", "arguments": {"arguments": opaque}}});
        let clean = sanitize_request(&invoke, ProtocolRoute::Meta).expect("sanitizes");
        let inner = clean["params"]["arguments"]["arguments"]
            .as_str()
            .expect("a string");
        assert_ne!(inner, opaque, "the meta slot was not re-encoded");
        let decoded: serde_json::Value = serde_json::from_str(inner).expect("JSON");
        assert_eq!(decoded, json!({"b": 1, "a": 2}));
    }

    /// Round-3 seats (both): `gateway_execute`'s `chain` step arguments are a
    /// slot: an encoded NUL there is refused on the meta route.
    #[test]
    fn s9g_an_encoded_nul_in_a_chain_step_is_refused() {
        let step =
            json!({"tool": "alpha:read", "arguments": json!({"cmd": "a\u{0}b"}).to_string()});
        let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "gateway_execute", "arguments": {"chain": [step]}}});
        assert!(sanitize_request(&request, ProtocolRoute::Meta).is_err());
    }

    /// Round-3 seat muse 2 and 4: `gateway_invoke`'s argument nonce is
    /// refused when dirty whether `arguments` is an object or a JSON string,
    /// and whether or not the tool name carries a strippable character.
    #[test]
    fn s4e_the_invoke_nonce_is_checked_in_every_form() {
        use super::validate_protocol_fields;
        let nonce_args = json!({"server": "alpha", "tool": "read", "nonce": "a\u{7}b"});
        for (name, arguments) in [
            ("gateway_invoke", nonce_args.clone()),
            ("gateway_invoke", json!(nonce_args.to_string())),
            ("gateway_invoke\u{7}", nonce_args.clone()),
        ] {
            let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}});
            assert!(
                validate_protocol_fields(&request, &[], ProtocolRoute::Meta).is_err(),
                "{request}"
            );
        }
    }
}
