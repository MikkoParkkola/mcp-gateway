// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The request-level parts of the one sanitize step (MIK-8154 SAN.1): the
//! protocol fields it validates without rewriting, and the walk that reaches
//! tool arguments a client sent as a JSON string.

use serde_json::Value;

use super::{sanitize_json_value, sanitize_string, validate_protocol_text};
use crate::Result;
use crate::gateway::{ArgsPolicy, EXECUTION_DIRECTIVES, args_policy};
use crate::protocol::meta::KEY_CLIENT_CAPABILITIES;

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
    // `params` members are read by key: a JSON pointer unescapes every segment
    // into a new string, on every call (MIK-8014 PERF.11). None of the keys is
    // numeric or escaped, so `get` answers exactly as `pointer` did.
    let params = request.get("params");
    let member = |key: &str| params.and_then(|params| params.get(key));
    let meta = member("_meta");
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
    own_keys(request)?;
    params.map_or(Ok(()), own_keys)?;
    meta.map_or(Ok(()), validate_keys)?;
    let client_capabilities = meta.and_then(|meta| meta.get(KEY_CLIENT_CAPABILITIES));
    for capabilities in [member("capabilities"), client_capabilities] {
        capabilities.map_or(Ok(()), validate_keys)?;
    }
    // A tool call's arguments, read where the meta route reads them: the
    // name as dispatch routes on it (sanitized), `arguments` decoded when a
    // client sent them as a JSON string, so neither form launders a dirty key
    // or nonce. A name off the META_TOOLS roster is a surfaced backend tool,
    // whose arguments `invoke_tool` reads directives from.
    if route == ProtocolRoute::Meta
        && let Some(Value::String(name)) = member("name")
        && let Ok(name) = sanitize_string(name)
        && let Some(arguments) = decoded(member("arguments"))
    {
        match args_policy(&name) {
            ArgsPolicy::BackendWhole => directive_keys(Some(&*arguments))?,
            ArgsPolicy::MetaOpaque | ArgsPolicy::MetaParsedInner | ArgsPolicy::MetaParsedChain => {
                meta_tool_arguments(&name, &arguments)?;
            }
        }
    }
    Ok(())
}

/// `value`'s own keys pass [`validate_protocol_text`]; a non-object passes.
fn own_keys(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => map.keys().try_for_each(|key| validate_protocol_text(key)),
        _ => Ok(()),
    }
}

/// An `arguments` member as its reader takes it: an object as it is
/// (borrowed), a JSON string decoded; `None` when absent or undecodable
/// (dispatch answers that).
fn decoded(arguments: Option<&Value>) -> Option<std::borrow::Cow<'_, Value>> {
    match arguments? {
        Value::String(raw) => serde_json::from_str(raw).ok().map(std::borrow::Cow::Owned),
        other => Some(std::borrow::Cow::Borrowed(other)),
    }
}

/// A slot `invoke_tool` reads gateway directives from (`_full`, `_claim`;
/// invoke.rs): a dirty key that cleans to one is refused, never stripped into
/// it. Any other key there is the tool's business data and keeps today's
/// stripping (S9c).
fn directive_keys(slot: Option<&Value>) -> Result<()> {
    match decoded(slot).as_deref() {
        Some(Value::Object(tool)) => tool
            .keys()
            .filter(|key| {
                sanitize_string(key).is_ok_and(|key| EXECUTION_DIRECTIVES.contains(&key.as_str()))
            })
            .try_for_each(|key| validate_protocol_text(key)),
        _ => Ok(()),
    }
}

/// The keys the gateway reads inside a meta tool's `arguments` (MIK-8378
/// ENV.2), refused when dirty, never stripped into the key they clean to:
/// the arguments' own keys and, for `gateway_execute`, each chain step's;
/// for `gateway_invoke` the signing nonce and the own keys of `_meta` (trace
/// context, prompt cache key); and in every tool-arguments slot `invoke_tool`
/// reads (`gateway_invoke`'s and `gateway_execute`'s inner `arguments`, each
/// chain step's), a key that cleans to a gateway directive. Any other key there is the tool's
/// business data and keeps today's stripping (S9c).
fn meta_tool_arguments(name: &str, arguments: &Value) -> Result<()> {
    own_keys(arguments)?;
    match name {
        // Dispatch takes the chain branch whenever `chain` is an array
        // (search.rs `code_mode_execute`) and then never reads the single-call
        // `arguments`, so each slot is checked only on the branch that reads it.
        "gateway_execute" => match arguments.get("chain") {
            Some(Value::Array(chain)) => chain.iter().try_for_each(|step| {
                own_keys(step)?;
                directive_keys(step.get("arguments"))
            }),
            _ => directive_keys(arguments.get("arguments")),
        },
        "gateway_invoke" => {
            if let Some(Value::String(nonce)) = arguments.get("nonce") {
                validate_protocol_text(nonce)?;
            }
            arguments.get("_meta").map_or(Ok(()), own_keys)?;
            directive_keys(arguments.get("arguments"))
        }
        _ => Ok(()),
    }
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
/// gateway parses the inner `arguments` inside it, and for a chained one the
/// `chain` steps too), any other tool's own (its contents are the tool's,
/// plain values), or one the gateway parses inside a meta tool's.
#[derive(Clone, Copy)]
enum Slot {
    Meta,
    MetaChain,
    Tool,
    Inner,
}

/// [`sanitize_json_value`] for one top-level request member, reaching into
/// the `arguments` slots the gateway decodes after this step when a client
/// sends them as a JSON string (MIK-8154 F1): there they are decoded,
/// sanitized and re-encoded, so an escaped NUL is refused before the decode
/// can produce it. Keys are matched as sent: every key reaching a match was
/// validated first, and a valid key sanitizes to itself (`sanitize_object`),
/// so a dirty `arguments` key is refused before it could get around it. No other string is decoded or re-encoded.
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
    // On a meta route a meta tool's own `arguments` are read by its handler
    // as they are: decoded inside only for the parsing meta tools, never
    // decoded as a whole (round-5 seats: decoding them made a string payload
    // the gateway refused act). Everything else is a backend tool's.
    let name = match (route, name) {
        (ProtocolRoute::Meta, Some(Ok(name))) => Some(name),
        _ => None,
    };
    // The decode decision, made once per policy (`ArgsPolicy`). A meta name
    // always resolves to the gateway's own handler: surfacing refuses a
    // backend tool under one (`MetaMcp::with_surfaced_tools`, pinned by
    // `with_surfaced_tools_drops_all_known_meta_tool_names`).
    let slot = match name
        .as_deref()
        .map_or(ArgsPolicy::BackendWhole, args_policy)
    {
        ArgsPolicy::MetaParsedInner => Some(Slot::Meta),
        ArgsPolicy::MetaParsedChain => Some(Slot::MetaChain),
        ArgsPolicy::MetaOpaque => None,
        ArgsPolicy::BackendWhole => Some(Slot::Tool),
    };
    sanitize_object(params, |key, member| {
        slot.filter(|_| key == "arguments")
            .map(|slot| sanitize_slot(member, slot))
    })
}

/// `map` sanitized member by member; `special` handles a member itself when
/// it returns `Some`. Every key here was validated first: each admission
/// point runs [`validate_protocol_fields`] before [`super::sanitize_request`]
/// (intake, stdio, the direct route, a task's re-admission), and a key that
/// passes validation sanitizes to itself (`sanitize_string` strips only what
/// validation refuses, and its NFC step is the identity). So a key is matched
/// and kept as sent (MIK-8378).
fn sanitize_object(
    map: &serde_json::Map<String, Value>,
    special: impl Fn(&str, &Value) -> Option<Result<Value>>,
) -> Result<Value> {
    let mut sanitized = serde_json::Map::with_capacity(map.len());
    for (key, member) in map {
        let clean = match special(key, member) {
            Some(handled) => handled?,
            None => sanitize_json_value(member)?,
        };
        sanitized.insert(key.clone(), clean);
    }
    Ok(Value::Object(sanitized))
}

/// An `arguments` slot. Where the gateway decodes a JSON string here (a
/// backend tool's own, a meta tool's inner, a chain step's), it is decoded by
/// the gateway's own decoder, once, on the bytes the client sent, and the
/// decoded object is sanitized and handed onward in place of the string:
/// dispatch then takes the object as it is, so what was checked is what is
/// used. A meta tool's own `arguments` are not decoded (dispatch does not
/// decode them either). Anything else is sanitized as it is.
///
/// # Errors
///
/// The decoder's own -32602 for a string that is not a JSON object, as
/// dispatch would answer it; `Error::Protocol` for a NUL.
fn sanitize_slot(value: &Value, slot: Slot) -> Result<Value> {
    match (value, slot) {
        (Value::String(_), Slot::Tool | Slot::Inner) => {
            let holder = serde_json::json!({ "arguments": value });
            let decoded = crate::gateway::parse_tool_arguments_cow(&holder)?;
            match decoded.as_ref() {
                Value::Object(map) => sanitize_arguments(map, slot),
                other => sanitize_json_value(other),
            }
        }
        (Value::Object(map), _) => sanitize_arguments(map, slot),
        _ => sanitize_json_value(value),
    }
}

/// A meta call's arguments: its inner `arguments` is a slot too and, for a
/// chained meta tool (`gateway_execute`, dispatched through the invoke funnel,
/// which decodes them), each `chain` step's `arguments`. Another meta tool's
/// `chain` is not read by its handler, so it is sanitized as plain values,
/// never decoded (MIK-8378). An inner slot holds a tool's own arguments,
/// sanitized as plain values.
fn sanitize_arguments(map: &serde_json::Map<String, Value>, slot: Slot) -> Result<Value> {
    match slot {
        Slot::Tool | Slot::Inner => sanitize_json_value(&Value::Object(map.clone())),
        Slot::Meta | Slot::MetaChain => sanitize_object(map, |key, member| match (key, member) {
            ("arguments", _) => Some(sanitize_slot(member, Slot::Inner)),
            ("chain", Value::Array(steps)) if matches!(slot, Slot::MetaChain) => {
                Some(sanitize_steps(steps))
            }
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
        // Decoded once, by the gateway's decoder, and handed on as the object.
        assert_eq!(
            clean["params"]["arguments"]["arguments"],
            json!({"b": 1, "a": 2})
        );
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

    /// MIK-8378: a `chain` is decoded only where its handler reads one
    /// (`gateway_execute`). `gateway_invoke` ignores a `chain`, so its steps
    /// are sanitized as plain values: an encoded string stays a string, and
    /// an escaped NUL inside it is not refused.
    #[test]
    fn an_ignored_chain_is_not_decoded() {
        let encoded = json!({"cmd": "a\u{0}b"}).to_string();
        let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "gateway_invoke", "arguments": {"server": "alpha",
                "tool": "read", "arguments": {},
                "chain": [{"tool": "alpha:read", "arguments": encoded}]}}});
        let clean = sanitize_request(&request, ProtocolRoute::Meta).expect("sanitizes");
        assert_eq!(
            clean["params"]["arguments"]["chain"][0]["arguments"],
            json!(encoded)
        );
    }

    /// Round-4 seat gpt: a raw control character that makes an encoded
    /// `arguments` invalid JSON until it is stripped does not hide an escaped
    /// NUL: the client's own bytes are decoded, once, by the gateway's
    /// decoder, which refuses them, so no stripped form is ever decoded.
    #[test]
    fn s9i_stripping_cannot_turn_an_encoded_nul_into_a_plain_string() {
        let raw = "{\"cmd\":\"\\u0000\"}\u{7}";
        for (name, arguments) in [
            ("read", json!(raw)),
            (
                "gateway_execute",
                json!({"chain": [{"tool": "alpha:read", "arguments": raw}]}),
            ),
        ] {
            let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}});
            assert!(
                sanitize_request(&request, ProtocolRoute::Meta).is_err(),
                "{request}"
            );
        }
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
            ("gateway_invoke\u{7}", json!(nonce_args.to_string())),
        ] {
            let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}});
            assert!(
                validate_protocol_fields(&request, &[], ProtocolRoute::Meta).is_err(),
                "{request}"
            );
        }
    }

    /// Round-5 seats (both): on a meta route a meta tool's own `arguments`
    /// string is never decoded as a whole, as its handler never decodes it:
    /// a string payload stays a string (dispatch refuses it, as before), and
    /// an invalid one is not refused here for a tool that ignores arguments.
    #[test]
    fn s9j_a_meta_tools_own_arguments_string_is_not_decoded() {
        for (name, arguments) in [
            ("gateway_kill_server", json!("{\"server\": \"alpha\"}")),
            ("gateway_list_tools", json!("{\"server\": \"alpha\"}")),
            ("gateway_get_stats", json!("not json")),
            // A parsing meta tool's own string is not decoded either: only
            // its inner `arguments` are (its handler refuses the string).
            ("gateway_invoke", json!("not json")),
            ("gateway_invoke", json!("{\"server\": \"alpha\"}")),
            ("gateway_execute", json!("{\"chain\": []}")),
        ] {
            let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": name, "arguments": arguments}});
            let clean = sanitize_request(&request, ProtocolRoute::Meta).expect("sanitizes");
            assert_eq!(clean["params"]["arguments"], arguments, "{name}");
        }
    }

    /// The parsing meta tools decode inside; the other meta tools are read
    /// as they are; a name off the roster is a backend tool's.
    #[test]
    fn args_policy_resolves_each_kind_of_tool() {
        use super::{ArgsPolicy, args_policy};
        assert_eq!(args_policy("gateway_execute"), ArgsPolicy::MetaParsedChain);
        for name in ["gateway_invoke", "gateway_run_playbook"] {
            assert_eq!(args_policy(name), ArgsPolicy::MetaParsedInner, "{name}");
        }
        assert_eq!(args_policy("gateway_list_servers"), ArgsPolicy::MetaOpaque);
        assert_eq!(args_policy("github_search"), ArgsPolicy::BackendWhole);
    }
}

#[cfg(test)]
#[path = "protocol_alloc_tests.rs"]
mod alloc_tests;
