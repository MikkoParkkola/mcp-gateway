// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8499 INTAKE.3: the in-place sanitizer gives exactly what the copying
//! one gave. The reference below is the sanitizer as it stood before MIK-8499
//! (line tip 7b555372b), copied verbatim with its names prefixed `ref_`;
//! every corpus input must give the same value, or the same error, on both.

use serde_json::{Value, json};

use super::ProtocolRoute;
use super::{
    sanitize_json_value, sanitize_request_in_place, sanitize_string, validate_protocol_text,
};
use crate::Result;
use crate::gateway::{ArgsPolicy, args_policy};

// ---- the reference: the pre-MIK-8499 sanitizer, verbatim --------------------

#[derive(Clone, Copy)]
enum RefSlot {
    Meta,
    MetaChain,
    Tool,
    Inner,
}

fn ref_value(key: &str, value: &Value, route: ProtocolRoute) -> Result<Value> {
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
        ArgsPolicy::MetaParsedInner => Some(RefSlot::Meta),
        ArgsPolicy::MetaParsedChain => Some(RefSlot::MetaChain),
        ArgsPolicy::MetaOpaque => None,
        ArgsPolicy::BackendWhole => Some(RefSlot::Tool),
    };
    ref_object(params, |key, member| {
        slot.filter(|_| key == "arguments")
            .map(|slot| ref_slot(member, slot))
    })
}

/// `map` sanitized member by member; `special` handles a member itself when
/// it returns `Some`. Every key here was validated first: each admission
/// point runs [`validate_protocol_fields`] before [`super::sanitize_request`]
/// (intake, stdio, the direct route, a task's re-admission), and a key that
/// passes validation sanitizes to itself (`sanitize_string` strips only what
/// validation refuses, and its NFC step is the identity). So a key is matched
/// and kept as sent (MIK-8378).
fn ref_object(
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
fn ref_slot(value: &Value, slot: RefSlot) -> Result<Value> {
    match (value, slot) {
        (Value::String(_), RefSlot::Tool | RefSlot::Inner) => {
            let holder = serde_json::json!({ "arguments": value });
            let decoded = crate::gateway::parse_tool_arguments_cow(&holder)?;
            match decoded.as_ref() {
                Value::Object(map) => ref_arguments(map, slot),
                other => sanitize_json_value(other),
            }
        }
        (Value::Object(map), _) => ref_arguments(map, slot),
        _ => sanitize_json_value(value),
    }
}

/// A meta call's arguments: its inner `arguments` is a slot too and, for a
/// chained meta tool (`gateway_execute`, dispatched through the invoke funnel,
/// which decodes them), each `chain` step's `arguments`. Another meta tool's
/// `chain` is not read by its handler, so it is sanitized as plain values,
/// never decoded (MIK-8378). An inner slot holds a tool's own arguments,
/// sanitized as plain values.
fn ref_arguments(map: &serde_json::Map<String, Value>, slot: RefSlot) -> Result<Value> {
    match slot {
        RefSlot::Tool | RefSlot::Inner => sanitize_json_value(&Value::Object(map.clone())),
        RefSlot::Meta | RefSlot::MetaChain => ref_object(map, |key, member| match (key, member) {
            ("arguments", _) => Some(ref_slot(member, RefSlot::Inner)),
            ("chain", Value::Array(steps)) if matches!(slot, RefSlot::MetaChain) => {
                Some(ref_steps(steps))
            }
            _ => None,
        }),
    }
}

/// A `chain`'s steps, each step's `arguments` an inner slot.
fn ref_steps(steps: &[Value]) -> Result<Value> {
    steps
        .iter()
        .map(|step| match step {
            Value::Object(map) => ref_object(map, |key, member| {
                (key == "arguments").then(|| ref_slot(member, RefSlot::Inner))
            }),
            other => sanitize_json_value(other),
        })
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}

fn ref_request(request: &Value, route: ProtocolRoute) -> Result<Value> {
    let Some(map) = request.as_object() else {
        return sanitize_json_value(request);
    };
    if let Some(Value::String(id)) = map.get("id") {
        validate_protocol_text(id)?;
    }
    let mut sanitized = serde_json::Map::with_capacity(map.len());
    for (key, value) in map {
        let clean_key = sanitize_string(key)?;
        let clean = if key == "id" {
            value.clone()
        } else {
            ref_value(&clean_key, value, route)?
        };
        sanitized.insert(clean_key, clean);
    }
    Ok(Value::Object(sanitized))
}

// ---- the corpus ---------------------------------------------------------------

/// A `tools/call` for `name` with `arguments`.
fn call(name: &str, arguments: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": name, "arguments": arguments}})
}

/// The inputs both sanitizers must agree on. Unsafe control characters:
/// U+0001, U+007F is not one (DEL is allowed), U+0085 (C1), U+200B
/// (zero-width space), U+FEFF; a NUL refuses.
fn corpus() -> Vec<Value> {
    let dirty = "a\u{1}b\u{85}c\u{200B}d\u{FEFF}e";
    let multibyte = "\u{e9}t\u{e9}\u{1}\u{1F600}\u{1}";
    let mut deep = json!("leaf\u{1}");
    for _ in 0..100 {
        deep = json!({"k\u{1}": [deep]});
    }
    vec![
        // Clean, on every slot kind.
        call(
            "backend_tool",
            json!({"q": "find", "n": 3, "ok": true, "z": null}),
        ),
        call(
            "gateway_invoke",
            json!({"server": "s", "tool": "t", "arguments": {"q": "x"}}),
        ),
        call(
            "gateway_execute",
            json!({"chain": [{"server": "s", "tool": "t", "arguments": {"q": 1}}]}),
        ),
        call("gateway_search_tools", json!({"query": "mail"})),
        // A string-encoded slot in each kind the gateway decodes.
        call("backend_tool", json!("{\"q\": \"x\u{1}\"}")),
        call(
            "gateway_invoke",
            json!({"server": "s", "tool": "t", "arguments": "{\"q\": \"y\"}"}),
        ),
        call(
            "gateway_execute",
            json!({"chain": [{"server": "s", "tool": "t", "arguments": "{\"q\": 2}"}]}),
        ),
        // A string slot that is not a JSON object, and one that is not JSON.
        call("backend_tool", json!("[1, 2]")),
        call("backend_tool", json!("not json")),
        // Dirty strings in every position, next to multi-byte text.
        call(
            "backend_tool",
            json!({"q": dirty, "m": multibyte, "start": "\u{1}x", "end": "x\u{1}", "only": "\u{1}\u{1}"}),
        ),
        call(
            "gateway_invoke",
            json!({"server": "s\u{200B}", "tool": "t", "arguments": {"q": dirty}}),
        ),
        // Key rewrites, at depth, and two keys that collide after stripping,
        // the overwritten one holding a NUL.
        call(
            "backend_tool",
            json!({"k\u{1}ey": 1, "deep": {"in\u{200B}ner": "v"}}),
        ),
        call(
            "backend_tool",
            json!({"key": "first", "ke\u{1}y": "second"}),
        ),
        call(
            "backend_tool",
            json!({"ke\u{1}y": "bad\u{0}", "key": "kept"}),
        ),
        call(
            "backend_tool",
            json!({"key": "kept", "ke\u{1}y": "bad\u{0}"}),
        ),
        // NULs: a value, a key, encoded in a string slot, in a chain step.
        call("backend_tool", json!({"q": "a\u{0}b"})),
        call("backend_tool", json!({"k\u{0}": 1})),
        call("backend_tool", json!("{\"q\": \"\\u0000\"}")),
        call(
            "gateway_execute",
            json!({"chain": [{"server": "s", "tool": "t", "arguments": "{\"q\": \"\\u0000\"}"}]}),
        ),
        // Nested arrays.
        call(
            "backend_tool",
            json!({"a": [[["x\u{1}"]], [], [{"b": "y\u{85}"}, 1, null, true]]}),
        ),
        // Unicode normalisation forms: NFC, NFD, NFKC, NFKD spellings of the
        // same text, and combining marks, all passed through unchanged.
        call(
            "backend_tool",
            json!({"nfc": "caf\u{e9}", "nfd": "cafe\u{301}", "nfkc": "\u{fb01}", "nfkd": "f\u{69}", "marks": "a\u{301}\u{302}\u{303}"}),
        ),
        // Edge inputs.
        json!({}),
        json!("not an object \u{1}"),
        json!([1, "x\u{1}"]),
        call("backend_tool", json!({"e": ""})),
        call("backend_tool", json!({"deep": deep})),
        call("backend_tool", json!({"big": "x".repeat(3 << 20)})),
        // Top-level keys: a dirty one rebuilds the request; a dirty `id`.
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params\u{1}": {}, "x\u{200B}": 1}),
        json!({"jsonrpc": "2.0", "id": "a\u{1}", "method": "tools/call", "params": {}}),
    ]
}

// ---- the comparison -------------------------------------------------------------

/// The outcome both forms are compared on: the value, or the error's
/// JSON-RPC code and text, so a changed error class is caught even when the
/// text matches.
fn outcome(result: Result<Value>) -> std::result::Result<Value, (i32, String)> {
    result.map_err(|e| (e.to_rpc_code(), e.to_string()))
}

fn in_place(request: &Value, route: ProtocolRoute) -> Result<Value> {
    let mut owned = request.clone();
    sanitize_request_in_place(&mut owned, route)?;
    Ok(owned)
}

/// INTAKE.3: on every corpus input and both routes, the in-place sanitizer
/// gives the reference's value or the reference's error.
#[test]
fn the_in_place_sanitizer_matches_the_reference_on_the_corpus() {
    let corpus = corpus();
    let mut refused = 0;
    for (i, request) in corpus.iter().enumerate() {
        for (route, label) in [
            (ProtocolRoute::Meta, "Meta"),
            (ProtocolRoute::Direct, "Direct"),
        ] {
            let expected = outcome(ref_request(request, route));
            let got = outcome(in_place(request, route));
            refused += usize::from(expected.is_err());
            assert!(
                got == expected,
                "INTAKE.3 corpus[{i}] {label}: in place {:.300} vs reference {:.300}",
                format!("{got:?}"),
                format!("{expected:?}")
            );
        }
    }
    // Premise: the corpus exercises refusals as well as rewrites.
    assert!(
        refused >= 8,
        "the corpus refuses too little to test refusals: {refused}"
    );
}

/// INTAKE.3: a value the sanitizer must rewrite is still rewritten, and a
/// clean value is left exactly as sent (the NFC step is the identity).
#[test]
fn a_dirty_value_is_still_rewritten_and_a_clean_one_kept() {
    let mut dirty = call("backend_tool", json!({"q": "a\u{1}b", "k\u{200B}": 1}));
    sanitize_request_in_place(&mut dirty, ProtocolRoute::Meta).expect("sanitizes");
    assert_eq!(dirty["params"]["arguments"], json!({"q": "ab", "k": 1}));
    let clean = call("backend_tool", json!({"nfd": "cafe\u{301}", "q": "find"}));
    let mut kept = clean.clone();
    sanitize_request_in_place(&mut kept, ProtocolRoute::Meta).expect("sanitizes");
    assert_eq!(kept, clean, "a clean request changed");
}

/// INTAKE.3: a string-encoded slot is decoded into the object it encodes,
/// and an encoded NUL in it is refused, as before.
#[test]
fn a_string_slot_is_decoded_and_its_encoded_nul_refused() {
    // Escaped, as a client sends it: a raw U+0001 inside a JSON string is
    // refused by the decoder itself (both sanitizers agree; corpus row).
    let mut slot = call("backend_tool", json!("{\"q\": \"x\\u0001\"}"));
    sanitize_request_in_place(&mut slot, ProtocolRoute::Meta).expect("sanitizes");
    assert_eq!(slot["params"]["arguments"], json!({"q": "x"}));
    let mut nul = call("backend_tool", json!("{\"q\": \"\\u0000\"}"));
    assert!(sanitize_request_in_place(&mut nul, ProtocolRoute::Meta).is_err());
}
