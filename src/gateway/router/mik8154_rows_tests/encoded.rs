// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8154 S9 (implementation seat F1): tool arguments sent as a JSON string
//! (a client style) are decoded after the sanitize step, so the step reaches
//! into them: an escaped NUL is refused and an escaped control character
//! stripped before the decode can produce it, on every route.

use super::*;

/// `arguments` as the JSON string a client may send in place of the object.
fn encoded(arguments: &Value) -> Value {
    Value::String(arguments.to_string())
}

/// S9a: on the direct route, a NUL escaped inside string-encoded arguments is
/// refused with the sanitizer's refusal, and the backend does not run. RED
/// before the fix: the decode after the step produced the NUL and sent it.
#[tokio::test]
async fn s9a_direct_refuses_a_nul_in_encoded_arguments() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let args = encoded(&json!({"cmd": NUL}));
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", args, None, None).await;
    assert_eq!(message(&body), NUL_REFUSED, "s9a: {body}");
    assert_eq!(calls(&fx), 0, "s9a: dispatched");
}

/// S9b: the same through `/mcp` `gateway_invoke`, whose inner `arguments` is
/// the encoded string.
#[tokio::test]
async fn s9b_mcp_refuses_a_nul_in_encoded_arguments() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let args = encoded(&json!({"cmd": NUL}));
    let (_, body) = post_meta_invoke(&fx, "k-std", "alpha", "read", args, None, None).await;
    assert_eq!(message(&body), NUL_REFUSED, "s9b: {body}");
    assert_eq!(calls(&fx), 0, "s9b: dispatched");
}

/// S9c: a control character escaped inside encoded arguments is stripped: the
/// backend receives the clean value.
#[tokio::test]
async fn s9c_direct_strips_a_control_character_in_encoded_arguments() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let args = encoded(&json!({"cmd": "a\u{7}b"}));
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", args, None, None).await;
    assert!(body.get("error").is_none(), "s9c: {body}");
    let seen = fx.seen.lock().expect("seen lock").last().cloned();
    assert_eq!(
        seen.as_ref().and_then(|p| p.pointer("/arguments/cmd")),
        Some(&json!("ab")),
        "s9c: {seen:?}"
    );
}

/// S9d (fixes seat, both): a control character in an inner `arguments` key
/// (`gateway_invoke`'s) is no way around the decode, and nothing runs. Since
/// MIK-8378 ENV.2 protocol key validation reaches `gateway_invoke`'s own
/// argument keys, so `arg\x07uments` is refused as a dirty key before the
/// decode would refuse the encoded NUL under it (was: refused by the decode,
/// with the NUL message).
#[tokio::test]
async fn s9d_a_dirty_arguments_key_does_not_skip_the_decode() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "gateway_invoke", "arguments": {"server": "alpha", "tool": "read",
        "arg\u{7}uments": encoded(&json!({"cmd": NUL}))}}});
    let body = send_raw(&fx, "/mcp", "k-std", &body).await;
    assert_eq!(body["error"]["code"], -32600, "s9d: {body}");
    assert!(
        message(&body).contains("control characters"),
        "s9d: not the dirty-key refusal: {body}"
    );
    assert_eq!(calls(&fx), 0, "s9d: dispatched");
}

/// S4d (fixes seat gpt, protocol-position aliases): a dirty key where the
/// gateway reads its own fields is refused, never stripped into another
/// field: in `params` (`arg\x07uments`) and in `_meta` (an alias of the
/// idempotency key). Nothing runs.
#[tokio::test]
async fn s4d_a_dirty_protocol_key_is_refused_not_aliased() {
    let alias = format!("{}\u{7}", crate::protocol::mrtr::IDEMPOTENCY_KEY_META);
    for params in [
        json!({"name": "read", "arg\u{7}uments": {}}),
        json!({"name": "read", "arguments": {}, "_meta": {alias: "k"}}),
    ] {
        let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params});
        let answer = send_raw(&fx, "/mcp/alpha", "k-std", &body).await;
        assert!(
            message(&answer).contains(CONTROL_REFUSED),
            "s4d {params}: {answer}"
        );
        assert_eq!(calls(&fx), 0, "s4d {params}: dispatched");
    }
}

/// S9f (lead: the wiring behind the unit row S9e): on `/mcp/{name}` a
/// backend tool named `gateway_invoke` is the backend's, so its own field
/// named `arguments`, a JSON string, reaches the backend byte for byte. The
/// direct route passes its route to the sanitize step; passed as the meta
/// route, the step would decode and re-encode that field.
#[tokio::test]
async fn s9f_direct_route_keeps_a_tools_arguments_field() {
    let fx = Box::pin(sanitizing(
        true,
        fixture_built(Answer::WithNote, |meta| meta),
    ))
    .await;
    let opaque = "{\"b\": 1,  \"a\": 2}";
    let args = json!({"arguments": opaque});
    let (_, body) = post_direct(&fx, "alpha", "k-std", "gateway_invoke", args, None, None).await;
    assert_eq!(calls(&fx), 1, "s9f: not dispatched: {body}");
    let seen = fx.seen.lock().expect("seen lock").last().cloned();
    assert_eq!(
        seen.as_ref()
            .and_then(|p| p.pointer("/arguments/arguments")),
        Some(&json!(opaque)),
        "s9f: {seen:?}"
    );
}

/// S4c (fixes seat gpt): on `/mcp/{name}` a backend tool named
/// `gateway_invoke` is the backend's, so a control character in its own
/// `arguments.nonce` is business data, never refused as the signing nonce.
#[tokio::test]
async fn s4c_a_direct_tool_named_gateway_invoke_keeps_its_nonce_field() {
    let fx = Box::pin(sanitizing(
        true,
        fixture_built(Answer::WithNote, |meta| meta),
    ))
    .await;
    let args = json!({"nonce": "a\u{7}b"});
    let (_, body) = post_direct(&fx, "alpha", "k-std", "gateway_invoke", args, None, None).await;
    assert!(!message(&body).contains(CONTROL_REFUSED), "s4c: {body}");
    // Dispatched, its business field sanitized as any other value.
    assert_eq!(calls(&fx), 1, "s4c: not dispatched: {body}");
    let seen = fx.seen.lock().expect("seen lock").last().cloned();
    assert_eq!(
        seen.as_ref().and_then(|p| p.pointer("/arguments/nonce")),
        Some(&json!("ab")),
        "s4c: {seen:?}"
    );
}

/// S9h (lead: the wiring behind the unit row S9g): a `gateway_execute` chain
/// step on `/mcp`, its `arguments` a JSON string holding a NUL, to the
/// non-passthrough backend: the sanitize step reaches the step's arguments
/// through the real chain field, so the NUL is refused at intake and the
/// backend never receives it. The chain path decodes the string later (the
/// invoke funnel), so a step the step missed would send the NUL.
#[tokio::test]
async fn s9h_an_encoded_nul_in_a_chain_step_never_reaches_a_backend() {
    let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
    let step = json!({"tool": "alpha:read", "arguments": encoded(&json!({"cmd": NUL}))});
    let chain = json!({"name": "gateway_execute", "arguments": {"chain": [step]}});
    let (_, body) =
        super::super::direct_guards_fixture::send(&fx, "/mcp", "k-std", "tools/call", chain, None)
            .await;
    assert_eq!(
        calls(&fx),
        0,
        "s9h: the chain step reached the backend: {body}"
    );
    assert_eq!(message(&body), NUL_REFUSED, "s9h: {body}");
}

/// S9k (round-5 seat): an encoded `arguments` string that does not decode is
/// refused at the sanitize step with the decoder's own -32602 and the
/// request's own id, on `/mcp` (`gateway_invoke`'s inner) and on
/// `/mcp/{name}`, so a client can match the refusal to its request. Nothing
/// runs. RED before the fix: the refusal carried no id.
#[tokio::test]
async fn s9k_an_undecodable_encoded_arguments_keeps_the_request_id() {
    let invoke = json!({"name": "gateway_invoke", "arguments":
        {"server": "alpha", "tool": "read", "arguments": "not json"}});
    let direct = json!({"name": "read", "arguments": "not json"});
    for (uri, params) in [("/mcp", invoke), ("/mcp/alpha", direct)] {
        let fx = Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await;
        let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params});
        let answer = send_raw(&fx, uri, "k-std", &body).await;
        assert_eq!(
            answer.pointer("/error/code"),
            Some(&json!(-32602)),
            "s9k {uri}: {answer}"
        );
        assert_eq!(answer.get("id"), Some(&json!(7)), "s9k {uri}: {answer}");
        assert_eq!(calls(&fx), 0, "s9k {uri}: dispatched");
    }
}
