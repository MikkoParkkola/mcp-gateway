// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8378 rows (design r1.2), HTTP routes. A dirty key at a position the
//! gateway reads is refused, never stripped into that field (ENV.2); the
//! direct route refuses a malformed chain nonce as `/mcp` does (ENV.3); a
//! non-scalar id is refused on every route (ENV.4, a guard: true today).
//! Each row is red on the MIK-8154 PR 2 head unless its doc says GUARD.

use super::*;

/// The protocol refusal `validate_protocol_text` answers for a control
/// character, at the code intake maps it to.
fn refused_dirty(body: &Value) -> bool {
    body.pointer("/error/code") == Some(&json!(-32600)) && message(body).contains(CONTROL_REFUSED)
}

async fn plain() -> Fx {
    Box::pin(sanitizing(true, fixture_built(Answer::Ok, |meta| meta))).await
}

/// ENV.4 GUARD: an object or array id is refused, -32600 with id null, and
/// nothing is dispatched, on `/mcp` and `/mcp/{name}`.
#[tokio::test]
async fn e4_a_non_scalar_id_is_refused_on_http() {
    for id in [json!({"x": NUL}), json!(["a\u{7}"])] {
        for uri in ["/mcp", "/mcp/alpha"] {
            let fx = plain().await;
            let body = send_raw(&fx, uri, "k-std", &direct_call(&id, "tools/call")).await;
            assert_eq!(
                body.pointer("/error/code"),
                Some(&json!(-32600)),
                "{uri} {id}: {body}"
            );
            assert_eq!(body["id"], Value::Null, "{uri} {id}: {body}");
            assert_eq!(calls(&fx), 0, "{uri} {id}: dispatched");
        }
    }
}

/// ENV.2 position 1: a dirty own key of `gateway_invoke`'s arguments is
/// refused, never stripped into `server`.
#[tokio::test]
async fn e2a_a_dirty_gateway_invoke_key_is_refused() {
    let fx = plain().await;
    let params = json!({"name": "gateway_invoke", "arguments":
        {"ser\u{7}ver": "alpha", "tool": "read", "arguments": {}}});
    let (_, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    assert!(refused_dirty(&body), "e2a: {body}");
    assert_eq!(calls(&fx), 0, "e2a: dispatched");
}

/// ENV.2 position 1, the JSON-string form of the same arguments.
#[tokio::test]
async fn e2b_a_dirty_key_in_string_arguments_is_refused() {
    let fx = plain().await;
    let inner = json!({"ser\u{7}ver": "alpha", "tool": "read", "arguments": {}}).to_string();
    let params = json!({"name": "gateway_invoke", "arguments": inner});
    let (_, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    assert!(refused_dirty(&body), "e2b: {body}");
    assert_eq!(calls(&fx), 0, "e2b: dispatched");
}

/// ENV.2 position 1: a dirty own key of a `gateway_execute` chain step.
#[tokio::test]
async fn e2c_a_dirty_chain_step_key_is_refused() {
    let fx = Box::pin(sanitizing(
        true,
        fixture_built(Answer::Ok, |meta| meta.with_code_mode(true)),
    ))
    .await;
    let params = json!({"name": "gateway_execute", "arguments": {"chain": [
        {"too\u{7}l": "alpha:read", "arguments": {}}
    ]}});
    let (_, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    assert!(refused_dirty(&body), "e2c: {body}");
    assert_eq!(calls(&fx), 0, "e2c: dispatched");
}

/// MIK-8378 (lead ruling, sanitizer matches dispatch): `gateway_invoke`
/// ignores a `chain`, so an encoded NUL in one is neither decoded nor
/// refused, and the call dispatches as it would without it.
#[tokio::test]
async fn an_ignored_invoke_chain_is_not_decoded_and_dispatches() {
    let fx = plain().await;
    let encoded = json!({"cmd": "a\u{0}b"}).to_string();
    let params = json!({"name": "gateway_invoke", "arguments": {"server": "alpha",
        "tool": "read", "arguments": {},
        "chain": [{"tool": "alpha:read", "arguments": encoded}]}});
    let (_, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    assert!(body.get("error").is_none(), "ignored chain refused: {body}");
    assert_eq!(calls(&fx), 1, "not dispatched: {body}");
}

/// ENV.2 position 2: a dirty own key of `gateway_invoke`'s `arguments._meta`.
#[tokio::test]
async fn e2e_a_dirty_invoke_meta_key_is_refused() {
    let fx = plain().await;
    let params = json!({"name": "gateway_invoke", "arguments": {"server": "alpha",
        "tool": "read", "arguments": {}, "_meta": {"tracepar\u{7}ent": "00-x"}}});
    let (_, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    assert!(refused_dirty(&body), "e2e: {body}");
    assert_eq!(calls(&fx), 0, "e2e: dispatched");
}

/// ENV.2 position 3: a dirty key that cleans to a gateway directive inside
/// the tool's own arguments is refused on the meta route, where the gateway
/// reads `_full` and `_claim` (admission.rs `execution_arguments`). On the
/// direct route the gateway does not read them: there a `_full` is the
/// tool's parameter (see the E2d guard).
#[tokio::test]
async fn e2f_a_dirty_directive_in_tool_arguments_is_refused() {
    let mcp = plain().await;
    let (_, via_mcp) = post_meta_invoke(
        &mcp,
        "k-std",
        "alpha",
        "read",
        json!({"_fu\u{7}ll": true}),
        None,
        None,
    )
    .await;
    assert!(refused_dirty(&via_mcp), "e2f /mcp: {via_mcp}");
    assert_eq!(calls(&mcp), 0, "e2f /mcp: dispatched");
}

/// ENV.2 GUARD (S9c): any other dirty key in tool arguments is business
/// data, stripped and dispatched as today, on both routes; a clean `_full`
/// is still the gateway's directive on the meta route, and on the direct
/// route it stays the tool's own (unknown) parameter, as today.
#[tokio::test]
async fn e2d_business_keys_keep_todays_stripping() {
    let business = json!({"cm\u{7}d": "x"});
    let mcp = plain().await;
    let (_, via_mcp) =
        post_meta_invoke(&mcp, "k-std", "alpha", "read", business.clone(), None, None).await;
    assert!(via_mcp.get("error").is_none(), "e2d /mcp: {via_mcp}");
    assert_eq!(calls(&mcp), 1, "e2d /mcp: not dispatched: {via_mcp}");
    let forwarded = mcp.seen.lock().expect("seen lock").last().cloned();
    assert_eq!(
        forwarded.as_ref().and_then(|p| p.get("arguments")),
        Some(&json!({"cmd": "x"})),
        "e2d /mcp: the business key is forwarded stripped, as today: {forwarded:?}"
    );
    let direct = plain().await;
    let (_, via_direct) =
        post_direct(&direct, "alpha", "k-std", "read", business, None, None).await;
    assert!(
        via_direct.get("error").is_none(),
        "e2d direct: {via_direct}"
    );
    assert_eq!(
        calls(&direct),
        1,
        "e2d direct: not dispatched: {via_direct}"
    );

    let full = plain().await;
    let (_, via_full) = post_meta_invoke(
        &full,
        "k-std",
        "alpha",
        "read",
        json!({"_full": true}),
        None,
        None,
    )
    .await;
    assert!(
        via_full.get("error").is_none(),
        "e2d _full /mcp: {via_full}"
    );
    assert_eq!(
        calls(&full),
        1,
        "e2d _full /mcp: not dispatched: {via_full}"
    );
    let direct_full = plain().await;
    let (_, via_direct_full) = post_direct(
        &direct_full,
        "alpha",
        "k-std",
        "read",
        json!({"_full": true}),
        None,
        None,
    )
    .await;
    assert!(
        via_direct_full.to_string().contains("unknown parameter"),
        "e2d _full direct is the tool's parameter: {via_direct_full}"
    );
}

/// ENV.3 GUARD: `/mcp/{name}` refuses a malformed or over-long chain nonce
/// with the code and message `/mcp` gives it, and dispatches nothing. True on
/// the PR 2 head: `RetryFields::from_params` validates the nonce and
/// direct_preflight refuses it before `take_nonces` runs.
#[tokio::test]
async fn e3_the_direct_route_refuses_a_malformed_chain_nonce_like_mcp() {
    let meta_key = crate::protocol::mrtr::CHAIN_NONCE_META;
    for nonce in [json!(""), json!(7), json!("n".repeat(257))] {
        let params = |name: &str, arguments: Value| json!({"name": name, "arguments": arguments, "_meta": {(meta_key): nonce.clone()}});
        let mcp = plain().await;
        let (_, via_mcp) = send(
            &mcp,
            "/mcp",
            "k-std",
            "tools/call",
            params(
                "gateway_invoke",
                json!({"server": "alpha", "tool": "read", "arguments": {}}),
            ),
            None,
        )
        .await;
        let direct = plain().await;
        let (_, via_direct) = send(
            &direct,
            "/mcp/alpha",
            "k-std",
            "tools/call",
            params("read", json!({})),
            None,
        )
        .await;
        assert_eq!(
            via_mcp.pointer("/error/code"),
            Some(&json!(-32602)),
            "e3 /mcp {nonce}: {via_mcp}"
        );
        assert_eq!(
            (via_direct.pointer("/error/code"), message(&via_direct)),
            (via_mcp.pointer("/error/code"), message(&via_mcp)),
            "e3 {nonce}: direct {via_direct} vs /mcp {via_mcp}"
        );
        assert_eq!(calls(&direct), 0, "e3 {nonce}: direct dispatched");
    }
}

/// ENV.2 position 3 at every meta-route slot `invoke_tool` reads directives
/// from (code seat, MIK-8378): a dirty key that cleans to `_full` is refused
/// in `gateway_execute`'s single-call `arguments`, in a chain step's
/// `arguments`, and in a surfaced tool's own arguments on `/mcp`.
#[tokio::test]
async fn e2h_a_dirty_directive_in_every_invoked_slot_is_refused() {
    let dirty = json!({"_fu\u{7}ll": true});
    let cases = [
        (
            "execute single",
            json!({"name": "gateway_execute",
            "arguments": {"tool": "alpha:read", "arguments": dirty}}),
        ),
        (
            "execute chain",
            json!({"name": "gateway_execute",
            "arguments": {"chain": [{"tool": "alpha:read", "arguments": dirty}]}}),
        ),
        ("surfaced", json!({"name": "read", "arguments": dirty})),
    ];
    for (case, params) in cases {
        let fx = Box::pin(sanitizing(
            true,
            fixture_built(Answer::Ok, |meta| {
                meta.with_code_mode(true).with_surfaced_tools(vec![
                    crate::config::SurfacedToolConfig {
                        server: "alpha".to_string(),
                        tool: "read".to_string(),
                    },
                ])
            }),
        ))
        .await;
        let (_, body) = send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
        assert!(refused_dirty(&body), "e2h {case}: {body}");
        assert_eq!(calls(&fx), 0, "e2h {case}: dispatched");
    }
}
