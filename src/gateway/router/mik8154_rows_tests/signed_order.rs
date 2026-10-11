// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8154 S6 and S7 (test plan r1 H3): where sanitization sits against the
//! signing capture, restore and the malformed-nonce refusal on `/mcp`.

use super::*;

/// `params` sent as a modern `tools/call` to `/mcp` on the signed, sanitizing
/// fixture, its name header naming `header_name`.
async fn signed_mcp(params: Value, header_name: &str) -> (Fx, Value) {
    let fx = Box::pin(sanitizing(
        true,
        super::super::direct_guards_fixture::fixture_hardened_signed(Answer::Ok, true),
    ))
    .await;
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", header_name),
    ];
    let (_, body) = super::super::direct_guards_fixture::send_with_headers(
        &fx,
        "/mcp",
        "k-std",
        "tools/call",
        params,
        None,
        &headers,
    )
    .await;
    (fx, body)
}

fn modern_meta(nonce: &Value) -> Value {
    use crate::gateway::meta_mcp::signing::NONCE_META;
    json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        NONCE_META: nonce,
    })
}

/// S6: a signed request whose routing name becomes `gateway_invoke` only once
/// sanitization strips a control character is refused "Invalid signing
/// request origin": the origin captured before sanitizing is the one restore
/// holds it to, and no backend runs.
#[tokio::test]
async fn s6_a_routing_alias_made_by_sanitization_is_refused() {
    let params = json!({
        "name": "gateway_\u{7}invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": {}},
        "_meta": modern_meta(&json!("s6-n1")),
    });
    let (fx, body) = Box::pin(signed_mcp(params, "gateway_invoke")).await;
    assert!(
        message(&body).contains("Invalid signing request origin"),
        "s6: {body}"
    );
    assert_eq!(calls(&fx), 0, "s6: dispatched");
}

/// S7: a payload NUL together with a malformed (non-string) signing nonce is
/// refused with the sanitizer's refusal, not the nonce's: sanitization runs
/// first. No backend runs.
#[tokio::test]
async fn s7_a_nul_beside_a_malformed_nonce_gets_the_sanitizer_refusal() {
    let params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": {"cmd": NUL}},
        "_meta": modern_meta(&json!(7)),
    });
    let (fx, body) = Box::pin(signed_mcp(params, "gateway_invoke")).await;
    assert_eq!(message(&body), NUL_REFUSED, "s7: {body}");
    assert_eq!(calls(&fx), 0, "s7: dispatched");
}

/// S4b (implementation seat F3): `gateway_invoke`'s argument nonce, which
/// signing capture removes before sanitizing, is validated like the `_meta`
/// nonces: a NUL or a control character in it is refused, and no backend
/// runs. RED before the fix: it was never checked.
#[tokio::test]
async fn s4b_the_invoke_argument_nonce_is_validated() {
    let mut accepted = Vec::new();
    for bad in [NUL, "a\u{7}b"] {
        let params = json!({
            "name": "gateway_invoke",
            "arguments": {"server": "alpha", "tool": "read", "arguments": {}, "nonce": bad},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        });
        let (fx, body) = Box::pin(signed_mcp(params, "gateway_invoke")).await;
        let refused = body.get("error").is_some() && calls(&fx) == 0;
        let nul_exact = bad != NUL || message(&body) == NUL_REFUSED;
        if !(refused && nul_exact) {
            accepted.push(format!("{bad:?}: {body}"));
        }
    }
    assert!(accepted.is_empty(), "s4b: {}", accepted.join("\n"));
}
