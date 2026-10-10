// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only drivers for the route x check matrix (MIK-8137 family, b3).
//!
//! Each driver builds an existing router fixture and sends one backend
//! `tools/call` through that route's real entry point, nothing more. The
//! matrix (`gateway::route_check_matrix_tests`) owns every assertion.

use std::path::Path;
use std::sync::atomic::Ordering;

use serde_json::Value;

use super::direct_guards_fixture::{Answer, post_direct, post_meta_invoke};
use crate::gateway::meta_mcp::MetaMcp;

/// What one call through a route produced.
pub(crate) struct Sent {
    /// The JSON-RPC body the client got.
    pub(crate) body: Value,
    /// How many `tools/call` sends reached the backend.
    pub(crate) backend_calls: usize,
    /// The params each of those sends carried.
    pub(crate) seen: Vec<Value>,
}

fn sent(fx: &super::direct_guards_fixture::Fx, body: Value) -> Sent {
    Sent {
        body,
        backend_calls: fx.calls.load(Ordering::SeqCst),
        seen: fx.seen.lock().expect("seen lock").clone(),
    }
}

/// R1 `/mcp` `gateway_invoke alpha read`, with the production firewall on both
/// layers writing audit rows to `audit`.
pub(crate) async fn invoke_firewalled(audit: &Path, args: Value) -> Sent {
    let fx = super::direct_guards_fixture::fixture_firewalled_audited(
        Answer::Ok,
        audit.to_path_buf(),
    )
    .await;
    let (_, body) = post_meta_invoke(&fx, "k-std", "alpha", "read", args, None, None).await;
    sent(&fx, body)
}

/// R3 `/mcp/alpha` `tools/call read`, on the same firewalled fixture.
pub(crate) async fn direct_firewalled(audit: &Path, args: Value) -> Sent {
    let fx = super::direct_guards_fixture::fixture_firewalled_audited(
        Answer::Ok,
        audit.to_path_buf(),
    )
    .await;
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", args, None, None).await;
    sent(&fx, body)
}

/// R1 `/mcp` `gateway_invoke alpha read` with `security.sanitize_input` = `on`.
pub(crate) async fn invoke_sanitizing(on: bool, args: Value) -> Sent {
    let fx = super::direct_guards_fixture::fixture_sanitizing(Answer::Ok, on).await;
    let (_, body) = post_meta_invoke(&fx, "k-std", "alpha", "read", args, None, None).await;
    sent(&fx, body)
}

/// R3 `/mcp/alpha` `tools/call read` with `security.sanitize_input` = `on`.
pub(crate) async fn direct_sanitizing(on: bool, args: Value) -> Sent {
    let fx = super::direct_guards_fixture::fixture_sanitizing(Answer::Ok, on).await;
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", args, None, None).await;
    sent(&fx, body)
}

/// R1 `/mcp` `gateway_invoke alpha read` on the firewalled fixture, whose
/// backend answers `text`.
pub(crate) async fn invoke_answering(text: &'static str) -> Sent {
    let fx = super::direct_guards_fixture::fixture_firewalled_with(Answer::Text(text), None, false)
        .await;
    let (_, body) = post_meta_invoke(&fx, "k-std", "alpha", "read", serde_json::json!({}), None, None)
        .await;
    sent(&fx, body)
}

/// R3 `/mcp/alpha` `tools/call read` on the firewalled fixture, whose backend
/// answers `text`.
pub(crate) async fn direct_answering(text: &'static str) -> Sent {
    let fx = super::direct_guards_fixture::fixture_firewalled_with(Answer::Text(text), None, false)
        .await;
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", serde_json::json!({}), None, None)
        .await;
    sent(&fx, body)
}

/// R1 `/mcp` `gateway_invoke alpha read` whose backend asks one elicitation
/// question the client never declared.
pub(crate) async fn invoke_asking() -> Sent {
    let fx = super::direct_guards_fixture::fixture(Answer::AskOnce, |_| {}).await;
    let (_, body) = post_meta_invoke(&fx, "k-std", "alpha", "read", serde_json::json!({}), None, None)
        .await;
    sent(&fx, body)
}

/// R3 `/mcp/alpha` `tools/call read` whose backend asks the same question.
pub(crate) async fn direct_asking() -> Sent {
    let fx = super::direct_guards_fixture::fixture(Answer::AskOnce, |_| {}).await;
    let (_, body) = post_direct(&fx, "alpha", "k-std", "read", serde_json::json!({}), None, None)
        .await;
    sent(&fx, body)
}

/// R1 `/mcp` `gateway_invoke alpha read` with a chain signer emitting on
/// request, the call carrying a chain nonce.
pub(crate) async fn invoke_chained() -> Sent {
    use crate::gateway::chain_test_support::{NONCE_KEY, signer};
    let fx = super::direct_guards_fixture::fixture(Answer::Ok, |meta| {
        meta.set_chain_signer(signer(), crate::config::ChainEmit::OnRequest);
    })
    .await;
    let params = serde_json::json!({
        "name": "gateway_invoke",
        "arguments": { "server": "alpha", "tool": "read", "arguments": {} },
        "_meta": { NONCE_KEY: "matrix-nonce" },
    });
    let (_, body) =
        super::direct_guards_fixture::send(&fx, "/mcp", "k-std", "tools/call", params, None).await;
    sent(&fx, body)
}

/// R3 `/mcp/alpha` `tools/call read` with the same signer and nonce.
pub(crate) async fn direct_chained() -> Sent {
    use crate::gateway::chain_test_support::{NONCE_KEY, signer};
    let fx = super::direct_guards_fixture::fixture(Answer::Ok, |meta| {
        meta.set_chain_signer(signer(), crate::config::ChainEmit::OnRequest);
    })
    .await;
    let params = serde_json::json!({
        "name": "read", "arguments": {}, "_meta": { NONCE_KEY: "matrix-nonce" },
    });
    let (_, body) =
        super::direct_guards_fixture::send(&fx, "/mcp/alpha", "k-std", "tools/call", params, None)
            .await;
    sent(&fx, body)
}

/// `alpha`'s `read` surfaced under its own name on the Meta-MCP.
fn surfacing(meta: MetaMcp) -> MetaMcp {
    meta.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
        server: "alpha".to_string(),
        tool: "read".to_string(),
    }])
}

/// `tools/call read` on `/mcp`: the surfaced-name route (R2), with `meta`
/// as the params' `_meta` when given.
async fn call_surfaced(
    fx: &super::direct_guards_fixture::Fx,
    args: Value,
    meta: Option<Value>,
) -> Value {
    let mut params = serde_json::json!({ "name": "read", "arguments": args });
    if let Some(meta) = meta {
        params["_meta"] = meta;
    }
    super::direct_guards_fixture::send(fx, "/mcp", "k-std", "tools/call", params, None)
        .await
        .1
}

/// R2 with a chain signer emitting on request, the call carrying a chain nonce.
pub(crate) async fn surfaced_chained() -> Sent {
    use crate::gateway::chain_test_support::{NONCE_KEY, signer};
    let fx = super::direct_guards_fixture::fixture_built(Answer::Ok, |meta| {
        let mut meta = surfacing(meta);
        meta.set_chain_signer(signer(), crate::config::ChainEmit::OnRequest);
        meta
    })
    .await;
    let body = call_surfaced(
        &fx,
        serde_json::json!({}),
        Some(serde_json::json!({ NONCE_KEY: "matrix-nonce" })),
    )
    .await;
    sent(&fx, body)
}

/// R2 on the firewalled fixture writing audit rows to `audit`.
pub(crate) async fn surfaced_firewalled(audit: &Path, args: Value) -> Sent {
    let fx = super::direct_guards_fixture::fixture_firewalled_audited_built(
        Answer::Ok,
        audit.to_path_buf(),
        surfacing,
    )
    .await;
    let body = call_surfaced(&fx, args, None).await;
    sent(&fx, body)
}

/// The params of a modern `tools/call` of `name` declaring form elicitation,
/// extended by `extra`.
fn modern(name: &str, arguments: Value, extra: &Value) -> Value {
    let mut params = serde_json::json!({
        "name": name,
        "arguments": arguments,
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}
        }
    });
    if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        params.extend(extra.clone());
    }
    params
}

/// A modern call on `uri` (`/mcp` or `/mcp/alpha`) of `name`.
async fn modern_call(
    fx: &super::direct_guards_fixture::Fx,
    uri: &str,
    (name, arguments): (&str, Value),
    extra: &Value,
) -> Value {
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", name),
    ];
    let params = modern(name, arguments, extra);
    super::direct_guards_fixture::send_with_headers(fx, uri, "k-std", "tools/call", params, None, &headers)
        .await
        .1
}

/// The backend asks one question on `uri`; the retry answers it with
/// `answer`, on the firewalled fixture writing audit rows to `audit`.
/// Returns the retry's outcome.
async fn retry_answering(audit: &Path, uri: &str, call: (&str, Value), answer: &str) -> Sent {
    let fx = super::direct_guards_fixture::fixture_firewalled_audited(
        Answer::AskOnce,
        audit.to_path_buf(),
    )
    .await;
    let asked = modern_call(&fx, uri, call.clone(), &serde_json::json!({})).await;
    let state = super::direct_continuation_tests::state_of(&asked);
    let retry = serde_json::json!({
        "requestState": state,
        "inputResponses": {"k1": {"action": "accept", "content": {"account": answer}}},
    });
    let body = modern_call(&fx, uri, call, &retry).await;
    sent(&fx, body)
}

/// R1: a continuation retry on `gateway_invoke` whose answer is `answer`.
pub(crate) async fn invoke_retry_answering(audit: &Path, answer: &str) -> Sent {
    let call = serde_json::json!({ "server": "alpha", "tool": "read", "arguments": {} });
    retry_answering(audit, "/mcp", ("gateway_invoke", call), answer).await
}

/// R3: the same retry on `/mcp/alpha` `read`.
pub(crate) async fn direct_retry_answering(audit: &Path, answer: &str) -> Sent {
    retry_answering(audit, "/mcp/alpha", ("read", serde_json::json!({})), answer).await
}

/// A hardened, signed `gateway_invoke read` on `/mcp` as `key` under `nonce`,
/// declaring form elicitation, with `args`.
async fn signed_invoke(
    fx: &super::direct_guards_fixture::Fx,
    key: &str,
    nonce: &str,
    args: Value,
) -> Value {
    let params = serde_json::json!({
        "name": "gateway_invoke",
        "arguments": {"server": "alpha", "tool": "read", "arguments": args, "nonce": nonce},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}
        }
    });
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_invoke"),
    ];
    super::direct_guards_fixture::send_with_headers(fx, "/mcp", key, "tools/call", params, None, &headers)
        .await
        .1
}

/// R1, MIK-8150 NONCE.3: on the signed, relayed fixture whose backend answers
/// `text`, `k-std` reads it (the receipt), then `k-budget` relays it under
/// nonce `b1` and is refused, then re-sends a clean call under `b1`. Returns
/// (the relay refusal, the clean re-send).
pub(crate) async fn invoke_relay_then_resend(text: &'static str) -> (Value, Value) {
    let fx = super::direct_guards_fixture::fixture_signed_relayed(Answer::Text(text)).await;
    let read = signed_invoke(&fx, "k-std", "a1", serde_json::json!({})).await;
    assert!(read.get("error").is_none(), "premise: the read ran: {read}");
    let relayed = signed_invoke(&fx, "k-budget", "b1", serde_json::json!({ "cmd": text })).await;
    let resent = signed_invoke(&fx, "k-budget", "b1", serde_json::json!({})).await;
    (relayed, resent)
}

/// R3, R20: on the signed fixture with a spend budget, `k-budget` runs once,
/// is refused by the budget under nonce `n2`, then re-sends under `n2`.
/// Returns (the spend refusal, the re-send).
#[cfg(feature = "cost-governance")]
pub(crate) async fn direct_spend_then_resend() -> (Value, Value) {
    use super::direct_continuation_tests::{budget, signed_call};
    let fx = super::direct_guards_fixture::fixture_hardened_signed_built(Answer::Ok, true, budget)
        .await;
    let who = ("k-budget", "alpha");
    let (_, first) = signed_call(&fx, who, "n1", serde_json::json!({})).await;
    assert!(first.get("error").is_none(), "premise: the first call ran: {first}");
    let (_, refused) = signed_call(&fx, who, "n2", serde_json::json!({})).await;
    let (_, again) = signed_call(&fx, who, "n2", serde_json::json!({})).await;
    (refused, again)
}
