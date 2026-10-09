// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8150` (`/mcp` half, MIK-8137 P1 row N1): a signed `gateway_invoke`
//! refused before its backend runs gives its signing nonce back, as the direct
//! route does since #3451 (R18, R20), so the honest call re-sent under that
//! nonce is judged on its merits, not refused as a replay.

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::direct_continuation_tests::{BACKENDS, answers, code, dispatched, state_of};
use super::direct_guards_fixture::{Answer, Fx, fixture_hardened_signed, send_with_headers};

/// `gateway_invoke read` on `/mcp` as `key`, a hardened modern request
/// declaring form elicitation, signed with `nonce`, with `extra` in the params.
async fn signed_invoke(
    fx: &Fx,
    (key, backend): (&str, &str),
    nonce: &str,
    extra: Value,
) -> (StatusCode, Value) {
    let mut params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": backend, "tool": "read", "arguments": {}, "nonce": nonce},
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}
        }
    });
    if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        params.extend(extra.clone());
    }
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_invoke"),
    ];
    send_with_headers(fx, "/mcp", key, "tools/call", params, None, &headers).await
}

/// N1a (R18 on `/mcp`): a continuation refused before the backend consumes
/// no nonce; the honest retry under that nonce is served. Mutant: the nonce
/// kept on a refused redeem.
#[tokio::test]
async fn n1a_a_refused_continuation_consumes_no_nonce_on_mcp() {
    for backend in BACKENDS {
        let fx = fixture_hardened_signed(Answer::AskOnce, true).await;
        let who = ("k-std", backend);
        let (_, asked) = signed_invoke(&fx, who, &format!("{backend}-n1"), json!({})).await;
        let state = state_of(&asked);
        let n2 = format!("{backend}-n2");
        let forged = json!({"requestState": "forged", "inputResponses": answers()});
        let (_, refused) = signed_invoke(&fx, who, &n2, forged).await;
        assert_eq!(code(&refused), Some(-32602), "{backend}: {refused}");
        let honest = json!({"requestState": state, "inputResponses": answers()});
        let (status, done) = signed_invoke(&fx, who, &n2, honest).await;
        assert_eq!(status, StatusCode::OK, "{backend}: nonce burned: {done}");
        assert!(done.get("error").is_none(), "{backend}: {done}");
        assert_eq!(dispatched(&fx), 2, "{backend}");
    }
}

/// N1b (R20 on `/mcp`): a call the spend budget refuses consumes no nonce;
/// re-sent under it, it meets the budget again, not a replay refusal.
/// Mutant: the nonce kept on a spend refusal.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn n1b_a_spend_refusal_consumes_no_nonce_on_mcp() {
    use super::direct_continuation_tests::budget;
    use super::direct_guards_fixture::fixture_hardened_signed_built;
    for backend in BACKENDS {
        let fx = fixture_hardened_signed_built(Answer::Ok, true, budget).await;
        let who = ("k-budget", backend);
        let (_, first) = signed_invoke(&fx, who, &format!("{backend}-n1"), json!({})).await;
        assert!(first.get("error").is_none(), "{backend}: {first}");
        let n2 = format!("{backend}-n2");
        let (status, refused) = signed_invoke(&fx, who, &n2, json!({})).await;
        assert_eq!(code(&refused), Some(-32003), "{backend}: {refused}");
        let (again_status, again) = signed_invoke(&fx, who, &n2, json!({})).await;
        assert_eq!(
            (again_status, code(&again)),
            (status, code(&refused)),
            "{backend}: nonce burned: {again}"
        );
        assert_eq!(dispatched(&fx), 1, "{backend}");
    }
}

/// N1c (gpt i1 CRIT): a signed chain whose first step ran keeps its nonce
/// spent when a later step is refused before its backend (here by the spend
/// budget). Re-sent under that nonce, the chain is refused as a replay and its
/// first step never runs twice. Mutant: the give-back ignoring earlier
/// dispatches of the same signed execution.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn n1c_a_signed_chain_that_ran_a_step_keeps_its_nonce() {
    use super::direct_continuation_tests::budget;
    use super::direct_guards_fixture::fixture_hardened_signed_built;
    let fx = fixture_hardened_signed_built(Answer::Ok, true, budget).await;
    let chain = json!({"chain": [
        {"tool": "alpha:read", "arguments": {}},
        {"tool": "alpha:read", "arguments": {"cmd": "two"}}
    ]});
    let params = json!({"name": "gateway_execute", "arguments": chain, "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        crate::gateway::meta_mcp::signing::NONCE_META: "chain-n1"
    }});
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_execute"),
    ];
    let send = || {
        send_with_headers(
            &fx,
            "/mcp",
            "k-budget",
            "tools/call",
            params.clone(),
            None,
            &headers,
        )
    };
    let (_, first) = send().await;
    assert!(
        first.get("error").is_some(),
        "step 2 is refused by the budget: {first}"
    );
    assert_eq!(dispatched(&fx), 1, "step 1 ran once: {first}");
    let (_, again) = send().await;
    assert_eq!(code(&again), Some(-32001), "replay refused: {again}");
    assert_eq!(dispatched(&fx), 1, "step 1 ran twice");
}
