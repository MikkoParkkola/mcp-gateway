// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The resend drivers of the route matrix: a relayed, a spent and a surfaced
//! call each answered once and then sent again. Moved from
//! `route_matrix_driver_tests.rs` for the file-size ceiling; the parent
//! re-exports what other rows call.

use super::*;

/// What [`invoke_relay_then_resend`] saw.
pub(crate) struct RelayResend {
    /// The relay refusal.
    pub(crate) relayed: Value,
    /// The clean re-send under the refused nonce.
    pub(crate) resent: Value,
    /// A third send under that nonce.
    pub(crate) third: Value,
    /// Tool-list fills admitted on the target across the relayed call.
    pub(crate) fills: u64,
    /// Backend `tools/call` sends made by the clean re-send.
    pub(crate) resent_calls: usize,
}

/// R1, NONCE.3: on the signed, relayed fixture whose backend answers
/// `text`, `k-std` reads it from `alpha` (the receipt, and the warm schema),
/// then `k-budget` relays it to `server` under nonce `b1` and is refused,
/// then re-sends a clean call under `b1`, then sends once more under it.
pub(crate) async fn invoke_relay_then_resend(text: &'static str, server: &str) -> RelayResend {
    let fx = super::super::direct_guards_fixture::fixture_signed_relayed(Answer::Text(text)).await;
    let read = signed_invoke(&fx, "k-std", "a1", serde_json::json!({})).await;
    assert!(read.get("error").is_none(), "premise: the read ran: {read}");
    let target = fx.state.backends.get(server).expect("fixture backend");
    let before = target.list_fills();
    let who = ("k-budget", server);
    let relayed = signed_invoke_on(&fx, who, "b1", serde_json::json!({ "cmd": text })).await;
    let fills = target.list_fills() - before;
    let sent = fx.calls.load(std::sync::atomic::Ordering::SeqCst);
    let resent = signed_invoke_on(&fx, who, "b1", serde_json::json!({})).await;
    let resent_calls = fx.calls.load(std::sync::atomic::Ordering::SeqCst) - sent;
    let third = signed_invoke_on(&fx, who, "b1", serde_json::json!({})).await;
    RelayResend {
        relayed,
        resent,
        third,
        fills,
        resent_calls,
    }
}

/// R3, R20: on the signed fixture with a spend budget, `k-budget` runs once
/// under `n1`, is refused by the budget under `n2`, re-sends under `n2`, then
/// re-sends under `n1`. Returns (the spend refusal, the `n2` re-send, the `n1`
/// re-send, the backend's `tools/call` count).
#[cfg(feature = "cost-governance")]
pub(crate) async fn direct_spend_then_resend() -> (Value, Value, Value, usize) {
    use super::super::direct_continuation_tests::{budget, signed_call};
    let fx = super::super::direct_guards_fixture::fixture_hardened_signed_built(
        Answer::Ok,
        true,
        budget,
    )
    .await;
    let who = ("k-budget", "alpha");
    let (_, first) = signed_call(&fx, who, "n1", serde_json::json!({})).await;
    assert!(
        first.get("error").is_none(),
        "premise: the first call ran: {first}"
    );
    let (_, refused) = signed_call(&fx, who, "n2", serde_json::json!({})).await;
    let (_, again) = signed_call(&fx, who, "n2", serde_json::json!({})).await;
    // Control: the first call's nonce was admitted, so its re-send is a replay.
    let (_, replay) = signed_call(&fx, who, "n1", serde_json::json!({})).await;
    (refused, again, replay, fx.calls.load(Ordering::SeqCst))
}

/// R2, NONCE.4: on the hardened, signed fixture surfacing
/// `alpha/read`, a keyed surfaced-name call runs under `s1`; the key reused for
/// other arguments is refused by execution admission (409) under `s2`; the
/// honest call is re-sent under `s2` with its own key; then a third call under
/// `s2`. Returns (the admission refusal, the re-send, the third send, the
/// backend's `tools/call` count).
pub(crate) async fn surfaced_admission_then_resend() -> (Value, Value, Value, usize) {
    use crate::gateway::meta_mcp::signing::NONCE_META;
    use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;
    let fx = super::super::direct_guards_fixture::fixture_hardened_signed_built(
        Answer::Ok,
        true,
        surfacing,
    )
    .await;
    let call = |key: &'static str, nonce: &'static str, args: Value| {
        let fx = &fx;
        async move {
            let params = serde_json::json!({ "name": "read", "arguments": args, "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                NONCE_META: nonce,
                IDEMPOTENCY_KEY_META: key,
            }});
            let headers = [
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "tools/call"),
                ("mcp-name", "read"),
            ];
            super::super::direct_guards_fixture::send_with_headers(
                fx,
                "/mcp",
                "k-std",
                "tools/call",
                params,
                None,
                &headers,
            )
            .await
            .1
        }
    };
    let first = call("s-k1", "s1", serde_json::json!({})).await;
    assert!(
        first.get("error").is_none(),
        "premise: the first call ran: {first}"
    );
    let refused = call("s-k1", "s2", serde_json::json!({ "cmd": "other" })).await;
    let resent = call("s-k2", "s2", serde_json::json!({ "cmd": "other" })).await;
    let third = call("s-k3", "s2", serde_json::json!({ "cmd": "other" })).await;
    (refused, resent, third, fx.calls.load(Ordering::SeqCst))
}
