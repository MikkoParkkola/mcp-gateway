// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8433 R-MCP (design §3.1, §4): on `/mcp`, signing runs after the route
//! stage. A per-user tool in error-rate cooldown, called signed by a caller
//! with a view whose nonce an earlier call already spent: where the caller
//! verdict recorded `Visible` (Offers) the cooldown is answered before the
//! nonce, unchanged; where it recorded nothing (Unknown, failed fill) the
//! nonce is judged first, so the replay is refused as a replay. A fresh nonce
//! in those arms is still refused for the cooldown. Split out of
//! `slot_verdict_witness_tests.rs`; it uses the parent's fixture.

use super::*;
use crate::gateway::router::slot_verdict_http_tests::post_as_alpha;

/// The per-user gateway, signing armed (nonce required), alpha's slot in
/// `warmth` under `enforcement`.
async fn signed(warmth: Warmth, enforcement: crate::config::InputSchemaEnforcement) -> Gateway {
    gateway_built(
        (CallerSlot::Valid, &valid(), warmth),
        enforcement,
        Surfaced::No,
        |_| {},
        |meta| {
            meta.enable_message_signing(
                crate::security::message_signing::MessageSigner::new(
                    b"cooldown-mcp-signing-secret-at-least-32-bytes".to_vec(),
                    None,
                    "cooldown-mcp".into(),
                ),
                std::time::Duration::from_secs(300),
                true,
            );
        },
    )
    .await
}

/// An unkeyed signed `gateway_invoke` of [`TOOL`] under `nonce`, as alpha.
async fn invoke_tool(gw: &Gateway, nonce: &str) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {
        "name": "gateway_invoke",
        "arguments": {"server": BACKEND, "tool": TOOL, "arguments": {"q": "x"}, "nonce": nonce},
    }});
    post_as_alpha(&gw.router, "/mcp", &body).await.1
}

/// [`TOOL`] pushed into error-rate cooldown, as other callers' failures would.
fn cool(gw: &Gateway) {
    let kill_switch = gw.meta.kill_switch();
    let cfg = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        kill_switch.record_capability_failure(BACKEND, TOOL, &cfg);
    }
    assert!(
        kill_switch.is_capability_disabled(BACKEND, TOOL),
        "premise: {TOOL} is in cooldown"
    );
}

/// One arm: spend `spent` with an earlier call, check it is spent, cool
/// [`TOOL`], then the replay under `spent` and a fresh-nonce call. Both
/// answers, and the upstream sends the two added.
async fn arm(gw: &Gateway, row: &str) -> (Value, Value, usize) {
    let spent = format!("{row}-spent");
    let earlier = invoke_tool(gw, &spent).await;
    let again = invoke_tool(gw, &spent).await;
    assert!(
        message(&again).contains(REPLAY),
        "{row} premise: the earlier call spent its nonce: {earlier} then {again}"
    );
    cool(gw);
    let dispatched = gw.dispatched();
    let replay = invoke_tool(gw, &spent).await;
    let fresh = invoke_tool(gw, &format!("{row}-fresh")).await;
    (replay, fresh, gw.dispatched() - dispatched)
}

const COOLDOWN: &str = "temporarily disabled";

/// R-MCP (a), Offers (green, kills M3 and M6): the verdict recorded
/// `Visible`, so signing runs the policy first: the replay and a fresh-nonce
/// call both get the cooldown, unprefixed, before the nonce. Nothing sent.
#[tokio::test]
async fn r_mcp_a_offers_answers_the_cooldown_before_the_nonce() {
    let gw = signed(Warmth::Warm, CLOSED).await;
    let (replay, fresh, sent) = arm(&gw, "rmcp-a").await;
    let cooldown = format!(
        "Capability '{TOOL}' on server '{BACKEND}' is temporarily disabled due to a high \
         error rate. It will auto-recover after the cooldown period. Use \
         gateway_list_disabled_capabilities to see all disabled capabilities."
    );
    for (call, answer) in [("replay", &replay), ("fresh nonce", &fresh)] {
        assert_eq!(
            answer.pointer("/error/code"),
            Some(&json!(-32000)),
            "R-MCP (a) {call}: {answer}"
        );
        assert_eq!(message(answer), cooldown, "R-MCP (a) {call}: {answer}");
    }
    assert_eq!(sent, 0, "R-MCP (a): sent");
}

/// The (b)/(c) assertions: the fresh-nonce control is refused for the
/// cooldown (the arm reaches the policy), then the replay is refused as a
/// replay, never with the cooldown. Nothing sent.
fn assert_nonce_first(row: &str, (replay, fresh, sent): &(Value, Value, usize)) {
    assert!(
        fresh.to_string().contains(COOLDOWN),
        "{row} control: a fresh nonce is not refused for the cooldown: {fresh}"
    );
    assert!(
        message(replay).contains(REPLAY),
        "{row}: the replay was not judged as a replay: {replay}"
    );
    assert!(
        !replay.to_string().contains(COOLDOWN),
        "{row}: the cooldown answered before the nonce: {replay}"
    );
    assert_eq!(*sent, 0, "{row}: sent");
}

/// R-MCP (b), Unknown (red first, kills M1): alpha's fill fails under
/// `standard`, so the verdict is `Unknown` (`catalogue_verdict.rs:52`) and
/// records nothing. RED at base: signing answers the cooldown first.
#[tokio::test]
async fn r_mcp_b_unknown_judges_the_nonce_before_the_cooldown() {
    let gw = signed(
        Warmth::ColdFailing,
        crate::config::InputSchemaEnforcement::Standard,
    )
    .await;
    assert_nonce_first("R-MCP (b)", &arm(&gw, "rmcp-b").await);
}

/// R-MCP (c), failed fill (red first): alpha's fill fails under `closed`,
/// so the verdict is `Unavailable` and records nothing. RED at base, as (b).
#[tokio::test]
async fn r_mcp_c_failed_fill_judges_the_nonce_before_the_cooldown() {
    let gw = signed(Warmth::ColdFailing, CLOSED).await;
    assert_nonce_first("R-MCP (c)", &arm(&gw, "rmcp-c").await);
}
