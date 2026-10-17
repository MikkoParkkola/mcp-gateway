// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8433 R-MCP (design §3.1, §4), re-pinned for MIK-8439 (design §3.4,
//! §5): on `/mcp`, signing runs after the route stage. A per-user tool in
//! error-rate cooldown, called signed by a caller with a view whose nonce an
//! earlier call already spent: in every arm the nonce is judged first, so the
//! replay is refused as a replay, and a fresh nonce meets what the dispatch
//! answers first (the cooldown, or the failed fill). R-MCP (s) pins a shared
//! backend, whose policy still answers the cooldown before the nonce. Split
//! out of `slot_verdict_witness_tests.rs`; it uses the parent's fixture.

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

/// R-MCP (a), Offers: the verdict recorded `Visible`, and on a
/// per-user backend the policy no longer reads the cooldown (MIK-8439): the
/// replay is refused as a replay, before the cooldown is read, and a
/// fresh-nonce call meets the cooldown at dispatch, in the dispatch's
/// rendering. Nothing sent. Before MIK-8439 both answered the cooldown,
/// unprefixed, before the nonce; that order now holds for a shared backend
/// only (R-MCP (s)). After MIK-8439 this arm and (b) converge on a per-user
/// backend by design: each pins its own verdict arm, so keep both.
#[tokio::test]
async fn r_mcp_a_offers_judges_the_nonce_then_meets_the_cooldown_at_dispatch() {
    let gw = signed(Warmth::Warm, CLOSED).await;
    let (replay, fresh, sent) = arm(&gw, "rmcp-a").await;
    assert!(
        message(&replay).contains(REPLAY) && !replay.to_string().contains(COOLDOWN),
        "R-MCP (a) replay: not judged as a replay first: {replay}"
    );
    assert_eq!(
        replay.pointer("/error/code"),
        Some(&json!(-32001)),
        "R-MCP (a) replay: {replay}"
    );
    assert_eq!(
        fresh.pointer("/error/code"),
        Some(&json!(-32000)),
        "R-MCP (a) fresh nonce: {fresh}"
    );
    assert_eq!(
        message(&fresh),
        format!(
            "JSON-RPC error -32000: {}",
            crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::cooldown_refusal(
                BACKEND, TOOL
            )
        ),
        "R-MCP (a) fresh nonce: {fresh}"
    );
    assert_eq!(sent, 0, "R-MCP (a): sent");
}

/// The (b)/(c) assertions: the fresh-nonce control is answered with
/// `first`, what the dispatch meets first in that arm, then the replay is
/// refused as a replay, never with the cooldown. Nothing sent.
fn assert_nonce_first(row: &str, first: &str, (replay, fresh, sent): &(Value, Value, usize)) {
    assert!(
        fresh.to_string().contains(first),
        "{row} control: a fresh nonce is not answered with {first:?}: {fresh}"
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
/// records nothing. RED at base: signing answers the cooldown first. It
/// converges with (a) on a per-user backend after MIK-8439, by design.
#[tokio::test]
async fn r_mcp_b_unknown_judges_the_nonce_before_the_cooldown() {
    let gw = signed(
        Warmth::ColdFailing,
        crate::config::InputSchemaEnforcement::Standard,
    )
    .await;
    assert_nonce_first("R-MCP (b)", COOLDOWN, &arm(&gw, "rmcp-b").await);
}

/// R-MCP (c), failed fill (red first): alpha's fill fails under `closed`,
/// so the verdict is `Unavailable` and records nothing. RED at base, as (b).
/// The fresh-nonce control gets the failed fill: the dispatch answers the
/// carried fill failure before the cooldown, which waits for the credential
/// step (MIK-8439); before MIK-8439 it got the cooldown from the policy.
#[tokio::test]
async fn r_mcp_c_failed_fill_judges_the_nonce_before_the_cooldown() {
    let gw = signed(Warmth::ColdFailing, CLOSED).await;
    let answers = arm(&gw, "rmcp-c").await;
    assert!(
        !answers.1.to_string().contains(COOLDOWN),
        "R-MCP (c) control: the cooldown answered before the failed fill: {}",
        answers.1
    );
    assert_nonce_first("R-MCP (c)", "upstream refused tools/list", &answers);
}

/// R-MCP (s), shared backend (green, kills MIK-8433's M6): on a shared
/// backend signing still runs the full policy, cooldown included, before the
/// nonce (MIK-8439 keeps the policy's check there). A caller with a view, the
/// tool in cooldown: its replayed nonce and a fresh one both get the
/// cooldown, unprefixed, before the nonce. Nothing sent. The order R-MCP (a)
/// pinned for a per-user backend before MIK-8439: since then this is the only
/// row that exercises the policy's cooldown-before-nonce order.
#[tokio::test]
async fn r_mcp_s_shared_backend_answers_the_cooldown_before_the_nonce() {
    use crate::gateway::router::direct_guards_fixture::{Answer, fixture, post_meta_invoke_nonce};
    const SHARED: &str = "alpha";
    let fx = fixture(Answer::Ok, |meta| {
        meta.enable_message_signing(
            crate::security::message_signing::MessageSigner::new(
                b"cooldown-mcp-shared-signing-secret-32-bytes".to_vec(),
                None,
                "cooldown-mcp-shared".into(),
            ),
            std::time::Duration::from_secs(300),
            true,
        );
    })
    .await;
    assert!(
        !fx.state
            .backends
            .get(SHARED)
            .expect("the shared backend")
            .keeps_per_user_catalogues(),
        "premise: {SHARED} is a shared backend"
    );
    let invoke = |nonce: &'static str| post_meta_invoke_nonce(&fx, "k-std", SHARED, TOOL, nonce);
    let before = fx.calls.load(std::sync::atomic::Ordering::SeqCst);
    let earlier = invoke("rmcp-s-spent").await;
    assert!(
        earlier.1.get("error").is_none()
            && earlier.1.pointer("/result/isError") != Some(&json!(true)),
        "R-MCP (s) premise: the first call succeeds: {earlier:?}"
    );
    assert_eq!(
        fx.calls.load(std::sync::atomic::Ordering::SeqCst) - before,
        1,
        "R-MCP (s) premise: the first call was sent once: {earlier:?}"
    );
    let again = invoke("rmcp-s-spent").await;
    assert!(
        message(&again.1).contains(REPLAY),
        "R-MCP (s) premise: the earlier call spent its nonce: {earlier:?} then {again:?}"
    );
    let kill_switch = fx.state.meta_mcp.kill_switch();
    let cfg = crate::kill_switch::CapabilityErrorBudgetConfig::default();
    for _ in 0..=cfg.window_size.max(cfg.min_samples) {
        kill_switch.record_capability_failure(SHARED, TOOL, &cfg);
    }
    assert!(
        kill_switch.is_capability_disabled(SHARED, TOOL),
        "premise: {TOOL} is in cooldown"
    );
    let calls = fx.calls.load(std::sync::atomic::Ordering::SeqCst);
    let cooldown =
        crate::gateway::meta_mcp::account_resolver_fixture::direct_bridge::cooldown_refusal(
            SHARED, TOOL,
        );
    for (call, nonce) in [("replay", "rmcp-s-spent"), ("fresh nonce", "rmcp-s-fresh")] {
        let (_, answer) = invoke(nonce).await;
        assert_eq!(
            answer.pointer("/error/code"),
            Some(&json!(-32000)),
            "R-MCP (s) {call}: {answer}"
        );
        assert_eq!(message(&answer), cooldown, "R-MCP (s) {call}: {answer}");
    }
    assert_eq!(
        fx.calls.load(std::sync::atomic::Ordering::SeqCst),
        calls,
        "R-MCP (s): sent"
    );
}
