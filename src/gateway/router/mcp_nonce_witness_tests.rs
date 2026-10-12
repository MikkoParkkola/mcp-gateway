// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 slice 3a (NONCEFX.9): a signed `gateway_invoke` refused after a
//! step that may have taken effect keeps its nonce spent. A refund needs the
//! refund witness, and a credential mint or refresh, a backend `tools/list`
//! or a consumed continuation drops it. Each KEEP row pairs with a REFUND
//! control on the effect-free path (`mcp_nonce_tests.rs` n1a, n1b).

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::direct_continuation_tests::{answers, code, dispatched, state_of};
use super::direct_guards_fixture::{Answer, Fx, fixture_propagating_signed};

const SUBJECT: &str = "alice";

/// Seed `SUBJECT`'s per-user slot on each backend with the scripted
/// transport, so a propagated call dispatches to it (as
/// `slot_quota_direct_tests.rs` does).
pub(super) fn seed_caller_slots(fx: &Fx) {
    for backend in ["alpha", "alpha-pt"] {
        let registered = fx.state.backends.get(backend).expect("fixture backend");
        let shared = registered
            .pooled_transport_for_test(&crate::backend::PoolKey::Shared)
            .expect("the fixture's scripted transport");
        registered.set_pooled_transport_for_test(
            &crate::backend::PoolKey::PerUser {
                binding: format!("{SUBJECT}@aud-{backend}"),
            },
            shared,
        );
    }
}

/// A signed `gateway_invoke read` on `/mcp` as `key` against `backend`, under
/// `nonce`, carrying `SUBJECT`'s verified identity (so the backend's required
/// propagation mints), from a modern client that declares form elicitation.
pub(super) async fn signed_call(
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
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
        },
    });
    if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        params.extend(extra.clone());
    }
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "gateway_invoke")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
                .to_string(),
        ))
        .expect("request");
    request
        .extensions_mut()
        .insert(crate::key_server::oidc::VerifiedIdentity {
            subject: SUBJECT.to_string(),
            email: format!("{SUBJECT}@example.invalid"),
            name: None,
            groups: vec![],
            issuer: "https://a.example.invalid".to_string(),
        });
    let response = tower::ServiceExt::oneshot(fx.router.clone(), request)
        .await
        .expect("response");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, serde_json::from_slice(&body).expect("json"))
}

fn refused_as_replay(body: &Value) -> bool {
    body["error"]["message"]
        .as_str()
        .is_some_and(|m| m.to_lowercase().contains("replay"))
}

/// K-spend-mint: the refused call minted a credential, then the spend budget
/// refused it. The mint dropped the witness, so the nonce stays spent: the
/// same call re-sent is a replay. Red on base: it meets the budget again
/// (n1b's refund, which ignores the mint).
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_spend_refusal_after_a_mint_keeps_the_nonce() {
    use super::direct_continuation_tests::budget;
    let (fx, minting) = fixture_propagating_signed(Answer::Ok, false, budget).await;
    seed_caller_slots(&fx);
    let who = ("k-budget", "alpha");
    let (_, first) = signed_call(&fx, who, "n1", json!({})).await;
    assert!(first.get("error").is_none(), "the paying call: {first}");
    assert!(
        minting.count() > 0,
        "the identity extension reached propagation"
    );

    let before = minting.count();
    let (_, refused) = signed_call(&fx, who, "n2", json!({})).await;
    assert_eq!(code(&refused), Some(-32003), "the spend refusal: {refused}");
    assert!(minting.count() > before, "the refused call itself minted");

    let (_, again) = signed_call(&fx, who, "n2", json!({})).await;
    assert!(
        refused_as_replay(&again),
        "the nonce was given back after a mint: {again}"
    );
    assert_eq!(dispatched(&fx), 1);
}

/// K-retry-mint: an honest warm-up call (schema held, the question asked),
/// then a forged retry that mints before it fails at `redeem_retry` (keyring
/// `open`, before any consume). `k-std` has no budget, so the spend check
/// cannot refuse first. The mint dropped the witness: the honest retry under
/// the same nonce is a replay. Red on base: it is served (n1a's refund).
#[tokio::test]
async fn a_refused_retry_after_a_mint_keeps_the_nonce() {
    let (fx, minting) = fixture_propagating_signed(Answer::AskOnce, false, |meta| meta).await;
    seed_caller_slots(&fx);
    let who = ("k-std", "alpha");
    let (_, asked) = signed_call(&fx, who, "n1", json!({})).await;
    let state = state_of(&asked);
    assert!(
        minting.count() > 0,
        "the identity extension reached propagation"
    );

    let before = minting.count();
    let forged = json!({"requestState": "forged", "inputResponses": answers()});
    let (_, refused) = signed_call(&fx, who, "n2", forged).await;
    assert_eq!(
        code(&refused),
        Some(-32602),
        "the redeem refusal: {refused}"
    );
    assert!(minting.count() > before, "the refused call itself minted");

    let honest = json!({"requestState": state, "inputResponses": answers()});
    let (_, again) = signed_call(&fx, who, "n2", honest).await;
    assert!(
        refused_as_replay(&again),
        "the nonce was given back after a mint: {again}"
    );
    assert_eq!(dispatched(&fx), 1, "only the warm-up reached the backend");
}

/// K-cold-schema: no mint; the refused call is the first on `alpha-pt`, so
/// the undeclared-key check fetches `tools/list` from the backend before the
/// spend budget refuses it. The per-key budget is shared across backends, the
/// schema slot is per backend, so paying on `alpha` leaves `alpha-pt` cold.
/// The fetch dropped the witness: the re-send is a replay. Red on base.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_spend_refusal_after_a_cold_schema_fetch_keeps_the_nonce() {
    use super::direct_continuation_tests::budget;
    use super::direct_guards_fixture::fixture_hardened_signed_built;
    let fx = fixture_hardened_signed_built(Answer::Ok, true, budget).await;
    let (_, first) = signed_call(&fx, ("k-budget", "alpha"), "n1", json!({})).await;
    assert!(first.get("error").is_none(), "the paying call: {first}");
    let cold = fx.state.backends.get("alpha-pt").expect("fixture backend");
    assert!(
        !cold.has_cached_tools(),
        "alpha-pt must be cold before the refused call"
    );

    let fills = cold.list_fills();

    let who = ("k-budget", "alpha-pt");
    let (_, refused) = signed_call(&fx, who, "n2", json!({})).await;
    assert_eq!(code(&refused), Some(-32003), "the spend refusal: {refused}");
    assert!(
        cold.has_cached_tools(),
        "the refused call fetched tools/list"
    );
    assert!(cold.list_fills() > fills, "and the fill was counted");

    let (_, again) = signed_call(&fx, who, "n2", json!({})).await;
    assert!(
        refused_as_replay(&again),
        "the nonce was given back after a fetch: {again}"
    );
    assert_eq!(dispatched(&fx), 1);
}

/// R-schema-off (gpt code r1): with the input-schema check off, a call on a
/// cold slot fills no tool list, so the spend refusal acted on nothing and
/// gives its nonce back: the re-send meets the budget again, not a replay.
/// Red on the snapshot rule (a cold slot counted as a fetch whatever the
/// mode); the fill counter must not move.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_spend_refusal_with_the_schema_check_off_gives_the_nonce_back() {
    use super::direct_continuation_tests::budget;
    use super::direct_guards_fixture::fixture_hardened_signed_schema_off;
    let fx = fixture_hardened_signed_schema_off(Answer::Ok, budget).await;
    let (_, first) = signed_call(&fx, ("k-budget", "alpha"), "n1", json!({})).await;
    assert!(first.get("error").is_none(), "the paying call: {first}");
    let cold = fx.state.backends.get("alpha-pt").expect("fixture backend");
    assert!(!cold.has_cached_tools(), "premise: alpha-pt is cold");
    let fills = cold.list_fills();

    let who = ("k-budget", "alpha-pt");
    let (_, refused) = signed_call(&fx, who, "n2", json!({})).await;
    assert_eq!(code(&refused), Some(-32003), "the spend refusal: {refused}");
    assert_eq!(
        cold.list_fills(),
        fills,
        "premise: the check filled nothing"
    );

    let (_, again) = signed_call(&fx, who, "n2", json!({})).await;
    assert_eq!(
        code(&again),
        Some(-32003),
        "the nonce was kept though nothing acted: {again}"
    );
    assert_eq!(dispatched(&fx), 1);
}

/// An answer the request firewall refuses: a shell command separator and a
/// recursive delete, split here so the test source does not spell it.
#[cfg(feature = "firewall")]
fn blocked_answer() -> String {
    format!("; {} -rf / ", "rm")
}

/// K-choke-consume: a valid retry whose answers the firewall blocks consumes
/// its continuation in `redeem_retry`, then the chokepoint refuses it. The
/// consume dropped the witness: a fresh call under that nonce is a replay.
/// Red on base: it is served (the /mcp twin of `f2d_giveback`, which refunds).
/// Run twice: with a backend question that carries its own `requestState`,
/// and with one that carries none (muse code r1: the consume is the caller's
/// continuation, whatever state the backend issued).
#[cfg(feature = "firewall")]
#[tokio::test]
async fn a_chokepoint_refusal_after_a_consume_keeps_the_nonce() {
    use super::direct_guards_fixture::fixture_hardened_signed_firewalled;
    for (label, answer) in [
        ("backend state", Answer::AskOnce),
        ("no backend state", Answer::AskNoState),
    ] {
        let fx = fixture_hardened_signed_firewalled(answer).await;
        let who = ("k-std", "alpha");
        let (_, asked) = signed_call(&fx, who, "n1", json!({})).await;
        let state = state_of(&asked);
        let blocked = json!({"k1": {"action": "accept", "content": {"account": blocked_answer()}}});
        let hostile = json!({"requestState": state, "inputResponses": blocked});
        let (_, refused) = signed_call(&fx, who, "n2", hostile).await;
        assert_eq!(
            code(&refused),
            Some(-32600),
            "{label}: the chokepoint refusal: {refused}"
        );
        assert_eq!(
            dispatched(&fx),
            1,
            "{label}: the hostile answer was not sent"
        );

        let (_, fresh) = signed_call(&fx, who, "n2", json!({})).await;
        assert!(
            refused_as_replay(&fresh),
            "{label}: the nonce was given back after a consume: {fresh}"
        );
        assert_eq!(dispatched(&fx), 1);

        // The consume itself: the same continuation, honestly answered under a
        // fresh nonce, is refused as already redeemed.
        let honest = json!({"requestState": state, "inputResponses": answers()});
        let (_, again) = signed_call(&fx, who, "n3", honest).await;
        assert_eq!(
            code(&again),
            Some(-32602),
            "{label}: the continuation was consumed: {again}"
        );
        assert_eq!(dispatched(&fx), 1);
    }
}

/// K-optional-mint (MIK-8379 H1): an optional propagating backend whose mint
/// fails, or succeeds with a header that does not parse, falls back to the
/// static credential, so no binding comes back; the mint was still attempted
/// (it may have reached the issuer), so the spend refusal that follows keeps
/// the nonce. Red on slice 3a: `minted` read the binding only.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_spend_refusal_after_a_failed_optional_mint_keeps_the_nonce() {
    use super::direct_continuation_tests::budget;
    use super::direct_guards_fixture::{MINT_MODES, fixture_optional_failing_mint};
    for (mode, mint) in MINT_MODES {
        let (fx, failing) = fixture_optional_failing_mint(Answer::Ok, mint(), budget).await;
        let who = ("k-budget", "alpha");
        let (_, first) = signed_call(&fx, who, "n1", json!({})).await;
        assert!(
            first.get("error").is_none(),
            "{mode}: the paying call fell back: {first}"
        );

        let before = failing.count();
        let (_, refused) = signed_call(&fx, who, "n2", json!({})).await;
        assert_eq!(
            code(&refused),
            Some(-32003),
            "{mode}: the spend refusal: {refused}"
        );
        assert!(
            failing.count() > before,
            "{mode}: the refused call attempted a mint"
        );

        let (_, again) = signed_call(&fx, who, "n2", json!({})).await;
        assert!(
            refused_as_replay(&again),
            "{mode}: the nonce was given back after the attempt: {again}"
        );
        assert_eq!(dispatched(&fx), 1, "{mode}");
    }
}
