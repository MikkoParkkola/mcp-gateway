// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8379.DIRECTREFUND.4: the direct route (`/mcp/{name}`) gives a signing
//! nonce back by the same rule as `/mcp` (MIK-8353 slice 3a): only when no
//! step before the refusal may have acted. Each row is the direct twin of a
//! `/mcp` row in `mcp_nonce_witness_tests.rs` and runs on both backends.

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::direct_continuation_tests::{BACKENDS, answers, code, dispatched, state_of};
use super::direct_guards_fixture::{Answer, Fx, fixture_propagating_signed};
use super::mcp_nonce_witness_tests::seed_caller_slots;

const SUBJECT: &str = "alice";

/// `tools/call read` on `/mcp/{backend}` as `key`, signed with `nonce`, from a
/// modern client that declares form elicitation, carrying `SUBJECT`'s verified
/// identity (so a backend that requires propagation mints), with `extra`.
async fn signed_direct(
    fx: &Fx,
    (key, backend): (&str, &str),
    nonce: &str,
    extra: Value,
) -> (StatusCode, Value) {
    use crate::gateway::meta_mcp::signing::NONCE_META;
    let mut params = json!({"name": "read", "arguments": {}, "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
        NONCE_META: nonce,
    }});
    if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        params.extend(extra.clone());
    }
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{backend}"))
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "read")
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
    body.to_string().to_lowercase().contains("replay")
}

/// Site A, KEEP (twin of K-spend-mint): the refused call minted a credential,
/// then the spend budget refused it. The mint is an effect, so the nonce stays
/// spent. Red on base: the direct route refunded unconditionally.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_direct_spend_refusal_after_a_mint_keeps_the_nonce() {
    use super::direct_continuation_tests::budget;
    for backend in BACKENDS {
        let (fx, minting) = fixture_propagating_signed(Answer::Ok, false, budget).await;
        seed_caller_slots(&fx);
        let who = ("k-budget", backend);
        let (_, first) = signed_direct(&fx, who, "n1", json!({})).await;
        assert!(
            first.get("error").is_none(),
            "{backend}: the paying call: {first}"
        );

        let before = minting.count();
        let (_, refused) = signed_direct(&fx, who, "n2", json!({})).await;
        assert!(
            refused.to_string().contains("budget exceeded"),
            "{backend}: the spend refusal: {refused}"
        );
        assert!(
            minting.count() > before,
            "{backend}: the refused call minted"
        );

        let (_, again) = signed_direct(&fx, who, "n2", json!({})).await;
        assert!(
            refused_as_replay(&again),
            "{backend}: the nonce was given back after a mint: {again}"
        );
        assert_eq!(dispatched(&fx), 1, "{backend}");
    }
}

/// Site R, KEEP (twin of K-retry-mint): an honest warm-up asks; a forged retry
/// mints, then fails at `redeem_retry` before any consume. The mint is an
/// effect: the honest retry under the same nonce is a replay. `k-std` has no
/// budget. Red on base.
#[tokio::test]
async fn a_direct_refused_retry_after_a_mint_keeps_the_nonce() {
    for backend in BACKENDS {
        let (fx, minting) = fixture_propagating_signed(Answer::AskOnce, false, |meta| meta).await;
        seed_caller_slots(&fx);
        let who = ("k-std", backend);
        let (_, asked) = signed_direct(&fx, who, "n1", json!({})).await;
        let state = state_of(&asked);

        let before = minting.count();
        let forged = json!({"requestState": "forged", "inputResponses": answers()});
        let (_, refused) = signed_direct(&fx, who, "n2", forged).await;
        assert_eq!(
            code(&refused),
            Some(-32602),
            "{backend}: the redeem refusal: {refused}"
        );
        assert!(
            minting.count() > before,
            "{backend}: the refused call minted"
        );

        let honest = json!({"requestState": state, "inputResponses": answers()});
        let (_, again) = signed_direct(&fx, who, "n2", honest).await;
        assert!(
            refused_as_replay(&again),
            "{backend}: the nonce was given back after a mint: {again}"
        );
        assert_eq!(
            dispatched(&fx),
            1,
            "{backend}: only the warm-up reached the backend"
        );
    }
}

/// Pre-admission, KEEP (twin of K-cold-schema): no mint; the refused call is
/// the first on `alpha-pt`, so its schema check fills `tools/list` before the
/// nonce is even admitted, then the budget refuses it. The fill is an effect:
/// the witness is never minted, and the re-send is a replay. Red on base.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_direct_spend_refusal_after_a_cold_schema_fill_keeps_the_nonce() {
    use super::direct_continuation_tests::budget;
    use super::direct_guards_fixture::fixture_hardened_signed_built;
    let fx = fixture_hardened_signed_built(Answer::Ok, true, budget).await;
    let (_, first) = signed_direct(&fx, ("k-budget", "alpha"), "n1", json!({})).await;
    assert!(first.get("error").is_none(), "the paying call: {first}");
    let cold = fx.state.backends.get("alpha-pt").expect("fixture backend");
    assert!(
        !cold.has_cached_tools(),
        "alpha-pt is cold before the refused call"
    );
    let fills = cold.list_fills();

    let who = ("k-budget", "alpha-pt");
    let (_, refused) = signed_direct(&fx, who, "n2", json!({})).await;
    assert!(
        refused.to_string().contains("budget exceeded"),
        "the spend refusal: {refused}"
    );
    assert!(
        cold.list_fills() > fills,
        "the refused call filled tools/list"
    );

    let (_, again) = signed_direct(&fx, who, "n2", json!({})).await;
    assert!(
        refused_as_replay(&again),
        "the nonce was given back after a fill: {again}"
    );
    assert_eq!(dispatched(&fx), 1);
}

/// Pre-admission, KEEP (MIK-8379 H1, twin of K-optional-mint): an optional
/// propagating backend whose mint fails, or succeeds with a header that does
/// not parse, falls back to the static credential; the attempt counts as an
/// effect, so the witness is never minted and the spend refusal keeps the
/// nonce. Both backends.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_direct_spend_refusal_after_a_failed_optional_mint_keeps_the_nonce() {
    use super::direct_continuation_tests::budget;
    use super::direct_guards_fixture::{FailingMint, fixture_optional_failing_mint};
    let modes: [(&str, fn() -> FailingMint); 2] = [
        ("failed mint", FailingMint::default),
        ("invalid header", FailingMint::with_bad_header),
    ];
    for (mode, mint) in modes {
        for backend in BACKENDS {
            let (fx, failing) = fixture_optional_failing_mint(Answer::Ok, mint(), budget).await;
            let who = ("k-budget", backend);
            let (_, first) = signed_direct(&fx, who, "n1", json!({})).await;
            assert!(
                first.get("error").is_none(),
                "{mode} {backend}: the paying call: {first}"
            );

            let before = failing.count();
            let (_, refused) = signed_direct(&fx, who, "n2", json!({})).await;
            assert!(
                refused.to_string().contains("budget exceeded"),
                "{mode} {backend}: the spend refusal: {refused}"
            );
            assert!(
                failing.count() > before,
                "{mode} {backend}: the refused call attempted a mint"
            );

            let (_, again) = signed_direct(&fx, who, "n2", json!({})).await;
            assert!(
                refused_as_replay(&again),
                "{mode} {backend}: the nonce was given back after the attempt: {again}"
            );
            assert_eq!(dispatched(&fx), 1, "{mode} {backend}");
        }
    }
}
