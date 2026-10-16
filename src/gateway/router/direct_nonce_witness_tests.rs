// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8379.DIRECTREFUND.4: the direct route (`/mcp/{name}`) gives a signing
//! nonce back by the same rule as `/mcp` (MIK-8353 slice 3a): only when no
//! step before the refusal may have acted. Each row is the direct twin of a
//! `/mcp` row in `mcp_nonce_witness_tests.rs`; each runs on both backends
//! except the cold-schema row, which needs a backend left cold (`alpha-pt`).

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
    use super::direct_guards_fixture::{MINT_MODES, fixture_optional_failing_mint};
    for (mode, mint) in MINT_MODES {
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

/// `inner`, every `tools/list` held until released and counted on arrival.
#[cfg(feature = "cost-governance")]
pub(super) struct HeldList {
    pub(super) inner: std::sync::Arc<dyn crate::transport::Transport>,
    pub(super) lists: std::sync::atomic::AtomicUsize,
    pub(super) release: tokio::sync::Semaphore,
}

#[cfg(feature = "cost-governance")]
#[async_trait::async_trait]
impl crate::transport::Transport for HeldList {
    async fn request(
        &self,
        method: &str,
        params: Option<Value>,
    ) -> crate::Result<crate::protocol::JsonRpcResponse> {
        if method == "tools/list" {
            self.lists.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.release.acquire().await.expect("never closed").forget();
        }
        self.inner.request(method, params).await
    }
    async fn notify(&self, method: &str, params: Option<Value>) -> crate::Result<()> {
        self.inner.notify(method, params).await
    }
    fn is_connected(&self) -> bool {
        true
    }
    async fn close(&self) -> crate::Result<()> {
        Ok(())
    }
}

/// Pre-admission, KEEP (MIK-8353 PR-W, K-waiter-direct): A's cold
/// `tools/list` on `alpha-pt` is held on the wire; B's direct call starts
/// only once A is past `admit_fill` (so B's `fills_before` already counts A),
/// its key check joins A's fill, and A is released only once the join is
/// observed and B has not returned. The join is an effect (r4 §70): the
/// witness is never minted and the re-send is a replay. Red on base: a join
/// never moves `list_fills`. Mutant: mW (backend/metadata.rs:414).
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn a_direct_spend_refusal_after_joining_a_fill_keeps_the_nonce() {
    use super::direct_guards_fixture::fixture_hardened_signed_built;
    use std::sync::atomic::{AtomicBool, Ordering};
    let fx = fixture_hardened_signed_built(Answer::Ok, true, budget_below_one_call).await;
    let cold = fx.state.backends.get("alpha-pt").expect("fixture backend");
    assert!(!cold.has_cached_tools(), "premise: alpha-pt is cold");
    let shared = crate::backend::PoolKey::Shared;
    let wire = std::sync::Arc::new(HeldList {
        inner: cold
            .pooled_transport_for_test(&shared)
            .expect("scripted transport"),
        lists: std::sync::atomic::AtomicUsize::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    cold.set_pooled_transport_for_test(&shared, wire.clone());
    let fills = cold.list_fills();

    let who = ("k-budget", "alpha-pt");
    let (a_listed, b_done) = (AtomicBool::new(false), AtomicBool::new(false));
    let a = async {
        cold.get_tools_shared().await.expect("A's fill answers");
    };
    let b = async {
        until("A's tools/list", || a_listed.load(Ordering::SeqCst)).await;
        let (_, refused) = signed_direct(&fx, who, "n2", json!({})).await;
        b_done.store(true, Ordering::SeqCst);
        refused
    };
    let control = async {
        until("A's tools/list", || wire.lists.load(Ordering::SeqCst) == 1).await;
        assert_eq!(
            cold.list_fills(),
            fills + 1,
            "premise: A's fill was admitted"
        );
        a_listed.store(true, Ordering::SeqCst);
        until("B to join A's fill", || cold.tools_waiters_for_test() >= 1).await;
        assert!(
            !b_done.load(Ordering::SeqCst),
            "premise: B waits on A's fill"
        );
        wire.release.add_permits(1);
    };
    let ((), refused, ()) = tokio::join!(a, b, control);
    assert!(
        refused.to_string().contains("budget exceeded"),
        "premise: the spend refusal: {refused}"
    );
    assert_eq!(
        wire.lists.load(Ordering::SeqCst),
        1,
        "premise: one tools/list, A's"
    );

    let (_, again) = signed_direct(&fx, who, "n2", json!({})).await;
    assert!(
        refused_as_replay(&again),
        "the nonce was given back after joining a fill: {again}"
    );
    assert_eq!(dispatched(&fx), 0, "nothing reached a backend");
}

/// Wait until `ready`, failing the row (not hanging it) after 10 s.
#[cfg(feature = "cost-governance")]
pub(super) async fn until(what: &str, ready: impl Fn() -> bool) {
    let waited = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while !ready() {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await;
    assert!(waited.is_ok(), "timed out waiting for {what}");
}

/// Spend governance with `read` at 1.0 and `k-budget` allowed 0.5, so its
/// first call is refused with no paying call before it.
#[cfg(feature = "cost-governance")]
pub(super) fn budget_below_one_call(
    meta: crate::gateway::meta_mcp::MetaMcp,
) -> crate::gateway::meta_mcp::MetaMcp {
    use crate::cost_accounting::config::CostGovernanceConfig;
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.tool_costs.insert("read".to_string(), 1.0);
    cfg.budgets.per_key.insert("k-budget".to_string(), 0.5);
    let registry = std::sync::Arc::new(crate::cost_accounting::registry::CostRegistry::new(&cfg));
    let enforcer = std::sync::Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
        cfg,
        std::sync::Arc::clone(&registry),
    ));
    meta.with_cost_governance(enforcer, registry)
}
