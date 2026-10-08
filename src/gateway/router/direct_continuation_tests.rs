// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8078`: the direct route `POST /mcp/{name}` seals a backend's
//! `requestState` the way the meta route does (`MIK-7212.MRTR.2a`). The client
//! sees a gateway continuation bound to it and to the call; only a retry
//! presenting that continuation, once, reaches the backend with the backend's
//! own state. Every row runs on `alpha` (the sanitized arm) and `alpha-pt` (the
//! pass-through arm).

use axum::body::to_bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};
use tower::ServiceExt;

use super::direct_guards_fixture::{Answer, Fx, fixture, post_meta_invoke};
use crate::key_server::oidc::VerifiedIdentity;
use crate::protocol::mrtr::IDEMPOTENCY_KEY_META;

pub(super) const BACKENDS: [&str; 2] = ["alpha", "alpha-pt"];
/// The state the fixture backend issues with its question.
pub(super) const BACKEND_STATE: &str = "backend-state-1";

fn identity(subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        subject: subject.to_string(),
        email: format!("{subject}@example.invalid"),
        name: None,
        groups: vec![],
        issuer: "https://a.example.invalid".to_string(),
    }
}

/// `tools/call read` on `/mcp/{backend}` as key `k-std`, carrying `subject`'s
/// verified identity when one is given, with `extra` merged into the params.
pub(super) async fn call(
    fx: &Fx,
    backend: &str,
    subject: Option<&str>,
    extra: Value,
) -> (StatusCode, Value) {
    call_as(fx, "k-std", backend, subject, extra).await
}

/// [`call`] as API key `key`.
async fn call_as(
    fx: &Fx,
    key: &str,
    backend: &str,
    subject: Option<&str>,
    extra: Value,
) -> (StatusCode, Value) {
    let mut params = json!({"name": "read", "arguments": {}});
    if let (Some(params), Some(extra)) = (params.as_object_mut(), extra.as_object()) {
        params.extend(extra.clone());
    }
    let mut request = axum::http::Request::builder()
        .method("POST")
        .uri(format!("/mcp/{backend}"))
        .header("authorization", format!("Bearer {key}"))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(
            json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
                .to_string(),
        ))
        .unwrap();
    if let Some(subject) = subject {
        request.extensions_mut().insert(identity(subject));
    }
    let response = fx.router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
}

pub(super) fn code(body: &Value) -> Option<i64> {
    body.get("error")
        .and_then(|e| e.get("code"))
        .and_then(Value::as_i64)
}

fn answers() -> Value {
    json!({"k1": {"action": "accept", "content": {"account": "work"}}})
}

/// The continuation the interim answer carries.
fn state_of(body: &Value) -> String {
    body["result"]["requestState"]
        .as_str()
        .unwrap_or_else(|| panic!("an interim answer with a state: {body}"))
        .to_owned()
}

pub(super) fn dispatched(fx: &Fx) -> usize {
    fx.calls.load(std::sync::atomic::Ordering::SeqCst)
}

/// R1 (`MRTR.2a`): the backend's own state never reaches the client.
/// Mutant: the seal removed.
#[tokio::test]
async fn r1_the_client_sees_a_sealed_state_never_the_backends() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let (_, body) = call(&fx, backend, Some("alice"), json!({})).await;
        assert_eq!(
            body["result"]["resultType"], "input_required",
            "{backend}: {body}"
        );
        assert_ne!(state_of(&body), BACKEND_STATE, "{backend}");
        assert!(
            !body.to_string().contains(BACKEND_STATE),
            "{backend}: the backend's state leaked: {body}"
        );
    }
}

/// R2: the issued continuation, presented once by its caller, reaches the
/// backend as the backend's own state, with the answers beside it.
#[tokio::test]
async fn r2_the_issued_state_resumes_with_the_backends_own_state() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let (_, asked) = call(&fx, backend, Some("alice"), json!({})).await;
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answers()});
        let (_, done) = call(&fx, backend, Some("alice"), retry).await;
        assert!(done.get("error").is_none(), "{backend}: {done}");
        assert_eq!(dispatched(&fx), 2, "{backend}");
        let seen = fx.seen.lock().unwrap().last().cloned().unwrap();
        assert_eq!(seen["requestState"], BACKEND_STATE, "{backend}: {seen}");
        assert_eq!(seen["inputResponses"], answers(), "{backend}: {seen}");
    }
}

/// R3: a state the gateway did not issue (the backend's literal, or the
/// envelope altered) is refused before the backend. Mutant: the redeem removed.
#[tokio::test]
async fn r3_a_state_the_gateway_did_not_issue_is_refused() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let (_, asked) = call(&fx, backend, Some("alice"), json!({})).await;
        let mut altered = state_of(&asked);
        let last = altered.pop().unwrap();
        altered.push(if last == 'A' { 'B' } else { 'A' });
        for forged in [BACKEND_STATE.to_owned(), altered] {
            let retry = json!({"requestState": forged, "inputResponses": answers()});
            let (_, body) = call(&fx, backend, Some("alice"), retry).await;
            assert_eq!(code(&body), Some(-32602), "{backend} {forged}: {body}");
        }
        assert_eq!(dispatched(&fx), 1, "{backend}: a forged state dispatched");
    }
}

/// R4: another caller cannot redeem a continuation issued to alice.
#[tokio::test]
async fn r4_another_caller_cannot_redeem_it() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let (_, asked) = call(&fx, backend, Some("alice"), json!({})).await;
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answers()});
        let (_, body) = call(&fx, backend, Some("mallory"), retry).await;
        assert_eq!(code(&body), Some(-32602), "{backend}: {body}");
        assert_eq!(dispatched(&fx), 1, "{backend}: mallory's retry dispatched");
    }
}

/// R5: a continuation is redeemed once.
#[tokio::test]
async fn r5_a_continuation_is_redeemed_once() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let (_, asked) = call(&fx, backend, Some("alice"), json!({})).await;
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answers()});
        let (_, first) = call(&fx, backend, Some("alice"), retry.clone()).await;
        assert!(first.get("error").is_none(), "{backend}: {first}");
        let (_, again) = call(&fx, backend, Some("alice"), retry).await;
        assert_eq!(code(&again), Some(-32602), "{backend}: {again}");
        assert_eq!(dispatched(&fx), 2, "{backend}: the replay dispatched");
    }
}

/// R6: a seal the store refuses (here: no slot to hold the exchange) answers
/// -32003, and the backend's state is not handed out instead.
#[tokio::test]
async fn r6_a_refused_seal_is_refused_not_handed_the_state() {
    for backend in BACKENDS {
        let fx = full_store().await;
        let (_, body) = call(&fx, backend, Some("alice"), json!({})).await;
        assert_eq!(code(&body), Some(-32003), "{backend}: {body}");
        assert!(
            !body.to_string().contains(BACKEND_STATE),
            "{backend}: {body}"
        );
    }
}

/// R6b: a refused seal releases the idempotency key. The backend asked and
/// did not act, so re-sending the call under the same key reaches it again
/// rather than finding the key held. Mutant: the release on the refusal path
/// removed.
#[tokio::test]
async fn r6b_a_refused_seal_releases_the_key() {
    for backend in BACKENDS {
        let fx = full_store().await;
        let opening = json!({"_meta": { IDEMPOTENCY_KEY_META: format!("k-8078-6b-{backend}") }});
        let _ = call(&fx, backend, Some("alice"), opening.clone()).await;
        let (_, again) = call(&fx, backend, Some("alice"), opening).await;
        assert_eq!(dispatched(&fx), 2, "{backend}: the key was held: {again}");
    }
}

/// The fixture with a continuation store that refuses every mint.
async fn full_store() -> Fx {
    fixture(Answer::AskOnce, |meta| {
        meta.set_continuation_for_test(
            crate::protocol::continuation::ContinuationState::full_for_test(),
        );
    })
    .await
}

/// R7 (preservation, green on the base too: the cache already refuses a
/// non-final result): an interim answer is not settled under the
/// idempotency key, so re-sending the opening call under the same key reaches
/// the backend again rather than replaying the stored question.
#[tokio::test]
async fn r7_an_interim_answer_does_not_settle_the_key() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let opening = json!({"_meta": { IDEMPOTENCY_KEY_META: format!("k-8078-{backend}") }});
        let (_, asked) = call(&fx, backend, Some("alice"), opening.clone()).await;
        assert_eq!(
            asked["result"]["resultType"], "input_required",
            "{backend}: {asked}"
        );
        let (_, again) = call(&fx, backend, Some("alice"), opening).await;
        assert_eq!(
            dispatched(&fx),
            2,
            "{backend}: answered from the cache: {again}"
        );
        assert!(
            !again.to_string().contains(BACKEND_STATE),
            "{backend}: {again}"
        );
    }
}

/// R8: answers with no continuation are refused, as on the meta route: every
/// interim answer now carries one, so an honest retry always presents it.
#[tokio::test]
async fn r8_answers_without_a_continuation_are_refused() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let _ = call(&fx, backend, Some("alice"), json!({})).await;
        let (_, body) = call(
            &fx,
            backend,
            Some("alice"),
            json!({"inputResponses": answers()}),
        )
        .await;
        assert_eq!(code(&body), Some(-32602), "{backend}: {body}");
        assert_eq!(
            dispatched(&fx),
            1,
            "{backend}: answers without a state dispatched"
        );
    }
}

/// R9: the continuation is bound to the call it was issued for: presented
/// with other arguments, or on another backend, it is refused.
#[tokio::test]
async fn r9_a_continuation_is_bound_to_its_call() {
    let fx = fixture(Answer::AskOnce, |_| {}).await;
    let (_, asked) = call(&fx, "alpha", Some("alice"), json!({})).await;
    let token = state_of(&asked);
    let other_args = json!({
        "arguments": {"cmd": "other"},
        "requestState": token,
        "inputResponses": answers(),
    });
    let (_, body) = call(&fx, "alpha", Some("alice"), other_args).await;
    assert_eq!(code(&body), Some(-32602), "other arguments: {body}");
    let retry = json!({"requestState": token, "inputResponses": answers()});
    let (_, body) = call(&fx, "alpha-pt", Some("alice"), retry).await;
    assert_eq!(code(&body), Some(-32602), "another backend: {body}");
    assert_eq!(dispatched(&fx), 1, "a misbound continuation dispatched");
}

/// R10: a backend that keeps no state still gets none back: the client's
/// continuation is not forwarded in its place.
#[tokio::test]
async fn r10_a_backend_without_state_gets_none_back() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskNoState, |_| {}).await;
        let (_, asked) = call(&fx, backend, Some("alice"), json!({})).await;
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answers()});
        let (_, done) = call(&fx, backend, Some("alice"), retry).await;
        assert!(done.get("error").is_none(), "{backend}: {done}");
        let seen = fx.seen.lock().unwrap().last().cloned().unwrap();
        assert!(seen.get("requestState").is_none(), "{backend}: {seen}");
        assert_eq!(seen["inputResponses"], answers(), "{backend}: {seen}");
    }
}

/// R11 (`MRTR.2a`, both routes): a result claiming `input_required` that is not
/// a usable round still never carries the backend's state to the client.
#[tokio::test]
async fn r11_an_unusable_round_does_not_carry_the_state() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskMalformed, |_| {}).await;
        let (_, body) = call(&fx, backend, Some("alice"), json!({})).await;
        assert!(
            !body.to_string().contains(BACKEND_STATE),
            "direct {backend}: {body}"
        );
        let fx = fixture(Answer::AskMalformed, |_| {}).await;
        let (_, body) =
            post_meta_invoke(&fx, "k-std", backend, "read", json!({}), None, None).await;
        assert!(
            !body.to_string().contains(BACKEND_STATE),
            "meta {backend}: {body}"
        );
    }
}

/// Cost governance at 1.0 a `read`, `k-budget` holding 1.5: one call paid,
/// the next refused.
#[cfg(feature = "cost-governance")]
fn budget(meta: crate::gateway::meta_mcp::MetaMcp) -> crate::gateway::meta_mcp::MetaMcp {
    use crate::cost_accounting::config::CostGovernanceConfig;
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.tool_costs.insert("read".to_string(), 1.0);
    cfg.budgets.per_key.insert("k-budget".to_string(), 1.5);
    let registry = std::sync::Arc::new(crate::cost_accounting::registry::CostRegistry::new(&cfg));
    let enforcer = std::sync::Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
        cfg,
        std::sync::Arc::clone(&registry),
    ));
    meta.with_cost_governance(enforcer, registry)
}

/// R12: a retry the spend budget refuses is refused before its continuation is
/// spent, as on the meta route, so the caller can still resume it. `k-budget`
/// (1.5 at 1.0 a call) pays for the question and is refused the retry; the
/// same caller then resumes it under `k-std`. Mutant: the redeem before the
/// spend admission.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn r12_a_budget_refusal_does_not_spend_the_continuation() {
    for backend in BACKENDS {
        let fx = super::direct_guards_fixture::fixture_built(Answer::AskOnce, budget).await;
        let (_, asked) = call_as(&fx, "k-budget", backend, Some("alice"), json!({})).await;
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answers()});
        let (_, refused) = call_as(&fx, "k-budget", backend, Some("alice"), retry.clone()).await;
        assert!(refused.get("error").is_some(), "{backend}: {refused}");
        assert_eq!(
            dispatched(&fx),
            1,
            "{backend}: the refused retry dispatched"
        );
        let (_, done) = call_as(&fx, "k-std", backend, Some("alice"), retry).await;
        assert!(done.get("error").is_none(), "{backend}: {done}");
        assert_eq!(dispatched(&fx), 2, "{backend}");
    }
}

/// R13: the redeem replaces only the state, so the answers the sanitizing arm
/// cleaned are the answers the backend gets. Mutant: the client's raw answers
/// written back over the sanitized ones.
#[tokio::test]
async fn r13_the_backend_gets_the_sanitized_answers() {
    let fx = fixture(Answer::AskOnce, |_| {}).await;
    let (_, asked) = call(&fx, "alpha", Some("alice"), json!({})).await;
    let raw = json!({"k1": {"action": "accept", "content": {"account": "wo\u{7}rk"}}});
    let retry = json!({"requestState": state_of(&asked), "inputResponses": raw});
    let (_, done) = call(&fx, "alpha", Some("alice"), retry).await;
    assert!(done.get("error").is_none(), "{done}");
    let seen = fx.seen.lock().unwrap().last().cloned().unwrap();
    assert_eq!(seen["inputResponses"], answers(), "{seen}");
}

/// R14: a client-authored state that is not a string never reaches the
/// backend: the preflight refuses it as a malformed retry field.
#[tokio::test]
async fn r14_a_non_string_client_state_is_refused_before_the_backend() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        for forged in [json!(5), json!({"k": BACKEND_STATE}), json!(null)] {
            let retry = json!({"requestState": forged, "inputResponses": answers()});
            let (_, body) = call(&fx, backend, Some("alice"), retry).await;
            assert_eq!(code(&body), Some(-32602), "{backend} {forged}: {body}");
        }
        assert_eq!(dispatched(&fx), 0, "{backend}: a forged state dispatched");
    }
}

/// R15 (`MRTR.2a`, both routes): a state a backend put on a completed answer
/// does not reach the client either, and the field is removed rather than
/// blanked. Mutants: the removal limited to answers claiming `input_required`;
/// a completed answer's state blanked to `null`.
#[tokio::test]
async fn r15_a_completed_answer_does_not_carry_the_backends_state() {
    for backend in BACKENDS {
        let fx = fixture(Answer::DoneWithState, |_| {}).await;
        let (_, body) = call(&fx, backend, Some("alice"), json!({})).await;
        assert!(body.get("error").is_none(), "direct {backend}: {body}");
        // Removed, not blanked: a completed answer carries no `requestState`
        // at all, so nothing downstream reads it as interim or malformed.
        assert!(
            !body.to_string().contains("requestState"),
            "direct {backend}: {body}"
        );
        let fx = fixture(Answer::DoneWithState, |_| {}).await;
        let (_, body) =
            post_meta_invoke(&fx, "k-std", backend, "read", json!({}), None, None).await;
        assert!(body.get("error").is_none(), "meta {backend}: {body}");
        assert!(body.to_string().contains("ok"), "meta {backend}: {body}");
        assert!(
            !body.to_string().contains("requestState"),
            "meta {backend}: {body}"
        );
    }
}

/// A1-A3 (lead ruling A): an API-key caller with no verified identity keeps
/// its round, bound to its key's credential principal, on the direct route.
/// A1: it resumes; A2: another key cannot redeem it; A3: once only.
#[tokio::test]
async fn a1_a3_an_api_key_caller_keeps_its_round_on_the_direct_route() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let (_, asked) = call_as(&fx, "k-std", backend, None, json!({})).await;
        assert_eq!(
            asked["result"]["resultType"], "input_required",
            "A1 {backend}: {asked}"
        );
        let retry = json!({"requestState": state_of(&asked), "inputResponses": answers()});
        let (_, other) = call_as(&fx, "k-budget", backend, None, retry.clone()).await;
        assert_eq!(code(&other), Some(-32602), "A2 {backend}: {other}");
        let (_, done) = call_as(&fx, "k-std", backend, None, retry.clone()).await;
        assert!(done.get("error").is_none(), "A1 {backend}: {done}");
        let seen = fx.seen.lock().unwrap().last().cloned().unwrap();
        assert_eq!(seen["requestState"], BACKEND_STATE, "A1 {backend}: {seen}");
        let (_, again) = call_as(&fx, "k-std", backend, None, retry).await;
        assert_eq!(code(&again), Some(-32602), "A3 {backend}: {again}");
        assert_eq!(dispatched(&fx), 2, "{backend}");
    }
}

/// `tools/call gateway_invoke` of `backend`/`read` on `/mcp` as `key`, a
/// modern request declaring form elicitation, with `extra` beside `name`.
pub(super) async fn meta_call(fx: &Fx, key: &str, backend: &str, extra: Value) -> Value {
    let mut params = json!({
        "name": "gateway_invoke",
        "arguments": {"server": backend, "tool": "read", "arguments": {}},
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
    super::direct_guards_fixture::send_with_headers(
        fx,
        "/mcp",
        key,
        "tools/call",
        params,
        None,
        &headers,
    )
    .await
    .1
}

/// A1-A3 on the meta route: one binding rule for both routes.
#[tokio::test]
async fn a1_a3_an_api_key_caller_keeps_its_round_on_the_meta_route() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskOnce, |_| {}).await;
        let asked = meta_call(&fx, "k-std", backend, json!({})).await;
        let state = asked["result"]["requestState"]
            .as_str()
            .unwrap_or_else(|| panic!("A1 {backend}: an interim answer with a state: {asked}"))
            .to_owned();
        assert_ne!(state, BACKEND_STATE, "{backend}");
        let retry = json!({"requestState": state, "inputResponses": answers()});
        let other = meta_call(&fx, "k-budget", backend, retry.clone()).await;
        assert_eq!(code(&other), Some(-32602), "A2 {backend}: {other}");
        let done = meta_call(&fx, "k-std", backend, retry.clone()).await;
        assert!(done.get("error").is_none(), "A1 {backend}: {done}");
        let again = meta_call(&fx, "k-std", backend, retry).await;
        assert_eq!(code(&again), Some(-32602), "A3 {backend}: {again}");
        assert_eq!(dispatched(&fx), 2, "{backend}");
    }
}

/// A4: callers the idempotency guard tells apart behind one shared key (here
/// by their grant subject) are told apart by the continuation too: one cannot
/// redeem the other's round. Mutant: the binding built from the key alone.
#[tokio::test]
async fn a4_a_shared_key_still_separates_callers_the_guard_separates() {
    let fx = fixture(Answer::AskOnce, |_| {}).await;
    let declared = crate::protocol::meta::classify_request(
        Some(&json!({"_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}}
        }})),
        Some("2026-07-28"),
    )
    .declared_capabilities();
    let subject = |name: &str| crate::identity_grants::GrantSubject {
        authority: "mtls".to_string(),
        subject: name.to_string(),
        label: None,
    };
    let (alice, bob) = (Some(subject("alice")), Some(subject("bob")));
    let caller = |grant: &Option<crate::identity_grants::GrantSubject>,
                  retry: &'static crate::protocol::mrtr::RetryFields| {
        crate::gateway::meta_mcp::MetaMcpCallerContext {
            credential_principal: Some("shared-key-principal"),
            authentication: crate::gateway::meta_mcp::Authentication::Authenticated,
            grant_subject: grant.clone(),
            input_capabilities: declared,
            retry,
            ..crate::gateway::meta_mcp::anonymous_caller()
        }
    };
    let args = json!({"server": "alpha", "tool": "read", "arguments": {}});
    let fresh: &'static _ = Box::leak(Box::default());
    let meta = &fx.state.meta_mcp;
    let asked = meta
        .invoke_tool_for_test(&args, None, &caller(&alice, fresh))
        .await
        .expect("alice is asked");
    let retry: &'static _ = Box::leak(Box::new(crate::protocol::mrtr::RetryFields::from_params(
        Some(
            &json!({"requestState": state_of(&json!({"result": asked})), "inputResponses": answers()}),
        ),
    )));
    let stolen = meta
        .invoke_tool_for_test(&args, None, &caller(&bob, retry))
        .await;
    let refused = stolen.expect_err("bob redeemed alice's continuation");
    assert_eq!(refused.to_rpc_code(), -32602, "{refused}");
    meta.invoke_tool_for_test(&args, None, &caller(&alice, retry))
        .await
        .expect("alice resumes her own round");
}

/// Exchanges this gateway still holds open.
pub(super) async fn held(fx: &Fx) -> usize {
    let now = crate::protocol::continuation::now_unix_secs();
    fx.state.meta_mcp.continuation().in_flight().len(now).await
}

/// R16 (both routes): a state too long to seal is refused, and the slot its
/// exchange took is given back rather than held until it expires. Mutant: the
/// hold left open when the keyring refuses the mint.
#[tokio::test]
async fn r16_a_refused_mint_gives_its_slot_back() {
    for backend in BACKENDS {
        let fx = fixture(Answer::AskBig, |_| {}).await;
        let (_, body) = call(&fx, backend, Some("alice"), json!({})).await;
        assert_eq!(code(&body), Some(-32003), "direct {backend}: {body}");
        assert_eq!(held(&fx).await, 0, "direct {backend}: slot kept");
        let fx = fixture(Answer::AskBig, |_| {}).await;
        let body = meta_call(&fx, "k-std", backend, json!({})).await;
        assert!(body.get("error").is_some(), "meta {backend}: {body}");
        assert_eq!(held(&fx).await, 0, "meta {backend}: slot kept");
    }
}

/// Matches the shipped CRITICAL `secret` rule of response inspection and the
/// firewall's credential rule (a fake, split so no scanner reads the source).
const SECRET: &str = concat!("gh", "p_", "abcdefghijklmnopqrstuvwxyz1234567890");

/// R17 (both routes): a sealed question a later gate refuses never reaches
/// the client, so its slot is given back. Mutants: the release dropped after
/// a refused payload gate (each route); after a direct firewall block.
#[tokio::test]
async fn r17_a_question_refused_after_its_seal_gives_its_slot_back() {
    let inspecting = |meta: &mut crate::gateway::meta_mcp::MetaMcp| {
        meta.enable_response_inspection_action_mode();
    };
    for backend in BACKENDS {
        let fx = fixture(Answer::AskWith(SECRET), inspecting).await;
        let (_, body) = call(&fx, backend, Some("alice"), json!({})).await;
        assert!(body.get("error").is_some(), "direct gate {backend}: {body}");
        assert_eq!(held(&fx).await, 0, "direct gate {backend}: slot kept");
        let fx = fixture(Answer::AskWith(SECRET), inspecting).await;
        let body = meta_call(&fx, "k-std", backend, json!({})).await;
        assert!(body.get("error").is_some(), "meta gate {backend}: {body}");
        assert_eq!(held(&fx).await, 0, "meta gate {backend}: slot kept");
        #[cfg(feature = "firewall")]
        {
            use super::direct_guards_fixture::fixture_firewalled_with;
            let fx = fixture_firewalled_with(Answer::AskWith(SECRET), None, false).await;
            let (_, body) = call(&fx, backend, Some("alice"), json!({})).await;
            assert!(body.get("error").is_some(), "direct fw {backend}: {body}");
            assert_eq!(held(&fx).await, 0, "direct fw {backend}: slot kept");
        }
    }
}

/// `tools/call read` on `/mcp/{backend}` as `key`, a hardened modern request that
/// declares form elicitation and carries `nonce`, with `extra` in the params.
pub(super) async fn signed_call(
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
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "read"),
    ];
    let path = format!("/mcp/{backend}");
    super::direct_guards_fixture::send_with_headers(
        fx,
        &path,
        key,
        "tools/call",
        params,
        None,
        &headers,
    )
    .await
}

/// R18 (MIK-7698 on this route): a continuation refused before the backend
/// consumes no signing nonce, so the honest retry under that nonce is served.
/// Mutant: the nonce kept on a refused redeem.
#[tokio::test]
async fn r18_a_refused_continuation_consumes_no_nonce() {
    use super::direct_guards_fixture::fixture_hardened_signed;
    for backend in BACKENDS {
        let fx = fixture_hardened_signed(Answer::AskOnce, true).await;
        let (_, asked) =
            signed_call(&fx, ("k-std", backend), &format!("{backend}-n1"), json!({})).await;
        let state = state_of(&asked);
        let n2 = format!("{backend}-n2");
        let forged = json!({"requestState": "forged", "inputResponses": answers()});
        let (_, refused) = signed_call(&fx, ("k-std", backend), &n2, forged).await;
        assert_eq!(code(&refused), Some(-32602), "{backend}: {refused}");
        let honest = json!({"requestState": state, "inputResponses": answers()});
        let (status, done) = signed_call(&fx, ("k-std", backend), &n2, honest).await;
        assert_eq!(status, StatusCode::OK, "{backend}: nonce burned: {done}");
        assert!(done.get("error").is_none(), "{backend}: {done}");
        assert_eq!(dispatched(&fx), 2, "{backend}");
    }
}

/// R19 (both routes): a continuation binds a caller as the idempotency guard
/// does, the propagated binding first, so one verified identity presenting
/// another binding (another backend credential) cannot redeem it. Mutant: the
/// verified identity bound ahead of the binding (each route).
#[tokio::test]
async fn r19_the_propagated_binding_binds_ahead_of_the_identity() {
    use crate::protocol::mrtr::source_fingerprint;
    let fx = fixture(Answer::Ok, |_| {}).await;
    let meta = &fx.state.meta_mcp;
    let alice = identity("alice");
    let who = |binding| (Some(&alice), (Some(binding), None), None);
    let sent = json!({"name": "read", "arguments": {}});
    let mut asked = json!({
        "resultType": "input_required",
        "inputRequests": {"k1": {"method": "elicitation/create",
            "params": {"message": "Which account?", "requestedSchema": {"type": "object"}}}},
        "requestState": BACKEND_STATE
    });
    meta.seal_direct_interim(who("binding-a"), ("alpha", Some(&sent)), &mut asked)
        .await
        .expect("sealed");
    let retry = json!({"name": "read", "arguments": {},
        "requestState": asked["requestState"], "inputResponses": answers()});
    let mut outbound = retry.clone();
    meta.redeem_direct_retry(who("binding-b"), ("alpha", Some(&retry)), &mut outbound)
        .await
        .expect_err("another binding redeemed it");
    meta.redeem_direct_retry(who("binding-a"), ("alpha", Some(&retry)), &mut outbound)
        .await
        .expect("its own binding redeems it");
    let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
        verified_identity: Some(&alice),
        ..crate::gateway::meta_mcp::anonymous_caller()
    };
    let bound = |binding| source_fingerprint(caller.principal_source(Some(binding)));
    assert_ne!(bound("binding-a"), bound("binding-b"), "meta");
}

/// R20 (MIK-7698 on this route, both arms): a call the spend budget refuses
/// consumes no signing nonce, so re-sent under that nonce it meets the budget
/// again, not a replay refusal. Mutant: the nonce kept on a spend refusal
/// (each arm).
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn r20_a_spend_refusal_consumes_no_nonce() {
    use super::direct_guards_fixture::fixture_hardened_signed_built;
    for backend in BACKENDS {
        let fx = fixture_hardened_signed_built(Answer::Ok, true, budget).await;
        let who = ("k-budget", backend);
        let _ = signed_call(&fx, who, &format!("{backend}-n1"), json!({})).await;
        let n2 = format!("{backend}-n2");
        let (status, refused) = signed_call(&fx, who, &n2, json!({})).await;
        assert!(refused.get("error").is_some(), "{backend}: {refused}");
        let (again_status, again) = signed_call(&fx, who, &n2, json!({})).await;
        assert_eq!(
            (again_status, code(&again)),
            (status, code(&refused)),
            "{backend}: nonce burned: {again}"
        );
        assert_eq!(dispatched(&fx), 1, "{backend}");
    }
}
