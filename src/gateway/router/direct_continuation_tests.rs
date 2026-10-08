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

const BACKENDS: [&str; 2] = ["alpha", "alpha-pt"];
/// The state the fixture backend issues with its question.
const BACKEND_STATE: &str = "backend-state-1";

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
async fn call(fx: &Fx, backend: &str, subject: Option<&str>, extra: Value) -> (StatusCode, Value) {
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

fn code(body: &Value) -> Option<i64> {
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

fn dispatched(fx: &Fx) -> usize {
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

/// R12: a retry the spend budget refuses is refused before its continuation is
/// spent, as on the meta route, so the caller can still resume it. `k-budget`
/// (1.5 at 1.0 a call) pays for the question and is refused the retry; the
/// same caller then resumes it under `k-std`. Mutant: the redeem before the
/// spend admission.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn r12_a_budget_refusal_does_not_spend_the_continuation() {
    use crate::cost_accounting::config::CostGovernanceConfig;
    for backend in BACKENDS {
        let mut cfg = CostGovernanceConfig {
            enabled: true,
            ..Default::default()
        };
        cfg.tool_costs.insert("read".to_string(), 1.0);
        cfg.budgets.per_key.insert("k-budget".to_string(), 1.5);
        let registry =
            std::sync::Arc::new(crate::cost_accounting::registry::CostRegistry::new(&cfg));
        let enforcer = std::sync::Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
            cfg,
            std::sync::Arc::clone(&registry),
        ));
        let fx = super::direct_guards_fixture::fixture_built(Answer::AskOnce, move |meta| {
            meta.with_cost_governance(enforcer, registry)
        })
        .await;
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
/// does not reach the client either. Mutant: the blanking limited to answers
/// claiming `input_required`.
#[tokio::test]
async fn r15_a_completed_answer_does_not_carry_the_backends_state() {
    for backend in BACKENDS {
        let fx = fixture(Answer::DoneWithState, |_| {}).await;
        let (_, body) = call(&fx, backend, Some("alice"), json!({})).await;
        assert!(body.get("error").is_none(), "direct {backend}: {body}");
        assert!(
            !body.to_string().contains(BACKEND_STATE),
            "direct {backend}: {body}"
        );
        let fx = fixture(Answer::DoneWithState, |_| {}).await;
        let (_, body) =
            post_meta_invoke(&fx, "k-std", backend, "read", json!({}), None, None).await;
        assert!(body.get("error").is_none(), "meta {backend}: {body}");
        assert!(body.to_string().contains("ok"), "meta {backend}: {body}");
        assert!(
            !body.to_string().contains(BACKEND_STATE),
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
async fn meta_call(fx: &Fx, key: &str, backend: &str, extra: Value) -> Value {
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
