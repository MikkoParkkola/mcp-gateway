// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-8191`: a keyed `/mcp` call whose backend asked a question the client
//! never declared is refused (MRTR.9). The refusal's own remedy, "declare the
//! capability and retry", must work under the same idempotency key: the
//! backend stopped to ask, so it did not act, and neither the key nor the
//! execution lease may keep the refusal as the call's outcome.

use serde_json::{Value, json};

use super::direct_continuation_tests::{code, dispatched, meta_call};
use super::direct_guards_fixture::{Answer, fixture};

/// `gateway_invoke` params under idempotency key `key`, declaring `caps`.
fn keyed(key: &str, caps: &Value) -> Value {
    json!({"_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": caps,
        crate::protocol::mrtr::IDEMPOTENCY_KEY_META: key,
    }})
}

/// M1 (`MIK-8191.1`): refused for the undeclared question, then retried under
/// the same key with elicitation declared: the retry reaches the backend
/// again instead of being served the stored refusal. Mutant: the lease
/// retaining an error answer whose backend stopped to ask.
#[tokio::test]
async fn m1_a_keyed_retry_after_an_undeclared_refusal_runs_again() {
    let fx = fixture(Answer::AskOnce, |_| {}).await;
    let refused = meta_call(&fx, "k-std", "alpha", keyed("op-1", &json!({}))).await;
    assert_eq!(code(&refused), Some(-32021), "MRTR.9 refusal: {refused}");
    assert_eq!(dispatched(&fx), 1, "the question was asked once");

    let declared = json!({"elicitation": {"form": {}}});
    let retried = meta_call(&fx, "k-std", "alpha", keyed("op-1", &declared)).await;
    assert!(
        retried.get("error").is_none(),
        "the retry was served the stored refusal: {retried}"
    );
    assert_eq!(dispatched(&fx), 2, "the retry reached the backend again");
}

/// `gateway_execute` of `chain` on `/mcp` as `key`, under idempotency key
/// `op`, declaring `caps`.
async fn keyed_chain(
    fx: &super::direct_guards_fixture::Fx,
    op: &str,
    caps: &Value,
    chain: &Value,
) -> Value {
    let mut params = keyed(op, caps);
    params["name"] = json!("gateway_execute");
    params["arguments"] = json!({"chain": chain});
    let headers = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "gateway_execute"),
    ];
    super::direct_guards_fixture::send_with_headers(
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

/// G4 + G4c (ADR-012 §Consequences): step 1 of a keyed chain runs, step 2
/// asks a question the client never declared and is refused. No retry under
/// the same key runs step 1 again: the identical retry is served the stored
/// outcome, which names the failed step, and a changed retry is refused. Guard (green on
/// base); mutant: the key or lease released whenever the last step stopped to
/// ask, regardless of earlier steps.
#[tokio::test]
async fn g4_a_keyed_chain_never_repeats_a_step_that_ran() {
    let fx = fixture(Answer::AskSecond, |_| {}).await;
    let chain = json!([
        {"tool": "alpha:read", "arguments": {}},
        {"tool": "alpha:read", "arguments": {"cmd": "two"}}
    ]);
    let first = keyed_chain(&fx, "op-g4", &json!({}), &chain).await;
    assert!(first.get("error").is_some(), "step 2 refused: {first}");
    assert_eq!(
        dispatched(&fx),
        2,
        "both steps reached the backend once: {first}"
    );

    // The identical retry is served the stored outcome (G4c), which names the
    // failed step, so the client knows step 1 ran.
    let again = keyed_chain(&fx, "op-g4", &json!({}), &chain).await;
    assert_eq!(dispatched(&fx), 2, "step 1 ran again: {again}");
    assert_eq!(again["error"], first["error"], "the stored outcome");
    assert!(
        first["error"]["message"]
            .as_str()
            .is_some_and(|m| m.contains("Chain step 1")),
        "G4c: the outcome names the failed step: {first}"
    );
    // A retry that now declares the capability is refused too, and still
    // runs nothing: the key keeps the work that already ran.
    let declared = json!({"elicitation": {"form": {}}});
    let retried = keyed_chain(&fx, "op-g4", &declared, &chain).await;
    assert!(retried.get("error").is_some(), "{retried}");
    assert_eq!(dispatched(&fx), 2, "step 1 ran again: {retried}");
}

/// G4b: step 1 runs, step 2 is refused before anything is sent (its server is
/// not configured). The same-key retry is served the stored outcome; step 1
/// does not run again. Guard (green on base).
#[tokio::test]
async fn g4b_a_pre_send_refusal_after_a_step_ran_keeps_the_outcome() {
    let fx = fixture(Answer::Ok, |_| {}).await;
    let chain = json!([
        {"tool": "alpha:read", "arguments": {}},
        {"tool": "nosuch:read", "arguments": {}}
    ]);
    let declared = json!({"elicitation": {"form": {}}});
    let first = keyed_chain(&fx, "op-g4b", &declared, &chain).await;
    assert!(first.get("error").is_some(), "step 2 refused: {first}");
    assert_eq!(dispatched(&fx), 1);
    let retried = keyed_chain(&fx, "op-g4b", &declared, &chain).await;
    assert_eq!(dispatched(&fx), 1, "step 1 ran again: {retried}");
    assert_eq!(retried["error"], first["error"], "the stored outcome");
}

/// M2 (pin, MIK-8137 P1-route): an interim answer refused by MRTR.9 still
/// records its spend, because `account_dispatch` charges any answered call
/// before the gate runs (`dispatch_guards.rs`), so a refusal refunds nothing.
/// With 1.5 of budget and 1.0 per call, the declared retry meets the budget.
/// Mutant: the refusal refunding the spend.
#[cfg(feature = "cost-governance")]
#[tokio::test]
async fn m2_a_refused_interim_answer_keeps_its_spend() {
    use super::direct_continuation_tests::budget;
    use super::direct_guards_fixture::fixture_built;
    let fx = fixture_built(Answer::AskOnce, budget).await;
    let refused = meta_call(&fx, "k-budget", "alpha", keyed("op-m2", &json!({}))).await;
    assert_eq!(code(&refused), Some(-32021), "MRTR.9 refusal: {refused}");
    let declared = json!({"elicitation": {"form": {}}});
    let retried = meta_call(&fx, "k-budget", "alpha", keyed("op-m2b", &declared)).await;
    assert_eq!(
        code(&retried),
        Some(-32003),
        "the refused call was refunded: {retried}"
    );
    assert_eq!(dispatched(&fx), 1, "the budget refused before the backend");
}
