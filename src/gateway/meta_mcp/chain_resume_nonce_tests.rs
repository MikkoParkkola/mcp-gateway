// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8353 slice 3b: a signed chain resume consumes its chain handle before
//! its pending step runs, so a refusal of that step (the spend budget, here)
//! keeps the nonce spent. Control: a fresh chain refused by the budget, with
//! nothing consumed, gives its nonce back.

use std::sync::Arc;

use serde_json::{Value, json};

use super::{
    AsksOnce, answers, chain, elicitation_caps, handle_in, identity, meta_over, resuming_ctx,
};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::refund_witness::RefundWitness;
use crate::gateway::meta_mcp::signing::{NONCE_META, SigningInvocationContext, SigningScope};
use crate::protocol::RequestId;
use crate::protocol::mrtr::{NO_RETRY, RetryFields};

/// `meta_over` with signing on (a nonce optional, so the unsigned stop and the
/// consumption probe need none) and `ask` costing 1.0 against `test-caller`'s
/// per-key `limit`.
fn signed_and_budgeted(stub: Arc<AsksOnce>, limit: f64) -> MetaMcp {
    use crate::cost_accounting::config::CostGovernanceConfig;
    let mut meta = meta_over(stub);
    meta.enable_message_signing(
        crate::security::message_signing::MessageSigner::new(
            b"chain-resume-nonce-key-0123456789ab".to_vec(),
            None,
            "k1".into(),
        ),
        std::time::Duration::from_secs(300),
        false,
    );
    let mut cfg = CostGovernanceConfig {
        enabled: true,
        ..Default::default()
    };
    cfg.tool_costs.insert("ask".to_string(), 1.0);
    cfg.budgets.per_key.insert("test-caller".to_string(), limit);
    let registry = Arc::new(crate::cost_accounting::registry::CostRegistry::new(&cfg));
    let enforcer = Arc::new(crate::cost_accounting::enforcer::BudgetEnforcer::new(
        cfg,
        Arc::clone(&registry),
    ));
    meta.with_cost_governance(enforcer, registry)
}

/// A hardened `tools/call` of `name` under `nonce`, captured as the adapters
/// capture it.
fn captured(name: &str, arguments: &Value, nonce: &str) -> (SigningInvocationContext, Value) {
    let mut request = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": name, "arguments": arguments, "_meta": {(NONCE_META): nonce}}});
    let context =
        SigningInvocationContext::capture_scoped(&mut request, SigningScope::EveryToolCall);
    let arguments = request["params"]["arguments"].clone();
    (context, arguments)
}

/// One signed `gateway_execute` of the two-step chain under `nonce`, admitted
/// and holding the witness as admission leaves it.
async fn signed_execute(meta: &MetaMcp, nonce: &str, retry: &RetryFields) -> Value {
    let (who, caps) = (identity(), elicitation_caps());
    let mut caller = resuming_ctx(&who, &caps, retry);
    let (mut signing, arguments) = captured("gateway_execute", &json!({"chain": chain()}), nonce);
    meta.prepare_signing_for_call(&mut signing, "gateway_execute", &arguments, None, &caller)
        .expect("the refusal is the dispatcher's to answer");
    assert!(
        !signing.awaits_admission(),
        "premise: the nonce was admitted"
    );
    signing.keep_witness(RefundWitness::at_capture());
    caller.signing = Some(&signing);
    let response = Box::pin(meta.handle_tools_call(
        RequestId::Number(7),
        "gateway_execute",
        arguments,
        None,
        caller,
    ))
    .await;
    serde_json::to_value(&response).expect("a response serializes")
}

/// One unsigned `gateway_execute` of the two-step chain.
async fn unsigned_execute(meta: &MetaMcp, retry: &RetryFields) -> Value {
    let (who, caps) = (identity(), elicitation_caps());
    let response = Box::pin(meta.handle_tools_call(
        RequestId::Number(1),
        "gateway_execute",
        json!({"chain": chain()}),
        None,
        resuming_ctx(&who, &caps, retry),
    ))
    .await;
    serde_json::to_value(&response).expect("a response serializes")
}

/// Whether `nonce` is still free: an ordinary call presenting it is admitted.
fn nonce_is_free(meta: &MetaMcp, nonce: &str) -> bool {
    let (who, caps) = (identity(), elicitation_caps());
    let caller = resuming_ctx(&who, &caps, &NO_RETRY);
    let (mut later, arguments) = captured("gateway_list_servers", &json!({}), nonce);
    meta.prepare_signing_for_call(
        &mut later,
        "gateway_list_servers",
        &arguments,
        None,
        &caller,
    )
    .is_ok()
        && !later.awaits_admission()
}

fn budget_refused(response: &Value) -> bool {
    response
        .to_string()
        .to_lowercase()
        .contains("budget exceeded")
}

/// K-chain-resume: the stop pays 1.0 of 1.5; the signed resume consumes the
/// chain handle, then the budget refuses its pending `ask`. The consumed
/// handle drops the witness, so the nonce stays spent. Red on base and on 3a:
/// the step's spend refusal refunds with the witness still held.
#[tokio::test]
async fn a_chain_resume_refused_after_its_handle_was_spent_keeps_the_nonce() {
    let stub = Arc::new(AsksOnce::default());
    let meta = signed_and_budgeted(Arc::clone(&stub), 1.5);
    let stop = unsigned_execute(&meta, &NO_RETRY).await;
    let handle = handle_in(&stop);
    let srv = meta.backends.get("srv").expect("fixture backend");
    let fills = srv.list_fills();

    let refused = signed_execute(&meta, "chain-n1", &answers(&handle)).await;
    assert!(
        budget_refused(&refused),
        "the resume's step was refused by the budget: {refused}"
    );
    assert_eq!(
        srv.list_fills(),
        fills,
        "premise: the resume filled nothing"
    );
    assert_eq!(
        stub.calls_to("ask").len(),
        1,
        "the refused step was not sent"
    );

    // The consume itself: the same handle again, with no nonce and so no
    // replay in the way, is refused before the step's budget check.
    let again = unsigned_execute(&meta, &answers(&handle)).await;
    assert_eq!(
        again["error"]["code"], -32602,
        "the handle was spent: {again}"
    );
    assert!(
        !budget_refused(&again),
        "refused by the handle, not the budget: {again}"
    );

    assert!(
        !nonce_is_free(&meta, "chain-n1"),
        "the nonce was given back after the chain handle was spent: {refused}"
    );
}

/// R-chain-fresh (control): a fresh signed chain whose first step the budget
/// refuses consumed nothing, so its nonce comes back.
#[tokio::test]
async fn a_fresh_chain_refused_by_the_budget_gives_the_nonce_back() {
    let stub = Arc::new(AsksOnce::default());
    let meta = signed_and_budgeted(Arc::clone(&stub), 0.5);
    let refused = signed_execute(&meta, "chain-n2", &NO_RETRY).await;
    assert!(
        budget_refused(&refused),
        "the first step was refused by the budget: {refused}"
    );
    assert!(stub.calls_to("ask").is_empty(), "nothing was sent");
    assert!(
        nonce_is_free(&meta, "chain-n2"),
        "the nonce was kept though nothing acted: {refused}"
    );
}
