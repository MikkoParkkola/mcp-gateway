// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8176 SLOT.3 (JSON arm): a chain whose grant decision cannot be written
//! is replaced by the grant-audit refusal (`slot_http`), so the question its
//! second step sealed never reaches the client and its slot is given back.
//! Delivered, the same chain keeps the slot for the retry.
use super::super::*;
use super::grant_decisions::armed;
use super::support::*;

use crate::gateway::meta_mcp::grant_audit_fixture::{CAPS, DECISION_KIND, PERSONAL};
use crate::security::audit::AuditFailurePolicy;

/// A backend question, as the mock's step answers.
fn question() -> Value {
    json!({
        "resultType": "input_required",
        "inputRequests": {"k1": {
            "method": "elicitation/create",
            "params": {"message": "Which account?", "requestedSchema": {"type": "object"}}
        }},
        "requestState": "backend-state"
    })
}

/// The personal capability (a grant decision), then the mock's question.
fn chain(id: i64) -> Value {
    let steps = json!([
        { "tool": format!("{CAPS}:{PERSONAL}"), "arguments": {} },
        { "tool": format!("{BACKEND}:{TOOL}"), "arguments": {} },
    ]);
    declaring_elicitation(modern(
        id,
        "tools/call",
        json!({ "name": "gateway_execute", "arguments": { "chain": steps } }),
        false,
    ))
}

async fn held(state: &Arc<AppState>) -> usize {
    let now = crate::protocol::continuation::now_unix_secs();
    state.meta_mcp.continuation().in_flight().len(now).await
}

/// Delivered: the chain stops at the question and its slot is kept.
#[tokio::test]
async fn a_delivered_chain_question_keeps_its_slot() {
    let row = armed(true, false, AuditFailurePolicy::FailClosed, |meta| meta).await;
    register(
        &row.state,
        BACKEND,
        &MockBackend::answering(Answer::Result(question())),
    );
    let answer = post(&row.state, "key-a", chain(7)).await;
    let text = answer.to_string();
    assert!(
        answer.get("error").is_none()
            && text.contains("requestState")
            && !text.contains("backend-state"),
        "control: the chain delivers a sealed question: {answer}"
    );
    std::assert_eq!(held(&row.state).await, 1, "{answer}");
}

/// Refused by the grant-audit replacement: the sealed question never leaves.
#[tokio::test]
async fn a_chain_question_replaced_by_the_grant_audit_gives_its_slot_back() {
    let row = armed(true, false, AuditFailurePolicy::FailClosed, |meta| meta).await;
    register(
        &row.state,
        BACKEND,
        &MockBackend::answering(Answer::Result(question())),
    );
    row.log.fail_next_append_of_kind_for_test(DECISION_KIND);
    let answer = post(&row.state, "key-a", chain(7)).await;
    std::assert_eq!(answer["error"]["code"], json!(-32005), "{answer}");
    std::assert_eq!(
        held(&row.state).await,
        0,
        "the replaced question kept its slot: {answer}"
    );
}
