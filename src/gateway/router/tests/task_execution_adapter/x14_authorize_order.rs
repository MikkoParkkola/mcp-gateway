// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8331: X14's confirmation challenge never precedes the grant and admin
//! checks. A modern, keyed, task-augmented call by a surfaced name, declaring
//! elicitation (so X14 has a question it could ask), from a caller the sync
//! call refuses, answers exactly as that sync call: status, code, message and
//! audit records, with no challenge, no task and no backend call. Each refusal
//! row carries its own control: the caller the policy admits, on the same
//! fixture shape, does get X14's challenge, so the refusal rows cannot pass
//! because X14 never engages.
use super::super::*;
use super::grant_decision_tasks::as_task;
use super::grant_decisions::{Armed, armed, surfaced};
use super::submit_authz::{WEBHOOK, refused_like_sync, ungranted, webhook_backend};
use super::support::*;

use crate::gateway::meta_mcp::grant_audit_fixture::{CAPS, PERSONAL};
use crate::security::audit::AuditFailurePolicy;

/// A modern call of `name` by its surfaced name, declaring elicitation.
fn by_surfaced_name(id: i64, name: &str) -> Value {
    declaring_elicitation(modern(
        id,
        "tools/call",
        json!({ "name": name, "arguments": {} }),
        true,
    ))
}

/// Panics unless `key`'s keyed task call of `name` is X14's challenge, with
/// no task and no backend call.
async fn assert_challenged(row: &Armed, key: &str, name: &str, idem: &str) {
    let answer = post(&row.state, key, as_task(by_surfaced_name(1, name), idem)).await;
    std::assert_eq!(
        answer.pointer("/result/resultType"),
        Some(&json!("input_required")),
        "control: the admitted caller is not challenged by X14: {answer}"
    );
    assert!(
        answer.pointer("/result/taskId").is_none(),
        "control: a task before the answer: {answer}"
    );
    std::assert_eq!(row.endpoint.arrivals(), 0, "control: dispatched: {answer}");
}

/// The webhook capability, an admin action, surfaced by its own name.
fn surfaced_webhook(meta: MetaMcp) -> MetaMcp {
    meta.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
        server: CAPS.to_string(),
        tool: WEBHOOK.to_string(),
    }])
}

/// MIK-8331 control: the granted owner's task call of the surfaced personal
/// capability is challenged by X14, as today.
async fn granted_control(idem: &str) {
    let row = armed(true, false, AuditFailurePolicy::BestEffort, surfaced).await;
    assert_challenged(&row, "key-a", PERSONAL, idem).await;
}

/// MIK-8331 grant row: without the grant, the same call answers as the sync
/// call does, with no challenge.
async fn ungranted_refusal(idem: &str) {
    let row = armed(false, false, AuditFailurePolicy::BestEffort, surfaced).await;
    let (sync, task) = (by_surfaced_name(1, PERSONAL), by_surfaced_name(2, PERSONAL));
    refused_like_sync(&row, sync, as_task(task, idem)).await;
}

/// MIK-8331 admin row, with its own control: an admin's task call of the
/// surfaced admin capability is challenged; a non-admin's answers as its
/// sync call does, with no challenge.
async fn non_admin_refusal(idem: &str) {
    let webhook = || async {
        let row = ungranted(surfaced_webhook).await;
        row.state.meta_mcp.set_capabilities(webhook_backend());
        row
    };
    let control = format!("{idem}-control");
    assert_challenged(&webhook().await, "key-admin", WEBHOOK, &control).await;
    let (sync, task) = (by_surfaced_name(1, WEBHOOK), by_surfaced_name(2, WEBHOOK));
    refused_like_sync(&webhook().await, sync, as_task(task, idem)).await;
}

#[tokio::test]
async fn a_granted_surfaced_task_call_is_challenged() {
    granted_control("x14-ga-control").await;
}

#[tokio::test]
async fn an_ungranted_surfaced_task_call_is_refused_before_x14() {
    ungranted_refusal("x14-ga-grant").await;
}

#[tokio::test]
async fn a_non_admin_surfaced_task_call_of_an_admin_capability_is_refused_before_x14() {
    non_admin_refusal("x14-ga-admin").await;
}

/// The route-check matrix's `TaskSubmit` x `Authorize` driver for X14's
/// order (MIK-8331): the granted control, the grant row and the admin row.
/// Gated as the matrix rows are (`route_check_matrix_tests.rs` `mod rows`).
#[cfg(feature = "firewall")]
pub(crate) async fn matrix_authorize_precedes_x14() {
    granted_control("x14-ga-m-control").await;
    ungranted_refusal("x14-ga-m-grant").await;
    non_admin_refusal("x14-ga-m-admin").await;
}
