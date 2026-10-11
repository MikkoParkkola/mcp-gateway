// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8331 pins: a task call by a surfaced capability's name, from a caller
//! the identity-grant rule or the admin-capability rule refuses, answers
//! exactly as the synchronous call does (status, code, message and audit
//! records), with no task and no backend call.
//!
//! X14 (`confirm_destructive_task`) never classifies a surfaced capability:
//! `classify_surfaced` reads the registry backend (`backends.get`), which a
//! capability is not, and since MIK-8326 it runs `may_invoke` (grants and the
//! admin rule included) first. So no granted caller is ever challenged here,
//! and no challenge control can exist. Each row instead asserts that premise
//! directly, with a scope the policy admits, then the sync parity. The rows
//! guard the ordering against a regression that would classify capabilities.
use super::super::*;
use super::grant_decision_tasks::as_task;
use super::grant_decisions::{OWNER, armed, surfaced};
use super::submit_authz::{WEBHOOK, refused_like_sync, ungranted, webhook_backend};
use super::support::*;

use crate::gateway::meta_mcp::grant_audit_fixture::{CAPS, PERSONAL};
use crate::gateway::meta_mcp::{TaskConfirmation, TaskConfirmationRequest};
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

/// The premise: X14 answers `NotRequired` for a keyed, modern task call of
/// the surfaced capability `tool`, asked with `scope`, a scope the policy
/// admits (so `may_invoke` passes and classification is reached).
async fn x14_does_not_classify(
    meta: &MetaMcp,
    tool: &str,
    scope: crate::gateway::meta_mcp::InvokeScope<'_>,
) {
    assert!(
        meta.may_invoke(CAPS, tool, scope, None).is_ok(),
        "premise: the scope does not admit {tool}, so the gate would not reach classification"
    );
    let retry = crate::protocol::mrtr::RetryFields {
        idempotency_key: Some("x14-premise".to_string()),
        ..crate::protocol::mrtr::RetryFields::default()
    };
    let admission = crate::idempotency::admission::ExecutionAdmission::new(Arc::new(|| 1_000));
    let (arguments, task) = (json!({}), json!({}));
    let outcome = meta
        .confirm_destructive_task_with(
            &TaskConfirmationRequest {
                id: crate::protocol::RequestId::Number(1),
                tool_name: tool,
                arguments: &arguments,
                task: Some(&task),
                retry: &retry,
                verified_identity: None,
                principal: Some("x14-premise".to_string()),
                quota: None,
                owner: "x14-premise",
                scope,
                session_id: None,
                input_capabilities: crate::protocol::meta::Declared::from_handshake(Some(
                    &json!({ "elicitation": {} }),
                )),
                is_modern: true,
                admission: &admission,
            },
            None,
        )
        .await
        .0;
    assert!(
        matches!(outcome, TaskConfirmation::NotRequired),
        "premise: X14 classified the surfaced capability {tool}"
    );
}

/// The webhook capability, an admin action, surfaced by its own name.
fn surfaced_webhook(meta: MetaMcp) -> MetaMcp {
    meta.with_surfaced_tools(vec![crate::config::SurfacedToolConfig {
        server: CAPS.to_string(),
        tool: WEBHOOK.to_string(),
    }])
}

/// MIK-8331 grant row: without the grant, a task call of the surfaced
/// personal capability answers as its sync call, with no challenge.
async fn ungranted_refusal(idem: &str) {
    let granted = armed(true, false, AuditFailurePolicy::BestEffort, surfaced).await;
    let owner = crate::identity_grants::GrantSubject::checked(OWNER.0, OWNER.1, None)
        .expect("the owner names someone");
    let scope = crate::gateway::meta_mcp::InvokeScope {
        authorizer: &crate::gateway::authz::AllowAll,
        is_admin: false,
        api_key_name: None,
        agent_id: None,
        grant_subject: Some(&owner),
        caller: crate::identity_propagation::CallerProof::Anonymous,
    };
    x14_does_not_classify(&granted.state.meta_mcp, PERSONAL, scope).await;
    let row = armed(false, false, AuditFailurePolicy::BestEffort, surfaced).await;
    let (sync, task) = (by_surfaced_name(1, PERSONAL), by_surfaced_name(2, PERSONAL));
    refused_like_sync(&row, sync, as_task(task, idem)).await;
}

/// MIK-8331 admin row: a non-admin's task call of the surfaced admin
/// capability answers as its sync call, with no challenge.
async fn non_admin_refusal(idem: &str) {
    let row = ungranted(surfaced_webhook).await;
    row.state.meta_mcp.set_capabilities(webhook_backend());
    let admin = crate::gateway::meta_mcp::InvokeScope {
        authorizer: &crate::gateway::authz::AllowAll,
        is_admin: true,
        api_key_name: None,
        agent_id: None,
        grant_subject: None,
        caller: crate::identity_propagation::CallerProof::Anonymous,
    };
    x14_does_not_classify(&row.state.meta_mcp, WEBHOOK, admin).await;
    let (sync, task) = (by_surfaced_name(1, WEBHOOK), by_surfaced_name(2, WEBHOOK));
    refused_like_sync(&row, sync, as_task(task, idem)).await;
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
/// order (MIK-8331): the grant row and the admin row. Gated as the matrix
/// rows are (`route_check_matrix_tests.rs` `mod rows`).
#[cfg(feature = "firewall")]
pub(crate) async fn matrix_authorize_precedes_x14() {
    ungranted_refusal("x14-ga-m-grant").await;
    non_admin_refusal("x14-ga-m-admin").await;
}
