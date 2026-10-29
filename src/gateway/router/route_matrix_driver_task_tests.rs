// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The task-submit drivers of the route matrix: a surfaced task submit and
//! its confirm round, read as a given key, ungranted, and authorized before
//! the nonce check. Moved from `route_matrix_driver_tests.rs` for the
//! file-size ceiling; the parent re-exports what other rows call.

use super::*;

/// R4a: a modern task-augmented `tools/call read` by its surfaced name on
/// `/mcp`, declaring form elicitation, where `read` is listed
/// `destructiveHint: true`, so X14 has a destructive call to decide. `k-std`
/// carries no verified identity, so X14 binds it by its key.
///
/// The whole round on one gateway: `k-std`'s call; its challenge, answered
/// `accept` and presented by another key (`k-budget`); then by `k-std`. With
/// the backend calls counted after each.
pub(crate) async fn task_submit_surfaced() -> TaskConfirmRound {
    let (fx, calls, params) = task_submit_fixture(Surfacing::On).await;
    let send = |key: &'static str, params: serde_json::Value| {
        super::super::direct_guards_fixture::send_with_headers(
            &fx,
            "/mcp",
            key,
            "tools/call",
            params,
            None,
            &TASK_SUBMIT_HEADERS,
        )
    };
    let (_, challenge) = send("k-std", params.clone()).await;
    let mut accepted = params;
    if let (Some(state), Some((issued, _))) = (
        challenge.pointer("/result/requestState").cloned(),
        challenge
            .pointer("/result/inputRequests")
            .and_then(serde_json::Value::as_object)
            .and_then(|requests| requests.iter().next()),
    ) {
        accepted["requestState"] = state;
        accepted["inputResponses"] = serde_json::json!({ issued.clone(): {"action": "accept"} });
    }
    let (_, other_key) = send("k-budget", accepted.clone()).await;
    let after_other_key = calls.load(Ordering::SeqCst);
    let (_, same_key) = send("k-std", accepted).await;
    TaskConfirmRound {
        challenge,
        other_key,
        after_other_key,
        same_key,
    }
}

/// [`task_submit_surfaced`]'s answers.
pub(crate) struct TaskConfirmRound {
    /// `k-std`'s first call: X14's question.
    pub challenge: serde_json::Value,
    /// The accepted answer presented by another key.
    pub other_key: serde_json::Value,
    /// Backend calls once that presentation was answered.
    pub after_other_key: usize,
    /// The accepted answer presented by `k-std`.
    pub same_key: serde_json::Value,
}

/// Whether the fixture surfaces `read` (P3).
#[derive(Clone, Copy)]
pub(crate) enum Surfacing {
    /// `read` is surfaced on `/mcp`.
    On,
    /// Nothing is surfaced, so the name `read` matches no tool.
    Off,
}

/// The R4a fixture, surfacing `read` per `surfacing_mode`, with its backend
/// call counter and the task-augmented call's params.
async fn task_submit_fixture(
    surfacing_mode: Surfacing,
) -> (
    super::super::direct_guards_fixture::Fx,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    serde_json::Value,
) {
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let transport = std::sync::Arc::new(Destructive {
        calls: std::sync::Arc::clone(&calls),
    });
    let fx = match surfacing_mode {
        Surfacing::On => {
            super::super::direct_guards_fixture::fixture_built_on(transport, surfacing).await
        }
        Surfacing::Off => {
            super::super::direct_guards_fixture::fixture_built_on(transport, |meta| meta).await
        }
    };
    (fx, calls, task_submit_params())
}

/// One R4a call sent with the API key `key`, on a fixture that surfaces
/// `read` per `surfacing_mode`. Returns the HTTP status with the answer.
/// `k-deny` is the fixture's key denied `read` (P3).
pub(crate) async fn task_submit_read_as(
    key: &str,
    surfacing_mode: Surfacing,
) -> (axum::http::StatusCode, Sent) {
    let (fx, calls, params) = task_submit_fixture(surfacing_mode).await;
    let (status, body) = super::super::direct_guards_fixture::send_with_headers(
        &fx,
        "/mcp",
        key,
        "tools/call",
        params,
        None,
        &TASK_SUBMIT_HEADERS,
    )
    .await;
    let sent = Sent {
        body,
        backend_calls: calls.load(Ordering::SeqCst),
        seen: Vec::new(),
    };
    (status, sent)
}

/// R4a `Authorize`: a modern task-augmented `gateway_invoke` of a
/// personal capability the caller holds no grant for, on `/mcp`. Panics
/// unless the submit answers the sync call's status, code and message,
/// writes the sync call's audit records, creates no task and reaches nothing.
pub(crate) async fn task_submit_ungranted() {
    super::super::tests::task_execution_adapter::submit_authz::matrix_ungranted_invoke_submit()
        .await;
}

/// R4a `Authorize` before `TaskConfirm`: a task call by a surfaced
/// name from a caller without the grant, and from a non-admin for an admin
/// capability, answers as the sync call with no X14 challenge, and X14 does
/// not classify the surfaced capability for an admitted scope. Panics
/// otherwise.
pub(crate) async fn task_submit_authorized_before_x14() {
    super::super::tests::task_execution_adapter::x14_authorize_order::matrix_authorize_precedes_x14()
        .await;
}
