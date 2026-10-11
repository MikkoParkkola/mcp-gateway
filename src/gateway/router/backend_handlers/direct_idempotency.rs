// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's two idempotency stages: 7a, the idempotency cache guard
//! (MIK-7272.SUB.4), and 7b, the execution lease `/mcp`, stdio and tasks share
//! (MIK-8154.LEASE.1, gap 11), so one key covers one backend operation
//! whichever route sends it.
//!
//! 7b runs after a 7a miss only (a cache hit is answered by 7a) and before the
//! signing nonce, so a 7b refusal spends no nonce and gives the 7a reservation
//! back. The lease is held through dispatch: marked just before the backend
//! can be reached, withdrawn when the backend provably did not act, settled on
//! the answer the 7a reservation settles on. Dropped unmarked it releases the
//! key; dropped marked and unsettled it records an uncertain outcome, so a
//! retry never runs the call twice (ADR-012 consequence 1).

use axum::http::StatusCode;
use serde_json::Value;

use super::super::helpers::build_http_error_response;
use super::direct_caller::{Envelope, Rejection};
use super::direct_dispatch::Scope;
use super::direct_preflight::{Preflight, Propagation};
use crate::gateway::meta_mcp::admission::{SyncAdmission, SyncLease};
use crate::idempotency::GuardOutcome;
use crate::protocol::JsonRpcResponse;
use crate::protocol::meta::Era;

/// A refusal from either stage, answered with the HTTP status its code names.
fn refused(scope: Scope<'_>, e: &crate::Error) -> Rejection {
    let code = e.to_rpc_code();
    let status = u16::try_from(code)
        .ok()
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    build_http_error_response(Some(scope.id.clone()), code, e.to_string(), status)
}

/// Stage 7a. A broken stream forces re-issue with a NEW request id, so without
/// this the duplicate side effect lands twice on the one route that never
/// reaches `invoke_tool_traced`.
pub(super) fn idempotency_outcome(
    scope: Scope<'_>,
    envelope: &Envelope,
    preflight: &Preflight,
    propagation: &Propagation,
) -> Result<Option<GuardOutcome>, Rejection> {
    if envelope.method != "tools/call" {
        return Ok(None);
    }
    let caller = scope.caller;
    scope
        .state
        .meta_mcp
        .direct_route_idempotency(
            preflight.retry.idempotency_key.as_deref(),
            scope.name,
            propagation.identity_key.as_deref(),
            caller.verified_identity.as_ref(),
            caller.grant_subject.as_ref(),
            caller
                .client
                .as_ref()
                .map(|client| client.principal.as_str()),
            crate::gateway::meta_mcp::Authentication::of(caller.client.as_ref()),
            envelope.params.as_ref(),
        )
        .map_err(|e| refused(scope, &e))
}

/// Stage 7b: the lease a keyed `tools/call` holds through dispatch, or the
/// stored answer it replays. A cache hit at 7a skips it; an unkeyed call is
/// unprotected, as on `/mcp`. A refusal or a replay gives the 7a reservation
/// back first: nothing dispatched under it.
pub(super) fn execution_lease(
    scope: Scope<'_>,
    envelope: &Envelope,
    preflight: &Preflight,
    guarded: &mut Option<GuardOutcome>,
) -> Result<(Option<SyncLease>, Option<JsonRpcResponse>), Rejection> {
    let hit = matches!(
        guarded,
        Some(GuardOutcome::CachedResult(_) | GuardOutcome::CachedError(_))
    );
    if hit || envelope.method != "tools/call" || preflight.retry.idempotency_key.is_none() {
        return Ok((None, None));
    }
    let caller = scope.caller;
    // The owner task admission spells (MIK-8193): one store, one identity.
    let (_, _, admission_owner) = super::super::handlers::route_owners(
        scope.state,
        caller.verified_identity.as_ref(),
        caller.oauth_agent_identity.as_ref(),
        (
            caller.grant_subject.as_ref(),
            caller.cert_identity.as_ref(),
            caller.client.as_ref(),
        ),
    );
    let tool = envelope
        .params
        .as_ref()
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let admitted = scope.state.meta_mcp.direct_route_admission(
        crate::gateway::meta_mcp::AdmissionOwner::routed(&admission_owner),
        (
            caller
                .client
                .as_ref()
                .map(|client| client.principal.as_str()),
            caller.grant_subject.as_ref(),
            Some(caller.spend_key.as_str()).filter(|key| !key.is_empty()),
        ),
        envelope.era == Era::Modern,
        caller.verified_identity.as_ref(),
        &preflight.retry,
        (scope.name, tool, envelope.params.as_ref()),
        scope.id,
    );
    let answer = match admitted {
        Ok(SyncAdmission::Unprotected) => return Ok((None, None)),
        Ok(SyncAdmission::Owned(lease)) => return Ok((Some(lease), None)),
        Ok(SyncAdmission::Replay(response, _)) => Ok((None, Some(response))),
        Err(e) => Err(refused(scope, &e)),
    };
    if let Some(GuardOutcome::Proceed(mut reservation)) = guarded.take() {
        reservation.release();
    }
    answer
}

/// Just before the backend can be reached: from here a drop is uncertain.
pub(super) fn mark(lease: Option<&SyncLease>) {
    lease.inspect(|lease| lease.mark_dispatched());
}

/// The backend provably did not act (it stopped to ask, or the failure was
/// raised before dispatch): the lease releases on drop.
pub(super) fn withdraw(lease: Option<&SyncLease>) {
    lease.inspect(|lease| lease.withdraw_dispatch());
}

/// Test seams: hold one call after admission, just before its lease is marked
/// (MIK-8154 L8's pre-dispatch cell).
#[cfg(test)]
pub(crate) mod seams {
    use std::sync::Arc;

    use tokio::sync::Notify;

    thread_local! {
        static HOLD: std::cell::RefCell<Option<(Arc<Notify>, Arc<Notify>)>> =
            const { std::cell::RefCell::new(None) };
    }

    /// The next call on this thread to reach the mark signals `entered`, then
    /// waits for `gate`. One call only.
    pub(crate) fn hold_before_mark(entered: Arc<Notify>, gate: Arc<Notify>) {
        HOLD.with(|hold| *hold.borrow_mut() = Some((entered, gate)));
    }

    pub(in crate::gateway::router::backend_handlers) async fn before_mark() {
        let held = HOLD.with(|hold| hold.borrow_mut().take());
        if let Some((entered, gate)) = held {
            entered.notify_one();
            gate.notified().await;
        }
    }
}
