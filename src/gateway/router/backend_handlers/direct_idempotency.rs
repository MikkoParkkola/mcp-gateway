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

use super::super::helpers::{build_http_error_response, build_http_response};
use super::direct_caller::{Envelope, Rejection};
use super::direct_dispatch::{Admitted, Scope};
use super::direct_preflight::{Preflight, Propagation};
use crate::gateway::meta_mcp::admission::{SyncAdmission, SyncLease};
use crate::gateway::meta_mcp::invoke::egress::Egressed;
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

/// A 7b refusal, answered with the HTTP status `/mcp` gives the same refusal
/// (`dispatch_tools_call.rs`): 409 for 409, otherwise 400 (MIK-8154 ANON.1,
/// design r3.2). Its own function: 7a's refusals keep [`refused`], so a 7a
/// cache-at-capacity 503 stays 503 (row CAP1).
fn lease_refused(scope: Scope<'_>, e: &crate::Error) -> Rejection {
    let code = e.to_rpc_code();
    let status = if code == 409 {
        StatusCode::CONFLICT
    } else {
        StatusCode::BAD_REQUEST
    };
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
                .map(|client| client.principal.storage_form()),
            crate::gateway::meta_mcp::Authentication::of(caller.client.as_ref()),
            envelope.params.as_ref(),
        )
        .map_err(|e| refused(scope, &e))
}

/// Stage 7b: the lease a keyed `tools/call` holds through dispatch, or the
/// stored answer it replays. A cache hit at 7a skips it; an unkeyed call is
/// unprotected, as on `/mcp`. A refusal or a replay gives the 7a reservation
/// back: nothing dispatched under it.
pub(super) fn execution_lease(
    scope: Scope<'_>,
    (envelope, preflight, propagation): (&Envelope, &Preflight, &Propagation),
    guarded: &mut Option<GuardOutcome>,
) -> Result<(Option<SyncLease>, Option<StoredReplay>), Rejection> {
    let hit = matches!(
        guarded,
        Some(GuardOutcome::CachedResult(_) | GuardOutcome::CachedError(_))
    );
    if hit || envelope.method != "tools/call" || preflight.retry.idempotency_key.is_none() {
        return Ok((None, None));
    }
    let caller = scope.caller;
    // The owner task admission spells (MIK-8193): one store, one identity.
    let task_caller = caller.task_caller();
    let admission_owner =
        super::super::handlers::tasks::owner::route_owners(scope.state, &task_caller).admission;
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
                .map(|client| client.principal.storage_form()),
            caller.grant_subject.as_ref(),
            Some(caller.spend_key.as_str()).filter(|key| !key.is_empty()),
        ),
        envelope.era == Era::Modern,
        caller.verified_identity.as_ref(),
        &preflight.retry,
        (scope.name, tool, envelope.params.as_ref()),
        scope.id,
    );
    match admitted {
        Ok(SyncAdmission::Unprotected) => Ok((None, None)),
        Ok(SyncAdmission::Owned(lease)) => {
            // MIK-8440: the forwarded credential this execution runs under.
            if binds_passthrough(scope) {
                lease.note_binding((scope.name, tool), propagation.identity_key.as_deref());
            }
            Ok((Some(lease), None))
        }
        // Released before the replay's delivery begins, not when it ends.
        // The second element is the replayed execution's record facts, which
        // `/mcp` writes into its invocation record. The direct route records a
        // replay as it records a cache hit (`note_cached`), so it sets them aside.
        Ok(SyncAdmission::Replay(response, _, _, _, bindings)) => {
            if let Some(GuardOutcome::Proceed(mut reservation)) = guarded.take() {
                reservation.release();
            }
            Ok((None, Some((response, bindings))))
        }
        // The caller's `?` drops the undispatched 7a reservation, which
        // releases it (`IdempotencyReservation`'s drop, OnDrop::Release).
        Err(e) => Err(lease_refused(scope, &e)),
    }
}

/// A 7b replay: the stored answer and the binding each step ran under.
pub(super) type StoredReplay = (
    JsonRpcResponse,
    Vec<crate::gateway::meta_mcp::admission::StepBinding>,
);

/// Whether this route binds its stored results (MIK-8440): only a
/// passthrough backend, whose binding is the forwarded credential's charged
/// binding (`Propagation::identity_key`, none when it forwarded none). Every
/// other backend's account re-bind needs a restart, which empties this store.
fn binds_passthrough(scope: Scope<'_>) -> bool {
    scope
        .route
        .backend
        .identity_propagation_config()
        .is_some_and(|config| {
            config.strategy == crate::identity_propagation::PropagationStrategyKind::Passthrough
        })
}

/// A 7a hit, else a 7b replay (whose 7a reservation is already given back),
/// answered here as an early return; otherwise the 7a reservation is kept.
///
/// A 7b replay to a caller stage 5 attached no per-caller credential for is
/// refused as `/mcp` refuses it (MIK-8434): the stored output was produced
/// under the owner's per-user credential, and running the call again under
/// the static one would send a write twice. The 7b execution-store key is
/// the owner and the operation, and deliberately not the per-caller binding,
/// which is why an unminted retry reaches the owner's entry at all. A retry
/// under a different forwarded credential reaches it too: the entry records
/// the credential it ran under, and that retry is refused (MIK-8440), never
/// re-run, so the key keeps its one execution. A 7a hit is keyed on the same
/// principal it was stored under, so it is served.
/// The refusal comes after nonce admission, and an admitted nonce is given
/// back only by `release_nonce`, so the refused nonce stays spent.
pub(super) fn deliver_replay(
    scope: Scope<'_>,
    (envelope, preflight, propagation): (&Envelope, &Preflight, &Propagation),
    admitted: &mut Admitted<'_>,
    (guarded, replay): (Option<GuardOutcome>, Option<StoredReplay>),
) -> Result<(), Rejection> {
    let (state, id, client) = (scope.state, scope.id, scope.caller.client.as_ref());
    // A stored answer is about to be served or refused: either way no scan of
    // this request judged it, so the delivery states no findings (A6).
    if replay.is_some() {
        crate::gateway::delivery_facts::unvouched();
    }
    if replay.is_some()
        && let Some(e) = propagation.unproven.as_ref()
    {
        // Refused, not delivered: the stored answer never leaves (A6).
        let e = crate::gateway::delivery_facts::refused(e);
        let refused = super::super::direct_guards::refusal(Some(id.clone()), e);
        return Err(build_http_response(
            &Egressed::gateway_own(refused),
            StatusCode::OK,
        ));
    }
    // MIK-8440: a replay is served only under the forwarded credential that
    // produced it; another credential's retry is refused, never re-run.
    let replay = match replay {
        Some((response, bindings)) => {
            let current = propagation
                .identity_key
                .as_deref()
                .filter(|_| binds_passthrough(scope));
            if let Err(e) = crate::gateway::meta_mcp::stored_binding::judge(&bindings, |_, _| {
                current.map(str::to_owned)
            }) {
                let e = crate::gateway::delivery_facts::refused(&e);
                let refused = super::super::direct_guards::refusal(Some(id.clone()), e);
                return Err(build_http_response(
                    &Egressed::gateway_own(refused),
                    StatusCode::OK,
                ));
            }
            Some(response)
        }
        None => None,
    };
    let replay = match guarded {
        Some(GuardOutcome::CachedResult(cached)) => {
            Some(JsonRpcResponse::success(id.clone(), cached))
        }
        Some(GuardOutcome::CachedError(error)) => {
            crate::gateway::meta_mcp::invoke::audit::note_cached_failure(&error);
            crate::gateway::meta_mcp::invoke::audit::counting::note_replay();
            let mut response = super::cached_error_response(Some(id.clone()), &error);
            replay_scan(state, (&admitted.call, envelope), client, &mut response);
            return Err(build_http_response(&Egressed::of(response), StatusCode::OK));
        }
        Some(GuardOutcome::Proceed(reservation)) => {
            admitted.idem_reservation = Some(reservation);
            replay
        }
        None => replay,
    };
    if let Some(mut response) = replay {
        #[cfg(test)]
        seams::note_replay(admitted.idem_reservation.is_some());
        // Either store's replay delivers an answer already counted.
        crate::gateway::meta_mcp::invoke::audit::counting::note_replay();
        crate::gateway::meta_mcp::invoke::audit::note_cached();
        // A replay is a delivery too: it renews this caller's own copy,
        // shaped for this request's era (MIK-8022).
        replay_scan(state, (&admitted.call, envelope), client, &mut response);
        let auth = (admitted.auth, admitted.call.tool);
        let response =
            super::direct_dispatch::finish_tail(scope, envelope, preflight, auth, response);
        return Err(build_http_response(&Egressed::of(response), StatusCode::OK));
    }
    Ok(())
}

/// Just before the backend can be reached: from here a drop is uncertain.
pub(super) fn mark(lease: Option<&SyncLease>) {
    lease.inspect(|lease| lease.mark_dispatched());
}

/// The backend provably did not act (the failure was raised before
/// dispatch): the lease releases on drop.
pub(super) fn withdraw(lease: Option<&SyncLease>) {
    lease.inspect(|lease| lease.withdraw_dispatch());
}

/// A replay is scanned like a fresh answer: the idempotency cache is shared
/// across routes, and the meta route settles before its delivery scan, so an
/// entry's provenance proves nothing (design round 2).
fn replay_scan(
    state: &super::super::AppState,
    (call, envelope): (
        &crate::gateway::meta_mcp::invoke::dispatch_guards::BackendCall<'_>,
        &Envelope,
    ),
    client: Option<&crate::gateway::auth::AuthenticatedClient>,
    response: &mut JsonRpcResponse,
) {
    let method = envelope.method.as_str();
    let target = super::direct_dispatch::screen_target(call, method);
    super::super::direct_guards::scan_direct_egress(
        state,
        (
            &target,
            crate::gateway::meta_mcp::invoke::egress::ContentChecks::for_method(method),
        ),
        client,
        response,
    );
}

/// Test seams: hold one call after admission, just before its lease is marked
/// (MIK-8154 L8's pre-dispatch cell).
#[cfg(test)]
pub(crate) mod seams {
    use std::sync::Arc;

    use tokio::sync::Notify;

    thread_local! {
        // One-shot: the first arrival parks until released; later arrivals pass (test_pause::Slot).
        static HOLD: Arc<crate::test_pause::Slot> = Arc::new(crate::test_pause::Slot::default());
    }

    /// The next call on this thread to reach the mark signals `entered`, then
    /// waits for `gate`. One call only. Returns `(entered, gate)`.
    pub(crate) fn hold_before_mark() -> (Arc<Notify>, Arc<Notify>) {
        HOLD.with(|hold| hold.arm())
    }

    thread_local! {
        static REPLAY_HELD: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    }

    /// Whether the last 7b replay on this thread still held a 7a reservation
    /// when its delivery began (test plan G1); taken once.
    pub(crate) fn replay_held_7a() -> Option<bool> {
        REPLAY_HELD.with(std::cell::Cell::take)
    }

    pub(in crate::gateway::router::backend_handlers) fn note_replay(held_7a: bool) {
        REPLAY_HELD.with(|cell| cell.set(Some(held_7a)));
    }

    pub(in crate::gateway::router::backend_handlers) async fn before_mark() {
        let hold = HOLD.with(Arc::clone);
        hold.pause().await;
    }
}
