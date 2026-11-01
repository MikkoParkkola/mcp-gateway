// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's two forwarding arms: the sanitized call, sent the
//! params the gate returned, and the plain pass-through call.

use super::{
    Admission, Admitted, DirectRouteGuards, Egressed, Envelope, JsonRpcResponse, Preflight,
    Propagation, RefundWitness, Rejection, Scope, StatusCode, Value, answer_failure,
    build_http_response, finish_response, give_back_nonce, park_if_interim, redeem_retry, refusal,
    rw, settle_parked, spend_witness,
};
use crate::gateway::router::backend_handlers::{
    direct_idempotency, direct_list, direct_permit, direct_send, dispatch_armed,
};

/// The sanitized arm: the gate returned params, so those are what the backend
/// is sent.
pub(super) async fn forward_sanitized(
    scope: Scope<'_>,
    envelope: &Envelope,
    (preflight, propagation): (&Preflight, &Propagation),
    (mut admitted, mut sanitized_params): (Admitted<'_>, Value),
) -> Rejection {
    let Scope {
        state,
        caller,
        route,
        id,
        ..
    } = scope;
    let call = &admitted.call;
    let admission = match DirectRouteGuards::before_dispatch(&state.meta_mcp, call) {
        Ok(admission) => admission,
        Err(e) => {
            give_back_nonce(state, &mut admitted);
            return build_http_response(
                &Egressed::gateway_own(refusal(Some(id.clone()), &e)),
                StatusCode::OK,
            );
        }
    };
    if preflight.retry.is_retry()
        && let Err(refused) = redeem_retry(
            (scope, propagation),
            envelope,
            &mut admitted,
            &mut sanitized_params,
        )
        .await
    {
        // Not dispatched: the spend reservation is given back on drop.
        drop(admission);
        return refused;
    }
    // Redeemed: a continuation the caller presented was consumed.
    admitted.witness = RefundWitness::carry(
        admitted.witness.take(),
        rw::retry_effect(preflight.retry.request_state.is_some()),
    );
    // After redeem, on the exact bytes sent: the answers are in the params now.
    let permit = match direct_permit::mint_permit(scope, Some(&sanitized_params)) {
        Ok(permit) => permit,
        Err(e) => {
            let answer = (&mut admitted, Some(admission));
            return direct_permit::refused_send(state, answer, id, &e);
        }
    };
    // Forward the sanitized params to the backend
    spend_witness(&mut admitted);
    #[cfg(test)]
    direct_idempotency::seams::before_mark().await;
    direct_idempotency::mark(admitted.lease.as_ref());
    let cancel_on = admitted.cancel_on.take();
    let forward = Box::pin(dispatch_armed(
        admitted.idem_reservation.as_mut(),
        crate::gateway::router::inflight_calls::explicitly_cancellable(
            cancel_on,
            direct_send::dispatch_tool_call(
                permit,
                &route.backend,
                id,
                Some(sanitized_params),
                (propagation.lent(), propagation.identity_key.as_deref()),
            ),
        ),
    ))
    .await;
    let client = caller.client.as_ref();
    let parked = park_if_interim(&forward, &mut admitted);
    let seen = (&admitted.call, preflight.challenge.as_deref());
    let seal = (
        (
            caller.verified_identity.as_ref(),
            (
                propagation.identity_key.as_deref(),
                caller.grant_subject.as_ref(),
            ),
            caller.client.as_ref(),
        ),
        (
            envelope.params.as_ref(),
            route.backend.instance(),
            envelope.declared,
        ),
    );
    let forward = DirectRouteGuards::after_dispatch(
        state,
        (seen, seal),
        (client, admitted.auth.generation),
        (&admission, admitted.cancel_entry.as_ref()),
        forward,
    )
    .await;
    settle_parked(parked, &forward, &mut admitted);
    // The spend is settled; an unsettled reservation is given back here.
    drop(admission);
    match forward {
        // The same delivery as a plain answer: one tail, so a modern
        // sanitized call is shaped like any other.
        Ok(response) => {
            finish_response(scope, envelope, preflight, (&mut admitted, response)).await
        }
        // Settled as terminal unless raised before dispatch
        // (ADR-012 consequence 1; see `settle_direct_failure`).
        Err(e) => answer_failure(admitted, e, envelope.method.as_str()).await,
    }
}

/// Forward to the backend as sent. `tools/list` drains the whole upstream
/// catalogue so it can be filtered per caller and answered without a cursor
/// (A3). The outer `Err` is a refusal raised before dispatch.
pub(super) async fn forward_plain(
    scope: Scope<'_>,
    envelope: &Envelope,
    (preflight, propagation): (&Preflight, &Propagation),
    admitted: &mut Admitted<'_>,
) -> Result<crate::Result<JsonRpcResponse>, Rejection> {
    let Scope {
        state,
        name,
        caller,
        route,
        id,
    } = scope;
    let client = caller.client.as_ref();
    let method = envelope.method.as_str();
    if method == "tools/list" {
        let (headers, key) = (propagation.lent(), propagation.identity_key.as_deref());
        // Success is recorded after the firewall pass: a listing it refuses is
        // not a client success.
        let drain = direct_list::drain(
            &route.backend,
            id,
            envelope.params.as_ref(),
            headers,
            key,
            name,
        );
        let drained = crate::gateway::router::inflight_calls::explicitly_cancellable(
            admitted.cancel_on.take(),
            drain,
        )
        .await;
        // Index the slot a complete drain stored.
        state
            .meta_mcp
            .remember_caller_slot(&route.backend, caller.proof(), key)
            .await;
        return Ok(drained);
    }
    let admission = if method == "tools/call" {
        match DirectRouteGuards::before_dispatch(&state.meta_mcp, &admitted.call) {
            Ok(admission) => admission,
            Err(e) => {
                give_back_nonce(state, admitted);
                return Err(build_http_response(
                    &Egressed::gateway_own(refusal(Some(id.clone()), &e)),
                    StatusCode::OK,
                ));
            }
        }
    } else {
        Admission::default()
    };
    let dispatch = match direct_permit::plain_send(scope, envelope, propagation, admitted) {
        Ok(dispatch) => dispatch,
        Err(refused) => {
            // Not dispatched: the spend admission is given back on drop.
            drop(admission);
            return Err(refused);
        }
    };
    spend_witness(admitted);
    #[cfg(test)]
    direct_idempotency::seams::before_mark().await;
    direct_idempotency::mark(admitted.lease.as_ref());
    let cancel_on = admitted.cancel_on.take();
    let forward = Box::pin(dispatch_armed(
        admitted.idem_reservation.as_mut(),
        crate::gateway::router::inflight_calls::explicitly_cancellable(cancel_on, dispatch),
    ))
    .await;
    let answered = if method == "tools/call" {
        let parked = park_if_interim(&forward, admitted);
        let seen = (&admitted.call, preflight.challenge.as_deref());
        let seal = (
            (
                caller.verified_identity.as_ref(),
                (
                    propagation.identity_key.as_deref(),
                    caller.grant_subject.as_ref(),
                ),
                caller.client.as_ref(),
            ),
            (
                envelope.params.as_ref(),
                route.backend.instance(),
                envelope.declared,
            ),
        );
        let guarded = DirectRouteGuards::after_dispatch(
            state,
            (seen, seal),
            (client, admitted.auth.generation),
            (&admission, admitted.cancel_entry.as_ref()),
            forward,
        )
        .await;
        settle_parked(parked, &guarded, admitted);
        guarded
    } else {
        // Client success is recorded once the egress scan admits the answer
        // (`finish_response`): a refused answer must not reset a breaker.
        forward
    };
    // The spend is settled; an unsettled reservation is given back here.
    drop(admission);
    Ok(answered)
}
