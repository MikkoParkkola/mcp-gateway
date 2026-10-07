// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Stage 6 and the terminal arm of the direct backend route: admission, then
//! the dispatch and what the caller receives.
//!
//! The order is the order `backend_handler_inner` always had: the shared
//! dispatch controls, then the tool-call security gate (#2445, before the
//! idempotency cache so a call the gate now refuses is refused on the re-issue
//! too), then the idempotency guard, then the signing nonce (after every
//! refusal, so a refused call consumes none, MIK-7698).

use axum::http::StatusCode;
use serde_json::Value;

use super::super::AppState;
use super::super::direct_guards::{DirectRouteGuards, refusal};
use super::super::helpers::{build_http_error_response, build_http_response};
use super::direct_caller::{Caller, Envelope, Rejection, Route};
use super::direct_failure::DirectFailure;
use super::direct_preflight::{Preflight, Propagation};
use super::{BackendAuthContext, sign_and_record};
use crate::gateway::meta_mcp::invoke::dispatch_guards::{Admission, BackendCall};
use crate::gateway::meta_mcp::invoke::relay::GatewayStamps;
use crate::protocol::meta::Era;
use crate::protocol::{JsonRpcResponse, RequestId};

/// What every stage after routing needs to name the request it serves.
#[derive(Clone, Copy)]
pub(super) struct Scope<'a> {
    pub(super) state: &'a AppState,
    pub(super) name: &'a str,
    pub(super) caller: &'a Caller,
    pub(super) route: &'a Route<'a>,
    pub(super) id: &'a RequestId,
}

/// What admission decided: the answer for a dispatched failure, the shared
/// dispatch controls' view of the call, the sanitized params (`None`:
/// pass-through, forwarded as sent) and the idempotency reservation.
pub(super) struct Admitted<'a> {
    pub(super) failed: DirectFailure<'a>,
    pub(super) call: BackendCall<'a>,
    pub(super) auth: BackendAuthContext<'a>,
    pub(super) sanitized: Option<Value>,
    pub(super) idem_reservation: Option<crate::idempotency::IdempotencyReservation>,
}

/// SECURITY: apply tool policy, name validation, and input sanitization to
/// `tools/call` requests unless the backend explicitly opts into pass-through
/// mode (`passthrough: true` in config, only for fully-trusted internals).
/// #2445: before the idempotency cache, so a call the gate now refuses is
/// refused on the re-issue too, never answered from the cache.
async fn guard_and_sanitize(
    scope: Scope<'_>,
    envelope: &Envelope,
    propagation: &Propagation,
    admitted: &mut Admitted<'_>,
) -> Result<(), Rejection> {
    // MIK-7597: the shared dispatch controls, S1 and G7 before the reservation.
    // (`DirectRouteGuards::run` needs the signing scope, so the caller runs it.)
    if envelope.method == "tools/call" {
        admitted.sanitized = super::apply_backend_tool_call_security(
            scope.state,
            scope.name,
            admitted.auth,
            envelope.params.as_ref(),
            scope.id,
            &scope.route.backend,
            (
                (propagation.identity_key.as_deref(), &propagation.headers),
                &admitted.failed,
            ),
        )
        .await?;
    } else if matches!(envelope.method.as_str(), "prompts/get" | "resources/read") {
        // MIK-7765: a catalogue read's forwarded params are an egress too.
        #[cfg(feature = "firewall")]
        if let Some(refusal) = super::catalogue_refusal(
            scope.state,
            admitted.auth,
            scope.id,
            (scope.name, envelope.method.as_str()),
            envelope.params.as_ref(),
        ) {
            return Err(refusal);
        }
    }
    Ok(())
}

/// MIK-7272.SUB.4: the bypass re-enforces the idempotency guard locally, the
/// same shape as the isolation guard. A broken stream forces re-issue with a
/// NEW request id, so without this the duplicate side effect lands twice on
/// the one route that never reaches `invoke_tool_traced`.
fn idempotency_outcome(
    scope: Scope<'_>,
    envelope: &Envelope,
    preflight: &Preflight,
    propagation: &Propagation,
) -> Result<Option<crate::idempotency::GuardOutcome>, Rejection> {
    if envelope.method != "tools/call" {
        return Ok(None);
    }
    let caller = scope.caller;
    match scope.state.meta_mcp.direct_route_idempotency(
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
    ) {
        Ok(outcome) => Ok(outcome),
        Err(e) => {
            let code = e.to_rpc_code();
            let status = u16::try_from(code)
                .ok()
                .and_then(|c| StatusCode::from_u16(c).ok())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            Err(build_http_error_response(
                Some(scope.id.clone()),
                code,
                e.to_string(),
                status,
            ))
        }
    }
}

/// Admitted once, here: after every refusal above and the idempotency guard,
/// so a refused call consumes no nonce (MIK-7698), and before a cached result
/// is delivered, so it is signed against the replaying request's own nonce.
fn admit_signing_nonce(scope: Scope<'_>, preflight: &Preflight) -> Result<(), Rejection> {
    if !preflight.signs {
        return Ok(());
    }
    let caller = scope.caller;
    DirectRouteGuards::admit_nonce(
        scope.state,
        (
            caller.client.as_ref(),
            caller.oauth_agent_identity.as_ref(),
            caller.cert_identity.as_ref(),
        ),
        preflight.signing_nonce.as_deref(),
    )
    .map_err(|e| {
        let message = crate::gateway::meta_mcp::signing::wire_error_message(&e);
        let code = e.to_rpc_code();
        build_http_error_response(
            Some(scope.id.clone()),
            code,
            message,
            StatusCode::BAD_REQUEST,
        )
    })
}

/// Stage 6: admission. A cached result or error is an early return today, so
/// it comes back as `Err(response)` at the same point in the same order.
pub(super) async fn admit<'a>(
    scope: Scope<'a>,
    envelope: &'a Envelope,
    preflight: &Preflight,
    propagation: &'a Propagation,
) -> Result<Admitted<'a>, Rejection> {
    let Scope {
        state,
        name,
        caller,
        route,
        id,
    } = scope;
    let client = caller.client.as_ref();
    // One answer for a dispatched failure, used by whichever arm dispatches.
    let failed = DirectFailure {
        state,
        name,
        id: id.clone(),
        client,
        identity: caller.verified_identity.as_ref(),
        managed: propagation.managed.as_ref(),
    };
    // A session-less call's spend goes to its caller's own report (MIK-7653);
    // a sessioned one is reported under its session, so it needs no key.
    let caller_key = route
        .session_id
        .is_none_or(str::is_empty)
        .then_some(caller.spend_key.as_str());
    let call = BackendCall {
        server: name,
        tool: envelope
            .params
            .as_ref()
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default(),
        session_id: route.session_id,
        api_key_name: client.map(|c| c.name.as_str()),
        trace_id: "",
        caller_key,
    };
    if envelope.method == "tools/call"
        && let Err(e) = DirectRouteGuards::run(&state.meta_mcp, &call, preflight.signing_scope)
    {
        return Err(build_http_response(
            &refusal(Some(id.clone()), &e),
            StatusCode::OK,
        ));
    }
    let auth = BackendAuthContext {
        client,
        oauth_agent_identity: caller.oauth_agent_identity.as_ref(),
        cert_identity: caller.cert_identity.as_ref(),
        #[cfg(feature = "firewall")]
        grant_subject: caller.grant_subject.as_ref(),
    };
    let mut admitted = Admitted {
        failed,
        call,
        auth,
        sanitized: None,
        idem_reservation: None,
    };
    guard_and_sanitize(scope, envelope, propagation, &mut admitted).await?;
    let guarded = idempotency_outcome(scope, envelope, preflight, propagation)?;
    admit_signing_nonce(scope, preflight)?;
    match guarded {
        Some(crate::idempotency::GuardOutcome::CachedResult(cached)) => {
            crate::gateway::meta_mcp::invoke::audit::note_cached();
            // A replay is a delivery too: it renews this caller's own copy,
            // shaped for this request's era (MIK-8022).
            let response = JsonRpcResponse::success(id.clone(), cached);
            let auth = (admitted.auth, admitted.call.tool);
            return Err(deliver_tail(scope, envelope, preflight, auth, response));
        }
        Some(crate::idempotency::GuardOutcome::CachedError(error)) => {
            crate::gateway::meta_mcp::invoke::audit::note_cached_failure(&error);
            let response = super::cached_error_response(Some(id.clone()), &error);
            return Err(build_http_response(&response, StatusCode::OK));
        }
        Some(crate::idempotency::GuardOutcome::Proceed(reservation)) => {
            admitted.idem_reservation = Some(reservation);
        }
        None => {}
    }
    Ok(admitted)
}

/// The sanitized arm: the gate returned params, so those are what the backend
/// is sent.
async fn forward_sanitized(
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
            return build_http_response(&refusal(Some(id.clone()), &e), StatusCode::OK);
        }
    };
    if preflight.retry.is_retry()
        && let Err(refused) =
            redeem_retry(scope, envelope, &mut admitted, &mut sanitized_params).await
    {
        // Not dispatched: the spend reservation is given back on drop.
        drop(admission);
        return refused;
    }
    // Forward the sanitized params to the backend
    let forward = Box::pin(super::dispatch_armed(
        admitted.idem_reservation.as_mut(),
        super::dispatch_in_scope(
            &route.backend,
            &envelope.method,
            id,
            Some(sanitized_params),
            &propagation.headers,
            propagation.identity_key.as_deref(),
        ),
    ))
    .await;
    let client = caller.client.as_ref();
    release_if_interim(&forward, &mut admitted);
    let seen = (&admitted.call, preflight.challenge.as_deref());
    let seal = (caller.verified_identity.as_ref(), envelope.params.as_ref());
    let forward =
        DirectRouteGuards::after_dispatch(state, (seen, seal), client, &admission, forward).await;
    // The spend is settled; an unsettled reservation is given back here.
    drop(admission);
    match forward {
        // The same delivery as a plain answer: one tail, so a modern
        // sanitized call is shaped like any other (MIK-8022).
        Ok(response) => finish_response(scope, envelope, preflight, (&mut admitted, response)),
        // Settled as terminal unless raised before dispatch
        // (ADR-012 consequence 1; see `settle_direct_failure`).
        Err(e) => answer_failure(admitted, e).await,
    }
}

/// Forward to the backend as sent. `tools/list` drains the whole upstream
/// catalogue so it can be filtered per caller and answered without a cursor
/// (A3). The outer `Err` is a refusal raised before dispatch.
async fn forward_plain(
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
        let (headers, key) = (&propagation.headers, propagation.identity_key.as_deref());
        // Success is recorded after the firewall pass: a listing it refuses is
        // not a client success (MIK-7708).
        return Ok(super::direct_list::drain(
            &route.backend,
            id,
            envelope.params.as_ref(),
            headers,
            key,
            name,
        )
        .await);
    }
    let admission = if method == "tools/call" {
        match DirectRouteGuards::before_dispatch(&state.meta_mcp, &admitted.call) {
            Ok(admission) => admission,
            Err(e) => {
                return Err(build_http_response(
                    &refusal(Some(id.clone()), &e),
                    StatusCode::OK,
                ));
            }
        }
    } else {
        Admission::default()
    };
    let dispatch = super::dispatch_in_scope(
        &route.backend,
        method,
        id,
        envelope.params.clone(),
        &propagation.headers,
        propagation.identity_key.as_deref(),
    );
    let forward = Box::pin(super::dispatch_armed(
        admitted.idem_reservation.as_mut(),
        dispatch,
    ))
    .await;
    let answered = if method == "tools/call" {
        release_if_interim(&forward, admitted);
        let seen = (&admitted.call, preflight.challenge.as_deref());
        let seal = (caller.verified_identity.as_ref(), envelope.params.as_ref());
        DirectRouteGuards::after_dispatch(state, (seen, seal), client, &admission, forward).await
    } else {
        forward.inspect(|_| super::record_client_success(state, client))
    };
    // The spend is settled; an unsettled reservation is given back here.
    drop(admission);
    Ok(answered)
}

/// What the caller receives from an answered plain dispatch: the id they
/// supplied, the list or call post-processing, the settled idempotency key,
/// the chain finish, and (for `tools/call`) the signature.
fn finish_response(
    scope: Scope<'_>,
    envelope: &Envelope,
    preflight: &Preflight,
    (admitted, mut response): (&mut Admitted<'_>, JsonRpcResponse),
) -> Rejection {
    let Scope {
        state,
        name,
        caller,
        route,
        id,
    } = scope;
    let client = caller.client.as_ref();
    let method = envelope.method.as_str();
    // Upstream transport IDs are private gateway correlation state;
    // direct-route clients must receive the ID they supplied.
    response.id = Some(id.clone());
    if method == "tools/list" {
        // Redaction FIRST, then the trust stamp. The firewall may remove a
        // `$defs` entry a surviving `$ref` points at, so a verdict computed
        // before it can say `within` about a document the client never
        // receives.
        super::scan_direct_tools_list_response(state, name, client, &mut response);
        if response.error.is_none() {
            super::record_client_success(state, client);
        }
        super::normalize_tools_list_response(&route.backend, &mut response);
        // List = invoke: only what this route's `tools/call` admits.
        let (oauth, cert) = (
            caller.oauth_agent_identity.as_ref(),
            caller.cert_identity.as_ref(),
        );
        super::direct_list::retain_invocable(state, client, oauth, cert, name, &mut response);
    } else if method == "tools/call" {
        super::stamp_direct_provenance(
            state,
            name,
            envelope.params.as_ref(),
            client,
            &mut response,
        );
    }
    // Settled before shaping: the cache holds no era-specific member, so a
    // replay is shaped for its own request's era (MIK-8022).
    super::settle_direct_idempotency(admitted.idem_reservation.as_mut(), &response);
    if method == "tools/list"
        && envelope.era != Era::Modern
        && let Some(result) = response.result.as_mut().and_then(Value::as_object_mut)
    {
        // The backend hint carried through the rebuild is for the modern
        // shaper alone; a legacy listing stays byte-identical.
        result.remove("ttlMs");
    }
    deliver_tail(
        scope,
        envelope,
        preflight,
        (admitted.auth, admitted.call.tool),
        response,
    )
}

/// The tail every success shares, a cached replay included: the 2026-07-28
/// shape for a modern request, the clamp and chain finish, then (for
/// `tools/call`) the signature, or the catalogue receipt. Shaping comes before
/// the finish and the signature, as on `/mcp`, so both cover what is sent; the
/// stamps tell the receipt which members the gateway wrote.
///
/// MIK-8025/MIK-8011 (secE) wrap this tail and the fresh steps in a
/// `gateway_writes` scope.
fn deliver_tail(
    scope: Scope<'_>,
    envelope: &Envelope,
    preflight: &Preflight,
    (auth, tool): (BackendAuthContext<'_>, &str),
    mut response: JsonRpcResponse,
) -> Rejection {
    let (state, name) = (scope.state, scope.name);
    let method = envelope.method.as_str();
    let stamps = if envelope.era == Era::Modern {
        crate::gateway::router::shape_modern_response(&mut response, method)
    } else {
        GatewayStamps::Legacy
    };
    // A replay's cached answer is not chain-eligible, so no new origin link.
    let nonce = preflight.chain_nonce.as_deref();
    state.meta_mcp.finish_direct(&mut response, method, nonce);
    if method == "tools/call" {
        let nonce = preflight.signs.then_some(&preflight.signing_nonce);
        sign_and_record(state, auth, (name, tool), &mut response, (nonce, stamps));
    } else if matches!(method, "prompts/get" | "resources/read") && response.error.is_none() {
        // MIK-7765: what a catalogue read delivers is a relay source too.
        #[cfg(feature = "firewall")]
        super::stage_direct_catalogue(
            state,
            auth,
            (name, method),
            response.result.as_ref(),
            stamps,
        );
    }
    build_http_response(&response, StatusCode::OK)
}

/// MIK-8078 (MRTR.1, MRTR.3-6): a retry presents the continuation this route
/// sealed, and the backend gets its own state back in `outbound` in its place,
/// as on the meta route. Refused before dispatch, so the key is released: the
/// backend has not acted.
async fn redeem_retry(
    scope: Scope<'_>,
    envelope: &Envelope,
    admitted: &mut Admitted<'_>,
    outbound: &mut Value,
) -> Result<(), Rejection> {
    let identity = scope.caller.verified_identity.as_ref();
    let sent = (scope.name, envelope.params.as_ref());
    let redeemed = scope
        .state
        .meta_mcp
        .redeem_direct_retry(identity, sent, outbound)
        .await;
    redeemed.map_err(|e| {
        if let Some(reservation) = admitted.idem_reservation.as_mut() {
            reservation.release();
        }
        build_http_response(&refusal(Some(scope.id.clone()), &e), StatusCode::OK)
    })
}

/// MIK-8078: a backend that stopped to ask did not act, so its key is
/// released rather than settled (the meta route's rule). Released here, before
/// the guards, because a seal they refuse returns before settlement, and an
/// armed reservation dropped unsettled records an uncertain outcome.
fn release_if_interim(forward: &crate::Result<JsonRpcResponse>, admitted: &mut Admitted<'_>) {
    let asked = forward
        .as_ref()
        .ok()
        .and_then(|response| response.result.as_ref())
        .is_some_and(crate::protocol::mrtr::InputRequired::claims_input_required);
    if asked && let Some(mut reservation) = admitted.idem_reservation.take() {
        reservation.release();
    }
}

/// Answer a dispatch that failed, settling the reservation (`answer` consumes
/// the failure context, so this takes the admission by value).
async fn answer_failure(admitted: Admitted<'_>, e: crate::Error) -> Rejection {
    let Admitted {
        failed,
        mut idem_reservation,
        ..
    } = admitted;
    failed.answer(idem_reservation.as_mut(), e).await
}

/// The terminal arm: dispatch, then answer. Settled, never dropped: an
/// unsettled reservation releases the key and lets a retry re-execute a side
/// effect (ADR-012 consequence 1).
pub(super) async fn dispatch(
    scope: Scope<'_>,
    envelope: &Envelope,
    stages: (&Preflight, &Propagation),
    mut admitted: Admitted<'_>,
) -> Rejection {
    // MIK-8078: a retry goes out through the sanitized arm, which redeems it
    // after the spend is admitted. For `tools/call` the two arms run the same
    // guards and the same dispatch; only `tools/list` differs, and it is never
    // a retry.
    if envelope.method == "tools/call" && stages.0.retry.is_retry() && admitted.sanitized.is_none()
    {
        admitted.sanitized = Some(envelope.params.clone().unwrap_or_default());
    }
    if let Some(sanitized_params) = admitted.sanitized.take() {
        return forward_sanitized(scope, envelope, stages, (admitted, sanitized_params)).await;
    }
    match forward_plain(scope, envelope, stages, &mut admitted).await {
        Err(refusal) => refusal,
        Ok(Ok(response)) => finish_response(scope, envelope, stages.0, (&mut admitted, response)),
        Ok(Err(e)) => answer_failure(admitted, e).await,
    }
}
