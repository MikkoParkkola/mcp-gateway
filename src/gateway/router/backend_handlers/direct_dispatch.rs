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
use super::super::direct_guards::{AdmittedNonce, DirectRouteGuards, refusal};
use super::super::helpers::{build_http_error_response, build_http_response};
use super::direct_caller::{Caller, Envelope, Rejection, Route};
use super::direct_failure::DirectFailure;
use super::direct_idempotency::idempotency_outcome;
use super::direct_preflight::{Preflight, Propagation};
use super::{BackendAuthContext, sign_and_record};
use crate::gateway::meta_mcp::invoke::dispatch_guards::{Admission, BackendCall};
use crate::gateway::meta_mcp::invoke::egress::Egressed;
use crate::gateway::meta_mcp::invoke::relay::GatewayStamps;
use crate::gateway::meta_mcp::refund_witness::{self as rw, RefundWitness};
use crate::protocol::meta::Era;
use crate::protocol::{JsonRpcResponse, RequestId};

mod forward;
use forward::{forward_plain, forward_sanitized};

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
    /// Stage 7b's execution lease (`direct_idempotency`), held through dispatch.
    pub(super) lease: Option<crate::gateway::meta_mcp::admission::SyncLease>,
    /// The signing nonce this call registered, if it registered one.
    pub(super) nonce: Option<AdmittedNonce>,
    /// The refund witness (MIK-8379): minted with the nonce only when nothing
    /// before it acted; dropped by a consume; spent at the send.
    pub(super) witness: Option<RefundWitness>,
    /// MIK-7642 PR.C: this call's explicit-cancel registration, held for the
    /// request's life so the caller's own cancel can find it.
    pub(super) cancel_entry: Option<crate::gateway::router::inflight_calls::Registered>,
    /// Its abort half, taken by the one dispatch this call makes.
    pub(super) cancel_on: Option<crate::gateway::router::inflight_calls::CancelOn>,
    /// The backend answered by asking: the lease is decided on the answer
    /// that leaves ([`finish_response`]), not on the backend's.
    pub(super) asked: bool,
}

/// A refusal before dispatch: give back the nonce this call admitted
/// (MIK-7698).
fn give_back_nonce(state: &AppState, admitted: &mut Admitted<'_>) {
    DirectRouteGuards::release_nonce(state, admitted.nonce.take(), admitted.witness.take());
}

/// The witness for a nonce admitted after propagation and the schema check:
/// only when neither may have acted, by `/mcp`'s classifiers (MIK-8379).
fn admission_witness(
    nonce: Option<&AdmittedNonce>,
    propagation: &Propagation,
    backend: &crate::backend::Backend,
) -> Option<RefundWitness> {
    nonce?;
    let credential = rw::dispatch_effect(
        propagation.identity_key.is_some() || propagation.attempted,
        propagation.managed.is_some(),
    );
    let filled = rw::schema_effect(backend.list_fills() != propagation.fills_before);
    let witness = RefundWitness::carry(Some(RefundWitness::at_capture()), credential);
    RefundWitness::carry(witness, filled)
}

/// The send is about to happen: the nonce stays spent whatever follows.
fn spend_witness(admitted: &mut Admitted<'_>) {
    if let Some(witness) = admitted.witness.take() {
        witness.spend();
    }
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
        let lent = propagation.lent();
        admitted.sanitized = super::apply_backend_tool_call_security(
            scope.state,
            scope.name,
            envelope.params.as_ref(),
            scope.id,
            &scope.route.backend,
            (
                (propagation.identity_key.as_deref(), &lent),
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

/// Admitted once, here: after every refusal above and the idempotency guard,
/// so a refused call consumes no nonce (MIK-7698), and before a cached result
/// is delivered, so it is signed against the replaying request's own nonce.
/// The refusals that can still follow (the spend, a continuation) give it back
/// ([`give_back_nonce`]).
fn admit_signing_nonce(
    scope: Scope<'_>,
    preflight: &Preflight,
) -> Result<Option<AdmittedNonce>, Rejection> {
    if !preflight.signs {
        return Ok(None);
    }
    let caller = scope.caller;
    DirectRouteGuards::admit_nonce(
        (scope.state, &caller.generation),
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
        generation: &caller.generation,
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
        cost_key: client.and_then(|c| c.api_key_identity()),
        trace_id: "",
        caller_key,
    };
    let auth = BackendAuthContext {
        generation: &caller.generation,
        client,
        oauth_agent_identity: caller.oauth_agent_identity.as_ref(),
        cert_identity: caller.cert_identity.as_ref(),
        #[cfg(feature = "firewall")]
        grant_subject: caller.grant_subject.as_ref(),
    };
    // Registered before the dispatch exists: a cancel that arrives first
    // aborts it before anything reaches the backend.
    let (cancel_entry, cancel_on) = serde_json::to_value(scope.id)
        .ok()
        .and_then(|id| {
            super::direct_caller::explicit_cancel_key(
                scope.name,
                scope.caller,
                scope.route.session_id,
                &id,
            )
        })
        .and_then(|key| scope.state.meta_mcp.inflight_calls().register(key))
        .unzip();
    let mut admitted = Admitted {
        failed,
        call,
        auth,
        sanitized: None,
        idem_reservation: None,
        lease: None,
        nonce: None,
        witness: None,
        cancel_entry,
        cancel_on,
        asked: false,
    };
    guard_and_sanitize(scope, envelope, propagation, &mut admitted).await?;
    // After authorize, the firewall and the caller's catalogue (MIK-8356 F3).
    if envelope.method == "tools/call"
        && let Err(e) =
            DirectRouteGuards::run(&state.meta_mcp, &admitted.call, preflight.signing_scope)
    {
        return Err(build_http_response(
            &Egressed::gateway_own(refusal(Some(id.clone()), &e)),
            StatusCode::OK,
        ));
    }
    let mut guarded = idempotency_outcome(scope, envelope, preflight, propagation)?;
    let (lease, replay) = super::direct_idempotency::execution_lease(
        scope,
        (envelope, preflight, propagation),
        &mut guarded,
    )?;
    admitted.lease = lease;
    admitted.nonce = admit_signing_nonce(scope, preflight)?;
    admitted.witness = admission_witness(admitted.nonce.as_ref(), propagation, &route.backend);
    super::direct_idempotency::deliver_replay(
        scope,
        (envelope, preflight, propagation),
        &mut admitted,
        (guarded, replay),
    )?;
    Ok(admitted)
}

/// What the caller receives from an answered plain dispatch: the id they
/// supplied, the list or call post-processing, the settled idempotency key,
/// the chain finish, and (for `tools/call`) the signature.
async fn finish_response(
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
    // The egress scan, every method and part, before the list stamps, client
    // accounting and the reservation settle: a replay serves what it left.
    // Redaction comes before the trust stamp: the firewall may remove a
    // `$defs` entry a surviving `$ref` points at.
    let target = screen_target(&admitted.call, method);
    super::super::direct_guards::scan_direct_egress(
        state,
        (
            &target,
            crate::gateway::meta_mcp::invoke::egress::ContentChecks::for_method(method),
        ),
        (client, admitted.auth.generation),
        &mut response,
    );
    if method == "tools/list" {
        if response.error.is_none() {
            super::record_client_success(state, client);
        }
        super::normalize_tools_list_response(&route.backend, &mut response);
        // List = invoke: only what this route's `tools/call` admits.
        let (oauth, cert) = (
            caller.oauth_agent_identity.as_ref(),
            caller.cert_identity.as_ref(),
        );
        super::direct_list::retain_invocable(
            (state, &caller.generation),
            client,
            oauth,
            cert,
            name,
            &mut response,
        );
    } else if method != "tools/call" {
        if !response.excludes_client_accounting() {
            super::record_client_success(state, client);
        }
    } else {
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
    // 7b on the same answer, unshaped and unsigned, as 7a stores it. An
    // asked call's lease stores nothing either way; it is held past the tail,
    // which can still refuse the question.
    let held = if admitted.asked {
        admitted.lease.take()
    } else {
        if let Some(lease) = admitted.lease.take() {
            lease.complete_delivery(&response, None);
        }
        None
    };
    if method == "tools/list"
        && envelope.era != Era::Modern
        && let Some(result) = response.result.as_mut().and_then(Value::as_object_mut)
    {
        // The backend hint carried through the rebuild is for the modern
        // shaper alone; a legacy listing stays byte-identical.
        result.remove("ttlMs");
    }
    let auth = (admitted.auth, admitted.call.tool);
    let response = finish_tail(scope, envelope, preflight, auth, response);
    if let Some(lease) = held {
        // Only a question the client can continue keeps the call counted, so a
        // fresh same-key call is answered "unavailable", as on `/mcp`. Any
        // refusal made of it (a seal, a gate, the tail) frees the key.
        if !carries_continuation(&response) {
            lease.withdraw_dispatch();
        }
        lease.complete_delivery(&response, None);
    }
    build_http_response(&Egressed::of(response), StatusCode::OK)
}

/// Whether `response` hands the client a question it can continue: no error,
/// a round the protocol reads as one, and the gateway's sealed state.
fn carries_continuation(response: &JsonRpcResponse) -> bool {
    response.error.is_none()
        && response.result.as_ref().is_some_and(|result| {
            result.get("requestState").is_some_and(Value::is_string)
                && crate::protocol::mrtr::InputRequired::from_result(result).is_some()
        })
}

/// The tail every success shares, a cached replay included: the 2026-07-28
/// shape for a modern request, the clamp and chain finish, then (for
/// `tools/call`) the signature, or the catalogue receipt. Shaping comes before
/// the finish and the signature, as on `/mcp`, so both cover what is sent; the
/// stamps tell the receipt which members the gateway wrote. Returns the
/// answer as it will leave, so a caller can still act on what it carries.
///
/// MIK-8025/MIK-8011 (secE) wrap this tail and the fresh steps in a
/// `gateway_writes` scope.
pub(super) fn finish_tail(
    scope: Scope<'_>,
    envelope: &Envelope,
    preflight: &Preflight,
    (auth, tool): (BackendAuthContext<'_>, &str),
    mut response: JsonRpcResponse,
) -> JsonRpcResponse {
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
        if let Some(result) = response.result.as_mut() {
            state.meta_mcp.seal_public_provenance(result);
        }
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
    response
}

/// MIK-8078 (MRTR.1, MRTR.3-6): a retry presents the continuation this route
/// sealed, and the backend gets its own state back in `outbound` in its place,
/// as on the meta route. Refused before dispatch, so the key is released: the
/// backend has not acted.
async fn redeem_retry(
    (scope, propagation): (Scope<'_>, &Propagation),
    envelope: &Envelope,
    admitted: &mut Admitted<'_>,
    outbound: &mut Value,
) -> Result<(), Rejection> {
    let who = (
        scope.caller.verified_identity.as_ref(),
        (
            propagation.identity_key.as_deref(),
            scope.caller.grant_subject.as_ref(),
        ),
        scope.caller.client.as_ref(),
    );
    let instance = Some(scope.route.backend.instance());
    let sent = (scope.name, instance, envelope.params.as_ref());
    let redeemed = scope
        .state
        .meta_mcp
        .redeem_direct_retry(who, sent, outbound)
        .await;
    redeemed.map_err(|e| {
        if let Some(reservation) = admitted.idem_reservation.as_mut() {
            reservation.release();
        }
        give_back_nonce(scope.state, admitted);
        build_http_response(
            &Egressed::gateway_own(refusal(Some(scope.id.clone()), &e)),
            StatusCode::OK,
        )
    })
}

/// A backend that stopped to ask: its idempotency key is released rather than
/// settled, as on the meta route, while the call's execution lease stays
/// counted until [`finish_response`] reads the answer that leaves. Taken out
/// here, before the guards, because a seal they refuse returns before
/// settlement, and an armed reservation dropped unsettled records an uncertain
/// outcome; [`settle_parked`] decides once they ran.
fn park_if_interim(
    forward: &crate::Result<JsonRpcResponse>,
    admitted: &mut Admitted<'_>,
) -> Option<crate::idempotency::IdempotencyReservation> {
    // A response that also carries an `error` leaves the outcome uncertain:
    // its key is settled with that error, never parked for release.
    let asked = forward
        .as_ref()
        .ok()
        .filter(|response| response.error.is_none())
        .and_then(|response| response.result.as_ref())
        .is_some_and(crate::protocol::mrtr::InputRequired::claims_input_required);
    if asked {
        admitted.asked = true;
        admitted.idem_reservation.take()
    } else {
        None
    }
}

/// The key [`park_if_interim`] took out: released once the guards read the
/// answer, put back to be settled when they refused it unread. A failed chain
/// receipt proves nothing about what the backend did, so a retry must not run
/// it again.
fn settle_parked(
    parked: Option<crate::idempotency::IdempotencyReservation>,
    guarded: &crate::Result<JsonRpcResponse>,
    admitted: &mut Admitted<'_>,
) {
    match (parked, guarded) {
        (Some(reservation), Err(_)) => {
            admitted.idem_reservation = Some(reservation);
        }
        (Some(mut reservation), Ok(_)) => reservation.release(),
        (None, _) => {}
    }
}

/// The policy target an answer of `method` is screened under (MIK-8139):
/// the named tool for `tools/call`, otherwise the method itself, as the
/// result scans target it.
pub(super) fn screen_target<'a>(call: &BackendCall<'a>, method: &'a str) -> BackendCall<'a> {
    BackendCall {
        server: call.server,
        tool: if method == "tools/call" {
            call.tool
        } else {
            method
        },
        session_id: call.session_id,
        api_key_name: call.api_key_name,
        cost_key: call.cost_key,
        trace_id: call.trace_id,
        caller_key: call.caller_key,
    }
}

/// Answer a dispatch that failed, settling the reservation (`answer` consumes
/// the failure context, so this takes the admission by value).
async fn answer_failure(mut admitted: Admitted<'_>, e: crate::Error, method: &str) -> Rejection {
    // Nothing reached the backend: no send of this delivery counted, and the
    // error is one the gateway raised before the backend or a refusal the
    // send itself recorded. The lease is withdrawn, so the key is released.
    // The nonce is offered back only through its refund witness, which this
    // site never holds: it stays spent for every pre-dispatch class, as on
    // `/mcp`, where a narrow pre-start refund was ruled out.
    if crate::gateway::delivery_facts::unsent(&e) {
        if crate::gateway::delivery_facts::refused_before_send_seen() {
            crate::gateway::delivery_facts::raise(
                crate::gateway::delivery_facts::ResponseEffect::Refused,
            );
        }
        give_back_nonce(admitted.failed.state, &mut admitted);
        super::direct_idempotency::withdraw(admitted.lease.as_ref());
    }
    // MIK-7642 PR.C: the caller's own cancel is its choice, not a failure: no
    // breaker strike, and answered 200 as on `/mcp`. The key still settles as
    // dispatched (ADR-012 consequence 1), so a retry never re-runs the call.
    let entry = admitted.cancel_entry.as_ref();
    if crate::gateway::router::inflight_calls::cancelled_by_caller(entry, Some(&e)) {
        let response = JsonRpcResponse::error(
            Some(admitted.failed.id.clone()),
            crate::gateway::router::inflight_calls::CLIENT_CANCELLED_CODE,
            crate::gateway::router::inflight_calls::CLIENT_CANCELLED_MESSAGE,
        );
        let settle = (admitted.idem_reservation.as_mut(), admitted.lease.take());
        super::settle_direct_failure(settle, &e, &response);
        return build_http_response(&Egressed::gateway_own(response), StatusCode::OK);
    }
    let Admitted {
        failed,
        call,
        mut idem_reservation,
        lease,
        ..
    } = admitted;
    failed
        .answer(
            (idem_reservation.as_mut(), lease),
            e,
            &screen_target(&call, method),
        )
        .await
}

/// The terminal arm, boxed: its future is too large to inline into the
/// orchestrator that awaits it, so the orchestrator still ends on a plain
/// `dispatch(..).await`.
pub(super) fn dispatch<'a>(
    scope: Scope<'a>,
    envelope: &'a Envelope,
    stages: (&'a Preflight, &'a Propagation),
    admitted: Admitted<'a>,
) -> std::pin::Pin<Box<impl std::future::Future<Output = Rejection> + 'a>> {
    Box::pin(dispatch_inline(scope, envelope, stages, admitted))
}

/// The terminal arm: dispatch, then answer. Settled, never dropped: an
/// unsettled reservation releases the key and lets a retry re-execute a side
/// effect (ADR-012 consequence 1).
async fn dispatch_inline(
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
    // Boxed: with the live key read and the notification strip, this arm's
    // future crosses clippy's 16 KiB `large_futures` limit.
    match Box::pin(forward_plain(scope, envelope, stages, &mut admitted)).await {
        Err(refusal) => refusal,
        Ok(Ok(response)) => {
            finish_response(scope, envelope, stages.0, (&mut admitted, response)).await
        }
        Ok(Err(e)) => answer_failure(admitted, e, envelope.method.as_str()).await,
    }
}
