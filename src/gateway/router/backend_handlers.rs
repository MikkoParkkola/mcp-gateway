// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Backend and cost API request handlers.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde_json::Value;

use super::AppState;
use super::direct_guards::refusal;
use super::helpers::{RpcHttp, bodiless_accepted, build_http_error_response};
use crate::gateway::auth::AuthenticatedClient;
use crate::gateway::meta_mcp::invoke::relay::GatewayStamps;
use crate::gateway::oauth::OAuthAgentIdentity;
use crate::mtls::CertIdentity;
use crate::protocol::{JsonRpcResponse, RequestId};

type BackendRejection = RpcHttp;
type BackendSecurityResult = Result<Option<Value>, BackendRejection>;

/// Forwarded passthrough headers paired with the caller's stable upstream-session
/// bucket key (MIK-6785): `Some(sha256_hex(credential))` when a credential is
/// forwarded, `None` on the no-credential path. See [`resolve_passthrough_headers`].
type PassthroughResolution = (Vec<(String, String)>, Option<String>);

#[derive(Clone, Copy)]
struct BackendAuthContext<'a> {
    /// The call's pinned generation (ADR-023).
    generation: &'a crate::config_reload::Generation,
    client: Option<&'a AuthenticatedClient>,
    oauth_agent_identity: Option<&'a OAuthAgentIdentity>,
    cert_identity: Option<&'a CertIdentity>,
    /// The caller as a grant subject, resolved for this request: the only
    /// carrier of an OIDC or trusted-header subject on this route.
    #[cfg(feature = "firewall")]
    grant_subject: Option<&'a crate::identity_grants::GrantSubject>,
}

#[cfg(feature = "firewall")]
mod relay;
#[cfg(feature = "firewall")]
use relay::{catalogue_refusal, stage_direct_catalogue, stage_direct_delivery};

/// Stable, collision-safe upstream-session bucket key for a passthrough caller
/// (MIK-6785). On the passthrough route the forwarded backend credential is the
/// only value that distinguishes one caller from another (there is usually no
/// gateway-verified identity), so the caller's `MCP-Session-Id` bucket is keyed
/// by the SHA-256 hex digest of that credential.
///
/// Privacy is load-bearing: the raw credential is hashed HERE, at the single
/// point it is read from the inbound header, and the digest — never the token —
/// becomes the in-memory `HttpTransport::sessions` map key. SHA-256 is one-way,
/// so a leaked bucket key cannot recover the credential, and the raw token is
/// never logged or stored anywhere else.
///
/// Correctness: distinct credentials produce distinct 64-char hex digests, hence
/// distinct session buckets (isolation); the same credential always produces the
/// same digest, hence a reused bucket (session continuity). A 64-char lowercase
/// hex digest can never collide with the minting path's `idp:`-prefixed bindings
/// nor with the shared default (`""`) bucket.
fn passthrough_identity_key(credential: &str) -> String {
    crate::hashing::sha256_hex(credential.as_bytes())
}

/// The slot binding of a passthrough credential digest, charged to the
/// caller's principal so one caller cannot hold more than its share of the
/// backend's slots however many header values it sends (#2300). The principal
/// is the verified identity, else `proven` (the API key, agent token or client
/// certificate, as `refusal_principal` names it), else the one anonymous
/// principal every unauthenticated caller shares.
fn charged_binding(
    state: &AppState,
    backend: &crate::backend::Backend,
    caller: crate::identity_propagation::CallerProof<'_>,
    proven: Option<&str>,
    digest: Option<String>,
) -> Option<String> {
    let principal = match (caller.verified(), proven) {
        (None, Some(proven)) => format!("proven:{proven}"),
        _ => state.meta_mcp.audit_subject_for(backend, caller),
    };
    digest.map(|digest| crate::backend::passthrough_binding(&principal, &digest))
}

/// The inbound header a capable client attaches its backend credential in
/// (advertised via RFC 9728 protected-resource metadata). Distinct
/// from `Authorization` so the gateway-auth token is never forwarded.
const PASSTHROUGH_HEADER: &str = "x-mcp-passthrough-authorization";

/// Resolve passthrough headers for the direct backend route (ADR-008 rung 2,
/// MIK-6746). Reads the caller's own backend credential from a fixed,
/// gateway-specific inbound header and forwards it to the backend under
/// `Authorization`. The gateway mints and stores NOTHING (INV-4). A dedicated
/// header (never the gateway-auth `Authorization`) means a multi-user gateway
/// can never forward its own inbound credential to a backend. Fail-closed: a
/// `required` backend with no caller credential returns `Err` (mapped to 403 by
/// the caller); a non-required backend with none returns an empty vec (static
/// path, after which the INV-2 guard decides whether a shared token may serve).
///
/// Returns `(headers, identity_key)`. `identity_key` (MIK-6785) is the caller's
/// stable upstream-session bucket key — `Some(sha256_hex(credential))` when a
/// credential is forwarded, so each distinct passthrough caller gets its own
/// `MCP-Session-Id` bucket and a stateful upstream cannot serve one caller's
/// session-bound data to another; `None` on the no-credential path (shared
/// default bucket, behavior unchanged). The credential is hashed at this single
/// read point (see [`passthrough_identity_key`]) so the raw token is never
/// re-extracted from the header vec downstream.
///
/// Also fails closed (MIK-6710) BEFORE reading the inbound header when
/// `transport_carries_headers` is `false` for a `required` backend — a stdio
/// or websocket backend would otherwise accept the caller's credential here
/// and then silently drop it in `request_with_headers`, running
/// unauthenticated while the audit trail records a resolved passthrough.
fn resolve_passthrough_headers(
    cfg: &crate::identity_propagation::IdentityPropagationConfig,
    inbound: &axum::http::HeaderMap,
    transport_carries_headers: bool,
) -> Result<PassthroughResolution, String> {
    crate::identity_propagation::ensure_transport_carries_identity_headers(
        cfg.required,
        transport_carries_headers,
    )?;
    let missing = || {
        if cfg.required {
            Err(
                "identity propagation required for this backend but the caller supplied no \
                 passthrough credential (ADR-008 D.3, fail-closed)"
                    .to_string(),
            )
        } else {
            // No credential on a non-required backend: static path, and no
            // per-caller session bucket — the shared default bucket is used,
            // exactly as before MIK-6785.
            Ok((Vec::new(), None))
        }
    };
    match inbound
        .get(PASSTHROUGH_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        Some(v) => Ok((
            vec![("Authorization".to_string(), v.to_string())],
            // Hash the credential at its single read point (MIK-6785): the raw
            // token stays in the forwarded header vec only; the digest is the
            // caller's per-identity upstream session bucket key.
            Some(passthrough_identity_key(v)),
        )),
        None => missing(),
    }
}

// The audit subject is the resolver's (`MetaMcp::audit_subject_for`); the
// identity-only form stays in reach of this module's tests.
#[cfg(test)]
use crate::identity_propagation::audit_subject;

// One writer for identity-propagation audit on both routes (the direct
// route used to carry a hand copy of it).
use crate::identity_propagation::audit_identity_propagation;

/// Whether a direct-route request reaches task state.
///
/// Every `tasks/*` method, in any letter case, because a backend that matches
/// names loosely acts on a case variant as the real method; plus
/// `subscriptions/listen` naming `taskIds`, at the params root or under
/// `notifications`. KEEP IN STEP with
/// `reaches_tasks_extension` in `router/handlers.rs`: a task-reaching method
/// added there and not here is forwarded here without an owner check.
/// The one intended difference: `tools/call` carrying `task` still forwards;
/// task creation on this route is separate work (LIFECYCLE.1).
fn is_task_method(method: &str, params: Option<&Value>) -> bool {
    method
        .get(..6)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("tasks/"))
        || (method.eq_ignore_ascii_case("subscriptions/listen")
            && params.is_some_and(crate::protocol::subscriptions::names_task_ids))
}

/// Backend handler (POST /mcp/{name})
pub(super) async fn backend_handler(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    request: axum::http::Request<axum::body::Body>,
) -> crate::gateway::outbound::OutboundReply {
    // Track in-flight request for graceful drain
    let _inflight_permit = state.inflight.acquire().await;

    // D1-f: while the audit log is down this route must not serve, or it is a
    // second, unaudited route. Checked before the body is read, so no D2 slot
    // exists yet and no record is attempted for this refusal.
    if let Some(log) = &state.transparency_log
        && log.admit().await.is_err()
    {
        let error = crate::Error::AuditUnavailable;
        return crate::gateway::outbound::gateway_reply(bodiless_accepted(
            build_http_error_response(
                None,
                error.to_rpc_code(),
                error.to_string(),
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ));
    }

    // The request's scope for what intake judges (MIK-8154 F2: the exempt
    // instance the send compares), boxed so the scope wraps a pointer.
    // The minted-receipt scope rides outside the memo.
    crate::gateway::meta_mcp::invoke::with_minted_receipts(Box::pin(
        // The caller's hiding judgment, filled once the caller is resolved.
        crate::gateway::meta_mcp::hiding::with_caller_slot(
            crate::gateway::meta_mcp::visible::memo::with_visibility_memo(Box::pin(
                direct_audit::audited_call(Arc::clone(&state), name, request),
            )),
        ),
    ))
    .await
}

/// The direct backend route, as an ordered sequence of stages. Each stage
/// returns the route's HTTP answer as its `Err`, so an early return inside a
/// stage is an early return here, at the same point in the same order:
/// refusal precedence is security-relevant (the keyed-principal intake before
/// the backend lookup and every backend touch, so one answer for every name,
/// MIK-8382; scope before backend lookup, so no 404 oracle; attestation before
/// the propagation mint; the tool-call gate before the idempotency cache; the
/// signing nonce after every refusal).
async fn backend_handler_inner(
    state: Arc<AppState>,
    name: String,
    request: axum::http::Request<axum::body::Body>,
    call: &mut Option<direct_audit::DirectCall>,
    reads: &mut direct_audit::DirectReads,
) -> RpcHttp {
    let shared = Arc::clone(&state);
    let state = &*state;
    let (caller, key, request) = match direct_caller::resolve_caller(state, request).await {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };
    // The owned session first: hiding is judged under the profile the call
    // is routed under.
    let session = direct_caller::owned_session(state, &caller, key);
    // Before the absence stage and the backend lookup read the scoped view.
    direct_caller::record_hiding_caller(shared, &caller, session);
    let mut envelope =
        match direct_caller::read_envelope(state, &name, request, &caller, (call, reads)).await {
            Ok(envelope) => envelope,
            Err(response) => return response,
        };
    let route = match direct_caller::route(state, &name, &caller, session, &envelope) {
        Ok(route) => route,
        Err(response) => return response,
    };
    // MIK-7996: the call's cost is recorded under this session after the
    // backend answers; held until this handler returns.
    let _session = state.meta_mcp.hold_session(route.session_id);
    if envelope.method.starts_with("notifications/") {
        return direct_caller::forward_notification(state, &name, &caller, &route, envelope).await;
    }
    // For requests, id is guaranteed to exist
    let id = envelope
        .id
        .take()
        .expect("id should exist for non-notification requests");
    // After authentication and the scope route, before any
    // propagation or dispatch, so the backend never sees it.
    if envelope.method == "events/lease" {
        return direct_caller::events_lease(state, &name, &caller, envelope.params.as_ref(), id)
            .await;
    }
    let preflight = match direct_preflight::preflight(state, &caller, &mut envelope, &route, &id) {
        Ok(preflight) => preflight,
        Err(response) => return response,
    };
    let scope = direct_dispatch::Scope {
        state,
        name: &name,
        caller: &caller,
        route: &route,
        id: &id,
    };
    // Authorize, the firewall and the withheld gate need no credential:
    // a call they refuse or answer resolves none (MIK-8361 ORACLE.4).
    match direct_gate::guard_before_credential(scope, &envelope).await {
        Ok(direct_gate::Guarded::Clear) => {}
        Ok(direct_gate::Guarded::Withheld(absent)) => return absent,
        // Ruling B (MIK-8361 A5) on the direct route: a caller with no view of
        // this per-user backend cannot tell names apart, so a withheld name
        // meets the credential step a missing name meets. Its refusal (the
        // account's connect answer) is the answer; if a view appeared
        // meanwhile, the withheld name keeps its absent answer. It is never
        // dispatched either way.
        Ok(direct_gate::Guarded::WithheldNoView(absent)) => {
            return match direct_preflight::propagate_identity(
                state, &name, &caller, &route, &preflight, &id,
            )
            .await
            {
                Err(offer) => offer,
                Ok(_) => absent,
            };
        }
        Err(response) => return response,
    }
    let propagation =
        match direct_preflight::propagate_identity(state, &name, &caller, &route, &preflight, &id)
            .await
        {
            Ok(propagation) => propagation,
            Err(response) => return response,
        };
    let admitted = match direct_dispatch::admit(scope, &envelope, &preflight, &propagation).await {
        Ok(admitted) => admitted,
        Err(response) => return response,
    };
    // What the called tool declared, from the slot this dispatch runs under.
    direct_idempotency::note_caller_slot_effect(scope, &propagation, admitted.call.tool);
    direct_dispatch::dispatch(scope, &envelope, (&preflight, &propagation), admitted).await
}

/// Sign when `nonce` is `Some`, then stage what is delivered: a refusal stages nothing.
#[cfg_attr(not(feature = "firewall"), allow(unused_variables))]
fn sign_and_record(
    state: &AppState,
    auth: BackendAuthContext<'_>,
    (server, tool): (&str, &str),
    response: &mut JsonRpcResponse,
    (nonce, stamps): (Option<&Option<String>>, GatewayStamps),
) {
    if let Some(nonce) = nonce.map(Option::as_deref) {
        state.meta_mcp.sign_direct_delivery(response, nonce);
    }
    #[cfg(feature = "firewall")]
    stage_direct_delivery(
        state,
        auth,
        (server, tool),
        response.result.as_ref(),
        stamps,
    );
}

/// #1962: run a backend dispatch with the reservation armed, so a caller
/// that disconnects mid-call leaves the key settled, not free.
async fn dispatch_armed<T>(
    reservation: Option<&mut crate::idempotency::IdempotencyReservation>,
    dispatch: impl std::future::Future<Output = T>,
) -> T {
    crate::gateway::meta_mcp::MetaMcp::arm_direct_dispatch(reservation);
    dispatch.await
}

/// Store the direct route's result under the client's idempotency key so a
/// re-issue replays it instead of invoking the backend again. Runs after the
/// scan and provenance stamp, before any chain link. Both terminal outcomes
/// settle: a dispatched JSON-RPC error may follow a committed side effect, so
/// the retry is served the same error (ADR-012 consequence 1).
fn settle_direct_idempotency(
    reservation: Option<&mut crate::idempotency::IdempotencyReservation>,
    response: &JsonRpcResponse,
) {
    // MIK-7636: a failure keeps the uninspected note across its replay.
    use crate::gateway::meta_mcp::invoke::audit::stored_failure;
    let Some(reservation) = reservation else {
        return;
    };
    if response.wire_meta.delivery_refusal {
        reservation.fail(&stored_failure(
            crate::gateway::meta_mcp::invoke::dispatch_guards::firewall_refusal_body(),
        ));
        return;
    }
    if let Some(error) = response.error.as_ref() {
        if let Ok(error) = serde_json::to_value(error) {
            reservation.fail(&stored_failure(error));
        }
        return;
    }
    if let Some(result) = response.result.as_ref() {
        // MIN.2 row 14: the direct route is one dispatch per read scope, so
        // all the scope noted is this call's reading.
        let reading =
            crate::gateway::meta_mcp::invoke::cache_reads::reading(std::collections::BTreeSet::new);
        // What the gateway wrote so far (provenance, cost warnings) is
        // stored with the answer, so a replay restores it (MIK-8025).
        reservation.complete_read(
            result,
            (reading, crate::gateway::gateway_writes::recorded()),
        );
    }
}

/// Settle a failed direct-route call, releasing the key when the gateway can
/// prove the request never reached the backend.
///
/// ADR-012 consequence 1 caches a dispatched failure so a retry cannot duplicate
/// a side effect that may already have committed. A refusal the gateway raised
/// itself — an open circuit, an unknown backend or tool — carries no such
/// ambiguity: nothing ran, so caching it for the entry's whole lifetime would
/// deny the caller a retry of work that provably never happened. See
/// [`crate::Error::is_pre_dispatch`] for why that allowlist stays tight, and
/// `delivery_facts::unsent` for the send count that must also be empty. A
/// lost round stores the uncertainty notice under the first caller's code
/// (MIK-7979), the same sentence the meta route stores.
fn settle_direct_failure(
    (mut reservation, lease): (
        Option<&mut crate::idempotency::IdempotencyReservation>,
        Option<crate::gateway::meta_mcp::admission::SyncLease>,
    ),
    error: &crate::Error,
    response: &JsonRpcResponse,
) {
    // The lease (7b) follows 7a: a pre-dispatch failure was withdrawn and
    // releases on drop; a lost round stays uncertain, as 7a's notice does;
    // otherwise it settles on the answer 7a stores.
    if crate::gateway::delivery_facts::unsent(error) {
        if let Some(reservation) = reservation {
            reservation.release();
        }
        return;
    }
    if let Some(sent) = response.error.as_ref() {
        let route = crate::gateway::meta_mcp::invoke::LostRoundRoute::Direct { code: sent.code };
        if crate::gateway::meta_mcp::invoke::settle_lost_round(
            error,
            reservation.as_deref_mut(),
            route,
        ) {
            return;
        }
    }
    settle_direct_idempotency(reservation, response);
    if let Some(lease) = lease {
        lease.complete_delivery(response, None);
    }
}

/// Rebuild the JSON-RPC error response stored under an idempotency key.
///
/// `data` is lifted back out of the stored error object because a backend puts
/// the machine-readable half of its refusal there — a retry-after hint, a
/// validation path. [`crate::idempotency::cached_error_parts`] returns only the
/// code and message, so a replay that used it alone answered the retry with a
/// strictly poorer error than the first caller received, which defeats the
/// point of replaying it at all.
fn cached_error_response(id: Option<RequestId>, error: &Value) -> JsonRpcResponse {
    if crate::gateway::meta_mcp::invoke::dispatch_guards::is_firewall_refusal(error) {
        return refusal(id, &crate::Error::ResponseFirewallRefused);
    }
    let (code, message) = crate::idempotency::cached_error_parts(error);
    match error.get("data") {
        Some(data) => JsonRpcResponse::error_with_data(id, code, message, data.clone()),
        None => JsonRpcResponse::error(id, code, message),
    }
}

/// Stamp a signed runtime-provenance receipt onto a direct-route `tools/call`
/// result (MIK-6905 rung 3). The `/mcp/{name}` passthrough bypasses the meta
/// chokepoint, so without this a client could route around provenance simply
/// by choosing the direct URL. No-op unless the tool name is present (a
/// `tools/call`) and stamping is enabled on the shared `MetaMcp`.
fn stamp_direct_provenance(
    state: &AppState,
    backend_name: &str,
    params: Option<&Value>,
    client: Option<&AuthenticatedClient>,
    response: &mut JsonRpcResponse,
) {
    let tool = params
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if tool.is_empty() {
        return;
    }
    let Some(result) = response.result.take() else {
        return;
    };
    let api_key_name = client.map(|c| c.name.as_str());
    response.result = Some(state.meta_mcp.stamp_direct_result(
        result,
        backend_name,
        tool,
        api_key_name,
    ));
}

mod client_outcome;
mod costs;
mod direct_audit;
mod direct_caller;
mod direct_dispatch;
mod direct_failure;
mod direct_gate;
mod direct_idempotency;
#[cfg(test)]
pub(super) use direct_idempotency::seams as direct_lease_seams;
mod direct_list;
mod direct_permit;
#[cfg(test)]
pub(super) use direct_permit::seams as direct_permit_seams;
mod direct_preflight;
mod direct_security;
#[cfg(feature = "firewall")]
use direct_security::backend_security_error_with_status;
use direct_security::{
    apply_backend_tool_call_security, direct_route_attestation_scope, guard_tool_call,
    take_attestation_token,
};
mod direct_send;
mod key_check;
mod notification_key;
pub(super) use costs::costs_handler;
use direct_failure::DirectFailure;
use direct_list::normalize_tools_list_response;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod passthrough_slot_cap_tests;

#[cfg(test)]
mod idempotency_settlement_tests;

#[cfg(test)]
mod direct_route_scope_tests;

#[cfg(test)]
mod direct_admission_edge_tests;

#[cfg(test)]
mod direct_captured_backend_tests;

#[cfg(test)]
mod direct_audit_subject_tests;

#[cfg(test)]
mod direct_unpinned_tests;
