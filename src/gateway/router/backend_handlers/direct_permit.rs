// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The direct route's permit to send (MIK-8351, MIK-8154 SAN.3): the dispatch
//! chokepoint judged on the bytes a `tools/call` is about to send, the plain
//! arm's choice of door, and the give-back when the chokepoint refuses.

use crate::error::rpc_codes::METHOD_NOT_FOUND;
use axum::http::StatusCode;
use serde_json::Value;

use super::super::AppState;
use super::super::direct_guards::{DirectRouteGuards, refusal};
use super::super::helpers::{build_http_error_response, build_http_response};
use super::direct_caller::{Envelope, Rejection};
use super::direct_dispatch::{Admitted, Scope};
use super::direct_preflight::Propagation;
use crate::gateway::meta_mcp::invoke::dispatch_guards::Admission;
use crate::gateway::meta_mcp::invoke::egress::Egressed;
use crate::protocol::{JsonRpcResponse, RequestId};

/// MIK-8351 (MIK-8154 SAN.3): pass the dispatch chokepoint on the bytes this
/// `tools/call` is about to send, its redeemed answers included, as every meta
/// send does. The caller is judged as the route's own entry check judges it.
pub(super) fn mint_permit(
    scope: Scope<'_>,
    params: Option<&Value>,
) -> crate::Result<crate::gateway::meta_mcp::invoke::DirectPermit> {
    #[cfg(test)]
    if seams::take_refusal() {
        return Err(crate::Error::Forbidden {
            code: -32003,
            status: 403,
            message: seams::REFUSED.to_string(),
        });
    }
    let caller = scope.caller;
    let client = caller.client.as_ref();
    let authorizer = super::super::authorization::RouterAuthorizer {
        state: scope.state,
        generation: &caller.generation,
        client,
        oauth_agent_identity: caller.oauth_agent_identity.as_ref(),
        cert_identity: caller.cert_identity.as_ref(),
        principal: caller.proven.clone(),
    };
    let invoke_scope = crate::gateway::meta_mcp::InvokeScope {
        authorizer: &authorizer,
        is_admin: client.is_some_and(|c| c.admin),
        api_key_name: client.map(|c| c.name.as_str()),
        grant_key: client.and_then(crate::gateway::auth::AuthenticatedClient::api_key_identity),
        agent_id: caller
            .agent_identity
            .as_ref()
            .and_then(crate::security::AgentIdentity::proven_agent_id),
        grant_subject: caller.grant_subject.as_ref(),
        caller: caller.proof(),
    };
    let empty = Value::Object(serde_json::Map::new());
    let arguments = params.and_then(|p| p.get("arguments")).unwrap_or(&empty);
    let answers = params.and_then(|p| p.get("inputResponses"));
    let tool = params
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let session = format!("direct:{}", scope.name);
    scope.state.meta_mcp.direct_send_permit(
        invoke_scope,
        Some(&session),
        (scope.name, tool),
        &crate::gateway::meta_mcp::invoke::Outbound {
            arguments,
            answers,
            backend: Some(&*scope.route.backend),
        },
    )
}

/// MIK-8351: a send the chokepoint refused gives back everything it took:
/// the nonce, the idempotency key (released now, not left to the unarmed
/// drop), and the spend admission and continuation slot, which the caller
/// drops with the refusal.
fn give_back_refused(state: &AppState, admitted: &mut Admitted<'_>) {
    DirectRouteGuards::release_nonce(state, admitted.nonce.take(), admitted.witness.take());
    if let Some(mut reservation) = admitted.idem_reservation.take() {
        // Today the reservation is unarmed here (it is armed only in
        // `dispatch_armed`, after the permit), so its drop would release the
        // key too and mutant m6b (no explicit release) is equivalent. If later
        // code arms it earlier, that stops holding and this release carries it.
        reservation.release();
    }
}

/// The answer to a send the chokepoint refused, on either arm: give back what
/// the call took, drop the spend admission when the caller hands it over, then
/// the refusal. The admission must be dropped before the response is built:
/// concurrent budget checks count outstanding holds.
pub(super) fn refused_send(
    state: &AppState,
    (admitted, admission): (&mut Admitted<'_>, Option<Admission>),
    id: &RequestId,
    e: &crate::Error,
) -> Rejection {
    give_back_refused(state, admitted);
    // Not dispatched: the spend reservation is given back on drop.
    drop(admission);
    build_http_response(
        &Egressed::gateway_own(refusal(Some(id.clone()), e)),
        StatusCode::OK,
    )
}

/// One plain-arm send, not yet awaited.
pub(super) type PlainSend<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = crate::Result<JsonRpcResponse>> + Send + 'a>,
>;

/// The plain arm's send (MIK-8351): a `tools/call` takes the chokepoint's
/// permit on its params; every other method the permit-free door, which cannot
/// name `tools/call`. A letter-case variant of `tools/call` gets neither: it
/// is not served (-32601). A refusal gives back what the call took.
pub(super) fn plain_send<'a>(
    scope: Scope<'a>,
    envelope: &'a Envelope,
    propagation: &'a Propagation,
    admitted: &mut Admitted<'_>,
) -> Result<PlainSend<'a>, Rejection> {
    let (method, id, backend) = (envelope.method.as_str(), scope.id, &scope.route.backend);
    let headers = (propagation.lent(), propagation.identity_key.as_deref());
    let params = envelope.params.clone();
    if method == "tools/call" {
        return match mint_permit(scope, envelope.params.as_ref()) {
            Ok(permit) => Ok(Box::pin(super::direct_send::dispatch_tool_call(
                permit, backend, id, params, headers,
            ))),
            // Fail-closed: on today's code the entry check already judged
            // exactly what the chokepoint judges here (a first call to a
            // passthrough backend; retries take the sanitized arm), so this
            // refusal cannot happen yet. It stays so that if the two ever
            // diverge, the refusal still gives back what the call took.
            // The caller (`forward_plain`) owns the admission and drops it after.
            Err(e) => Err(refused_send(scope.state, (admitted, None), id, &e)),
        };
    }
    let Some(other) = super::direct_send::NonToolMethod::new(method) else {
        return Err(build_http_error_response(
            Some(id.clone()),
            METHOD_NOT_FOUND,
            format!("{method} is not served on /mcp/{{name}}; use tools/call"),
            StatusCode::OK,
        ));
    };
    Ok(Box::pin(super::direct_send::dispatch_non_call(
        other, backend, id, params, headers,
    )))
}

/// MIK-8379: a chokepoint refusal on demand, so a row can reach it with
/// nothing acted before it (a warm schema, no mint, no consume). Test only.
#[cfg(test)]
pub(crate) mod seams {
    /// The message the forced refusal carries.
    pub(crate) const REFUSED: &str = "permit refused by the test seam";

    thread_local! {
        static REFUSE_NEXT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }

    /// The next permit minted on this thread is refused. One call only.
    pub(crate) fn refuse_next_permit() {
        REFUSE_NEXT.with(|refuse| refuse.set(true));
    }

    pub(super) fn take_refusal() -> bool {
        REFUSE_NEXT.with(std::cell::Cell::take)
    }
}
