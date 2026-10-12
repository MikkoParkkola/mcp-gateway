// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The legacy client's in-band ask (MIK-7212.WIRE): a pending question is
//! carried over the input bridge instead of handed back as a continuation.

use std::sync::Arc;

use serde_json::Value;
use tracing::warn;

use super::{
    BridgeDispatcher, CallerCredential, GuardedValue, INVOKE_TARGET, dispatch_error_result,
    run_input_bridge, uncertain_side_effect, undeclared_gate, withheld_side_effect,
};
use crate::gateway::input_bridge::BridgeError;
use crate::gateway::meta_mcp::MetaMcp;
use crate::idempotency::IdempotencyReservation;
use crate::identity_grants::GrantSubject;
use crate::identity_propagation::CallerProof;
use crate::protocol::mrtr::InputRequired;
use crate::{Error, Result};

impl MetaMcp {
    /// `Some` is the answer the call returns; `None` carries on with `result`
    /// and `interim` as the exchange left them.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub(super) async fn bridge_legacy_ask(
        &self,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        args: &Value,
        session_id: Option<&str>,
        (server, tool): (&str, &str),
        trace_id: &str,
        arguments: &Value,
        prompt_cache_key: Option<&str>,
        want_full: bool,
        (arm_key, api_key_name): (Option<&str>, Option<&str>),
        (caller_identity, caller_proof, credential_owner): (
            Option<&GrantSubject>,
            CallerProof<'_>,
            Option<&str>,
        ),
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
        caller_credential: &CallerCredential,
        dispatch_binding: Option<&str>,
        bridge_account_credential: &mut Option<
            Arc<crate::identity_propagation::PreparedAccountCredential>,
        >,
        (policy_epoch, protocol_revision): (u64, Option<&'static str>),
        routing_profile: &str,
        backend: Option<&Arc<crate::backend::Backend>>,
        idem_reservation: &mut Option<IdempotencyReservation>,
        result: &mut Value,
        interim: &mut Option<InputRequired>,
    ) -> Result<Option<GuardedValue>> {
        // MIK-7212.WIRE: a legacy client is asked here, in-band, instead of
        // being handed a continuation envelope it has no vocabulary for. A 2025
        // client does not know to send one back, so relaying it strands the
        // exchange at both ends. The envelope is the fallback, not the path.
        //
        // Placed between the two gates on purpose. After MRTR.9, because
        // reaching this line means the question has already been found
        // answerable by this client. Before the mint below, because an exchange
        // the bridge carries to completion has no continuation to redeem: on
        // success `interim` is cleared and the mint is skipped, and the
        // completed body then runs the same post-invoke contract and anomaly
        // gates every non-bridged result runs. Returning early here would buy a
        // shorter diff by skipping them.
        //
        // `!requests.is_empty()` is load-bearing, not defensive. An interim
        // result may carry `requestState` and no questions at all — MRTR.2's
        // own shape — and handing that to the bridge makes it spin rather than
        // refuse: `plan` yields no prompts, `ask` sends nothing, the backend is
        // re-invoked, answers the same empty interim, and `run` exhausts its
        // rounds. There is nothing here for a client to answer, so there is
        // nothing to bridge, and the continuation mint below is the whole of
        // the correct behaviour for that shape.
        if caller.era == crate::protocol::meta::Era::Legacy
            && let Some(pending) = interim.clone()
            && !pending.requests.is_empty()
            && let Some(session) = session_id
        {
            // Boxed: the exchange runs in `run_input_bridge`'s frame, and one
            // allocation on the branch a legacy client with a pending question
            // takes is cheaper than a wider `invoke` frame on every dispatch.
            let account_refusal = parking_lot::Mutex::new(None);
            let relay_refused = parking_lot::Mutex::new(None);
            let recording = self.recording_channel(caller, session_id, (server, tool), trace_id);
            let held = parking_lot::Mutex::new(idem_reservation.take());
            let bridged = Box::pin(run_input_bridge(
                BridgeDispatcher {
                    meta: self,
                    caller,
                    server,
                    tool,
                    arguments,
                    prompt_cache_key,
                    inbound_meta: args.get("_meta"),
                    want_full,
                    session_id,
                    arm_key,
                    caller_identity,
                    caller_proof,
                    credential_owner,
                    headers: &caller_credential.headers,
                    cache_binding: dispatch_binding,
                    account_credential: bridge_account_credential.take(),
                    api_key_name,
                    trace_id,
                    policy_epoch,
                    protocol_revision,
                    routing_profile,
                    scope: caller.scope(),
                    captured: backend.cloned(),
                    managed: caller_credential.managed.as_ref(),
                    account_refusal: &account_refusal,
                    reservation: &held,
                    relay: caller.relay_caller(session_id),
                    relay_refused: &relay_refused,
                },
                &recording,
                session,
                caller.input_capabilities,
                pending,
                trace_id,
            ))
            .await;
            // Taken once, here: a guard held into a match arm would be held
            // across that arm's awaits and make this future non-Send.
            let mut parked = account_refusal.into_inner();
            *idem_reservation = held.into_inner();
            // A relay refusal answers first, before the parked and generic arms.
            if let Some(refused) = relay_refused.into_inner() {
                if let Some(reservation) = idem_reservation.as_mut() {
                    reservation.release();
                }
                // The outer lease was marked before round one; this refusal
                // is no result of a call that acted, so it is not retained.
                if let Some(execution) = caller.execution {
                    execution.withdraw_dispatch();
                }
                return Err(refused);
            }
            match bridged {
                Ok(completed) => {
                    // The exchange finished, so the backend has now acted and
                    // the key may be settled. The commit above declined this
                    // reservation precisely because the backend had stopped to
                    // ask; that is no longer true.
                    //
                    // The withheld marker rather than `completed`, for the
                    // reason the commit above uses it: the gates between here
                    // and `complete` may yet block this body, and committing it
                    // would hand a retry under the same key the response the
                    // gate refused.
                    if let Some(reservation) = idem_reservation.as_mut() {
                        reservation.commit(&withheld_side_effect());
                    }
                    *result = completed;
                    *interim = None;
                    // `stopped_to_ask` stays true, and that is the point: it
                    // gates the response cache below, and a bridged body is
                    // derived from answers this caller gave in-band. The cache
                    // key covers `arguments`, not the answers, so caching one
                    // would serve the next identical call somebody else's
                    // reply instead of asking. Recomputing the flag from
                    // `result` here would look tidier and cache exactly the
                    // bodies that must not be cached.
                }
                // No client session to reach is not a failed exchange: it is
                // the absence of one. A legacy caller can arrive with a
                // declared capability and no session to carry the request on —
                // every stateless caller does — and the bridge is the wrong
                // messenger for it, not the last one. Fall through with
                // `interim` still set and the ask goes out as a continuation,
                // which is what this path did before the bridge was wired in
                // front of it.
                //
                // Stdio does not reach this arm. The serve loop passes a live
                // channel (MIK-7387), so its legacy caller is asked in-band;
                // the dispatchers outside it (a batch, `dispatch_single`)
                // carry `NoClientChannel` but declare `Declared::NONE`, so the
                // MRTR.9 gate above refuses the interim before the bridge. A
                // stdio context that did fall through would mint, bound by its
                // process nonce (MIK-7570.STDIO.1).
                //
                // ponytail: `run` walks rounds internally and a session lost on
                // round two surfaces the same way, so the mint would replay
                // prompts already answered. `RoundsExhausted` carries its last
                // round for exactly this; `Delivery` does not yet, because no
                // channel in tree fails later than round one.
                Err(crate::gateway::input_bridge::BridgeError::Delivery {
                    error: crate::gateway::input_bridge::DeliveryError::NoSession,
                    ..
                }) => {}
                // Out of rounds: hand back the LAST round, sealed (#569).
                Err(crate::gateway::input_bridge::BridgeError::RoundsExhausted { last }) => {
                    if let Some(last) = last {
                        *result = *last;
                        *interim = crate::protocol::mrtr::InputRequired::from_result(result);
                    }
                }
                Err(BridgeError::Undeclared {
                    key,
                    method,
                    reason,
                }) => {
                    // The backend's last round stopped to ask: as at the
                    // dispatch gate, the lease does not keep this refusal,
                    // and an earlier round that acted keeps its protection.
                    if let Some(execution) = caller.execution {
                        execution.withdraw_dispatch();
                    }
                    return Err(undeclared_gate::bridge_refusal(
                        &key, &method, reason, server, tool, trace_id,
                    ));
                }
                // A policy refusal keeps its type across the bridge boundary.
                // `error_response_preserving_status` carries a dedicated
                // `ResponseFirewallRefused` arm that builds the delivery-refusal
                // projection; flattening it into the -32003 below would report
                // the gateway's own refusal as a client-attributable error and
                // never reach that arm. The type survives either way; what the
                // refusal decides is the key. A refusal on round one ends a
                // call that never dispatched, so falling through releases it.
                // From round two on the tool has already run, and a released
                // key would readmit a retry of a side effect that may have
                // taken effect (ADR-012 consequence 1), so the key settles.
                Err(crate::gateway::input_bridge::BridgeError::ChallengeRefused { dispatched }) => {
                    if dispatched && let Some(reservation) = idem_reservation.as_mut() {
                        reservation.fail(&crate::gateway::meta_mcp::invoke::dispatch_guards::firewall_refusal_body());
                    }
                    warn!(target: INVOKE_TARGET,
                        server,
                        tool,
                        trace_id,
                        dispatched,
                        "Bridged challenge refused by the response firewall"
                    );
                    return Err(Error::ResponseFirewallRefused);
                }
                // A11-c: a round's 401 on a managed account answers with the
                // reconnect refusal or the rejection, not the generic refusal.
                // Settled like any round that reached the backend; one refused
                // at its cold-slot list (NotAdmitted, F13) is released.
                Err(round) if parked.is_some() => {
                    let refused = parked.take().expect("the arm's guard checked it");
                    let not_admitted = matches!(round, BridgeError::NotAdmitted { .. });
                    match idem_reservation.as_mut() {
                        Some(reservation) if not_admitted => reservation.release(),
                        Some(reservation) => reservation.commit(&uncertain_side_effect()),
                        None => {}
                    }
                    if crate::personal_accounts::refusal::marked(&refused).is_some() {
                        return self
                            .with_connect_offer(Err(refused), verified_identity)
                            .await;
                    }
                    // Anything else the 401 site produced (a rejection mark, or
                    // a custody refusal connecting cannot fix) answers exactly
                    // as the same failure on the first dispatch would. Sealed
                    // like the undeclared-key refusal above: the result is
                    // gateway-built from a typed error, never backend bytes.
                    return Ok(Some(GuardedValue::sealed_by_guard(dispatch_error_result(
                        &refused,
                        tool,
                        server,
                        self.hint_surface(caller),
                    ))));
                }
                Err(error) => {
                    // A round that reached the backend may have acted, so its
                    // key must not be readmitted. `BackendFailed` is the only
                    // variant raised from the backend call itself; `NotAdmitted`
                    // was refused above the dispatch, and `Deadline`,
                    // `RequestBudgetExhausted`, `Refused`, `Delivery` and `MalformedInterim` all
                    // leave the backend parked on a question that was never
                    // answered, and a backend that stopped to ask has not
                    // acted yet — the premise the `Ok` arm below rests on too.
                    // So their release-on-drop default still stands. A round
                    // that never left the gateway — no such backend, no such
                    // tool, an open circuit, a transport that never connected
                    // — is `NotAdmitted` rather than
                    // `BackendFailed`, because `classify_bridged_dispatch_error`
                    // defers to the error type's own pre-dispatch allowlist; it
                    // is provably unexecuted, so it keeps the default too. Only
                    // a round that may have acted settles with the
                    // uncertain-side-effect marker, which tells a retry of the
                    // same key that the effect is unknown — not that it ran.
                    if matches!(
                        error,
                        crate::gateway::input_bridge::BridgeError::BackendFailed {
                            dispatch: crate::gateway::input_bridge::Dispatch::MayHaveActed,
                            ..
                        }
                    ) && let Some(reservation) = idem_reservation.as_mut()
                    {
                        reservation.commit(&uncertain_side_effect());
                    }
                    warn!(target: INVOKE_TARGET,
                        server,
                        tool,
                        trace_id,
                        error = ?error,
                        "Bridged input exchange failed for a legacy client"
                    );
                    return Err(Error::JsonRpc {
                        code: -32003,
                        message: format!(
                            "Tool '{tool}' on server '{server}' asked for input and the bridged \
                             exchange could not be completed"
                        ),
                        data: None,
                    });
                }
            }
        }
        Ok(None)
    }
}
