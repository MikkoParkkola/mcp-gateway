// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The send stages of `invoke_tool_traced` (MIK-8488): the checks that run
//! before anything is sent, then the dispatch itself and its first reading.
//!
//! Moved verbatim from the orchestrator. The refund witness and the
//! idempotency reservation stay owned there and arrive as `&mut`, so each
//! drops where, and in the order, it always did.

use std::sync::Arc;

use serde_json::{Value, json};

use super::caller_credential::CallerCredential;
use super::continuation::{OutboundRetry, redeem_retry};
use super::post_dispatch::attach_tool_error_recovery;
use super::pre_dispatch::{derive_prompt_cache_key, log_tool_invoked};
use super::{
    ChainReceipt, arm_for_dispatch, audit, chokepoint, dispatch_guards, gateway_writes,
    nonce_settle, relay,
};
use crate::Result;
use crate::backend::Backend;
use crate::gateway::meta_mcp::refund_witness as rw;
use crate::gateway::meta_mcp::support::CachePrincipal;
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::gateway::recovery::MetaSurface;
use crate::idempotency::IdempotencyReservation;
use crate::identity_propagation::CallerProof;
use crate::routing_profile::RoutingProfile;
use crate::trust::ClientClaim;

/// What the stages after key admission read, borrowed from
/// `invoke_tool_traced`'s frame. Read-only: what a stage writes travels
/// beside it as `&mut`, owned by the orchestrator.
pub(super) struct Call<'a, 'c> {
    pub(super) args: &'a Value,
    pub(super) session_id: Option<&'a str>,
    pub(super) caller: &'a MetaMcpCallerContext<'c>,
    pub(super) trace_id: &'a str,
    pub(super) server: &'a str,
    pub(super) tool: &'a str,
    pub(super) target: (&'a str, Option<u64>),
    pub(super) arguments: &'a Value,
    pub(super) want_full: bool,
    pub(super) client_claim: &'a Option<ClientClaim>,
    pub(super) arm_key: Option<&'a str>,
    pub(super) projection_key_suffix: &'a str,
    pub(super) profile: &'a RoutingProfile,
    pub(super) tool_key: &'a str,
    pub(super) policy_epoch: u64,
    pub(super) writes_mark: gateway_writes::Mark,
    pub(super) surface: MetaSurface,
    pub(super) caller_proof: CallerProof<'a>,
    pub(super) credential_owner: &'a Option<String>,
    pub(super) backend: &'a Option<Arc<Backend>>,
    pub(super) caller_credential: &'a CallerCredential,
    pub(super) dispatch_binding: &'a Option<String>,
    pub(super) caller_principal: &'a CachePrincipal,
    pub(super) protocol_revision: Option<&'static str>,
    pub(super) chained: bool,
    pub(super) read_only: bool,
}

/// What the send admission hands the dispatch.
pub(super) struct Sent {
    pub(super) admission: dispatch_guards::Admission,
    #[cfg(feature = "cost-governance")]
    pub(super) cost_warnings: Vec<String>,
    pub(super) prompt_cache_key: Option<String>,
    pub(super) outbound_retry: OutboundRetry,
    pub(super) permit: chokepoint::Permit,
}

/// The dispatch's first reading: the result, the chain receipt and whether
/// the backend's own answer came back, with what the later stages still
/// read from the send admission.
pub(super) struct Dispatched {
    pub(super) result: Value,
    pub(super) receipt: ChainReceipt,
    pub(super) answered: bool,
    pub(super) prompt_cache_key: Option<String>,
    #[cfg(feature = "cost-governance")]
    pub(super) cost_warnings: Vec<String>,
}

/// What the relay check reads of `call`'s egress, the backend it was judged
/// on included: that backend's rules say which keys the send overwrites.
fn relay_egress<'e>(
    call: &'e Call<'_, '_>,
    prompt_cache_key: Option<&'e str>,
    retry: &'e OutboundRetry,
) -> relay::Egress<'e> {
    relay::Egress {
        arguments: call.arguments,
        backend: call.backend.as_ref(),
        inbound_meta: call.args.get("_meta"),
        prompt_cache_key,
        retry,
    }
}

impl MetaMcp {
    /// The use counters: the invocation stats and the ranker's usage.
    fn count_use(&self, server: &str, tool: &str) {
        if let Some(ref stats) = self.stats {
            stats.record_invocation(server, tool);
        }
        if let Some(ref ranker) = self.ranker {
            ranker.record_use(server, tool);
        }
    }

    /// S6, the send admission: the use counters and the invocation log, the
    /// spend admission, the retry's redemption, the relay refusal and the
    /// dispatch chokepoint. Every refusal here is before anything is sent.
    pub(super) async fn admit_send(
        &self,
        call: &Call<'_, '_>,
        idem_reservation: &mut Option<IdempotencyReservation>,
        witness: &mut nonce_settle::Witnessed<'_, '_>,
    ) -> Result<Sent> {
        let &Call {
            args,
            session_id,
            caller,
            trace_id,
            server,
            tool,
            target,
            arguments,
            dispatch_binding,
            ..
        } = call;
        #[cfg(feature = "cost-governance")]
        let api_key_name = caller.api_key_name;
        self.count_use(server, tool);

        log_tool_invoked(caller, server, tool, trace_id);

        // === PRE-INVOKE: Cost governance budget check ===
        //
        // Returns the warnings to inject post-dispatch and blocks when the
        // budget is exceeded (returns JSON-RPC -32003 error).
        #[cfg(feature = "cost-governance")]
        let mut admission = match self.admit_spend_for(&dispatch_guards::BackendCall {
            server,
            tool,
            session_id,
            api_key_name,
            cost_key: caller.cost_key(),
            trace_id,
            caller_key: None,
        }) {
            Ok(admission) => admission,
            Err(error) => {
                // The refusal records nothing outside the gateway; whatever
                // witness survived the steps above decides the refund.
                nonce_settle::settle_pre_send(caller, nonce_settle::PreSendExit::AskRefund);
                return Err(error);
            }
        };
        #[cfg(feature = "cost-governance")]
        let cost_warnings = std::mem::take(&mut admission.warnings);
        #[cfg(not(feature = "cost-governance"))]
        let admission = dispatch_guards::Admission::default();

        let prompt_cache_key: Option<String> = derive_prompt_cache_key(args, session_id);

        // MRTR.1: a retry's answers and the backend's own state go out beside
        // `arguments`. Redeemed here rather than at the router, because this is
        // the only scope holding all five values the mint sealed — the backend
        // server and tool, its argument object, the caller's identity, and the
        // handle itself.
        let source = (
            caller.principal_source(dispatch_binding.as_deref()),
            caller.retry,
        );
        let outbound_retry =
            match redeem_retry(&self.continuation, source, target, tool, arguments).await {
                Ok(retry) => retry,
                Err(error) => {
                    // Refused before the backend was reached, so it has not
                    // acted: the key is released rather than settled (settling
                    // would answer an honest retry with a side effect nothing
                    // performed), and the signing nonce is asked back. A
                    // refused redeem consumed nothing, so the witness stands.
                    nonce_settle::settle_pre_send(
                        caller,
                        nonce_settle::PreSendExit::GiveBackUnsent(idem_reservation),
                    );
                    return Err(error);
                }
            };
        // Redeemed: a continuation the caller presented was consumed, whatever
        // state the backend issued with it.
        witness.carry(rw::retry_effect(caller.retry.request_state.is_some()));

        let egress = relay_egress(call, prompt_cache_key.as_deref(), &outbound_retry);
        let reservation = idem_reservation.as_mut();
        if let Err(error) =
            self.refuse_relay(caller, session_id, (server, tool), &egress, reservation)
        {
            // Refused before anything is sent: the witness that survived the
            // steps above decides the refund (MIK-8353 3b, NONCEFX.3).
            nonce_settle::settle_pre_send(caller, nonce_settle::PreSendExit::AskRefund);
            return Err(error);
        }
        // MIK-8137 b1: the chokepoint, before anything marks this send.
        let answers = outbound_retry.input_responses.as_ref();
        let outbound = chokepoint::Outbound { arguments, answers };
        let source = chokepoint::Source::of_call(answers);
        let permit = match self.chokepoint(
            caller.scope(),
            session_id,
            (server, tool),
            &outbound,
            source,
        ) {
            Ok(permit) => permit,
            Err(error) => {
                nonce_settle::settle_pre_send(
                    caller,
                    nonce_settle::PreSendExit::GiveBackUnsent(idem_reservation),
                );
                crate::gateway::delivery_facts::refused_while_vouched();
                return Err(error);
            }
        };
        Ok(Sent {
            admission,
            #[cfg(feature = "cost-governance")]
            cost_warnings,
            prompt_cache_key,
            outbound_retry,
            permit,
        })
    }

    /// S7, the dispatch: the witness goes with the send, the key is armed,
    /// the backend is called, and its answer or error gets its first reading.
    #[allow(clippy::too_many_lines)] // moved verbatim from `invoke_tool_traced`, which carried it
    pub(super) async fn send(
        &self,
        call: &Call<'_, '_>,
        sent: Sent,
        account_credential: super::propagation::DispatchAccount,
        idem_reservation: &mut Option<IdempotencyReservation>,
        witness: &mut nonce_settle::Witnessed<'_, '_>,
    ) -> Result<Dispatched> {
        let &Call {
            args,
            session_id,
            caller,
            trace_id,
            server,
            tool,
            arguments,
            want_full,
            arm_key,
            profile,
            policy_epoch,
            surface,
            caller_proof,
            credential_owner,
            backend,
            caller_credential,
            dispatch_binding,
            protocol_revision,
            ..
        } = call;
        let Sent {
            admission,
            #[cfg(feature = "cost-governance")]
            cost_warnings,
            prompt_cache_key,
            outbound_retry,
            permit,
        } = sent;
        let caller_identity = caller.grant_subject.as_ref();
        let verified_identity = caller.verified_identity;
        // U12: a web UI call goes out only as the call its gate admitted.
        #[cfg(feature = "webui")]
        if let Err(refusal) = crate::gateway::ui_call::admit_send((server, tool)) {
            nonce_settle::settle_pre_send(caller, nonce_settle::PreSendExit::AskRefund);
            return Err(refusal);
        }
        // Dispatch: the witness goes with the send (the nonce stays spent).
        witness.spend();
        nonce_settle::mark_dispatched(caller, (server, tool));
        let lent = caller_credential.lent();
        // Boxed: the dispatch future is the largest thing this frame ever
        // holds, and inlining it puts `invoke_tool_traced` over
        // `clippy::large_futures` at every call site.
        // #1962: a drop during the dispatch settles the key as uncertain.
        arm_for_dispatch(idem_reservation.as_mut());
        let chain_slot = super::super::response_security::chain_receipt::ChainSlot::default();
        // A3 R1: only an MCP backend's own answer can be chain-eligible; a
        // capability's `Ok` also covers its local refusals and inner cache.
        let mcp_backend = self
            .caller_capabilities()
            .is_none_or(|cap| server != cap.name);
        let dispatch_result = Box::pin(self.accounted_dispatch(
            server,
            tool,
            arguments.clone(),
            &outbound_retry,
            prompt_cache_key.as_deref(),
            args.get("_meta"),
            want_full,
            session_id,
            arm_key,
            caller_identity,
            (caller_proof, credential_owner.as_deref()),
            &lent,
            dispatch_binding.as_deref(),
            account_credential,
            caller.cost_key(),
            trace_id,
            policy_epoch,
            protocol_revision,
            &profile.name,
            caller.scope(),
            backend.clone(),
            &chain_slot,
            &admission,
            permit,
        ))
        .await;
        // The spend is settled; an unsettled reservation is given back here.
        drop(admission);

        // A raw-receipt chain refusal is the answer, not a tool failure (D3).
        let receipt = std::mem::take(&mut *chain_slot.lock());
        if matches!(receipt, ChainReceipt::Refused)
            && let Err(error) = dispatch_result
        {
            let message = super::super::signing::wire_error_message(&error);
            if let Some(reservation) = idem_reservation.as_mut() {
                reservation.fail(&audit::stored_failure(
                    json!({"code": error.to_rpc_code(), "message": message}),
                ));
            }
            return Err(error);
        }
        let answered = mcp_backend && dispatch_result.is_ok();
        let result = match dispatch_result {
            Ok(value) => attach_tool_error_recovery(value, tool, server, surface),
            Err(e) => {
                self.settle_dispatch_error(
                    e,
                    caller_credential.managed.as_ref(),
                    (idem_reservation, caller.execution),
                    verified_identity,
                    (server, tool, surface),
                )
                .await?
            }
        };
        Ok(Dispatched {
            result,
            receipt,
            answered,
            prompt_cache_key,
            #[cfg(feature = "cost-governance")]
            cost_warnings,
        })
    }
}
