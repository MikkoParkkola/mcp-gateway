// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The resolve stage of `invoke_tool_traced` (MIK-8488): under what credential
//! the call dispatches, and whether a deferred answer serves it instead.
//!
//! Moved verbatim from the orchestrator. The order inside is the contract:
//! MIK-8475's cooldown precedes the lift, and the dispatch-effect carry
//! precedes the cooldown, so a cooled, minted call keeps its nonce spent.

use crate::gateway::meta_mcp::dispatch_log::PreSend;
use std::sync::Arc;

use super::caller_credential::CallerCredential;
use super::intake::Step;
use super::nonce_settle::Witnessed;
use super::propagation::DispatchAccount;
use super::stored_proof::{TracedOutcome, UnprovenReplay};
use crate::Result;
use crate::backend::Backend;
use crate::gateway::meta_mcp::refund_witness as rw;
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::gateway::recovery::MetaSurface;
use crate::identity_propagation::CallerProof;
use crate::key_server::oidc::VerifiedIdentity;

/// S3's input: exactly what the resolve reads.
pub(super) struct ResolveIn<'a, 'c> {
    pub(super) caller: &'a MetaMcpCallerContext<'c>,
    pub(super) session_id: Option<&'a str>,
    pub(super) trace_id: &'a str,
    pub(super) step: Step<'a>,
    pub(super) caller_proof: CallerProof<'c>,
    pub(super) verified_identity: Option<&'c VerifiedIdentity>,
    pub(super) surface: MetaSurface,
}

/// S3's output: the backend, the target it was judged on, the credentials the
/// dispatch consumes, and what the lift left unproven.
pub(super) struct ResolveOut<'a> {
    pub(super) backend: Option<Arc<Backend>>,
    pub(super) target: (&'a str, Option<u64>),
    pub(super) caller_credential: CallerCredential,
    pub(super) dispatch_binding: Option<String>,
    pub(super) unproven: Option<UnprovenReplay>,
    pub(super) account_credential: DispatchAccount,
}

impl MetaMcp {
    /// S3, the resolve: the resolution the call dispatches under, or the
    /// lift's stored answer when one is deferred for it.
    #[forbid(unused_variables)]
    pub(super) async fn resolve<'a>(
        &self,
        input: ResolveIn<'a, '_>,
        witness: &mut Witnessed<'_, '_>,
    ) -> Result<std::ops::ControlFlow<TracedOutcome, ResolveOut<'a>>> {
        // MIK-8356 R5.2: the resolution a caller verdict carried, or a fresh one.
        let ResolveIn {
            caller,
            session_id,
            trace_id,
            step: Step { server, tool },
            caller_proof,
            verified_identity,
            surface,
        } = input;
        // Before any credential, replay, key or cache (see the method).
        self.refuse_name_clash(server)?;
        let (backend, resolved) = match self
            .dispatch_resolution(
                &self.scoped(caller.scope().authorizer.backend_grant()),
                (server, tool),
                (caller_proof, verified_identity, caller.caller_key),
                surface,
                witness,
            )
            .await
        {
            Ok(std::ops::ControlFlow::Continue(resolution)) => resolution,
            Ok(std::ops::ControlFlow::Break(answer)) => {
                // The resolution answered for itself: nothing reached the backend.
                super::audit::note_pre_send(PreSend::Refused);
                return Ok(std::ops::ControlFlow::Break(TracedOutcome::Live(answer)));
            }
            Err(error) => {
                // A busy custody refused this call before its backend, with
                // its witness kept: ask for the nonce back, settled when
                // the call returns (MIK-8392 Busy parity).
                super::nonce_settle::ask_if_transient(caller, &error);
                super::audit::note_pre_send(PreSend::Refused);
                return Err(error);
            }
        };
        // MIK-8475: the cooldown check precedes the lift, so a keyed replay of
        // a cooling tool is refused as the live call is (same nonce accounting).
        witness.carry(rw::dispatch_effect(
            resolved.minted(),
            resolved.account_credential.is_some(),
        ));
        self.admit_after_credential((server, tool), session_id, trace_id)
            .inspect_err(|_| super::audit::note_pre_send(PreSend::Refused))?;
        // The lift (MIK-8392 STORED.2): proven live, before key/spend/redeem/relay act.
        let unproven = match self
            .lift_deferred((server, tool), &resolved, witness, session_id, caller)
            .await
        {
            std::ops::ControlFlow::Break(replay) => {
                return Ok(std::ops::ControlFlow::Break(TracedOutcome::Stored(replay)));
            }
            std::ops::ControlFlow::Continue(unproven) => unproven,
        };
        let target = (server, backend.as_ref().map(|backend| backend.instance()));
        let (caller_credential, account_credential, dispatch_binding) = resolved.into_parts();
        Ok(std::ops::ControlFlow::Continue(ResolveOut {
            backend,
            target,
            caller_credential,
            dispatch_binding,
            unproven,
            account_credential,
        }))
    }
}
