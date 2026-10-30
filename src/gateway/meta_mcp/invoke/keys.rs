// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The key stages of `invoke_tool_traced` (MIK-8488): the idempotency key's
//! admission, then the pre-send checks under the call's own key.
//!
//! Moved verbatim from the orchestrator. The reservation stays owned there
//! and arrives as `&mut`, so it drops where, and in the order, it always did.

use std::sync::Arc;

use serde_json::Value;

use super::super::support::idempotency_key_for;
use super::caller_credential::CallerCredential;
use super::intake::Step;
use super::nonce_settle::Witnessed;
use super::stored_proof::{TracedOutcome, UnprovenReplay};
use crate::Result;
use crate::backend::Backend;
use crate::gateway::meta_mcp::refund_witness as rw;
use crate::gateway::meta_mcp::support::CachePrincipal;
use crate::gateway::meta_mcp::{MetaMcp, MetaMcpCallerContext};
use crate::idempotency::{IdempotencyReservation, derive_key};
use crate::key_server::oidc::VerifiedIdentity;
use crate::routing_profile::RoutingProfile;
use crate::trust::ClientClaim;

/// S4's input: exactly what the key admission reads.
pub(super) struct KeysIn<'a, 'c> {
    pub(super) caller: &'a MetaMcpCallerContext<'c>,
    pub(super) session_id: Option<&'a str>,
    pub(super) trace_id: &'a str,
    pub(super) step: Step<'a>,
    pub(super) arguments: &'a Value,
    pub(super) arm_key: Option<&'a str>,
    pub(super) tool_key: &'a str,
    pub(super) projection_key_suffix: &'a str,
    pub(super) client_claim: &'a Option<ClientClaim>,
    pub(super) api_key_name: Option<&'c str>,
    pub(super) verified_identity: Option<&'c VerifiedIdentity>,
    pub(super) dispatch_binding: &'a Option<String>,
    pub(super) unproven: Option<UnprovenReplay>,
}

/// S4's output: who the response cache keys this call on.
pub(super) struct Keyed {
    pub(super) caller_principal: CachePrincipal,
}

/// S5's input: exactly what the pre-send reads.
pub(super) struct PreSendIn<'a, 'c> {
    pub(super) caller: &'a MetaMcpCallerContext<'c>,
    pub(super) session_id: Option<&'a str>,
    pub(super) trace_id: &'a str,
    pub(super) step: Step<'a>,
    pub(super) backend: &'a Option<Arc<Backend>>,
    pub(super) arguments: &'a Value,
    pub(super) dispatch_binding: &'a Option<String>,
    pub(super) caller_credential: &'a CallerCredential,
    pub(super) verified_identity: Option<&'c VerifiedIdentity>,
    pub(super) want_full: bool,
    pub(super) caller_principal: &'a CachePrincipal,
    pub(super) projection_key_suffix: &'a str,
    pub(super) profile: &'a RoutingProfile,
    pub(super) policy_epoch: u64,
    pub(super) arm_key: Option<&'a str>,
    pub(super) tool_key: &'a str,
    pub(super) api_key_name: Option<&'c str>,
    pub(super) client_claim: &'a Option<ClientClaim>,
}

/// S5's output: whether the call may be served from the cache.
pub(super) struct Cacheable {
    pub(super) protocol_revision: Option<&'static str>,
    pub(super) chained: bool,
    pub(super) read_only: bool,
}

impl MetaMcp {
    /// S4, the key admission: the call's idempotency key, or its stored
    /// answer when the key replays one.
    #[forbid(unused_variables)]
    pub(super) fn admit_keys(
        &self,
        input: KeysIn<'_, '_>,
        idem_reservation: &mut Option<IdempotencyReservation>,
    ) -> Result<std::ops::ControlFlow<TracedOutcome, Keyed>> {
        let KeysIn {
            caller,
            session_id,
            trace_id,
            step: Step { server, tool },
            arguments,
            arm_key,
            tool_key,
            projection_key_suffix,
            client_claim,
            api_key_name,
            verified_identity,
            dispatch_binding,
            unproven,
        } = input;
        // Who the response cache keys on, in one place and one namespace per
        // source (`support::caller_cache_principal`). The binding when identity
        // propagation is minting per-user credentials, then the verified OIDC
        // subject, then the caller's own `GrantSubject` (trusted headers, mTLS
        // or an OAuth agent, `router/identity.rs`), then, for an authenticated
        // caller, the digest of its validated credential (`cred:`). An
        // authenticated caller none of these names is `Unresolved` and gets no
        // cache key and no retry key; only an anonymous caller shares the
        // pooled namespace. The binding handed in is the dispatch one, so a
        // capability's account boundary reaches both keys.
        //
        // The retry entry is keyed on this same principal, so a caller the
        // response cache tells apart never shares a retry entry.
        let caller_principal = super::super::support::caller_cache_principal(
            dispatch_binding.as_deref(),
            verified_identity,
            caller.grant_subject.as_ref(),
            caller.owner_principal(),
            caller.authentication,
        );

        // `want_full` no longer suppresses the key. It selects the shape of the
        // *reply*, not whether the backend acts, and a directive that switches
        // off duplicate protection is a bypass any client can set — which is
        // exactly what the `_full` stripping above says must not be possible.
        let idem_key = idempotency_key_for(
            caller.retry.idempotency_key.as_deref(),
            &super::super::support::step_scoped(projection_key_suffix),
            &caller_principal,
            self.idempotency_cache.as_ref(),
            "meta",
        );
        // What the key is a key *for*. A client key is an opaque string it
        // chose, so nothing about it says which request it was minted for;
        // without this a key reused for a different call replays the first
        // call's result as though it were this one's.
        //
        // The retry pair is part of that binding (MRTR.10). A retry reuses the
        // client's key and the original arguments, so those alone cannot tell
        // one continuation from another: a confirmation answered "accept" and
        // then "decline" would fingerprint identically, and the decline would
        // be served the acceptance.
        let idem_fingerprint = idem_key.as_ref().map(|_| {
            let base = derive_key(tool_key, arguments);
            let discriminator = caller.retry.key_discriminator();
            format!("{base}{discriminator}")
        });

        if let Some(stored) = self.admit_idempotency_key(
            caller,
            session_id,
            (server, tool),
            trace_id,
            (idem_key.as_deref(), idem_fingerprint.as_deref()),
            (arm_key, tool_key),
            api_key_name,
            client_claim.as_ref(),
            idem_reservation,
        )? {
            super::nonce_settle::settle_pre_send(
                caller,
                super::nonce_settle::PreSendExit::Served((server, tool)),
            );
            return Ok(std::ops::ControlFlow::Break(TracedOutcome::Live(stored)));
        }
        // FIX 1b: at most once. Refused before its backend.
        super::stored_proof::refuse_unproven(unproven, server).inspect_err(|_| {
            super::audit::note_pre_send(crate::gateway::meta_mcp::dispatch_log::PreSend::Refused);
        })?;
        Ok(std::ops::ControlFlow::Continue(Keyed { caller_principal }))
    }

    /// S5, the pre-send: the undeclared-key check, then the cached answer when
    /// the call may be served from the cache.
    #[forbid(unused_variables)]
    pub(super) async fn pre_send(
        &self,
        input: PreSendIn<'_, '_>,
        witness: &mut Witnessed<'_, '_>,
        idem_reservation: &mut Option<IdempotencyReservation>,
    ) -> Result<std::ops::ControlFlow<TracedOutcome, Cacheable>> {
        let PreSendIn {
            caller,
            session_id,
            trace_id,
            step: Step { server, tool },
            backend,
            arguments,
            dispatch_binding,
            caller_credential,
            verified_identity,
            want_full,
            caller_principal,
            projection_key_suffix,
            profile,
            policy_epoch,
            arm_key,
            tool_key,
            api_key_name,
            client_claim,
        } = input;
        // Defense in depth on an already-classified value: the exact set both
        // layers accept, so a value that is not a revision this build serves —
        // including a whitespace-padded spelling of one that is — bypasses the
        // cache instead of naming a bucket of its own. Never trimmed onto a
        // canonical revision.
        let protocol_revision = caller
            .protocol_revision
            .and_then(crate::protocol::meta::served_revision);

        // Whether the check below fills a list from the backend: counted at
        // the fill, so a slot that expires mid-check still counts.
        let fills = || backend.as_ref().map_or(0, |b| b.list_fills());
        let fills_before = fills();
        let checked = self
            .answer_undeclared_key(
                caller,
                session_id,
                (server, tool),
                backend.as_ref(),
                arguments,
                dispatch_binding.as_deref(),
                caller_credential,
                verified_identity,
                idem_reservation,
            )
            .await;
        // Carried before either exit below, so neither hands back a witness
        // the check's fill spent.
        witness.carry(rw::schema_effect(fills() != fills_before));
        if let Some(refusal) = checked? {
            super::nonce_settle::settle_pre_send(
                caller,
                super::nonce_settle::PreSendExit::AskRefund,
            ); // MIK-8353 3d: the witness decides
            return Ok(std::ops::ControlFlow::Break(TracedOutcome::Live(refusal)));
        }

        // Counted only for a call the cache would otherwise have served, so an
        // `unresolved_principal` count always means a real bypass.
        if !want_full && protocol_revision.is_some() && self.cache.is_some() {
            super::super::support::note_cache_bypass(caller_principal, "meta");
        }
        // A chained backend's answer is bound to one challenge: no cache (D7).
        let chained = self.is_chained(backend.as_deref());
        // MIK-8393 (#3773): a stored result may stand in for a call only when
        // this caller's slot declared the tool read-only, so the call it
        // replaces had no effect to lose. Absent means deny: an unannotated
        // tool, an undiscovered slot and a write all go to the backend, and
        // their answers are never stored.
        let read_only = self.cache_admits(
            (server, tool),
            backend.as_deref(),
            dispatch_binding.as_deref(),
        );
        // U12: a web UI call runs only as the call the route checked, and a
        // tool this slot did not declare read-only only when confirmed. Here
        // the backend instance and the caller's binding are the dispatched
        // ones, so a replaced backend or a cold per-user slot asks.
        #[cfg(feature = "webui")]
        if let Err(refusal) =
            crate::gateway::ui_call::gate((server, tool), caller.credential_principal, read_only)
        {
            super::nonce_settle::settle_pre_send(
                caller,
                super::nonce_settle::PreSendExit::AskRefund,
            );
            return Err(refusal);
        }
        // A web UI call runs the tool itself: a stored answer is not a run.
        if read_only
            && !crate::gateway::ui_call_runs_live()
            && let Some(cached) = self.serve_cached_response(
                caller,
                session_id,
                (server, tool),
                trace_id,
                (want_full, chained),
                protocol_revision,
                arguments,
                (projection_key_suffix, caller_principal),
                (&profile.name, policy_epoch),
                (arm_key, tool_key),
                api_key_name,
                client_claim.as_ref(),
                idem_reservation,
            )
        {
            super::nonce_settle::settle_pre_send(
                caller,
                super::nonce_settle::PreSendExit::Served((server, tool)),
            );
            return Ok(std::ops::ControlFlow::Break(TracedOutcome::Live(cached)));
        }
        Ok(std::ops::ControlFlow::Continue(Cacheable {
            protocol_revision,
            chained,
            read_only,
        }))
    }
}
