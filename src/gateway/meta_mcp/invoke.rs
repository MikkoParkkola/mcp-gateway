// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tool invocation, dispatch, and operator-control handlers.
//!
//! Implements `gateway_invoke` (with idempotency and error-budget tracking),
//! `gateway_get_stats`, `gateway_kill_server`, `gateway_revive_server`,
//! `gateway_list_disabled_capabilities`, `gateway_reload_config`,
//! `gateway_webhook_status`, and `gateway_run_playbook`.

use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

use crate::Result;
use crate::idempotency::{IdempotencyReservation, derive_key};
use crate::identity_propagation::CallerProof;

/// `logger` field on every `notifications/message` this module raises
/// (ADR-014 §3). One name for both sites: a caller filtering on the logger
/// wants the tool-invocation channel, not one name per outcome.
const GATEWAY_INVOKE_LOGGER: &str = "gateway.invoke";

/// The `tracing` target of every event `invoke_tool_traced` raises, its
/// extracted steps included: a step moved into a child module keeps the target
/// a log filter or a dashboard already names.
const INVOKE_TARGET: &str = module_path!();

// The per-dispatch credential and its redacting `Debug`, kept out of this file's size baseline.
mod caller_credential;
mod gate;
use caller_credential::{CallerCredential, HeldCredential};

mod guarded;
use super::response_security::chain_receipt::ChainReceipt;
use guarded::GuardedValue;

use super::super::meta_mcp_helpers::{extract_required_str, parse_tool_arguments};
#[cfg(test)]
use super::super::recovery::ErrorCategory;
use super::MetaMcp;
use super::refund_witness as rw;
mod side_effect_markers;
mod undeclared_gate;
// D1: the invocation record, written around `invoke_tool_traced`.
pub(crate) mod audit;
mod chokepoint; // MIK-8137 b1: the dispatch chokepoint every send passes
// MIK-8351: the direct route's tools/call send passes it too.
#[cfg(feature = "firewall")]
pub(crate) use chokepoint::ScanTarget;
pub(in crate::gateway) use chokepoint::{DirectPermit, Outbound};
pub(crate) mod dispatch_guards; // S1-S4 stage methods (design doc 2026-09-27 #2.1)
pub(crate) mod egress;
mod nonce_settle; // MIK-8150: refund requests and dispatch marks of a signed execution
pub(super) use nonce_settle::{ask_if_refused_submit, refused_submit_answer, spend_witness};
mod r2_check;
mod step_fingerprint;
// #1962: settlement of a bridged round's key, kept out of this file's size baseline.
mod bridge_settle;
pub(crate) mod cache_reads;
pub(super) use bridge_settle::arm_for_dispatch;
pub(super) use bridge_settle::classify_bridged_dispatch_error;
mod withheld_evidence;
// #1961: the account-bound MCP mint, kept out of this file's size baseline.
mod account_mint;

use super::support::idempotency_key_for;
pub(crate) use side_effect_markers::{LostRoundRoute, settle_lost_round};
use side_effect_markers::{uncertain_side_effect, withheld_side_effect};
pub(crate) mod gateway_writes;
mod output_shape;
mod provenance_stamp;
pub(crate) mod relay;
pub(super) use output_shape::enforce_output_schema;
#[cfg(all(test, feature = "firewall"))]
pub(crate) mod receipt_test_support;

mod admin;
mod bridge_dispatch;
mod budget;
mod caller_verdict;
mod continuation;
mod dispatch;
mod errors;
mod legacy_bridge;
mod policy;
mod post_dispatch;
mod pre_dispatch;
mod projection;
// MIK-8488: the send admission and the dispatch, out of `invoke_tool_traced`.
mod send;
pub(crate) use caller_verdict::{CallerVerdict, TargetNaming};
mod propagation;
pub(crate) use propagation::ResolvedDispatch;
mod stored_proof;
pub(crate) mod worker_clock; // MIK-8202 AC12/AC13: the task worker's clock channel
use bridge_dispatch::{BridgeDispatcher, run_input_bridge, undeclared_input_request};
pub(super) use bridge_dispatch::{
    REQUIRED_CAPABILITIES_DATA_KEY, UNSUPPORTED_ELICITATION_MODE_DATA_KEY,
};
use continuation::OutboundRetry;
pub(super) use continuation::retry_origin_backend;
pub(super) use errors::BudgetOutcome;
#[cfg(test)]
use errors::classify_dispatch_error;
use errors::{classify_from_detail, dispatch_error_result};
use projection::{
    apply_capability_projection, call_capability_tool_with_identity, emit_projection_ab_event,
    extract_client_claim, json_is_populated,
};
pub(crate) use stored_proof::SourcedOutcome;
use stored_proof::TracedOutcome;

/// Monotonically increasing request counter for load-balanced cache key slot selection.
///
/// Global across all backends; overflow wraps (u64 → effectively infinite for our purposes).
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

impl MetaMcp {
    /// Inner implementation executed within a trace-ID scope.
    ///
    /// Returns a [`TracedOutcome`]: a sealed [`GuardedValue`] on every live path
    /// (MIK-6690), or beside it the lift's shaped stored answer (MIK-8392 D8).
    #[allow(clippy::too_many_lines)] // Complex dispatch logic; splitting further harms readability
    async fn invoke_tool_traced(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        trace_id: &str,
    ) -> Result<TracedOutcome> {
        // Unpacked once, here, so the context travels whole across the call
        // boundary for the same reason `invoke_tool` takes it whole: no call
        // site can pass an authorizer without the identity it authorizes.
        let api_key_name = caller.api_key_name;
        let verified_identity = caller.verified_identity;
        let provenance = caller.provenance();
        let caller_proof = CallerProof::new(verified_identity, provenance);
        // Names an MCP child when nothing above does (MIK-7825).
        let credential_owner = super::support::credential_owner(caller);
        // The meta-tools this caller can see, for its recovery hints (MIK-7974).
        let surface = self.hint_surface(caller);

        // Capture once, before any authorization input is read. A bump after
        // this strands the insert under the epoch this call was authorized
        // in. A second load at the write site is the 4.g race.
        let policy_epoch = self.policy_epoch.load(Ordering::Acquire);
        // MIK-7991: this call's own gateway writes start here, apart from an
        // earlier plan step's in the same delivery; stored with its answer.
        let writes_mark = gateway_writes::mark();

        let server = extract_required_str(args, "server")?;
        let tool = extract_required_str(args, "tool")?;
        if let Some(answer) = self.gated(args, (server, tool), caller, session_id).await {
            return answer.map(TracedOutcome::Live);
        }

        let mut arguments = parse_tool_arguments(args)?;
        // `_full` is a gateway directive (opt out of response projection), not
        // an upstream parameter. Capture and strip it BEFORE the argument hash
        // and idempotency key are computed, so toggling it cannot bypass
        // idempotency or pollute the cache key, and it never reaches a backend
        // (MIK-3533).
        let want_full = arguments
            .get("_full")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        if let Some(obj) = arguments.as_object_mut() {
            obj.remove("_full");
        }

        // MIK-6914 Option B: the caller may attach an untrusted claim-under-test
        // (`_claim`) about the result it will render. Like `_full` it is a
        // gateway directive, stripped here — before the argument hash and cache
        // key are computed — so it never reaches a backend and never fragments
        // the cache. Bound to this call's `trace_id`, it is threaded to the
        // provenance chokepoint and (with capture enabled) recorded as the claim
        // under scrutiny. It is never the ground-truth leg.
        let client_claim = extract_client_claim(&mut arguments, trace_id);

        // MIK-5877: in `experimental` mode the projected (treatment) and raw
        // (control) arms must NOT share response-cache / idempotency entries, or
        // one arm's shape would be served to the other (the key is otherwise
        // just server:tool:hash(args)). Suffix both keys with the arm so each
        // arm is isolated while still deduping within itself — preserving
        // idempotency's double-execution protection per arm. `off`/`on` add no
        // suffix, so their keys are byte-identical to before.
        // G4: the arm keys on the caller, never on the "" every modern caller
        // shares; a keyless caller gets the control arm and is not counted.
        let arm_key = caller.experiment_key();
        let projection_key_suffix =
            crate::projection::projection_key_suffix(self.projection_mode, arm_key);

        tracing::Span::current().record("trace_id", trace_id);

        let profile = self.active_profile(session_id);

        let tool_key = format!("{server}:{tool}");

        // `_full` requests bypass idempotency and response caching entirely.
        // A `_full` call returns a different (unprojected) payload than the
        // cached/projected result, so sharing a key would let one shape leak
        // into the other (a non-`_full` caller could hit a cached full payload
        // and receive fields the projection was meant to drop). A `_full` call
        // is therefore always a fresh, uncached dispatch.
        // Resolve the per-user propagation credential ONCE (MIK-6734 / ADR-007),
        // and the capability's account credential, before the outer response
        // cache is consulted: a cache key built before the caller's credential
        // is known cannot name the caller. Reused verbatim at dispatch so there
        // is no re-mint or drift.
        // MIK-8353 3a: the refund witness, carried through every may-effect
        // step below; any exit hands back what survived.
        let mut witness = nonce_settle::Witnessed::take(caller);
        // MIK-8356 R5.2: the resolution a caller verdict carried, or a fresh one.
        let (backend, resolved) = match self
            .dispatch_resolution(
                &self.scoped(caller.scope().authorizer.backend_grant()),
                (server, tool),
                (caller_proof, verified_identity, caller.caller_key),
                surface,
                &mut witness,
            )
            .await
        {
            Ok(std::ops::ControlFlow::Continue(resolution)) => resolution,
            Ok(std::ops::ControlFlow::Break(answer)) => return Ok(TracedOutcome::Live(answer)),
            Err(error) => {
                // A busy custody refused this call before its backend, with
                // its witness kept: ask for the nonce back, settled when
                // the call returns (MIK-8392 Busy parity).
                if crate::personal_accounts::refusal::transient_data(&error).is_some() {
                    nonce_settle::ask_refund(caller);
                }
                return Err(error);
            }
        };
        // MIK-8475: the cooldown check precedes the lift, so a keyed replay of
        // a cooling tool is refused as the live call is (same nonce accounting).
        witness.carry(rw::dispatch_effect(
            resolved.minted(),
            resolved.account_credential.is_some(),
        ));
        self.admit_after_credential((server, tool), session_id, trace_id)?;
        // The lift (MIK-8392 STORED.2): proven live, before key/spend/redeem/relay act.
        let unproven = match self
            .lift_deferred((server, tool), &resolved, &mut witness, session_id, caller)
            .await
        {
            std::ops::ControlFlow::Break(replay) => return Ok(TracedOutcome::Stored(replay)),
            std::ops::ControlFlow::Continue(unproven) => unproven,
        };
        let target = (server, backend.as_ref().map(|backend| backend.instance()));
        let (caller_credential, account_credential, dispatch_binding) = resolved.into_parts();
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
        let caller_principal = super::support::caller_cache_principal(
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
            &super::support::step_scoped(&projection_key_suffix),
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
            let base = derive_key(&tool_key, &arguments);
            let discriminator = caller.retry.key_discriminator();
            format!("{base}{discriminator}")
        });

        // Owns the in-flight entry from admission until a terminal state. Its
        // `Drop` releases the key, so an early return after dispatch cannot
        // strand the entry as in-flight until the guard times out.
        let mut idem_reservation: Option<IdempotencyReservation> = None;
        if let Some(stored) = self.admit_idempotency_key(
            caller,
            session_id,
            (server, tool),
            trace_id,
            (idem_key.as_deref(), idem_fingerprint.as_deref()),
            (arm_key, &tool_key),
            api_key_name,
            client_claim.as_ref(),
            &mut idem_reservation,
        )? {
            nonce_settle::note_served(caller, (server, tool));
            return Ok(TracedOutcome::Live(stored));
        }
        stored_proof::refuse_unproven(unproven, server)?; // FIX 1b: at most once

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
                &arguments,
                dispatch_binding.as_deref(),
                &caller_credential,
                verified_identity,
                &mut idem_reservation,
            )
            .await;
        // Carried before either exit below, so neither hands back a witness
        // the check's fill spent.
        witness.carry(rw::schema_effect(fills() != fills_before));
        if let Some(refusal) = checked? {
            nonce_settle::ask_refund(caller); // MIK-8353 3d: the witness decides
            return Ok(TracedOutcome::Live(refusal));
        }

        // Counted only for a call the cache would otherwise have served, so an
        // `unresolved_principal` count always means a real bypass.
        if !want_full && protocol_revision.is_some() && self.cache.is_some() {
            super::support::note_cache_bypass(&caller_principal, "meta");
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
        if read_only
            && let Some(cached) = self.serve_cached_response(
                caller,
                session_id,
                (server, tool),
                trace_id,
                (want_full, chained),
                protocol_revision,
                &arguments,
                (&projection_key_suffix, &caller_principal),
                (&profile.name, policy_epoch),
                (arm_key, &tool_key),
                api_key_name,
                client_claim.as_ref(),
                &mut idem_reservation,
            )
        {
            nonce_settle::note_served(caller, (server, tool));
            return Ok(TracedOutcome::Live(cached));
        }

        let call = send::Call {
            args,
            session_id,
            caller,
            trace_id,
            server,
            tool,
            target,
            arguments: &arguments,
            want_full,
            client_claim: &client_claim,
            arm_key,
            projection_key_suffix: &projection_key_suffix,
            profile: &profile,
            tool_key: &tool_key,
            policy_epoch,
            writes_mark,
            surface,
            caller_proof,
            credential_owner: &credential_owner,
            backend: &backend,
            caller_credential: &caller_credential,
            dispatch_binding: &dispatch_binding,
            caller_principal: &caller_principal,
            protocol_revision,
            chained,
            read_only,
        };
        let sent = self
            .admit_send(&call, &mut idem_reservation, &mut witness)
            .await?;
        // Cloned before `accounted_dispatch` takes it: a bridged round must reach
        // the backend with the credential the first round used, and an `Arc` clone
        // is that same credential rather than a second resolution of it.
        let mut bridge_account_credential = account_credential.clone();
        let mut dispatched = self
            .send(
                &call,
                sent,
                account_credential,
                &mut idem_reservation,
                &mut witness,
            )
            .await?;
        let settled = match self
            .settle_round(
                &call,
                &mut dispatched,
                &mut bridge_account_credential,
                &mut idem_reservation,
            )
            .await?
        {
            std::ops::ControlFlow::Break(answer) => return Ok(TracedOutcome::Live(answer)),
            std::ops::ControlFlow::Continue(settled) => settled,
        };
        self.deliver(&call, dispatched, settled, &mut idem_reservation)
    }
}

#[cfg(test)]
mod error_classification_tests;

// ============================================================================
// Tests — response_transform wiring
// ============================================================================

#[cfg(test)]
mod response_transform_tests;

#[cfg(test)]
mod identity_propagation_enforcement_tests;

#[cfg(test)]
mod error_budget_tests;

#[cfg(test)]
mod circuit_open_hint_tests;
#[cfg(test)]
mod suggestion_authz_tests;

#[cfg(test)]
mod f13_bridge_tests;

#[cfg(test)]
mod captured_invoke_tests;

#[cfg(test)]
mod cancel_settles_tests;

#[cfg(test)]
mod caller_cost_tests;

#[cfg(test)]
mod f13_hint_scope_tests;

#[cfg(test)]
mod caller_verdict_label_tests;

#[cfg(test)]
mod session_fp_tests;

#[cfg(test)]
mod response_cache_error_tests;

#[cfg(test)]
mod ask_expiry_budget_tests;

#[cfg(test)]
mod tracing_target_tests;

#[cfg(test)]
mod mcp_credential_principal_tests;
#[cfg(test)]
mod stage_boundary_tests;
