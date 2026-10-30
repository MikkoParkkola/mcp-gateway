// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tool invocation, dispatch, and operator-control handlers.
//!
//! Implements `gateway_invoke` (with idempotency and error-budget tracking),
//! `gateway_get_stats`, `gateway_kill_server`, `gateway_revive_server`,
//! `gateway_list_disabled_capabilities`, `gateway_reload_config`,
//! `gateway_webhook_status`, and `gateway_run_playbook`.

use std::sync::atomic::AtomicU64;

use serde_json::Value;

use crate::Result;
use crate::idempotency::IdempotencyReservation;

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
use caller_credential::{CallerCredential, DispatchCredential};

mod guarded;
use super::response_security::chain_receipt::ChainReceipt;
use guarded::GuardedValue;

#[cfg(test)]
use super::super::recovery::ErrorCategory;
use super::MetaMcp;
mod side_effect_markers;
mod undeclared_gate;
// D1: the invocation record, written around `invoke_tool_traced`.
pub(crate) mod audit;
mod chokepoint;
pub(crate) mod send_timer; // times each backend send // MIK-8137 b1: the dispatch chokepoint every send passes
// MIK-8351: the direct route's tools/call send passes it too.
#[cfg(feature = "firewall")]
pub(crate) use chokepoint::ScanTarget;
pub(in crate::gateway) use chokepoint::{DirectPermit, Outbound};
pub(crate) mod dispatch_guards; // S1-S4 stage methods (design doc 2026-09-27 #2.1)
pub(crate) mod egress;
mod nonce_settle; // MIK-8150: refund requests and dispatch marks of a signed execution
pub(super) use nonce_settle::{
    ask_if_refused_submit, ask_refund, refused_submit_answer, spend_witness,
};
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

pub(crate) use side_effect_markers::{LostRoundRoute, settle_lost_round};
use side_effect_markers::{uncertain_side_effect, withheld_side_effect};
pub(crate) mod gateway_writes;
mod output_shape;
mod provenance_stamp;
pub(crate) mod relay;
pub(super) use output_shape::enforce_output_schema;
pub(super) use provenance_stamp::lift_receipt;
pub(crate) use provenance_stamp::with_minted_receipts;
#[cfg(all(test, feature = "firewall"))]
pub(crate) mod receipt_test_support;

mod admin;
mod bridge_dispatch;
mod budget;
mod caller_verdict;
mod continuation;
mod dispatch;
mod errors;
mod intake;
mod keys;
mod legacy_bridge;
mod policy;
mod post_dispatch;
mod pre_dispatch;
mod projection;
mod resolve;
// MIK-8488: the send admission and the dispatch, out of `invoke_tool_traced`.
mod send;
pub(crate) use caller_verdict::{CallerVerdict, TargetNaming};
pub(in crate::gateway::meta_mcp) use caller_verdict::{ColdAttempt, ColdFill};
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
    json_is_populated,
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
        let intake = match self
            .intake(intake::IntakeIn {
                args,
                session_id,
                caller,
            })
            .await?
        {
            std::ops::ControlFlow::Break(outcome) => return Ok(outcome),
            std::ops::ControlFlow::Continue(intake) => intake,
        };

        let directives = self.directives(intake::DirectivesIn {
            args,
            session_id,
            caller,
            trace_id,
            step: intake.step,
        })?;

        // `_full` requests bypass the response cache, never idempotency (S4).
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
        let resolve_out = match self
            .resolve(
                resolve::ResolveIn {
                    caller,
                    session_id,
                    trace_id,
                    step: intake.step,
                    caller_proof: intake.facts.caller_proof,
                    verified_identity: intake.facts.verified_identity,
                    surface: intake.facts.surface,
                },
                &mut witness,
            )
            .await?
        {
            std::ops::ControlFlow::Break(outcome) => return Ok(outcome),
            std::ops::ControlFlow::Continue(resolve_out) => resolve_out,
        };
        // Owns the in-flight entry from admission until a terminal state. Its
        // `Drop` releases the key, so an early return after dispatch cannot
        // strand the entry as in-flight until the guard times out.
        let mut idem_reservation: Option<IdempotencyReservation> = None;
        let keyed = match self.admit_keys(
            keys::KeysIn {
                caller,
                session_id,
                trace_id,
                step: intake.step,
                arguments: &directives.arguments,
                arm_key: directives.arm_key,
                tool_key: &directives.tool_key,
                projection_key_suffix: &directives.projection_key_suffix,
                client_claim: &directives.client_claim,
                api_key_name: intake.facts.api_key_name,
                verified_identity: intake.facts.verified_identity,
                dispatch_binding: &resolve_out.dispatch_binding,
                unproven: resolve_out.unproven,
            },
            &mut idem_reservation,
        )? {
            std::ops::ControlFlow::Break(outcome) => return Ok(outcome),
            std::ops::ControlFlow::Continue(keyed) => keyed,
        };

        let cacheable = match self
            .pre_send(
                keys::PreSendIn {
                    caller,
                    session_id,
                    trace_id,
                    step: intake.step,
                    backend: &resolve_out.backend,
                    arguments: &directives.arguments,
                    dispatch_binding: &resolve_out.dispatch_binding,
                    caller_credential: &resolve_out.caller_credential,
                    verified_identity: intake.facts.verified_identity,
                    want_full: directives.want_full,
                    caller_principal: &keyed.caller_principal,
                    projection_key_suffix: &directives.projection_key_suffix,
                    profile: &directives.profile,
                    policy_epoch: intake.policy_epoch,
                    arm_key: directives.arm_key,
                    tool_key: &directives.tool_key,
                    api_key_name: intake.facts.api_key_name,
                    client_claim: &directives.client_claim,
                },
                &mut witness,
                &mut idem_reservation,
            )
            .await?
        {
            std::ops::ControlFlow::Break(outcome) => return Ok(outcome),
            std::ops::ControlFlow::Continue(cacheable) => cacheable,
        };

        let call = send::Call {
            args,
            session_id,
            caller,
            trace_id,
            server: intake.step.server,
            tool: intake.step.tool,
            target: resolve_out.target,
            arguments: &directives.arguments,
            want_full: directives.want_full,
            client_claim: &directives.client_claim,
            arm_key: directives.arm_key,
            projection_key_suffix: &directives.projection_key_suffix,
            profile: &directives.profile,
            tool_key: &directives.tool_key,
            policy_epoch: intake.policy_epoch,
            writes_mark: intake.writes_mark,
            surface: intake.facts.surface,
            caller_proof: intake.facts.caller_proof,
            credential_owner: &intake.facts.credential_owner,
            backend: &resolve_out.backend,
            caller_credential: &resolve_out.caller_credential,
            dispatch_binding: &resolve_out.dispatch_binding,
            caller_principal: &keyed.caller_principal,
            protocol_revision: cacheable.protocol_revision,
            chained: cacheable.chained,
            read_only: cacheable.read_only,
        };
        let sent = self
            .admit_send(&call, &mut idem_reservation, &mut witness)
            .await?;
        // Cloned before `accounted_dispatch` takes it: a bridged round must reach
        // the backend with the credential the first round used, and an `Arc` clone
        // is that same credential rather than a second resolution of it.
        let mut bridge_account_credential = resolve_out.account_credential.clone();
        let mut dispatched = self
            .send(
                &call,
                sent,
                resolve_out.account_credential,
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
mod bridge_round_recheck_tests;

#[cfg(test)]
mod captured_invoke_tests;

#[cfg(test)]
mod runtime_name_clash_tests;

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

#[cfg(test)]
mod plan_step_guard_tests;
