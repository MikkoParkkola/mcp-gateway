// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The steps `invoke_tool_traced` runs on a dispatch's result: the recovery
//! hint on a tool-level error, the settlement of a dispatch error, the cost
//! advice and the response-cache write; and, since MIK-8488, the stages that
//! run them: the settlement and ask (S8), then the payload gates and the
//! delivery (S9, S10).

use std::ops::ControlFlow;

use serde_json::{Value, json};
use tracing::{debug, warn};

use super::continuation::unbindable_continuation;
use super::send::{Call, Dispatched};
use super::{GuardedValue, TracedOutcome};
use super::{INVOKE_TARGET, classify_from_detail, dispatch_error_result, withheld_side_effect};
use super::{LostRoundRoute, settle_lost_round};
use super::{continuation, dispatch_guards, gateway_writes, undeclared_gate, worker_clock};
#[cfg(feature = "cost-governance")]
use crate::cost_accounting::suggestions;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::support::{
    CachePrincipal, augment_with_predictions, augment_with_trace, response_cache_key_for,
};
use crate::gateway::recovery::{MetaSurface, RecoveryContext, recovery_for_surface};
use crate::idempotency::IdempotencyReservation;
use crate::security::http_diagnostics::is_upstream_unauthorized;
use crate::{Error, Result};

pub(super) fn attach_tool_error_recovery(
    value: Value,
    tool: &str,
    server: &str,
    surface: MetaSurface,
) -> Value {
    // When the capability backend returns a tool-level error
    // (schema validation, executor failure) it sets `isError: true`
    // in the JSON value without propagating a Rust `Err`.  Attach a
    // recovery hint so the LLM has structured guidance to fix the
    // call — but only when the gateway has not set `_recovery` already;
    // a backend's own `recovery` is its data and does not count.
    if value
        .get("isError")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        && value.get("_recovery").is_none()
    {
        let detail = value
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|item| item.get("text"))
            .and_then(serde_json::Value::as_str);
        // A tool-level `isError` body is not always a schema
        // violation — capability backends surface upstream HTTP
        // failures (429 rate limit, 5xx, timeouts) here too.
        // Read the detail text for status signals so the LLM gets
        // the right recovery class (e.g. RATE_LIMITED, retryable)
        // instead of a misleading "fix your params" INVALID_PARAM.
        let category = classify_from_detail(detail);
        let hint = recovery_for_surface(
            category,
            RecoveryContext {
                tool: Some(tool),
                backend: Some(server),
                detail,
                ..Default::default()
            },
            surface,
        );
        // MIK-7939: the hint is the gateway's text, never a receipt's.
        let mut value = value;
        if let Ok(hint) = serde_json::to_value(hint) {
            super::gateway_writes::insert_noted(
                super::gateway_writes::Layer::Value,
                &["_recovery"],
                &mut value,
                hint,
            );
        }
        value
    } else {
        value
    }
}

impl MetaMcp {
    /// A dispatch error as the caller receives it, with the idempotency key
    /// settled or released; an account refusal returns as the error it is.
    pub(super) async fn settle_dispatch_error(
        &self,
        e: Error,
        managed: Option<&crate::personal_accounts::ManagedLease>,
        (idem_reservation, execution): (
            &mut Option<IdempotencyReservation>,
            Option<&crate::gateway::meta_mcp::admission::SyncLease>,
        ),
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
        (server, tool, surface): (&str, &str, MetaSurface),
    ) -> Result<Value> {
        // Every failure of a sent call: a web UI call answers "may have run",
        // unless the backend cannot have acted.
        #[cfg(feature = "webui")]
        crate::gateway::ui_call::note_send_error(matches!(
            e,
            Error::BackendNotFound(_) | Error::ToolNotFound(_)
        ));
        // A11-c: a 401 on a managed credential forces at most one
        // refresh, then either asks the user to reconnect (an offer,
        // returned as the refusal it is) or tells the caller whether a
        // retry can help (the recovery hint below).
        let e = match managed {
            Some(managed) if is_upstream_unauthorized(&e) => {
                super::audit::after_upstream_401(managed, e).await
            }
            _ => e,
        };
        // MIK-8139: the account marker rides on the backend's own error, so
        // it is honoured only when the shared screen passes that error clean;
        // otherwise the error becomes the result the gates and firewall read.
        if crate::personal_accounts::refusal::marked(&e).is_some()
            && self.backend_error_screens_clean(server, tool, &e)
        {
            // Settled like every dispatched failure (ADR-012).
            if let Some(reservation) = idem_reservation.as_mut() {
                reservation.commit(&withheld_side_effect());
            }
            return self.with_connect_offer(Err(e), verified_identity).await;
        }
        // ADR-012 consequence 1: a reservation may be released only
        // when the backend cannot have acted, because a released key
        // readmits the retry that would execute the side effect a
        // second time. `is_pre_dispatch()` is that allowlist, and it
        // is deliberately tight (`src/error.rs`); every other dispatch
        // error is a call that may already have acted, so its
        // reservation stays live and is settled as a terminal failure
        // by the commit below.
        //
        // `take()` is load-bearing rather than stylistic: a released
        // reservation left in the `Option` would be picked up by that
        // commit and re-inserted as a completed entry, which makes the
        // release a no-op and the key permanently wrong.
        if e.is_pre_dispatch() {
            // The backend never saw it: refused before its backend.
            super::audit::note_pre_send(crate::gateway::meta_mcp::dispatch_log::PreSend::Refused);
            if let Some(mut reservation) = idem_reservation.take() {
                reservation.release();
            }
            // The outer lease was marked before this call; a refusal the
            // backend never saw is not retained there either, or a keyed
            // retry replays a stale refusal and its hint (MIK-7974).
            if let Some(execution) = execution {
                execution.withdraw_dispatch();
            }
        }
        // MIK-7979: a lost round settles with the uncertainty notice, and the
        // reservation leaves the `Option` for the same reason as above: the
        // commit and the final completion below would overwrite it.
        if settle_lost_round(&e, idem_reservation.as_mut(), LostRoundRoute::Meta) {
            *idem_reservation = None;
        }
        // MIK-8429: a playbook step keeps a busy custody typed. Folded into a
        // tool value it reads as any tool error, and the plan would null-fill
        // the step and run its successor; as itself it ends the plan,
        // retryable. Its key was released above (pre-dispatch), so nothing
        // is left to settle. A direct call keeps the folded answer.
        if crate::playbook::current_step().is_some()
            && crate::personal_accounts::refusal::transient_data(&e).is_some()
        {
            return Err(e);
        }
        // The error budget already counted this failure (the shared
        // accounting stage).  The idempotency reservation is left
        // for the commit below unless it was released or settled above.
        Ok(dispatch_error_result(&e, tool, server, surface))
    }

    #[cfg(feature = "cost-governance")]
    pub(super) fn inject_cost_advice(
        &self,
        result: &mut Value,
        cost_warnings: &[String],
        tool: &str,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
    ) {
        // === POST-INVOKE: Inject cost warnings and suggestions ===
        //
        // `_cost_warnings` — active at ≥80% budget consumption (Notify tier).
        // `_cost_suggestion` — present when a cheaper alternative exists.
        if !cost_warnings.is_empty() {
            super::gateway_writes::insert_noted(
                super::gateway_writes::Layer::Value,
                &["_cost_warnings"],
                result,
                serde_json::json!(cost_warnings),
            );
        }

        if let Some(ref enforcer) = self.budget_enforcer {
            let cost = enforcer.registry.cost_for(tool);
            if cost > 0.0 {
                let all_costs = enforcer.registry.snapshot();
                let alternatives = enforcer.config.alternatives.as_ref();
                if let Some(suggestion) =
                    suggestions::suggest_cheaper(tool, cost, &all_costs, alternatives)
                    // Never point a caller at a tool it could not call (A3).
                    && self.admits_tool_named(&suggestion.alternative, caller.scope(), session_id)
                {
                    super::gateway_writes::insert_noted(
                        super::gateway_writes::Layer::Value,
                        &["_cost_suggestion"],
                        result,
                        serde_json::json!({
                            "message": suggestion.reason,
                            "alternative": suggestion.alternative,
                            "savings_per_call": suggestion.savings_per_call,
                            "alternative_cost": suggestion.alternative_cost,
                        }),
                    );
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn store_response(
        &self,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        args: &Value,
        (server, tool): (&str, &str),
        trace_id: &str,
        (want_full, stopped_to_ask, chained): (bool, bool, bool),
        protocol_revision: Option<&'static str>,
        arguments: &Value,
        (projection_key_suffix, caller_principal): (&str, &CachePrincipal),
        (routing_profile, policy_epoch): (&str, u64),
        (result, written): (&Value, &super::gateway_writes::WriteRecord),
    ) {
        // `!stopped_to_ask` for the reason the idempotency commit above is
        // gated the same way: a question is not an answer. A cached one would be
        // served to a later caller as though the backend had replied, and the
        // continuation it carries is redeemable only by the caller it was minted
        // for — so the reply they were handed could never be completed. Asking
        // the backend's claim rather than "was a continuation minted" also
        // covers the shapes `from_result` declines, which mint nothing and are
        // not answers either.
        if !want_full
            && !stopped_to_ask
            && !chained
            && protocol_revision.is_some()
            && let Some(ref cache) = self.cache
            && let Some(cache_key) = response_cache_key_for(
                server,
                tool,
                arguments,
                projection_key_suffix,
                caller_principal,
                caller.retry,
                crate::cache::KeyContext {
                    routing_profile,
                    protocol_revision,
                    policy_epoch,
                },
            )
            && cache.set_read(
                &cache_key,
                result.clone(),
                (self.dispatch_reading(args), written.clone()),
                self.default_cache_ttl,
            )
        {
            debug!(target: INVOKE_TARGET, server, tool, trace_id, ttl = ?self.default_cache_ttl, "Cached result");
        }
    }
}

/// What the settlement hands the delivery: whether the backend stopped to
/// ask, and a round withheld for a task worker to seal.
pub(super) struct Settled {
    pub(super) stopped_to_ask: bool,
    pub(super) withheld: Option<(super::worker_clock::Binding, Option<String>)>,
}

impl MetaMcp {
    /// S8, the settlement and the ask: the key is settled or disarmed on the
    /// backend's own claim, an undeclared question is refused, a legacy ask
    /// is bridged, and a backend's `requestState` is sealed or withheld.
    /// `Break` is the bridged round's answer.
    #[allow(clippy::too_many_lines)] // moved verbatim from `invoke_tool_traced`, which carried it
    pub(super) async fn settle_round(
        &self,
        call: &Call<'_, '_>,
        dispatched: &mut Dispatched,
        bridge_account_credential: &mut super::propagation::DispatchAccount,
        idem_reservation: &mut Option<IdempotencyReservation>,
    ) -> Result<ControlFlow<GuardedValue, Settled>> {
        let &Call {
            args,
            session_id,
            caller,
            trace_id,
            server,
            tool,
            target,
            arguments,
            want_full,
            arm_key,
            profile,
            policy_epoch,
            caller_proof,
            credential_owner,
            backend,
            caller_credential,
            dispatch_binding,
            protocol_revision,
            ..
        } = call;
        let Dispatched {
            result,
            prompt_cache_key,
            ..
        } = dispatched;
        let api_key_name = caller.api_key_name;
        let caller_identity = caller.grant_subject.as_ref();
        let verified_identity = caller.verified_identity;
        // Answering or asking? Read once, because the same verdict decides two
        // things: whether the idempotency key may be settled as completed, and
        // whether the question may be put to this client at all.
        let mut interim = crate::protocol::mrtr::InputRequired::from_result(result);
        // Whether the backend said it acted, which is a different question from
        // whether the gateway can carry what it sent. Both post-dispatch gates
        // below need this one, not `interim`.
        let stopped_to_ask = crate::protocol::mrtr::InputRequired::claims_input_required(result);

        // The backend has acted. Every early return below this point must settle
        // the idempotency key as completed rather than release it: a released key
        // readmits the retry that would execute the side effect a second time.
        // The dispatch-error path above releases only a refusal that provably
        // never reached the backend, and takes the reservation when it does, so
        // a dispatched failure arrives here still live and is settled by this
        // commit. The stored value withholds the response body on purpose — a
        // gate below may be about to block it.
        //
        // An interim result is excluded because there the backend has said it
        // did *not* act: it stopped to ask. Settling one would be false and
        // permanent — the placeholder reads "side effect executed", so a client
        // that declared the capability it was missing and retried under the same
        // key would be served that sentence in place of its question.
        // `mark_completed` refuses a non-final result for this reason
        // (`src/idempotency.rs:531-539`), and the placeholder is deliberately
        // final-shaped, so only this condition keeps the rule for it.
        //
        // The condition reads the backend's own claim rather than `interim`,
        // because `from_result` declines shapes that do claim `input_required`
        // — a malformed `inputRequests`, a round with neither question nor
        // state. Those are unusable, not finished, and settling one would write
        // "side effect executed" over a backend that stopped to ask. Keying on
        // the classification would exempt exactly the shapes it rejects.
        if let Some(reservation) = idem_reservation.as_mut() {
            if stopped_to_ask {
                reservation.disarm();
            } else {
                reservation.commit(&withheld_side_effect());
            }
        }

        // MRTR.9: a question the client never said it could answer is refused
        // where the backend's interim result is first seen — before a
        // continuation is minted and before the result is cached, so nothing
        // survives the refusal. Relaying it instead leaves the client holding
        // an `inputRequests` entry it has no handler for and the backend
        // holding an exchange that can never be completed.
        undeclared_gate::refuse_undeclared(result, caller, server, tool, trace_id)
            .inspect_err(|_| crate::gateway::delivery_facts::refused_while_vouched())?;

        if let Some(answer) = self
            .bridge_legacy_ask(
                caller,
                args,
                session_id,
                (server, tool),
                trace_id,
                arguments,
                prompt_cache_key.as_deref(),
                want_full,
                (arm_key, api_key_name),
                (caller_identity, caller_proof, credential_owner.as_deref()),
                verified_identity,
                caller_credential,
                dispatch_binding.as_deref(),
                bridge_account_credential,
                (policy_epoch, protocol_revision),
                &profile.name,
                backend.as_ref(),
                idem_reservation,
                result,
                &mut interim,
            )
            .await?
        {
            return Ok(ControlFlow::Break(answer));
        }

        // MRTR.2: the backend's own `requestState` never reaches the client.
        // It is sealed into a continuation the gateway minted, bound to this
        // caller and this request, and the envelope goes out in its place. The
        // backend's string is opaque to us and unauthenticated to it — a client
        // that could echo one it was not given could resume an exchange never
        // offered to it, and the backend has no way to tell the difference.
        //
        // Minted here, where the capability gate has just decided the question
        // may be asked at all: a continuation for a question the client will
        // never be shown is a redeemable envelope for an exchange that cannot
        // happen. Its slot is held in this request's scope: released with the
        // scope unless the answer carrying it is handed off (MIK-8176).
        let mut withheld = None;
        if let Some(interim) = interim {
            // The caller the slot is charged to (MIK-8293); a caller no
            // quota key names is refused like an unbindable one.
            let Some(quota) = caller.quota_key() else {
                return Err(refuse_unbindable(server, tool, trace_id));
            };
            match worker_clock::mint_or_withhold(
                &self.continuation,
                caller.principal_source(dispatch_binding.as_deref()),
                &quota,
                target,
                tool,
                arguments,
                interim.request_state,
            )
            .await
            {
                worker_clock::Minted::Sealed(envelope) => {
                    result["requestState"] = json!(&envelope);
                    // MIK-7994: the envelope is the gateway's text, up to 8 KiB, and
                    // must not take the receipt's capped budget from the backend's
                    // prompt. Noted at the value layer: `tool_value` still reads
                    // `requestState` to know the answer is interim, not wrapped.
                    gateway_writes::note(
                        gateway_writes::Layer::Value,
                        gateway_writes::REQUEST_STATE,
                        result,
                    );
                }
                // MIK-8202 AC12: a task worker seals this later. The backend's
                // state is withheld from the payload meanwhile (MRTR.2).
                worker_clock::Minted::Withheld(binding, state) => {
                    result["requestState"] = Value::Null;
                    withheld = Some((binding, state));
                }
                worker_clock::Minted::Refused => {
                    return Err(refuse_unbindable(server, tool, trace_id));
                }
            }
        } else {
            // MRTR.2a holds for an unusable round too (MIK-8078).
            continuation::withhold_unsealed_state(result);
        }
        Ok(ControlFlow::Continue(Settled {
            stopped_to_ask,
            withheld,
        }))
    }

    /// S9 and S10, the payload gates and the delivery: the response gates,
    /// the worker hand-off, the relay receipt, the chain verdict, the cost
    /// advice, the cache and idempotency writes, then the predictions, the
    /// trace, the provenance stamp and the seal.
    #[allow(clippy::too_many_lines)] // moved verbatim from `invoke_tool_traced`, which carried it
    pub(super) fn deliver(
        &self,
        call: &Call<'_, '_>,
        dispatched: Dispatched,
        settled: Settled,
        idem_reservation: &mut Option<IdempotencyReservation>,
    ) -> Result<TracedOutcome> {
        let &Call {
            args,
            session_id,
            caller,
            trace_id,
            server,
            tool,
            arguments,
            want_full,
            client_claim,
            arm_key,
            projection_key_suffix,
            profile,
            tool_key,
            policy_epoch,
            writes_mark,
            caller_principal,
            protocol_revision,
            chained,
            read_only,
            ..
        } = call;
        let Dispatched {
            mut result,
            receipt,
            mut answered,
            #[cfg(feature = "cost-governance")]
            cost_warnings,
            ..
        } = dispatched;
        let Settled {
            stopped_to_ask,
            withheld,
        } = settled;
        let api_key_name = caller.api_key_name;
        let call = dispatch_guards::BackendCall {
            server,
            tool,
            session_id,
            api_key_name,
            cost_key: caller.cost_key(),
            trace_id,
            caller_key: None,
        };
        let (gated, effect) = self.gate_payload(&call, result)?;
        if effect == super::super::response_security::GateEffect::Withheld {
            // Per step in a composite: refused only while this request still
            // vouches for the delivery, so a plan that goes on is not marked.
            crate::gateway::delivery_facts::refused_while_vouched();
        }
        // The gates have run on the payload; the worker takes it, unminted.
        if let Some(withheld) = withheld
            && worker_clock::hand_to_worker(withheld, gated.clone())
        {
            return Err(unbindable_continuation(server, tool));
        }
        result = gated;
        // A dispatch error the backend never saw, answered as a tool result,
        // is the gateway's text: no receipt names the backend for it.
        if super::audit::pre_send_now() != crate::gateway::meta_mcp::dispatch_log::PreSend::Refused
        {
            self.stage_relay_receipt(caller.relay_caller(session_id), (server, tool), &result);
        }
        // A chained backend is eligible only with a checked upstream outcome.
        let (source, upstream) = super::super::response_security::chain_after_gates(
            effect,
            receipt.eligibility(),
            receipt.into_upstream(),
        );
        answered &= source == crate::protocol::ChainSource::Backend;

        #[cfg(feature = "cost-governance")]
        self.inject_cost_advice(&mut result, &cost_warnings, tool, caller, session_id);
        let written = gateway_writes::snapshot_since(writes_mark);

        if read_only {
            self.store_response(
                caller,
                args,
                (server, tool),
                trace_id,
                (want_full, stopped_to_ask, chained),
                protocol_revision,
                arguments,
                (projection_key_suffix, caller_principal),
                (&profile.name, policy_epoch),
                (&result, &written),
            );
        }

        if let Some(reservation) = idem_reservation.as_mut()
            && reservation.complete_read(&result, (self.dispatch_reading(args), written))
        {
            debug!(
                target: INVOKE_TARGET,
                server,
                tool,
                trace_id,
                "Idempotency entry marked completed"
            );
        }

        let predictions = self.record_and_predict(session_id, arm_key, tool_key, caller.scope());

        // SEP-1862 dynamic promotion: auto-surface this tool in the session's
        // tools/list after a successful invocation so the LLM can call it
        // directly next time without going through gateway_invoke.
        #[cfg(feature = "spec-preview")]
        self.promote_tool_for_session(session_id, tool_key);

        // The invocation record is written by `invoke_tool`, around this
        // function, so a refused or failed call is recorded too (D1-d).

        // === POST-INVOKE: Response signing (ADR-001, OWASP ASI07) ===
        //
        // Sign the assembled response after all post-processing (cost warnings,
        // security findings, trace augmentation).  The MAC covers the full
        // response body so consumers can detect any tampering.
        let mut final_result =
            augment_with_trace(augment_with_predictions(result, predictions), trace_id);
        // Runtime provenance stamp (MIK-6905): off by default. Inserted BEFORE
        // response signing so the message MAC also covers the receipt. Cache
        // hits at the early returns above are stamped with cache=Hit; this is
        // the live-fetch (cache-miss) path.
        // The direct route stamps through `stamp_direct_result`; every route's
        // public signature is sealed at delivery by `seal_public_provenance`.
        final_result = self.maybe_stamp_provenance(
            final_result,
            server,
            tool,
            api_key_name,
            crate::trust::CacheOutcome::Miss,
            client_claim.as_ref(),
        );

        // `result` passed apply_context_integrity earlier on this path; the steps
        // since then add only gateway-authored metadata. Seal at the delivery
        // boundary so the return type proves the guard ran.
        let sealed = GuardedValue::sealed_by_guard(final_result);
        Ok(TracedOutcome::Live(if answered {
            sealed.backend(upstream)
        } else {
            sealed
        }))
    }
}

/// The refusal for a continuation the gateway cannot bind to this caller,
/// logged once at the refusal (MIK-8488 INVOKE.6: the post-dispatch side's one
/// copied refusal). The worker hand-off's own refusal does not log and does not
/// use it.
fn refuse_unbindable(server: &str, tool: &str, trace_id: &str) -> crate::Error {
    warn!(
        target: INVOKE_TARGET,
        server,
        tool,
        trace_id,
        "Cannot mint a continuation for this caller; refusing"
    );
    unbindable_continuation(server, tool)
}
