// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The steps `invoke_tool_traced` runs on a dispatch's result: the recovery
//! hint on a tool-level error, the settlement of a dispatch error, the cost
//! advice and the response-cache write.

use serde_json::Value;
use tracing::debug;

use super::{INVOKE_TARGET, classify_from_detail, dispatch_error_result, withheld_side_effect};
use super::{LostRoundRoute, settle_lost_round};
#[cfg(feature = "cost-governance")]
use crate::cost_accounting::suggestions;
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::support::{CachePrincipal, response_cache_key_for};
use crate::gateway::recovery::{
    MetaSurface, RecoveryContext, attach_recovery, recovery_for_surface,
};
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
    // call — but only when the `recovery` field is not already set.
    if value
        .get("isError")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
        && value.get("recovery").is_none()
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
        let value = attach_recovery(value, hint);
        // MIK-7939: the hint is the gateway's text, never a receipt's.
        super::gateway_writes::note(super::gateway_writes::Layer::Value, &["recovery"], &value);
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
        // A11-c: a 401 on a managed credential forces at most one
        // refresh, then either asks the user to reconnect (an offer,
        // returned as the refusal it is) or tells the caller whether a
        // retry can help (the recovery hint below).
        let e = match managed {
            Some(managed) if is_upstream_unauthorized(&e) => managed.after_upstream_401(e).await,
            _ => e,
        };
        if crate::personal_accounts::refusal::marked(&e).is_some() {
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
        if !cost_warnings.is_empty()
            && let Some(obj) = result.as_object_mut()
        {
            obj.insert(
                "_cost_warnings".to_string(),
                serde_json::json!(cost_warnings),
            );
            super::gateway_writes::note(
                super::gateway_writes::Layer::Value,
                &["_cost_warnings"],
                result,
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
                    && let Some(obj) = result.as_object_mut()
                {
                    obj.insert(
                        "_cost_suggestion".to_string(),
                        serde_json::json!({
                            "message": suggestion.reason,
                            "alternative": suggestion.alternative,
                            "savings_per_call": suggestion.savings_per_call,
                            "alternative_cost": suggestion.alternative_cost,
                        }),
                    );
                    super::gateway_writes::note(
                        super::gateway_writes::Layer::Value,
                        &["_cost_suggestion"],
                        result,
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
        result: &Value,
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
                self.dispatch_reading(args),
                self.default_cache_ttl,
            )
        {
            debug!(target: INVOKE_TARGET, server, tool, trace_id, ttl = ?self.default_cache_ttl, "Cached result");
        }
    }
}
