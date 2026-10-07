// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The steps `invoke_tool_traced` runs before it dispatches: the shared-login
//! guard, the idempotency and R2 admissions, the response-cache read, the
//! audit line and the prompt-cache key.

use std::sync::atomic::Ordering;

use serde_json::Value;
use tracing::debug;

use super::{
    CallerCredential, GATEWAY_INVOKE_LOGGER, GuardedValue, INVOKE_TARGET, REQUEST_COUNTER, audit,
    cache_reads,
};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::prompt_cache::CacheKeyDeriver;
use crate::gateway::meta_mcp::support::{
    CachePrincipal, augment_with_predictions, augment_with_trace, response_cache_key_for,
};
use crate::idempotency::{GuardOutcome, IdempotencyReservation, enforce};
use crate::protocol::LoggingLevel;
use crate::transport::notification_sink::emit_log;
use crate::{Error, Result};

impl MetaMcp {
    pub(super) fn refuse_shared_oauth_login(
        &self,
        server: &str,
        tool: &str,
        caller_credential: &CallerCredential,
        backend: Option<&crate::backend::Backend>,
    ) -> Result<()> {
        // ADR-008 INV-2 fail-closed guard. On a multi-user gateway, a backend
        // whose OAuth token is held once by the gateway (keyed by backend, not
        // by user — src/oauth/storage.rs) must NOT have that token attached for
        // an arbitrary caller: doing so serves user A's login to user B. Refuse
        // UNLESS a per-user credential was resolved above (identity propagation
        // minted caller-specific headers) or the operator blessed the account
        // as shared (`oauth.shared_account = true`, logged). A single-user
        // gateway never enters this branch. This never falls back to the shared
        // token (INV-1): it refuses.
        if self.multi_user.load(Ordering::Relaxed)
            && caller_credential.headers.is_empty()
            && backend.is_some_and(crate::backend::Backend::oauth_requires_per_user_isolation)
        {
            tracing::warn!(target: INVOKE_TARGET,
                server = %server,
                "refused: multi-user gateway would serve a gateway-held OAuth token \
                 that is not isolated per user (ADR-008 INV-2)"
            );
            // ADR-014 §3: the same fact, on the caller's own stream. A refusal
            // the client can see beats one it has to ask an operator to read
            // out of a log, and the `-32001` below carries the remedy but not
            // the severity.
            emit_log(LoggingLevel::Warning, GATEWAY_INVOKE_LOGGER, || {
                serde_json::json!({
                    "message": "refused: multi-user gateway would serve a gateway-held \
                                OAuth token that is not isolated per user (ADR-008 INV-2)",
                    "server": server,
                    "tool": tool,
                })
            });
            return Err(Error::json_rpc(
                -32001,
                format!(
                    "Backend '{server}' uses a gateway-held OAuth login that is not \
                     isolated per user. On a multi-user gateway this call is refused so \
                     one user's token is never served to another. Fix: supply a per-user \
                     credential (enable identity propagation for this backend), or set \
                     `oauth.shared_account = true` if this is a genuinely shared service \
                     account."
                ),
            ));
        }
        Ok(())
    }

    /// Admits the call's idempotency key. `Some` is a stored answer the call
    /// returns as is; `None` proceeds, with the in-flight reservation (if any)
    /// left in `idem_reservation`.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn admit_idempotency_key(
        &self,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
        (server, tool): (&str, &str),
        trace_id: &str,
        (idem_key, idem_fingerprint): (Option<&str>, Option<&str>),
        (arm_key, tool_key): (Option<&str>, &str),
        api_key_name: Option<&str>,
        client_claim: Option<&crate::trust::ClientClaim>,
        idem_reservation: &mut Option<IdempotencyReservation>,
    ) -> Result<Option<GuardedValue>> {
        if let (Some(idem_cache), Some(key), Some(fingerprint)) =
            (&self.idempotency_cache, idem_key, idem_fingerprint)
        {
            // A replay restores the stored call's write record; everything
            // noted after this mark is that record (MIK-7991).
            let mark = super::gateway_writes::mark();
            match enforce(idem_cache, key, fingerprint)? {
                // A dispatched call that failed is terminal: serving the stored
                // error is what stops the retry re-running a side effect that
                // may already have committed (ADR-012 consequence 1).
                GuardOutcome::CachedError(error) => {
                    audit::note_cached_failure(&error);
                    // A refusal keeps its provenance across the replay as well
                    // as across the bridge boundary. Served as a generic error
                    // it would skip the delivery-refusal projection and count
                    // as a client failure — a retry could then open the circuit
                    // breaker on a client whose only fault was retrying a call
                    // the gateway itself refused.
                    if crate::gateway::meta_mcp::invoke::dispatch_guards::is_firewall_refusal(
                        &error,
                    ) {
                        debug!(target: INVOKE_TARGET,
                            server,
                            tool, key, trace_id, "Idempotency cache hit (firewall refusal)"
                        );
                        return Err(Error::ResponseFirewallRefused);
                    }
                    let (code, message) = crate::idempotency::cached_error_parts(&error);
                    debug!(target: INVOKE_TARGET,
                        server,
                        tool, key, trace_id, "Idempotency cache hit (failed)"
                    );
                    return Err(Error::json_rpc(code, message));
                }
                GuardOutcome::CachedResult(cached) => {
                    debug!(target: INVOKE_TARGET, server, tool, key, trace_id, "Idempotency cache hit");
                    // A stored side-effect notice is the gateway's own text;
                    // its first call delivered no read either (MIK-7991).
                    // Reached when the sync admission's wall-clock entry has
                    // expired before this one (a forward clock step).
                    if !super::side_effect_markers::is_gateway_notice(&cached) {
                        self.stage_relay_receipt(
                            caller.relay_caller(session_id),
                            (server, tool),
                            &super::gateway_writes::without(
                                &cached,
                                &super::gateway_writes::snapshot_since(mark),
                            ),
                        );
                    }
                    if let Some(ref stats) = self.stats {
                        stats.record_cache_hit();
                    }
                    telemetry_metrics::counter!(
                        "mcp_cache_hits_total",
                        "server" => server.to_owned(),
                        "kind" => "idempotency"
                    )
                    .increment(1);
                    let predictions =
                        self.record_and_predict(session_id, arm_key, tool_key, caller.scope());
                    return Ok(Some(GuardedValue::from_cache(cached).augment(|v| {
                        let v =
                            augment_with_trace(augment_with_predictions(v, predictions), trace_id);
                        self.maybe_stamp_provenance(
                            v,
                            server,
                            tool,
                            api_key_name,
                            crate::trust::CacheOutcome::Hit,
                            client_claim,
                        )
                    })));
                }
                GuardOutcome::Proceed(reservation) => {
                    *idem_reservation = Some(reservation);
                    debug!(target: INVOKE_TARGET,
                        server,
                        tool, key, trace_id, "Idempotency key registered as in-flight"
                    );
                }
            }
        }
        Ok(None)
    }

    /// The R2 undeclared-key refusal. `Some` is the sealed refusal the call
    /// returns; `None` proceeds.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn answer_undeclared_key(
        &self,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
        (server, tool): (&str, &str),
        backend: Option<&std::sync::Arc<crate::backend::Backend>>,
        arguments: &Value,
        dispatch_binding: Option<&str>,
        caller_credential: &CallerCredential,
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
        idem_reservation: &mut Option<IdempotencyReservation>,
    ) -> Result<Option<GuardedValue>> {
        // MIK-7570.SCHEMA.1 (R2): refused above the response cache, so a result
        // cached before the rule (or under `off`) is never served to a call the
        // rule refuses, and before `mark_dispatched`, so a refusal is never
        // dispatched, charged or counted as an invocation. Nothing ran, so the
        // idempotency key is released for an honest retry.
        // F13: a cold slot is listed first, as this caller; the slot's
        // failsafe refusing that list answers as a refused dispatch does.
        let checked_at = std::time::Instant::now();
        let refusal = self.undeclared_key_refusal(
            (server, backend),
            tool,
            arguments,
            dispatch_binding,
            &caller_credential.headers,
            (caller.scope(), session_id),
        );
        let refusal = match refusal.await {
            Ok(refusal) => refusal,
            Err(e) => {
                let managed = caller_credential.managed.as_ref();
                match self
                    .answer_refused_fill(
                        (server, tool),
                        e,
                        managed,
                        (checked_at, self.hint_surface(caller)),
                    )
                    .await
                {
                    Ok((value, _)) => Some(value),
                    Err(e) => {
                        if let Some(reservation) = idem_reservation.as_mut() {
                            reservation.release();
                        }
                        return self.with_connect_offer(Err(e), verified_identity).await;
                    }
                }
            }
        };
        if let Some(refusal) = refusal {
            if let Some(reservation) = idem_reservation.as_mut() {
                reservation.release();
            }
            return Ok(Some(GuardedValue::sealed_by_guard(refusal)));
        }
        Ok(None)
    }

    /// A response-cache hit, served as the call's answer; `None` on a miss or
    /// when the call may not be served from the cache.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn serve_cached_response(
        &self,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        session_id: Option<&str>,
        (server, tool): (&str, &str),
        trace_id: &str,
        (want_full, chained): (bool, bool),
        protocol_revision: Option<&'static str>,
        arguments: &Value,
        (projection_key_suffix, caller_principal): (&str, &CachePrincipal),
        (routing_profile, policy_epoch): (&str, u64),
        (arm_key, tool_key): (Option<&str>, &str),
        api_key_name: Option<&str>,
        client_claim: Option<&crate::trust::ClientClaim>,
        idem_reservation: &mut Option<IdempotencyReservation>,
    ) -> Option<GuardedValue> {
        if !want_full
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
            && let Some((cached, read, writes)) = cache.get_read(&cache_key)
        {
            cache_reads::restore(read.as_ref());
            debug!(target: INVOKE_TARGET, server, tool, trace_id, "Cache hit");
            // MIK-7991: the hit serves what the storing call wrote; its
            // receipt and the delivered answer's rebuild both leave it out.
            self.stage_relay_receipt(
                caller.relay_caller(session_id),
                (server, tool),
                &super::gateway_writes::without(&cached, &writes),
            );
            super::gateway_writes::restore(&writes);
            if let Some(ref stats) = self.stats {
                stats.record_cache_hit();
            }
            telemetry_metrics::counter!(
                "mcp_cache_hits_total",
                "server" => server.to_owned(),
                "kind" => "response"
            )
            .increment(1);
            // Terminal state on the response-cache-hit return: settle through
            // the reservation, or its `Drop` would remove what was just stored.
            if let Some(reservation) = idem_reservation.as_mut() {
                reservation.complete_read(&cached, (read, writes));
            }
            let predictions =
                self.record_and_predict(session_id, arm_key, tool_key, caller.scope());
            return Some(GuardedValue::from_cache(cached).augment(|v| {
                let v = augment_with_trace(augment_with_predictions(v, predictions), trace_id);
                self.maybe_stamp_provenance(
                    v,
                    server,
                    tool,
                    api_key_name,
                    crate::trust::CacheOutcome::Hit,
                    client_claim,
                )
            }));
        }
        None
    }
}

pub(super) fn log_tool_invoked(
    caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    server: &str,
    tool: &str,
    trace_id: &str,
) {
    let agent_id = caller.agent_id;
    // === OWASP ASI03: per-agent identity audit log ===
    //
    // Proven and declared are recorded as DISTINCT fields, always. A record
    // that collapses them cannot tell "agent-a proved it" from "someone
    // said agent-a", which is the signal funded change 4 exists to create.
    // `agent_id` keeps its name and its meaning tightens: it is now the
    // proven principal only, never a caller-supplied tag.
    let agent_label = agent_id.map_or("anonymous", |a| a.as_str());
    let declared_label = caller
        .agent_declared
        .map(crate::security::DeclaredAgentLabel::as_str);
    tracing::info!(target: INVOKE_TARGET,
        agent_id = %agent_label,
        agent_declared = declared_label,
        server   = %server,
        tool     = %tool,
        trace_id = %trace_id,
        "tool invoked"
    );
    // ADR-014 §3: the audit line, on the stream of the request that asked
    // for it. Same fields as the `tracing` call above, deliberately -- a
    // caller correlating its own invocations should not have to map one
    // vocabulary onto another.
    emit_log(LoggingLevel::Info, GATEWAY_INVOKE_LOGGER, || {
        serde_json::json!({
            "message": "tool invoked",
            "agent_id": agent_label,
            "agent_declared": declared_label,
            "server": server,
            "tool": tool,
            "trace_id": trace_id,
        })
    });
    debug!(target: INVOKE_TARGET, server, tool, trace_id, "Invoking tool");
}

pub(super) fn derive_prompt_cache_key(args: &Value, session_id: Option<&str>) -> Option<String> {
    // Derive a prompt_cache_key for OpenAI-compatible backends.
    // Priority: explicit _meta.prompt_cache_key > hash of a real session id.
    args.get("_meta")
        .and_then(|m| m.get("prompt_cache_key"))
        .and_then(Value::as_str)
        .map(CacheKeyDeriver::from_header)
        .or_else(|| {
            session_id.filter(|sid| !sid.is_empty()).map(|sid| {
                let deriver = CacheKeyDeriver::with_slots(3);
                let base = CacheKeyDeriver::from_context(sid);
                let req_idx = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
                let slot = deriver.slot_for_request(req_idx);
                deriver.key_for_slot(&base, slot)
            })
        })
}

#[cfg(test)]
#[path = "prompt_cache_key_tests.rs"]
mod prompt_cache_key_tests;
