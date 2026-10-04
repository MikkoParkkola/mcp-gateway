// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tool invocation, dispatch, and operator-control handlers.
//!
//! Implements `gateway_invoke` (with idempotency and error-budget tracking),
//! `gateway_get_stats`, `gateway_kill_server`, `gateway_revive_server`,
//! `gateway_list_disabled_capabilities`, `gateway_reload_config`,
//! `gateway_webhook_status`, and `gateway_run_playbook`.

use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};
use tracing::{debug, warn};

#[cfg(feature = "cost-governance")]
use crate::cost_accounting::suggestions;
use crate::gateway::input_bridge::BridgeError;
use crate::idempotency::{GuardOutcome, IdempotencyReservation, derive_key, enforce};
use crate::identity_propagation::CallerProof;
use crate::protocol::LoggingLevel;
use crate::security::http_diagnostics::is_upstream_unauthorized;
use crate::transport::notification_sink::emit_log;
use crate::{Error, Result};

/// `logger` field on every `notifications/message` this module raises
/// (ADR-014 §3). One name for both sites: a caller filtering on the logger
/// wants the tool-invocation channel, not one name per outcome.
const GATEWAY_INVOKE_LOGGER: &str = "gateway.invoke";

/// The per-user identity-propagation credential resolved once for a single
/// dispatch (MIK-6704 / ADR-007). Carries the headers to put on the wire and
/// the cache binding to isolate cached results by user+audience. The default
/// (empty headers, `None` binding) means "not identity-scoped" — plain dispatch
/// and a shared cache key.
///
/// `Debug` is implemented manually to REDACT header values: `headers` may
/// carry a live bearer token/assertion resolved via identity propagation, and
/// a derived `Debug` would leak it through any `tracing!(?cred)`, error
/// context, or test-failure dump (CWE-532). Mirrors the sibling
/// [`crate::identity_propagation::PropagatedCredential`]'s redacting `Debug`
/// impl — header names are shown, values are replaced with `<redacted>`.
#[derive(Default)]
struct CallerCredential {
    /// Per-request outbound headers (empty = none). Never logged verbatim —
    /// see the redacting `Debug` impl below.
    headers: Vec<(String, String)>,
    /// Collision-safe user+audience cache binding. `Some` → mix into cache keys
    /// so per-user results stay isolated (IDP.8); `None` → shared key is safe.
    cache_binding: Option<String>,
    /// A11-e′: the managed custody handle and the lease the headers were
    /// released under, kept to the post-dispatch 401 site. Only a vault mint
    /// produces one; every other strategy leaves it `None`.
    managed: Option<crate::personal_accounts::ManagedLease>,
}

/// Headers, cache binding and, for a managed account, the lease they were
/// released under (A11-e′).
pub(crate) type HeldCredential = (
    Vec<(String, String)>,
    Option<String>,
    Option<crate::personal_accounts::ManagedLease>,
);

impl std::fmt::Debug for CallerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact header VALUES (they may carry a live token); show names only.
        let header_names: Vec<&str> = self.headers.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("CallerCredential")
            .field("headers", &format_args!("{header_names:?} = <redacted>"))
            .field("cache_binding", &self.cache_binding)
            .field("managed", &self.managed.is_some())
            .finish()
    }
}

mod guarded;
use super::response_security::chain_receipt::ChainReceipt;
use guarded::GuardedValue;

use super::super::meta_mcp_helpers::{extract_required_str, parse_tool_arguments};
#[cfg(test)]
use super::super::recovery::ErrorCategory;
use super::super::recovery::{RecoveryContext, attach_recovery, recovery_for};
use super::MetaMcp;
use super::prompt_cache::CacheKeyDeriver;
mod side_effect_markers;
mod undeclared_gate;
// D1: the invocation record, written around `invoke_tool_traced`.
pub(crate) mod audit;
pub(crate) mod dispatch_guards; // S1-S4 stage methods (design doc 2026-09-27 #2.1)
mod r2_check;
// #1962: settlement of a bridged round's key, kept out of this file's size baseline.
mod bridge_settle;
pub(crate) mod cache_reads;
pub(super) use bridge_settle::arm_for_dispatch;
pub(super) use bridge_settle::classify_bridged_dispatch_error;
mod withheld_evidence;
// #1961: the account-bound MCP mint, kept out of this file's size baseline.
mod account_mint;

use super::support::{
    augment_with_predictions, augment_with_trace, idempotency_key_for, response_cache_key_for,
};
use side_effect_markers::{uncertain_side_effect, withheld_side_effect};
mod output_shape;
mod provenance_stamp;
pub(crate) mod relay;
pub(super) use output_shape::enforce_output_schema;

mod admin;
mod bridge_dispatch;
mod budget;
mod continuation;
mod dispatch;
mod errors;
mod policy;
mod projection;
mod propagation;
use bridge_dispatch::{BridgeDispatcher, run_input_bridge, undeclared_input_request};
pub(super) use bridge_dispatch::{
    REQUIRED_CAPABILITIES_DATA_KEY, UNSUPPORTED_ELICITATION_MODE_DATA_KEY,
};
pub(super) use continuation::retry_origin_backend;
use continuation::{OutboundRetry, mint_continuation, redeem_retry, unbindable_continuation};
pub(super) use errors::BudgetOutcome;
#[cfg(test)]
use errors::classify_dispatch_error;
use errors::{classify_from_detail, dispatch_error_result};
use projection::{
    apply_capability_projection, call_capability_tool_with_identity, emit_projection_ab_event,
    extract_client_claim, json_is_populated,
};

/// Monotonically increasing request counter for load-balanced cache key slot selection.
///
/// Global across all backends; overflow wraps (u64 → effectively infinite for our purposes).
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

impl MetaMcp {
    /// Inner implementation executed within a trace-ID scope.
    ///
    /// Returns a [`GuardedValue`]: every success path must produce one, so the
    /// render guard cannot be bypassed at the chokepoint (MIK-6690).
    #[allow(clippy::too_many_lines)] // Complex dispatch logic; splitting further harms readability
    async fn invoke_tool_traced(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        trace_id: &str,
    ) -> Result<GuardedValue> {
        // Unpacked once, here, so the context travels whole across the call
        // boundary for the same reason `invoke_tool` takes it whole: no call
        // site can pass an authorizer without the identity it authorizes.
        let api_key_name = caller.api_key_name;
        let agent_id = caller.agent_id;
        let caller_identity = caller.grant_subject.as_ref();
        let verified_identity = caller.verified_identity;
        let provenance = caller.provenance();
        let caller_proof = CallerProof::new(verified_identity, provenance);

        // Capture once, before any authorization input is read. A bump after
        // this strands the insert under the epoch this call was authorized
        // in. A second load at the write site is the 4.g race.
        let policy_epoch = self.policy_epoch.load(Ordering::Acquire);

        let server = extract_required_str(args, "server")?;
        let tool = extract_required_str(args, "tool")?;

        self.check_or_stamp(args, session_id, caller, (server, tool))?;

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
        let arm_key = caller.experiment_key(session_id);
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
        // Resolve the per-user propagation credential ONCE (MIK-6734 / ADR-007).
        // Single identity gate: fail-closed here for a required backend, and the
        // resolved `cache_binding` (user+audience) is mixed into every cache key
        // so per-user results cache in ISOLATION rather than leaking across users
        // (IDP.3/8) — reused verbatim at dispatch so there is no re-mint or drift.
        let backend = self.backends.get(server);
        let caller_credential = if let Some(idp_cfg) = backend
            .as_ref()
            .and_then(|b| b.identity_propagation_config().cloned())
        {
            let resolved = self.resolve_caller_credential_as(
                server,
                backend.as_deref(),
                &idp_cfg,
                caller_proof,
            );
            self.with_connect_offer(resolved.await, verified_identity)
                .await?
        } else {
            Self::refuse_unbound_account_backend(server, backend.as_deref())?;
            CallerCredential::default()
        };

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
            && backend
                .as_deref()
                .is_some_and(crate::backend::Backend::oauth_requires_per_user_isolation)
        {
            tracing::warn!(
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
        // THE CAPABILITY ROUTE'S ACCOUNT BOUNDARY, RESOLVED HERE — BEFORE THE
        // OUTER RESPONSE CACHE IS CONSULTED.
        //
        // The MCP route resolves its credential above for the same reason: a
        // cache key built before the caller's credential is known cannot name
        // the caller. A REST capability's credential comes from its own
        // `auth.account` (its PRIMARY auth), not the BACKEND-keyed map, and must
        // resolve here, not in the executor, which runs after this lookup. It is
        // rechecked at dispatch, never minted twice; a refusal returns now.
        let resolving = self.resolve_capability_account_credential(server, tool, caller_proof);
        let account_credential = self
            .with_connect_offer(resolving.await, verified_identity)
            .await?;
        // ONE binding for both cache layers and for the transport's session
        // partitioning. The MCP route's propagation binding when there is one,
        // otherwise the account credential's — they are never both present,
        // because one describes a backend's propagation config and the other a
        // capability's account reference.
        let dispatch_binding = caller_credential.cache_binding.clone().or_else(|| {
            account_credential
                .as_ref()
                .map(|prepared| prepared.cache_binding().to_owned())
        });
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
            &projection_key_suffix,
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
            let base = derive_key(&format!("{server}:{tool}"), &arguments);
            let discriminator = caller.retry.key_discriminator();
            format!("{base}{discriminator}")
        });

        // Owns the in-flight entry from admission until a terminal state. Its
        // `Drop` releases the key, so an early return after dispatch cannot
        // strand the entry as in-flight until the guard times out.
        let mut idem_reservation: Option<IdempotencyReservation> = None;
        if let (Some(idem_cache), Some(key), Some(fingerprint)) =
            (&self.idempotency_cache, &idem_key, &idem_fingerprint)
        {
            match enforce(idem_cache, key, fingerprint)? {
                // A dispatched call that failed is terminal: serving the stored
                // error is what stops the retry re-running a side effect that
                // may already have committed (ADR-012 consequence 1).
                GuardOutcome::CachedError(error) => {
                    audit::note_cached();
                    // A refusal keeps its provenance across the replay as well
                    // as across the bridge boundary. Served as a generic error
                    // it would skip the delivery-refusal projection and count
                    // as a client failure — a retry could then open the circuit
                    // breaker on a client whose only fault was retrying a call
                    // the gateway itself refused.
                    if crate::gateway::meta_mcp::invoke::dispatch_guards::is_firewall_refusal(
                        &error,
                    ) {
                        debug!(
                            server,
                            tool, key, trace_id, "Idempotency cache hit (firewall refusal)"
                        );
                        return Err(Error::ResponseFirewallRefused);
                    }
                    let (code, message) = crate::idempotency::cached_error_parts(&error);
                    debug!(
                        server,
                        tool, key, trace_id, "Idempotency cache hit (failed)"
                    );
                    return Err(Error::json_rpc(code, message));
                }
                GuardOutcome::CachedResult(cached) => {
                    debug!(server, tool, key, trace_id, "Idempotency cache hit");
                    self.stage_relay_receipt(
                        caller.relay_caller(session_id),
                        (server, tool),
                        &cached,
                    );
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
                        self.record_and_predict(session_id, arm_key, &tool_key, caller.scope());
                    return Ok(GuardedValue::from_cache(cached).augment(|v| {
                        let v =
                            augment_with_trace(augment_with_predictions(v, predictions), trace_id);
                        self.maybe_stamp_provenance(
                            v,
                            server,
                            tool,
                            api_key_name,
                            crate::trust::CacheOutcome::Hit,
                            client_claim.as_ref(),
                        )
                    }));
                }
                GuardOutcome::Proceed(reservation) => {
                    idem_reservation = Some(reservation);
                    debug!(
                        server,
                        tool, key, trace_id, "Idempotency key registered as in-flight"
                    );
                }
            }
        }

        // Defense in depth on an already-classified value: the exact set both
        // layers accept, so a value that is not a revision this build serves —
        // including a whitespace-padded spelling of one that is — bypasses the
        // cache instead of naming a bucket of its own. Never trimmed onto a
        // canonical revision.
        let protocol_revision = caller
            .protocol_revision
            .and_then(crate::protocol::meta::served_revision);

        // MIK-7570.SCHEMA.1 (R2): refused above the response cache, so a result
        // cached before the rule (or under `off`) is never served to a call the
        // rule refuses, and before `mark_dispatched`, so a refusal is never
        // dispatched, charged or counted as an invocation. Nothing ran, so the
        // idempotency key is released for an honest retry.
        // F13: a cold slot is listed first, as this caller; the slot's
        // failsafe refusing that list answers as a refused dispatch does.
        let checked_at = std::time::Instant::now();
        let refusal = self.undeclared_key_refusal(
            (server, backend.as_ref()),
            tool,
            &arguments,
            dispatch_binding.as_deref(),
            &caller_credential.headers,
            (caller.scope(), session_id),
        );
        let refusal = match refusal.await {
            Ok(refusal) => refusal,
            Err(e) => {
                let managed = caller_credential.managed.as_ref();
                match self
                    .answer_refused_fill((server, tool), e, managed, checked_at)
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
            return Ok(GuardedValue::sealed_by_guard(refusal));
        }

        // Counted only for a call the cache would otherwise have served, so an
        // `unresolved_principal` count always means a real bypass.
        if !want_full && protocol_revision.is_some() && self.cache.is_some() {
            super::support::note_cache_bypass(&caller_principal, "meta");
        }
        // A chained backend's answer is bound to one challenge: no cache (D7).
        let chained = self.is_chained(backend.as_deref());
        if !want_full
            && !chained
            && protocol_revision.is_some()
            && let Some(ref cache) = self.cache
            && let Some(cache_key) = response_cache_key_for(
                server,
                tool,
                &arguments,
                &projection_key_suffix,
                &caller_principal,
                caller.retry,
                crate::cache::KeyContext {
                    routing_profile: &profile.name,
                    protocol_revision,
                    policy_epoch,
                },
            )
            && let Some((cached, read)) = cache.get_read(&cache_key)
        {
            cache_reads::restore(read.as_ref());
            debug!(server, tool, trace_id, "Cache hit");
            self.stage_relay_receipt(caller.relay_caller(session_id), (server, tool), &cached);
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
                reservation.complete_read(&cached, read);
            }
            let predictions =
                self.record_and_predict(session_id, arm_key, &tool_key, caller.scope());
            return Ok(GuardedValue::from_cache(cached).augment(|v| {
                let v = augment_with_trace(augment_with_predictions(v, predictions), trace_id);
                self.maybe_stamp_provenance(
                    v,
                    server,
                    tool,
                    api_key_name,
                    crate::trust::CacheOutcome::Hit,
                    client_claim.as_ref(),
                )
            }));
        }

        if let Some(ref stats) = self.stats {
            stats.record_invocation(server, tool);
        }
        if let Some(ref ranker) = self.ranker {
            ranker.record_use(server, tool);
        }

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
        tracing::info!(
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
        debug!(server, tool, trace_id, "Invoking tool");

        // === PRE-INVOKE: Cost governance budget check ===
        //
        // Returns the warnings to inject post-dispatch and blocks when the
        // budget is exceeded (returns JSON-RPC -32003 error).
        #[cfg(feature = "cost-governance")]
        let mut admission = self.admit_spend_for(&dispatch_guards::BackendCall {
            server,
            tool,
            session_id,
            api_key_name,
            trace_id,
        })?;
        #[cfg(feature = "cost-governance")]
        let cost_warnings = std::mem::take(&mut admission.warnings);

        // Derive a prompt_cache_key for OpenAI-compatible backends.
        // Priority: explicit _meta.prompt_cache_key > hash of a real session id.
        let prompt_cache_key: Option<String> = args
            .get("_meta")
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
            });

        // MRTR.1: a retry's answers and the backend's own state go out beside
        // `arguments`. Redeemed here rather than at the router, because this is
        // the only scope holding all five values the mint sealed — the backend
        // server and tool, its argument object, the caller's identity, and the
        // handle itself.
        // Cloned before `accounted_dispatch` takes it: a bridged round must reach
        // the backend with the credential the first round used, and an `Arc` clone
        // is that same credential rather than a second resolution of it.
        let bridge_account_credential = account_credential.clone();
        let outbound_retry =
            match redeem_retry(&self.continuation, caller, server, tool, &arguments).await {
                Ok(retry) => retry,
                Err(error) => {
                    // Refused before the backend was reached, so it has not
                    // acted: the key is released rather than settled. Settling
                    // one here would answer an honest retry, made after a fresh
                    // question, with a sentence naming a side effect nothing
                    // performed.
                    if let Some(reservation) = idem_reservation.as_mut() {
                        reservation.release();
                    }
                    return Err(error);
                }
            };

        let egress = relay::Egress {
            arguments: &arguments,
            inbound_meta: args.get("_meta"),
            prompt_cache_key: prompt_cache_key.as_deref(),
            retry: &outbound_retry,
        };
        let reservation = idem_reservation.as_mut();
        self.refuse_relay(caller, session_id, (server, tool), &egress, reservation)?;
        if let Some(execution) = caller.execution {
            execution.mark_dispatched();
        }
        // Boxed: the dispatch future is the largest thing this frame ever
        // holds, and inlining it puts `invoke_tool_traced` over
        // `clippy::large_futures` at every call site.
        // #1962: a drop during the dispatch settles the key as uncertain.
        arm_for_dispatch(idem_reservation.as_mut());
        let chain_slot = super::response_security::chain_receipt::ChainSlot::default();
        // A3 R1: only an MCP backend's own answer can be chain-eligible; a
        // capability's `Ok` also covers its local refusals and inner cache.
        let mcp_backend = self.get_capabilities().is_none_or(|cap| server != cap.name);
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
            caller_proof,
            &caller_credential.headers,
            dispatch_binding.as_deref(),
            account_credential,
            api_key_name,
            trace_id,
            policy_epoch,
            protocol_revision,
            &profile.name,
            caller.scope(),
            backend.clone(),
            &chain_slot,
        ))
        .await;
        // The spend is recorded: give the reservation back.
        #[cfg(feature = "cost-governance")]
        drop(admission);

        // A raw-receipt chain refusal is the answer, not a tool failure (D3).
        let receipt = std::mem::take(&mut *chain_slot.lock());
        if matches!(receipt, ChainReceipt::Refused)
            && let Err(error) = dispatch_result
        {
            let message = super::signing::wire_error_message(&error);
            if let Some(reservation) = idem_reservation.as_mut() {
                reservation.fail(&json!({"code": error.to_rpc_code(), "message": message}));
            }
            return Err(error);
        }
        let mut answered = mcp_backend && dispatch_result.is_ok();
        let mut result = match dispatch_result {
            Ok(value) => {
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
                    let hint = recovery_for(
                        category,
                        RecoveryContext {
                            tool: Some(tool),
                            backend: Some(server),
                            detail,
                            ..Default::default()
                        },
                    );
                    attach_recovery(value, hint)
                } else {
                    value
                }
            }
            Err(e) => {
                // A11-c: a 401 on a managed credential forces at most one
                // refresh, then either asks the user to reconnect (an offer,
                // returned as the refusal it is) or tells the caller whether a
                // retry can help (the recovery hint below).
                let e = match caller_credential.managed.as_ref() {
                    Some(managed) if is_upstream_unauthorized(&e) => {
                        managed.after_upstream_401(e).await
                    }
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
                if e.is_pre_dispatch()
                    && let Some(mut reservation) = idem_reservation.take()
                {
                    reservation.release();
                }
                // The error budget already counted this failure (the shared
                // accounting stage).  The idempotency reservation is left
                // for the commit below unless the refusal was pre-dispatch.
                dispatch_error_result(&e, tool, server)
            }
        };

        // Answering or asking? Read once, because the same verdict decides two
        // things: whether the idempotency key may be settled as completed, and
        // whether the question may be put to this client at all.
        let mut interim = crate::protocol::mrtr::InputRequired::from_result(&result);
        // Whether the backend said it acted, which is a different question from
        // whether the gateway can carry what it sent. Both post-dispatch gates
        // below need this one, not `interim`.
        let stopped_to_ask = crate::protocol::mrtr::InputRequired::claims_input_required(&result);

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
        undeclared_gate::refuse_undeclared(interim.as_ref(), caller, server, tool, trace_id)?;

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
                    server,
                    tool,
                    arguments: &arguments,
                    prompt_cache_key: prompt_cache_key.as_deref(),
                    inbound_meta: args.get("_meta"),
                    want_full,
                    session_id,
                    arm_key,
                    caller_identity,
                    caller_proof,
                    headers: &caller_credential.headers,
                    cache_binding: dispatch_binding.as_deref(),
                    account_credential: bridge_account_credential,
                    api_key_name,
                    trace_id,
                    policy_epoch,
                    protocol_revision,
                    routing_profile: &profile.name,
                    scope: caller.scope(),
                    captured: backend.clone(),
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
            idem_reservation = held.into_inner();
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
                    result = completed;
                    interim = None;
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
                        result = *last;
                        interim = crate::protocol::mrtr::InputRequired::from_result(&result);
                    }
                }
                Err(BridgeError::Undeclared {
                    key,
                    method,
                    reason,
                }) => {
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
                    warn!(
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
                    return Ok(GuardedValue::sealed_by_guard(dispatch_error_result(
                        &refused, tool, server,
                    )));
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
                    warn!(
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
        // happen.
        if let Some(interim) = interim {
            let Some(envelope) = mint_continuation(
                &self.continuation,
                caller,
                server,
                tool,
                &arguments,
                interim.request_state,
            )
            .await
            else {
                warn!(
                    server,
                    tool, trace_id, "Cannot mint a continuation for this caller; refusing"
                );
                return Err(unbindable_continuation(server, tool));
            };
            result["requestState"] = json!(envelope);
        }

        let call = dispatch_guards::BackendCall {
            server,
            tool,
            session_id,
            api_key_name,
            trace_id,
        };
        let (gated, effect) = self.gate_payload(&call, result)?;
        result = gated;
        self.stage_relay_receipt(caller.relay_caller(session_id), (server, tool), &result);
        // A chained backend is eligible only with a checked upstream outcome.
        let (source, upstream) = super::response_security::chain_after_gates(
            effect,
            receipt.eligibility(),
            receipt.into_upstream(),
        );
        answered &= source == crate::protocol::ChainSource::Backend;

        // === POST-INVOKE: Inject cost warnings and suggestions ===
        //
        // `_cost_warnings` — active at ≥80% budget consumption (Notify tier).
        // `_cost_suggestion` — present when a cheaper alternative exists.
        #[cfg(feature = "cost-governance")]
        {
            if !cost_warnings.is_empty()
                && let Some(obj) = result.as_object_mut()
            {
                obj.insert(
                    "_cost_warnings".to_string(),
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
                    }
                }
            }
        }

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
                &arguments,
                &projection_key_suffix,
                &caller_principal,
                caller.retry,
                crate::cache::KeyContext {
                    routing_profile: &profile.name,
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
            debug!(server, tool, trace_id, ttl = ?self.default_cache_ttl, "Cached result");
        }

        if let Some(reservation) = idem_reservation.as_mut()
            && reservation.complete_read(&result, self.dispatch_reading(args))
        {
            debug!(
                server,
                tool,
                key = reservation.key(),
                trace_id,
                "Idempotency entry marked completed"
            );
        }

        let predictions = self.record_and_predict(session_id, arm_key, &tool_key, caller.scope());

        // SEP-1862 dynamic promotion: auto-surface this tool in the session's
        // tools/list after a successful invocation so the LLM can call it
        // directly next time without going through gateway_invoke.
        #[cfg(feature = "spec-preview")]
        self.promote_tool_for_session(session_id, &tool_key);

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
        // ponytail: direct-backend HTTP passthrough (router/backend_handlers.rs)
        // is a separate surface — it has no MetaMcpInvoker/signer; wire when
        // provenance is needed there (threads signer through GatewayState).
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
        Ok(if answered {
            sealed.backend(upstream)
        } else {
            sealed
        })
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
mod f13_hint_scope_tests;

#[cfg(test)]
mod session_fp_tests;

#[cfg(test)]
mod response_cache_error_tests;

#[cfg(test)]
mod ask_expiry_budget_tests;
