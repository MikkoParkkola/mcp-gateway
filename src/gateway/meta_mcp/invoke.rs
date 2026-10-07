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
use super::MetaMcp;
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

use super::support::{augment_with_predictions, augment_with_trace, idempotency_key_for};
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
mod continuation;
mod dispatch;
mod errors;
mod legacy_bridge;
mod policy;
mod post_dispatch;
mod pre_dispatch;
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
use post_dispatch::attach_tool_error_recovery;
use pre_dispatch::{derive_prompt_cache_key, log_tool_invoked};
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
        let caller_identity = caller.grant_subject.as_ref();
        let verified_identity = caller.verified_identity;
        let provenance = caller.provenance();
        let caller_proof = CallerProof::new(verified_identity, provenance);
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

        self.refuse_shared_oauth_login(server, tool, &caller_credential, backend.as_deref())?;
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
            return Ok(stored);
        }

        // Defense in depth on an already-classified value: the exact set both
        // layers accept, so a value that is not a revision this build serves —
        // including a whitespace-padded spelling of one that is — bypasses the
        // cache instead of naming a bucket of its own. Never trimmed onto a
        // canonical revision.
        let protocol_revision = caller
            .protocol_revision
            .and_then(crate::protocol::meta::served_revision);

        if let Some(refusal) = self
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
            .await?
        {
            return Ok(refusal);
        }

        // Counted only for a call the cache would otherwise have served, so an
        // `unresolved_principal` count always means a real bypass.
        if !want_full && protocol_revision.is_some() && self.cache.is_some() {
            super::support::note_cache_bypass(&caller_principal, "meta");
        }
        // A chained backend's answer is bound to one challenge: no cache (D7).
        let chained = self.is_chained(backend.as_deref());
        if let Some(cached) = self.serve_cached_response(
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
        ) {
            return Ok(cached);
        }

        if let Some(ref stats) = self.stats {
            stats.record_invocation(server, tool);
        }
        if let Some(ref ranker) = self.ranker {
            ranker.record_use(server, tool);
        }

        log_tool_invoked(caller, server, tool, trace_id);

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
            caller_key: None,
        })?;
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
        // Cloned before `accounted_dispatch` takes it: a bridged round must reach
        // the backend with the credential the first round used, and an `Arc` clone
        // is that same credential rather than a second resolution of it.
        let mut bridge_account_credential = account_credential.clone();
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
            &admission,
        ))
        .await;
        // The spend is settled; an unsettled reservation is given back here.
        drop(admission);

        // A raw-receipt chain refusal is the answer, not a tool failure (D3).
        let receipt = std::mem::take(&mut *chain_slot.lock());
        if matches!(receipt, ChainReceipt::Refused)
            && let Err(error) = dispatch_result
        {
            let message = super::signing::wire_error_message(&error);
            if let Some(reservation) = idem_reservation.as_mut() {
                reservation.fail(&audit::stored_failure(
                    json!({"code": error.to_rpc_code(), "message": message}),
                ));
            }
            return Err(error);
        }
        let mut answered = mcp_backend && dispatch_result.is_ok();
        let mut result = match dispatch_result {
            Ok(value) => attach_tool_error_recovery(value, tool, server, surface),
            Err(e) => {
                self.settle_dispatch_error(
                    e,
                    caller_credential.managed.as_ref(),
                    (&mut idem_reservation, caller.execution),
                    verified_identity,
                    (server, tool, surface),
                )
                .await?
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

        if let Some(answer) = self
            .bridge_legacy_ask(
                caller,
                args,
                session_id,
                (server, tool),
                trace_id,
                &arguments,
                prompt_cache_key.as_deref(),
                want_full,
                (arm_key, api_key_name),
                (caller_identity, caller_proof),
                verified_identity,
                &caller_credential,
                dispatch_binding.as_deref(),
                &mut bridge_account_credential,
                (policy_epoch, protocol_revision),
                &profile.name,
                backend.as_ref(),
                &mut idem_reservation,
                &mut result,
                &mut interim,
            )
            .await?
        {
            return Ok(answer);
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
            // MIK-7994: the envelope is the gateway's text, up to 8 KiB, and
            // must not take the receipt's capped budget from the backend's
            // prompt. Noted at the value layer: `tool_value` still reads
            // `requestState` to know the answer is interim, not wrapped.
            gateway_writes::note(
                gateway_writes::Layer::Value,
                gateway_writes::REQUEST_STATE,
                &result,
            );
        }

        let call = dispatch_guards::BackendCall {
            server,
            tool,
            session_id,
            api_key_name,
            trace_id,
            caller_key: None,
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

        #[cfg(feature = "cost-governance")]
        self.inject_cost_advice(&mut result, &cost_warnings, tool, caller, session_id);
        let written = gateway_writes::snapshot_since(writes_mark);

        self.store_response(
            caller,
            args,
            (server, tool),
            trace_id,
            (want_full, stopped_to_ask, chained),
            protocol_revision,
            &arguments,
            (&projection_key_suffix, &caller_principal),
            (&profile.name, policy_epoch),
            (&result, &written),
        );

        if let Some(reservation) = idem_reservation.as_mut()
            && reservation.complete_read(&result, (self.dispatch_reading(args), written))
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
mod caller_cost_tests;

#[cfg(test)]
mod f13_hint_scope_tests;

#[cfg(test)]
mod session_fp_tests;

#[cfg(test)]
mod response_cache_error_tests;

#[cfg(test)]
mod ask_expiry_budget_tests;

#[cfg(test)]
mod tracing_target_tests;
