// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Tool invocation, dispatch, and operator-control handlers.
//!
//! Implements `gateway_invoke` (with idempotency and error-budget tracking),
//! `gateway_get_stats`, `gateway_kill_server`, `gateway_revive_server`,
//! `gateway_list_disabled_capabilities`, `gateway_reload_config`,
//! `gateway_webhook_status`, and `gateway_run_playbook`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::capability::validate_output;
use crate::context_integrity::{
    ContextActionRisk, ContextIntegrityDecisionKind, ContextIntegrityEvaluation,
    ContextIntegrityInput, ContextProvenance, ContextTrustBoundary,
};
#[cfg(feature = "cost-governance")]
use crate::cost_accounting::suggestions;
use crate::gateway::authz::{Authorize as _, Emit};
use crate::idempotency::{GuardOutcome, IdempotencyReservation, derive_key, enforce};
use crate::identity_grants::GrantSubject;
use crate::identity_propagation::{CallerProof, CallerProvenance};
use crate::playbook::PlaybookEngine;
use crate::protocol::LoggingLevel;
use crate::protocol::mrtr::{InputRequired, Refusal};
use crate::provider::Transform as _;
use crate::provider::transforms::ResponseTransform;
use crate::security::validate_tool_name;
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
}

impl std::fmt::Debug for CallerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact header VALUES (they may carry a live token); show names only.
        let header_names: Vec<&str> = self.headers.iter().map(|(k, _)| k.as_str()).collect();
        f.debug_struct("CallerCredential")
            .field("headers", &format_args!("{header_names:?} = <redacted>"))
            .field("cache_binding", &self.cache_binding)
            .finish()
    }
}

/// Render-guard non-bypassability (MIK-5854 / MIK-6690).
///
/// `GuardedValue` wraps a tool result that has passed the context-integrity
/// render guard. Its inner field is private to this module, so the ONLY ways to
/// obtain one are the two named, greppable constructors below. Because
/// [`MetaMcp::invoke_tool_traced`] returns `Result<GuardedValue>`, the compiler
/// rejects any `return Ok(...)` that has not produced a `GuardedValue` — a
/// future code path cannot emit un-guarded tool content from the chokepoint
/// without consciously calling one of these constructors (which review/grep
/// will catch).
mod guarded {
    use serde_json::Value;

    /// A tool result that has passed (or is exempt from) the render guard.
    pub(super) struct GuardedValue(Value);

    impl GuardedValue {
        /// Seal a value that has just been through `apply_context_integrity`.
        /// Call this ONLY immediately after the guard runs on live dispatch.
        pub(super) fn sealed_by_guard(value: Value) -> Self {
            Self(value)
        }

        /// Seal a value served from cache. Cached results were guarded at store
        /// time (the cache is populated only after `apply_context_integrity`),
        /// so re-serving them is in-policy without re-running the guard.
        pub(super) fn from_cache(value: Value) -> Self {
            Self(value)
        }

        /// Apply gateway-authored, non-content augmentation (trace id,
        /// predictions, cost warnings, signature) while preserving guard status.
        /// The closure must only add gateway metadata, never new tool content.
        #[must_use]
        pub(super) fn augment(self, f: impl FnOnce(Value) -> Value) -> Self {
            Self(f(self.0))
        }

        /// Unwrap at the single delivery boundary.
        pub(super) fn into_inner(self) -> Value {
            self.0
        }
    }
}

use guarded::GuardedValue;

use super::super::meta_mcp_helpers::{
    build_circuit_breaker_stats_json, build_server_safety_status, build_stats_response,
    did_you_mean, extract_bool_or, extract_optional_str, extract_required_str,
    parse_tool_arguments,
};
use super::super::recovery::{ErrorCategory, RecoveryContext, attach_recovery, recovery_for};
use super::super::trace;
use super::MetaMcp;
use super::prompt_cache::{CacheKeyDeriver, build_outbound_meta, extract_cached_tokens};
mod side_effect_markers;
// D1: the invocation record, written around `invoke_tool_traced`.
mod audit;

use super::support::{
    MetaMcpInvoker, augment_with_predictions, augment_with_provenance, augment_with_trace,
    idempotency_key_for, response_cache_key_for, strip_backend_provenance,
};
use side_effect_markers::{uncertain_side_effect, withheld_side_effect};

async fn call_capability_tool_with_identity(
    cap: &crate::capability::CapabilityBackend,
    tool: &str,
    arguments: Value,
    context: crate::capability::CapabilityExecutionContext,
) -> Result<crate::protocol::ToolsCallResult> {
    cap.call_tool_with_context(tool, arguments, context).await
}

pub(super) fn enforce_output_schema(
    server: &str,
    tool: &str,
    result: Value,
    output_schema: Option<&Value>,
) -> Value {
    let Some(schema) = output_schema else {
        return result;
    };

    if result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return result;
    }

    // No inner payload, no validation. The schema describes the tool's output,
    // not the MCP envelope carrying it, so falling back to the envelope
    // validates the wrong document and then republishes it under
    // `structuredContent` — carrying the backend's own `requestState` past the
    // mint that exists to replace it (MIK-7212.MRTR.2a), and overwriting a
    // single plain-text item with a dump of its own wrapper.
    // `apply_capability_projection` refuses this same case as bug #167; the
    // schema path refuses it here.
    let validation_target = match extract_output_validation_target(&result) {
        Some(target) => target,
        // A bare payload is its own validation target: no envelope to unwrap,
        // and `apply_validated_output` returns the coerced value directly.
        None if !is_mcp_envelope(&result) => result.clone(),
        None => return result,
    };
    let validation = validate_output(&validation_target, schema);
    if validation.is_valid() {
        apply_validated_output(&result, validation.coerced)
    } else {
        // Output-schema mismatch is ADVISORY, not fatal, for proxied tools.
        // Upstream APIs (e.g. open-meteo, travel providers) legitimately return
        // more fields than a hand-authored capability schema declares; hard-
        // rejecting would break a working tool and surface as an opaque error in
        // clients. We log the mismatch and pass the result through, still
        // populating `structuredContent` from the actual payload so spec-
        // compliant clients (Open WebUI) receive structured output. The gateway
        // does not author these fields — it proxies them — so extra keys are not
        // a trust-boundary concern here.
        tracing::warn!(
            server,
            tool,
            mismatch = %validation.format_output_error(schema),
            "tool output did not match its declared output schema; passing through (advisory)"
        );
        apply_validated_output(&result, validation_target)
    }
}

/// Strip and parse the MIK-6914 Option B claim-under-test (`_claim`) directive
/// from an invocation's arguments, binding it to this call's `call_id`.
///
/// The directive is a gateway directive, not an upstream parameter, so it is
/// removed from `arguments` (like `_full`) and never forwarded to a backend. A
/// malformed or absent directive yields `None`, and capture then falls back to
/// the honest `Claim::Succeeded` floor. The parsed claim is untrusted client
/// input: it is only ever the claim-under-test, never the ground-truth leg.
fn extract_client_claim(arguments: &mut Value, call_id: &str) -> Option<crate::trust::ClientClaim> {
    let raw = arguments.as_object_mut()?.remove("_claim")?;
    let claim = serde_json::from_value::<crate::trust::provenance_eval::Claim>(raw).ok()?;
    Some(crate::trust::ClientClaim::untrusted(call_id, claim))
}

fn extract_output_validation_target(result: &Value) -> Option<Value> {
    if let Some(structured) = result.get("structuredContent") {
        return Some(structured.clone());
    }

    let content = result.get("content")?.as_array()?;
    if content.len() != 1 {
        return None;
    }
    let text = content[0].get("text")?.as_str()?;
    serde_json::from_str::<Value>(text).ok()
}

/// Whether a value is an MCP tool-result envelope rather than a bare payload.
///
/// The two are validated differently: an envelope's schema describes what it
/// CARRIES, so an envelope with nothing extractable has nothing to validate,
/// while a bare payload is its own target. [`apply_validated_output`] keys its
/// re-wrap on the same two fields, so the answer stays consistent across both.
fn is_mcp_envelope(result: &Value) -> bool {
    result.as_object().is_some_and(|obj| {
        // `content` must be an ARRAY, which is the shape
        // `extract_output_validation_target` consumes and the specification
        // requires. Keying on the bare presence of the name would classify a
        // payload that merely has a `content` field as an envelope and return
        // it unvalidated — failing the schema gate open on exactly the values
        // it exists to check.
        obj.get("content").is_some_and(Value::is_array) || obj.contains_key("structuredContent")
    })
}

fn apply_validated_output(result: &Value, validated: Value) -> Value {
    if !is_mcp_envelope(result) {
        return validated;
    }
    let Some(obj) = result.as_object() else {
        return validated;
    };

    let mut obj = obj.clone();
    obj.insert("structuredContent".to_owned(), validated.clone());
    if let Some(content) = obj.get_mut("content").and_then(Value::as_array_mut)
        && content.len() == 1
        && let Some(text_obj) = content[0].as_object_mut()
        && text_obj.get("type").and_then(Value::as_str) == Some("text")
    {
        text_obj.insert(
            "text".to_owned(),
            Value::String(
                serde_json::to_string_pretty(&validated).unwrap_or_else(|_| validated.to_string()),
            ),
        );
    }
    Value::Object(obj)
}

/// Apply a capability's canonical [`ProjectionSpec`](crate::projection::schema::ProjectionSpec)
/// to a dispatched response (MIK-3534).
///
/// Invoked *last* in `dispatch_to_backend` — after `response_transform` and
/// `enforce_output_schema` — for two load-bearing reasons:
///
/// 1. **No leak.** Because it runs after `response_transform`, the canonical
///    view and the preserved `_raw` are built from the already-redacted
///    payload; a field that `response_transform` redacted cannot reappear under
///    `_raw`. Projection is a presentation layer, never redaction.
/// 2. **Shape.** The projected `{actor, …, _raw}` value would not satisfy a
///    backend output schema, so projection must follow schema validation.
///
/// It operates on the inner capability payload (unwrapping the MCP envelope via
/// [`extract_output_validation_target`]) and re-wraps via
/// [`apply_validated_output`] — projecting the outer envelope is bug #167.
/// `want_full` (the `_full: true` directive) bypasses projection, mirroring
/// `response_transform`. Error envelopes are never projected. When the spec
/// resolves no fields, [`project`](crate::projection::project) returns the
/// payload unchanged (fail-fast) and the original response passes through
/// untouched — re-wrapping it would clobber a non-JSON `content` text.
fn apply_capability_projection(
    response: Value,
    spec: &crate::projection::schema::ProjectionSpec,
    want_full: bool,
) -> Value {
    // `_full` opts out of projection (and, upstream, out of the response cache
    // and idempotency), mirroring `response_transform`.
    if want_full {
        return response;
    }
    // Never project an error envelope: its `content` text must stay legible for
    // the caller and for the recovery-hint classifier. Mirrors the `isError`
    // skip in `enforce_output_schema`.
    if response
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return response;
    }
    let inner = extract_output_validation_target(&response).unwrap_or_else(|| response.clone());
    let projected = crate::projection::project(&inner, spec);
    // Fail-fast: `project` resolved no fields and returned `inner` verbatim
    // (a successful projection always adds `_raw`, so it never equals `inner`).
    // Re-wrapping here would replace a non-JSON `content` text with a JSON dump
    // of the envelope, so pass the original response through untouched.
    if projected == inner {
        return response;
    }
    apply_validated_output(&response, projected)
}

/// Emit one A/B telemetry record for an eligible (experimental-mode,
/// projection-capable) invocation (MIK-5877, PROJ-ROLLOUT.3).
///
/// Emits both metrics (a labelled counter + a response-size histogram, for
/// dashboards) and a structured `target: "projection_ab"` tracing event keyed by
/// `session_id` (so an offline analysis can join arm → task outcome). Called
/// only when [`crate::projection::ab_classification`] returns `Some`, so it is
/// zero-cost outside the experiment.
fn emit_projection_ab_event(
    session_id: Option<&str>,
    server: &str,
    tool: &str,
    rec: crate::projection::AbRecord,
    result: &Value,
) {
    let response_bytes = serde_json::to_string(result).map_or(0, |s| s.len());
    let is_error = result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let projected = if rec.projected { "true" } else { "false" };

    telemetry_metrics::counter!(
        "projection_ab_invocations_total",
        "arm" => rec.arm,
        "projected" => projected
    )
    .increment(1);
    telemetry_metrics::histogram!(
        "projection_ab_response_bytes",
        "arm" => rec.arm
    )
    // u32->f64 is lossless; clamp the (absurd) >4 GiB case rather than risk a
    // precision-losing usize->f64 cast.
    .record(f64::from(u32::try_from(response_bytes).unwrap_or(u32::MAX)));
    tracing::info!(
        target: "projection_ab",
        // Un-sessioned calls log "none" and are always control (see
        // projection_decision); exclude them when joining arm -> task outcome.
        session_id = %session_id.map_or_else(|| "none".to_string(), crate::gateway::session_id::session_fp),
        server = server,
        tool = tool,
        arm = rec.arm,
        projected = rec.projected,
        response_bytes = response_bytes,
        is_error = is_error,
        "projection A/B invocation"
    );
}

/// Whether a JSON value is non-empty at the top level: `null`, `{}`, and `[]`
/// are considered empty; any scalar (including `0`, `false`, `""`) and any
/// non-empty object/array are non-empty. This is a deliberately shallow check
/// used by the projection fail-fast guard — when a projection reduces a
/// populated payload to one of the empty forms, the guard logs a warning. It
/// intentionally treats a present-but-empty scalar as non-empty so legitimate
/// values are preserved.
fn json_is_populated(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Object(map) => !map.is_empty(),
        Value::Array(items) => !items.is_empty(),
        _ => true,
    }
}

impl crate::gateway::meta_mcp::MetaMcpCallerContext<'_> {
    /// Who a continuation minted or redeemed for this caller is bound to.
    ///
    /// The one derivation both the mint and the redeem read, so the two cannot
    /// name one caller two ways.
    pub(crate) fn principal_source(&self) -> crate::protocol::mrtr::PrincipalSource<'_> {
        match self.stdio_nonce {
            Some(nonce) => crate::protocol::mrtr::PrincipalSource::Stdio {
                nonce: nonce.bytes(),
            },
            None => crate::protocol::mrtr::PrincipalSource::Credential(self.verified_identity),
        }
    }
}

/// Seal one interim exchange into a continuation this caller can redeem, or
/// `None` when it cannot be bound (MRTR.2).
///
/// `None` is a refusal, not a degraded mint. A continuation names who may
/// redeem it, and there is no honest name for a caller the gateway cannot
/// identify: a placeholder would be shared with every other such caller, so the
/// envelope would satisfy its own binding check while binding nothing. See
/// `mrtr::source_fingerprint` for which credential schemes are constructible
/// today (a verified agent, and the stdio client) and why the others are not.
///
/// A keyring refusal — budget exhausted, envelope too large — lands here too,
/// and so does a full in-flight table. The cause is logged and not returned,
/// because the caller can act on none of them: they are properties of this
/// gateway's state, not of the request, and naming them tells a client how
/// close the mint budget is to being spent.
///
/// The exchange is opened on this replica before the envelope is sealed, so the
/// handle that goes out names a slot this process is holding (MRTR.8).
async fn mint_continuation(
    continuation: &crate::protocol::continuation::ContinuationState,
    caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    server: &str,
    tool: &str,
    arguments: &Value,
    backend_request_state: Option<String>,
) -> Option<String> {
    let Some(payload) = continuation
        .begin_exchange(
            server.to_string(),
            backend_request_state,
            crate::protocol::mrtr::source_fingerprint(caller.principal_source())?,
            crate::protocol::mrtr::original_request_digest(server, tool, arguments),
            crate::protocol::continuation::now_unix_secs(),
        )
        .await
    else {
        warn!(server, tool, "No slot to hold this exchange open; refusing");
        record_continuation_mint("no_slot");
        return None;
    };
    match continuation.keyring().mint(&payload) {
        Ok(envelope) => {
            record_continuation_mint("ok");
            Some(envelope)
        }
        Err(error) => {
            warn!(server, tool, %error, "Continuation mint refused");
            record_continuation_mint(continuation_error_reason(&error));
            None
        }
    }
}

/// The refusal for an interim exchange this gateway cannot bind to its caller
/// (MRTR.2).
///
/// `-32003` is the gateway's existing "Forbidden", reused rather than minted:
/// this is a refusal to proceed, and the client has done nothing it could undo.
/// Deliberately *not* `-32021`: that code invites the client to declare a
/// capability and retry, and no declaration makes an unnameable caller
/// nameable, so pointing at one would be a lie the client would act on.
///
/// One message for every cause. A client that could tell "we cannot name you"
/// from "our mint budget is spent" learns the gateway's internal state from a
/// call it was refused; the distinction is in the log, where the operator who
/// can act on it will look.
fn unbindable_continuation(server: &str, tool: &str) -> Error {
    Error::JsonRpc {
        code: -32003,
        message: format!(
            "Tool '{tool}' on server '{server}' asked for input, but this exchange cannot be \
             continued for this caller"
        ),
        data: None,
    }
}

/// What a retry sends the backend beside `arguments` (MRTR.1).
///
/// A second type rather than reusing [`crate::protocol::mrtr::RetryFields`].
/// That one is inbound and attacker-controlled, and its `request_state` is this
/// gateway's own envelope; what goes upstream is the state the *backend*
/// issued, unsealed from inside it. One struct for both directions is how a
/// client-supplied string reaches a backend as if the gateway had issued it.
#[derive(Debug, Default)]
struct OutboundRetry {
    /// The backend's own opaque state, or `None` when it issued none.
    request_state: Option<String>,
    /// The client's answers, verbatim.
    input_responses: Option<Value>,
}

impl OutboundRetry {
    /// Add whatever this retry carries beside `name` and `arguments`.
    ///
    /// Beside, never inside: the specification makes both fields siblings of
    /// `arguments`, so a tool whose own argument is called `requestState` keeps
    /// it, and a backend reads ours where it is looking for it.
    ///
    /// An absent field is left absent rather than sent empty. A backend is
    /// entitled to read the presence of `requestState` as meaning something,
    /// and a server that issued no state never sent one to echo.
    fn apply(&self, params: &mut Value) {
        let Some(object) = params.as_object_mut() else {
            return;
        };
        if let Some(state) = &self.request_state {
            object.insert("requestState".to_string(), json!(state));
        }
        if let Some(responses) = &self.input_responses {
            object.insert("inputResponses".to_string(), responses.clone());
        }
    }
}

/// The refusal for a continuation this gateway will not redeem (MRTR.3).
///
/// One sentence for every cause, taken from [`ContinuationError`] itself rather
/// than written here: a caller able to tell a forged tag from a spent handle
/// from a passed deadline can map the keyring one probe at a time, and can do
/// nothing differently with any of them. The cause reaches the operator through
/// the log, where it can be acted on.
fn rejected_continuation(reason: &crate::protocol::continuation::ContinuationError) -> Error {
    Error::JsonRpc {
        code: -32602,
        message: reason.client_message().to_string(),
        data: None,
    }
}

/// Stable, low-cardinality tag for a [`ContinuationError`], for metrics and
/// structured logs — never the client, which gets `client_message()`.
/// `UnknownVersion`/`UnknownKey` drop their payload here: a build supports a
/// handful of wire versions and a keyring holds a handful of live keys, but a
/// metric label is not where that bound should be re-proven, so the tag names
/// the cause, not the value.
fn continuation_error_reason(
    reason: &crate::protocol::continuation::ContinuationError,
) -> &'static str {
    use crate::protocol::continuation::ContinuationError;
    match reason {
        ContinuationError::Malformed => "malformed",
        ContinuationError::UnknownVersion(_) => "unknown_version",
        ContinuationError::UnknownKey(_) => "unknown_key",
        ContinuationError::NotAuthentic => "not_authentic",
        ContinuationError::Expired => "expired",
        ContinuationError::MintBudgetExhausted => "mint_budget_exhausted",
        ContinuationError::TooLarge => "too_large",
        ContinuationError::LifetimeExceeded => "lifetime_exceeded",
    }
}

/// Count one continuation mint outcome (NFR.OBS.4). `reason` is `"ok"` for a
/// successful mint, [`continuation_error_reason`] for a keyring refusal, or a
/// call-site tag for a refusal with no `ContinuationError` of its own (a full
/// in-flight table refuses before the keyring is ever asked).
fn record_continuation_mint(reason: &'static str) {
    telemetry_metrics::counter!("continuation_mint_total", "reason" => reason).increment(1);
}

/// Count one continuation rejection (NFR.OBS.4), and fold it into the expiry
/// signal when the cause is a deadline that has already passed. `reason` is
/// the real [`ContinuationError`] tag where one was returned, or a call-site
/// tag for a cause this module synthesizes rather than forwards: MRTR.2 and
/// MRTR.6 deliberately collapse several causes into one client message so a
/// caller cannot map the keyring or the in-flight table one probe at a time —
/// the metric keeps them apart for the operator that collapse was never meant
/// to blind.
fn record_continuation_rejection(reason: &'static str) {
    telemetry_metrics::counter!("continuation_rejection_total", "reason" => reason).increment(1);
    if reason == "expired" {
        // A client presenting a stale envelope. Counted apart from the
        // in-flight table's own eviction of an aged-out exchange
        // (`reclaim_abandoned`, `continuation.rs`, `reason="hold_evicted"`
        // under NFR.OBS.4) by `reason`, not by a second counter.
        //
        // The two are observation points, not disjoint causes: a client that
        // returns too late is refused here AND has its hold evicted by the
        // next reader, so one continuation can raise both. Neither count is a
        // population of continuations, and summing them double-counts.
        telemetry_metrics::counter!("continuation_expiry_total", "reason" => "deadline_passed")
            .increment(1);
    }
}

/// Which backend holds the exchange a retry continues (MRTR.6).
///
/// `None` when the call carries no continuation at all — an ordinary call,
/// routed by its name like any other. `Some` otherwise, because a retry names
/// the *backend* tool it continues, and a backend tool is reachable by its own
/// name only where an operator surfaced it: routing a retry by name would
/// refuse every honest one on a tool nobody pinned. The route therefore comes
/// from the envelope this gateway minted, which is the one value in a retry a
/// client cannot author.
///
/// Only the route comes from here. The presented name and arguments are still
/// checked against the digest sealed inside the same envelope, downstream in
/// [`redeem_retry`] — that check, not this one, is what refuses a handle
/// replayed against another tool.
pub(super) fn retry_origin_backend(
    continuation: &crate::protocol::continuation::ContinuationState,
    retry: &crate::protocol::mrtr::RetryFields,
) -> Option<Result<String>> {
    let token = retry.request_state.as_deref()?;
    let now = crate::protocol::continuation::now_unix_secs();
    let payload = match continuation.keyring().open(token, now) {
        Ok(payload) => payload,
        Err(error) => {
            warn!(%error, "Continuation refused before routing");
            record_continuation_rejection(continuation_error_reason(&error));
            return Some(Err(rejected_continuation(&error)));
        }
    };
    // A destructive confirmation continues no backend exchange: this gateway
    // asked the question and its own gate reads the answer. `None` already
    // means "nothing to route", which is exactly true here — routing it would
    // hand the answer to a backend named after a meta-tool, and the gate that
    // must see it would never run.
    //
    // A chain resume is the same shape for the same reason: the envelope
    // licenses the chain driver to run `chain[next_step..]`, and the step it
    // resumes is named by the sealed `next_step`, not by the tool the client
    // called. Routing it by `backend_id` would dispatch the pending step's
    // backend with the whole chain array as its arguments and skip every
    // binding `plan_chain_resume` exists to check.
    if matches!(
        payload.purpose,
        crate::protocol::continuation::ContinuationPurpose::DestructiveConfirm
            | crate::protocol::continuation::ContinuationPurpose::ChainResume
    ) {
        return None;
    }
    Some(Ok(payload.backend_id))
}

/// Open the continuation a retry presents and recover what the backend gets
/// (MRTR.1, MRTR.3-5).
///
/// Not a retry — neither field present — yields an empty [`OutboundRetry`], and
/// the call proceeds as the fresh one it is.
///
/// Answers with no envelope are carried, not refused: the specification lets a
/// server ask for input without state of its own, so there is nothing to open
/// and nothing a binding check could be performed against.
///
/// The continuation is spent the moment it opens, before the dispatch it
/// authorises. Spending it on success instead would leave it redeemable again
/// to anyone who can make a dispatch fail, which is the replay this ledger
/// exists to close.
async fn redeem_retry(
    continuation: &crate::protocol::continuation::ContinuationState,
    caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    server: &str,
    tool: &str,
    arguments: &Value,
) -> Result<OutboundRetry> {
    use crate::protocol::continuation::ContinuationError;

    let input_responses = caller.retry.input_responses.clone();
    let Some(token) = caller.retry.request_state.as_deref() else {
        return Ok(OutboundRetry {
            request_state: None,
            input_responses,
        });
    };

    let now = crate::protocol::continuation::now_unix_secs();
    let payload = continuation.keyring().open(token, now).map_err(|error| {
        warn!(server, tool, %error, "Continuation refused");
        record_continuation_rejection(continuation_error_reason(&error));
        rejected_continuation(&error)
    })?;

    // Which domain the envelope was sealed for, before anything is read out of
    // it and before the hold or the ledger is touched.
    //
    // One keyring and one ledger serve two domains — this one, and the
    // destructive confirmation a task-augmented call is admitted through. An
    // envelope minted for the other one is *authentic*, so authentication
    // cannot refuse it; only its purpose can. Checked first so a wrong-domain
    // envelope cannot spend the hold or the redemption belonging to the
    // exchange whose `jti` and `hold_key` it happens to carry: a refusal that
    // arrived after either would leave the caller's own honest retry with
    // nothing left to redeem.
    payload
        .require_purpose(crate::protocol::continuation::ContinuationPurpose::BackendInput)
        .map_err(|error| {
            warn!(
                server,
                tool, "Continuation from another domain presented as a backend retry"
            );
            record_continuation_rejection("wrong_purpose");
            rejected_continuation(&error)
        })?;

    // The same fingerprint the mint bound to, derived the same way — both read
    // `caller.principal_source()`. A caller the gateway cannot name cannot match
    // one it could: `source_fingerprint` returns `None` for exactly the
    // credential schemes no continuation is ever minted for, so there is no
    // handle here for such a caller to hold.
    let Some(fingerprint) = crate::protocol::mrtr::source_fingerprint(caller.principal_source())
    else {
        warn!(
            server,
            tool, "Retry from a caller no continuation can be bound to"
        );
        record_continuation_rejection("unidentifiable_caller");
        return Err(rejected_continuation(&ContinuationError::NotAuthentic));
    };
    payload
        .redeemable_by(
            &fingerprint,
            &crate::protocol::mrtr::original_request_digest(server, tool, arguments),
        )
        .map_err(|error| {
            warn!(server, tool, %error, "Continuation not redeemable by this caller");
            record_continuation_rejection(continuation_error_reason(&error));
            rejected_continuation(&error)
        })?;

    // MRTR.6: the exchange this handle continues must still be open, here. The
    // table is written only by this process's own mint, so a retry that reaches
    // a replica which did not mint it asks a table that never knew the key —
    // and one whose exchange has since ended asks a table that no longer does.
    // Both answer `Gone`, and both must refuse rather than dispatch: dispatching
    // would open a *second* exchange with a legacy backend, leaving the first
    // hanging and asking the user the same question twice.
    //
    // Checked before the handle is spent. A retry the gateway cannot honour
    // should not also burn the client's one redemption.
    if continuation.in_flight().route(&payload.hold_key, now).await
        == crate::protocol::continuation::Routing::Gone
    {
        warn!(
            server,
            tool, "Retry for an exchange this replica no longer holds"
        );
        record_continuation_rejection("hold_gone");
        return Err(rejected_continuation(&ContinuationError::NotAuthentic));
    }

    if !continuation
        .ledger()
        .consume(&payload.jti, payload.expires_at, now)
        .await
    {
        // Already spent, or the ledger is full and refuses rather than forgets.
        // One answer for both: a client can act on neither, and telling them
        // apart reports whether another caller has just redeemed a handle.
        warn!(
            server,
            tool, "Continuation already spent or ledger at capacity"
        );
        record_continuation_rejection("ledger_spent_or_full");
        return Err(rejected_continuation(&ContinuationError::NotAuthentic));
    }

    // The exchange ends here: this retry carries the answers it was waiting for.
    // Releasing the slot is what keeps capacity a measure of exchanges still
    // open rather than of every exchange ever started, and it is what makes the
    // refusal above true of a handle redeemed twice.
    continuation
        .in_flight()
        .complete(&payload.hold_key, now)
        .await;
    telemetry_metrics::counter!("continuation_redeem_total", "reason" => "ok").increment(1);

    Ok(OutboundRetry {
        request_state: payload.backend_request_state,
        input_responses,
    })
}

/// The key under which a refusal names the capabilities the client would have
/// had to declare. Shared with `error_response_preserving_status`, which
/// forwards this key out of a gateway-authored error's `data` — a literal in
/// both places would let the two drift apart silently, and the drift would be
/// invisible because the field would simply be absent.
pub(super) const REQUIRED_CAPABILITIES_DATA_KEY: &str = "requiredCapabilities";

/// The key under which a mode refusal names the mode it refused, rendered from
/// the gateway's own enum and never from the caller's string. Forwarded by the
/// same allowlist and named here for the same reason: the write site, the
/// allowlist and the test must not each pick their own spelling.
pub(super) const UNSUPPORTED_ELICITATION_MODE_DATA_KEY: &str = "unsupportedElicitationMode";

/// The refusal for an interim result naming a request type this client cannot
/// be asked (MRTR.9).
///
/// `-32021` with a `requiredCapabilities` payload is the router's existing
/// answer to "the client did not declare that", reused here so one condition
/// meets a client in one shape however the request reached it. The payload
/// tracks what the client can actually do about it: a missing capability names
/// itself, a missing *mode* names the mode instead (the capability is already
/// declared), and neither an unrecognised method nor an unrecognised mode names
/// anything at all — there is nothing a client could add to its declaration to
/// make either acceptable, and naming something would invite exactly that.
fn undeclared_input_request(
    server: &str,
    tool: &str,
    refused: &crate::protocol::mrtr::Undeclared<'_>,
) -> Error {
    let (message, data) = match refused.reason {
        Refusal::Capability(capability) => (
            format!(
                "Tool '{tool}' on server '{server}' asked for input '{}', which needs the \
                 '{capability}' capability the client did not declare",
                refused.key
            ),
            Some(json!({ REQUIRED_CAPABILITIES_DATA_KEY: [capability] })),
        ),
        Refusal::UnrecognisedMethod => (
            format!(
                "Tool '{tool}' on server '{server}' asked for input '{}' of unrecognised type \
                 '{}', which no client can have declared",
                refused.key, refused.method
            ),
            None,
        ),
        // No `requiredCapabilities`: this client *did* declare elicitation, and
        // naming it again would send the client to add what it already has.
        Refusal::Mode(mode) => (
            format!(
                "Tool '{tool}' on server '{server}' asked for input '{}' in elicitation mode \
                 '{}', which the client did not declare",
                refused.key,
                mode.as_str()
            ),
            Some(json!({ UNSUPPORTED_ELICITATION_MODE_DATA_KEY: mode.as_str() })),
        ),
        // The refused mode is not echoed: it is the caller's string, and the
        // gateway names only modes it can render from its own vocabulary.
        Refusal::UnrecognisedMode => (
            format!(
                "Tool '{tool}' on server '{server}' asked for input '{}' in an elicitation mode \
                 this gateway does not recognise",
                refused.key
            ),
            None,
        ),
    };
    Error::JsonRpc {
        code: -32021,
        message,
        data,
    }
}

/// Re-dispatches the original call with the answers collected so far.
///
/// Holds the dispatch arguments rather than a closure because
/// [`crate::gateway::input_bridge::BackendInvoker`] is an async trait and every
/// bridged round needs the same values the first dispatch used: a round that
/// differed in any of them would be a second call, not a retry of this one.
/// Every field is read off the first `accounted_dispatch` call site, argument
/// for argument, so a parameter added there is a compile error here rather than
/// a retry that silently diverges.
struct BridgeDispatcher<'a> {
    meta: &'a MetaMcp,
    server: &'a str,
    tool: &'a str,
    arguments: &'a Value,
    prompt_cache_key: Option<&'a str>,
    inbound_meta: Option<&'a Value>,
    want_full: bool,
    session_id: Option<&'a str>,
    caller_identity: Option<&'a GrantSubject>,
    caller_proof: CallerProof<'a>,
    headers: &'a [(String, String)],
    cache_binding: Option<&'a str>,
    account_credential: Option<Arc<crate::identity_propagation::PreparedAccountCredential>>,
    api_key_name: Option<&'a str>,
    trace_id: &'a str,
    policy_epoch: u64,
    protocol_revision: Option<&'a str>,
    routing_profile: &'a str,
    scope: super::InvokeScope<'a>,
}

impl crate::gateway::input_bridge::ChallengeGate for BridgeDispatcher<'_> {
    /// Scans the batch as the backend composed it, against the backend's own
    /// target, and refuses the exchange rather than rewriting the question:
    /// `enforce_firewall_challenge` runs `Immutable`, so a redaction is not
    /// one of the outcomes available here.
    fn admit(
        &self,
        challenge: &Value,
    ) -> std::result::Result<(), crate::gateway::input_bridge::BridgeError> {
        let targets = [crate::security::response_policy::ResponsePolicyTarget {
            server: self.server.to_owned(),
            tool: self.tool.to_owned(),
        }];
        let correlation = crate::security::response_policy::ResponseCorrelation {
            session_id: self.session_id.unwrap_or_default(),
            caller: self.api_key_name.unwrap_or("anonymous"),
            external_server: "gateway",
            external_tool: "gateway_invoke",
        };
        self.meta
            .enforce_firewall_challenge(challenge, &targets, &correlation)
            .map_err(
                |_| crate::gateway::input_bridge::BridgeError::ChallengeRefused {
                    dispatched: false,
                },
            )
    }
}

#[async_trait::async_trait]
impl crate::gateway::input_bridge::BackendInvoker for BridgeDispatcher<'_> {
    async fn invoke(
        &self,
        retry_params: Value,
    ) -> std::result::Result<Value, crate::gateway::input_bridge::BridgeError> {
        // Admitted here as well as at the first dispatch, because the spend
        // check is per backend call and `invoke_tool` ran it once, before the
        // backend asked anything. A bridged exchange adds a call per round, so
        // a budget enforced only at the top is a budget a backend can walk past
        // by asking. The warnings are dropped: the ones that ride the envelope
        // are the first call's, and a bridged round has nowhere to put its own.
        //
        // `NotAdmitted`, not `BackendFailed`: the round is refused before the
        // dispatch, so there is no side effect for the settlement arm to
        // protect and burning the idempotency key here would deny the caller a
        // retry of work that never ran.
        #[cfg(feature = "cost-governance")]
        self.meta
            .admit_spend(self.tool, self.api_key_name)
            .map_err(|e| crate::gateway::input_bridge::BridgeError::NotAdmitted {
                message: e.to_string(),
            })?;

        // Through `accounted_dispatch`, not `dispatch_to_backend`: a bridged
        // round is a real backend call and is accounted and gated exactly like
        // the first one. A round that skipped the accounting would let a
        // backend that keeps asking spend an unmetered budget.
        // The same key rule as the first round, against the slot as it is now.
        if let Some(refusal) = self.meta.undeclared_key_refusal(
            self.server,
            self.tool,
            self.arguments,
            self.cache_binding,
        ) {
            return Err(crate::gateway::input_bridge::BridgeError::NotAdmitted {
                message: refusal["content"][0]["text"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            });
        }
        let outbound = OutboundRetry {
            request_state: retry_params
                .get("requestState")
                .and_then(Value::as_str)
                .map(str::to_owned),
            input_responses: retry_params.get("inputResponses").cloned(),
        };
        self.meta
            .accounted_dispatch(
                self.server,
                self.tool,
                self.arguments.clone(),
                &outbound,
                self.prompt_cache_key,
                self.inbound_meta,
                self.want_full,
                self.session_id,
                self.caller_identity,
                self.caller_proof,
                self.headers,
                self.cache_binding,
                self.account_credential.clone(),
                self.api_key_name,
                self.trace_id,
                self.policy_epoch,
                self.protocol_revision,
                self.routing_profile,
                self.scope,
            )
            .await
            .map_err(|e| classify_bridged_dispatch_error(&e))
    }
}

/// Decides whether a failed bridged dispatch releases the idempotency key.
///
/// The error type already carries a tight, deliberate allowlist of failures that
/// provably happened above the backend. A bridged round that hit one of those ran
/// nothing, so it releases the key on the same terms as a pre-dispatch refusal;
/// everything else stays dispatched and settles, because a round the backend may
/// have executed must not readmit a retry of a side effect (ADR-012 consequence 1).
pub(super) fn classify_bridged_dispatch_error(
    error: &crate::Error,
) -> crate::gateway::input_bridge::BridgeError {
    let message = error.to_string();
    if error.is_pre_dispatch() {
        crate::gateway::input_bridge::BridgeError::NotAdmitted { message }
    } else {
        // Always `MayHaveActed`: `is_pre_dispatch()` already diverted every
        // provably-unexecuted case to `NotAdmitted` above, so anything
        // reaching here may have run.
        crate::gateway::input_bridge::BridgeError::BackendFailed {
            message,
            dispatch: crate::gateway::input_bridge::Dispatch::MayHaveActed,
        }
    }
}

/// Runs one bridged exchange in a frame of its own.
///
/// A free function taking the dispatcher and the pending round BY VALUE rather
/// than an inline `async` block: everything the exchange needs then lives in
/// this future instead of in `invoke`'s state machine, which is what keeps
/// `invoke` under clippy's `large_futures` threshold at every call site in the
/// tree.
async fn run_input_bridge(
    dispatcher: BridgeDispatcher<'_>,
    channel: &dyn crate::gateway::input_bridge::ClientChannel,
    session: &str,
    declared: crate::protocol::meta::Declared,
    pending: crate::protocol::mrtr::InputRequired,
    trace_id: &str,
) -> std::result::Result<Value, crate::gateway::input_bridge::BridgeError> {
    let observer = TracingBridgeObserver { trace_id };
    let bridge = crate::gateway::input_bridge::InputBridge {
        channel,
        backend: &dispatcher,
        gate: &dispatcher,
        observer: &observer,
        bounds: crate::gateway::input_bridge::BridgeBounds::DEFAULT,
    };
    // `None` slice: the per-request capability slice narrows a *modern*
    // caller's declaration, and this call is the legacy one — there is no
    // per-request `_meta` to narrow by, so the session store's value stands
    // alone.
    bridge.run(session, declared, None, &pending).await
}

/// Emits the bridge's counters as structured trace events.
///
/// ponytail: tracing rather than the metrics registry — the record carries no
/// answer body, so a log line is a complete rendering of it. Move to a counter
/// when an operator needs it aggregated rather than searched.
struct TracingBridgeObserver<'a> {
    trace_id: &'a str,
}

impl crate::gateway::input_bridge::BridgeObserver for TracingBridgeObserver<'_> {
    fn record(&self, record: crate::gateway::input_bridge::BridgeRecord) {
        debug!(trace_id = self.trace_id, record = ?record, "input bridge round");
    }
}

/// Monotonically increasing request counter for load-balanced cache key slot selection.
///
/// Global across all backends; overflow wraps (u64 → effectively infinite for our purposes).
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

impl MetaMcp {
    /// Current authorization must run before either execution or retained replay.
    pub(crate) fn check_invocation_policy(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    ) -> Result<()> {
        let server = extract_required_str(args, "server")?;
        let tool = extract_required_str(args, "tool")?;
        self.authorize_invocation(args, caller)?;
        if let Err(reason) = validate_tool_name(tool) {
            return Err(Error::Protocol(format!(
                "Invalid tool name '{tool}': {reason}"
            )));
        }
        self.check_attestation(
            args,
            caller.agent_id.map(crate::security::ProvenAgentId::as_str),
            "gateway_invoke",
        )?;
        self.active_profile(session_id)
            .check(server, tool)
            .map_err(Error::Protocol)
    }

    pub(super) fn authorize_invocation(
        &self,
        args: &Value,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    ) -> Result<()> {
        let server = extract_required_str(args, "server")?;
        let tool = extract_required_str(args, "tool")?;
        // === THE AUTHORIZATION CHOKEPOINT (MIK-7252) ===
        //
        // Every meta-layer dispatch passes through here: a surfaced tool, a
        // `gateway_invoke`, a code-mode step, a playbook step. The router
        // authorizes only the shapes whose targets appear in the request, so a
        // playbook step — whose targets come from the playbook definition —
        // reached a backend with none of the caller's scope checks applied.
        //
        // Placed at the top, reading `arguments` raw, for two reasons. It is
        // the earliest point at which the target is known, so nothing has yet
        // happened that a refused call is not entitled to: no nonce consumed,
        // no cache read, no idempotency entry, no credential minted, no budget
        // consulted. And the router builds its own target from the same raw
        // arguments, so a policy that one day reads them cannot give the two
        // layers two answers.
        // `{}` and not `Null`: the router's own target builder defaults a
        // missing inner `arguments` to an empty object, and two gates that see
        // different targets are two gates that can disagree.
        let empty_args = serde_json::json!({});
        let target = crate::gateway::authz::ToolTarget {
            server,
            tool,
            arguments: args.get("arguments").unwrap_or(&empty_args),
        };
        let authorizer = caller.authorizer;
        if let Err(e) = authorizer.authorize(target) {
            crate::gateway::authz::audit_refusal(
                authorizer.transport(),
                authorizer.caller_name(),
                server,
                tool,
                &e.message,
            );
            return Err(Error::Forbidden {
                code: e.code,
                status: e.status.as_u16(),
                message: e.message,
            });
        }
        self.admin_capability_rule(server, tool, caller.is_admin)?;
        // Identity grants are the same decision as the authorizer above, taken
        // here with every other refusal because the response cache and the
        // idempotency short-circuit both return below this point: a gate under
        // a cache read decides nothing on a hit.
        self.identity_grant_rule(server, tool, caller.scope(), Emit::Audit)
    }

    /// Validate the per-action attestation token presented at `boundary`
    /// (MIK-5223, B1-IDENT): `gateway_invoke` for every meta-layer dispatch,
    /// `direct_route` for `/mcp/{name}`. The label names the boundary in the
    /// audit record and in the -32002 message.
    ///
    /// Returns `Ok(())` immediately when no validator is attached (the
    /// default), so the attestation path is zero-cost for existing
    /// deployments. When a validator is attached, the optional top-level
    /// `attestation` token is validated at the `gateway_invoke` boundary
    /// against the gateway's *trusted* clock (`Utc::now()`), never a
    /// caller-supplied timestamp. Rejections are recorded in the validator's
    /// audit ring buffer by `validate_boundary_call`. In **observe** mode the
    /// rejection is logged and the call proceeds; in **enforce** mode the call
    /// fails closed with JSON-RPC -32002.
    ///
    /// # Errors
    ///
    /// Returns a JSON-RPC -32002 error only in enforce mode when the token is
    /// missing or fails validation.
    pub(crate) fn check_attestation(
        &self,
        args: &Value,
        agent_id: Option<&str>,
        boundary: &str,
    ) -> Result<()> {
        let token = args.get("attestation").and_then(Value::as_str);
        // The requested action is the tool being invoked: the token's capability
        // allow-list must grant it (MIK-6163). Missing tool → empty action,
        // which only a "*" wildcard token can satisfy (fail-closed). The
        // authenticity checks still run first, so a forged/expired token is
        // rejected on those grounds regardless of capability.
        let requested = args.get("tool").and_then(Value::as_str).unwrap_or_default();
        self.check_attestation_scoped(
            token,
            crate::attestation::validator::AttestationScope::Capability(requested),
            agent_id,
            boundary,
        )
    }

    /// The body of [`Self::check_attestation`], taking the token and what it
    /// must grant directly. The direct route calls this for methods whose
    /// target is not a tool (MIK-7570.ATTEST.1 part 3).
    ///
    /// # Errors
    ///
    /// Returns a JSON-RPC -32002 error only in enforce mode when the token is
    /// missing or fails validation.
    pub(crate) fn check_attestation_scoped(
        &self,
        token: Option<&str>,
        scope: crate::attestation::validator::AttestationScope<'_>,
        agent_id: Option<&str>,
        boundary: &str,
    ) -> Result<()> {
        let Some(validator) = self.attestation_validator.as_ref() else {
            return Ok(());
        };
        let required = match scope {
            crate::attestation::validator::AttestationScope::Capability(capability) => {
                Some(capability)
            }
            crate::attestation::validator::AttestationScope::AuthenticOnly => None,
        };
        match validator.validate_boundary_call(token, boundary, required, chrono::Utc::now()) {
            Ok(_claims) => Ok(()),
            Err(rejection) => match self.attestation_mode {
                crate::attestation::AttestationMode::Enforce => Err(Error::json_rpc(
                    -32002,
                    format!("Attestation rejected at {boundary}: {rejection}"),
                )),
                crate::attestation::AttestationMode::Observe => {
                    warn!(
                        agent_id = agent_id.unwrap_or("unattributed"),
                        rejection = %rejection,
                        "attestation_observe_reject"
                    );
                    Ok(())
                }
            },
        }
    }

    /// Refuse a multi-step plan under enforce (MIK-7570.ATTEST.1).
    ///
    /// A playbook or code-mode step is synthesized from a definition and has
    /// no token slot, so under enforce every step would fail as unattested.
    /// Saying so once, up front, keeps the refusal from reading as a bad token.
    pub(super) fn refuse_unattested_plan(&self) -> Result<()> {
        if self.attestation_validator.is_some()
            && self.attestation_mode == crate::attestation::AttestationMode::Enforce
        {
            return Err(Error::json_rpc(
                -32002,
                "Attestation rejected: multi-step plans carry no attestation in 4.0.0; \
                 call each tool with its own token",
            ));
        }
        Ok(())
    }

    /// `gateway_invoke` — invoke a tool on a backend with full tracing, caching,
    /// idempotency, error-budget tracking, and predictive prefetch.
    ///
    /// `agent_id` identifies the calling agent for audit logging (OWASP ASI03).
    // Takes the caller context whole rather than five loose parameters: the
    // authorizer travels with the identity it authorizes, so no call site can
    // pass one without the other.
    pub(super) async fn invoke_tool(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    ) -> Result<Value> {
        // D1-f: a degraded audit log refuses before dispatch, after one probe.
        if let Some(log) = &self.transparency_logger {
            log.admit().await?;
        }
        let trace_id = trace::generate();
        let trace_id_clone = trace_id.clone();
        trace::with_trace_id(trace_id, async move {
            // Boxed: the traced future is large, and every caller of
            // `invoke_tool` would otherwise carry it inline (clippy::large_futures).
            let traced =
                Box::pin(self.invoke_tool_traced(args, session_id, caller, &trace_id_clone));
            let (result, dispatch_failure) = audit::with_dispatch_scope(traced).await;
            // Single delivery boundary: unwrap the guard-sealed result.
            let result = result.map(GuardedValue::into_inner);
            // One record per call, refusals and failures included (D1-d).
            self.audit_invocation(
                args,
                session_id,
                caller,
                &trace_id_clone,
                result,
                dispatch_failure,
            )
            .await
        })
        .await
    }

    /// Stamp a signed runtime-provenance receipt into `value._meta` when
    /// provenance stamping is enabled (MIK-6905). No-op when the signer is
    /// absent, so payloads stay byte-identical with the feature off.
    ///
    /// `backend_ok` is derived from the result's `isError` flag so cache hits
    /// carrying a stored error are reported honestly.
    ///
    /// When shadow claim capture is also enabled (MIK-6908, rung 3.1), this
    /// is the single chokepoint both the meta and direct-route call paths
    /// funnel through, so a call whose receipt carries a `call_id` is
    /// shadow-captured here alongside the derived claim. A `call_id`-less
    /// receipt (no trace scope active) is skipped rather than captured
    /// un-joinable — consistent with `score_corpus`'s mis-join contract,
    /// which treats a missing join key as unscoreable, not as evidence.
    ///
    /// `client_claim` is the MIK-6914 Option B claim-under-test — an untrusted
    /// typed claim the caller supplied for this call. When present it is
    /// captured verbatim as the claim under scrutiny; when absent, capture
    /// falls back to the honest `Claim::Succeeded` floor. It is never used as
    /// the ground-truth leg (that is the receipt's extractor-observed
    /// `row_count`).
    fn maybe_stamp_provenance(
        &self,
        value: Value,
        server: &str,
        tool: &str,
        api_key_name: Option<&str>,
        cache: crate::trust::CacheOutcome,
        client_claim: Option<&crate::trust::ClientClaim>,
    ) -> Value {
        let Some(ref signer) = self.provenance_signer else {
            // Stamping disabled: the gateway authors no receipt, so any
            // `_meta.provenance` here was injected by the backend. Strip it so a
            // naive reader cannot mistake a backend-forged receipt for a
            // gateway-signed one (MIK-6909). Honest backends set no such key, so
            // this stays a no-op and the off path remains byte-identical.
            return strip_backend_provenance(value);
        };
        let backend_ok = !value
            .get("isError")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let (stamped, signed_receipt) =
            augment_with_provenance(value, signer, server, tool, api_key_name, cache, backend_ok);
        if let Some(sink) = &self.claim_capture
            && let Some(call_id) = signed_receipt.receipt.call_id.clone()
        {
            let claim = crate::trust::derive_claim(client_claim);
            sink.capture(call_id, claim, signed_receipt);
        }
        stamped
    }

    /// Stamp provenance onto a direct per-backend route result (the
    /// `/mcp/{name}` passthrough, which bypasses the meta chokepoint — rung 3).
    ///
    /// Tagged [`CacheOutcome::Bypass`] because the direct route never consults
    /// the meta response cache. No-op when stamping is disabled, so the
    /// passthrough stays byte-identical with the feature off.
    #[must_use]
    pub fn stamp_direct_result(
        &self,
        result: Value,
        backend_id: &str,
        tool: &str,
        api_key_name: Option<&str>,
    ) -> Value {
        self.maybe_stamp_provenance(
            result,
            backend_id,
            tool,
            api_key_name,
            crate::trust::CacheOutcome::Bypass,
            // The direct passthrough carries no gateway-parsed `_claim`
            // directive, so there is no client claim-under-test here.
            None,
        )
    }

    /// The post-dispatch response gates a backend result must pass before any
    /// caller — or any durable record — may hold it.
    ///
    /// Extracted so the ONE implementation serves both the live dispatch below
    /// and an upstream task result recovered later
    /// (`meta_mcp::upstream::recover_task_result`). The dispatch half is
    /// deliberately not reachable from here: recovering a result must never be
    /// able to invoke anything.
    ///
    /// Scope is exactly the gates that judge the payload — response contract,
    /// anomaly screening, context integrity. Dispatch ACCOUNTING is not here
    /// and must not be: an idempotency reservation, a response-cache write, an
    /// error budget or a prediction belongs to the call that dispatched, and a
    /// later read of an already-executed job must not consume or refresh any of
    /// them.
    pub(super) fn apply_response_gates(
        &self,
        server: &str,
        tool: &str,
        api_key_name: Option<&str>,
        trace_id: &str,
        result: Value,
    ) -> Result<Value> {
        let mut result = result;
        self.apply_response_contract_gate(server, tool, trace_id, &mut result)?;

        // === POST-INVOKE: Response content inspection (issue #133, D2) ===
        //
        // Scan the backend response for secrets, exfiltration URLs, code
        // injection patterns, and suspicious encoding.
        //
        // Observe mode (default, `action_mode = false`): logs findings and
        // annotates the result with `_security_findings`.
        // Action mode (`action_mode = true`): blocks any response with a
        // HIGH/CRITICAL finding, returning a security error to the caller.
        {
            let text = crate::security::response_inspect::extract_text_from_result(&result);
            if !text.is_empty() {
                let inspection = crate::security::response_inspect::inspect_response(
                    &text,
                    self.response_inspection_action_mode,
                );
                if inspection.has_findings() {
                    for finding in &inspection.findings {
                        warn!(
                            server,
                            tool,
                            trace_id,
                            category = finding.category,
                            severity = ?finding.severity,
                            description = finding.description,
                            "Response inspection finding"
                        );
                    }
                    if inspection.should_block {
                        return Err(Error::json_rpc(
                            -32603,
                            format!(
                                "Tool '{tool}' on server '{server}' returned a response blocked \
                                 by anomaly screening (HIGH/CRITICAL security finding detected). \
                                 See gateway logs for details."
                            ),
                        ));
                    }
                    if let Some(obj) = result.as_object_mut() {
                        obj.insert(
                            "_security_findings".to_string(),
                            serde_json::to_value(&inspection.findings).unwrap_or_default(),
                        );
                    }
                }
            }
        }

        Ok(self.apply_context_integrity(server, tool, api_key_name, trace_id, result))
    }

    /// The response contract gate (issue #133, D1), split out of
    /// [`Self::apply_response_gates`] purely to keep that function under the
    /// line budget — logic, ordering and return semantics are unchanged.
    ///
    /// Validates the response against the per-tool contract declared in
    /// `config`. Default-deny (`fail_closed=true`) can block responses from
    /// tools with no declared contract.
    ///
    /// Runs BEFORE D2 anomaly screening so contract violations abort early.
    fn apply_response_contract_gate(
        &self,
        server: &str,
        tool: &str,
        trace_id: &str,
        result: &mut Value,
    ) -> Result<()> {
        let Some(ref contract_cfg) = self.response_contract else {
            return Ok(());
        };
        let text = crate::security::response_inspect::extract_text_from_result(result);
        let tool_entry = contract_cfg.tools.get(tool);

        // fail_closed: no contract declared for this tool → treat as violation
        if contract_cfg.fail_closed && tool_entry.is_none() {
            let effective_action_mode = contract_cfg.action_mode;
            warn!(
                server,
                tool,
                trace_id,
                reason = "no_contract_declared",
                detail = "fail_closed is enabled and no contract is declared for this tool",
                "Response contract violation"
            );
            if effective_action_mode {
                return Err(Error::json_rpc(
                    -32603,
                    format!(
                        "Tool '{tool}' on server '{server}' response blocked by contract gate: \
                         no contract declared and fail_closed is enabled."
                    ),
                ));
            }
            if let Some(obj) = result.as_object_mut() {
                obj.insert(
                    "_contract_violation".to_string(),
                    serde_json::Value::Bool(true),
                );
                obj.insert(
                    "_contract_reason".to_string(),
                    serde_json::Value::String("no_contract_declared".to_string()),
                );
            }
        } else if !text.is_empty() {
            // Build effective contract merging global defaults with per-tool overrides.
            let effective_max_bytes = tool_entry
                .and_then(|e| e.max_bytes)
                .or(contract_cfg.default_max_bytes);
            let effective_action_mode = tool_entry
                .and_then(|e| e.action_mode)
                .unwrap_or(contract_cfg.action_mode);
            let patterns: &[String] = tool_entry.map_or(&[], |e| e.forbidden_patterns.as_slice());

            let forbidden_patterns = if patterns.is_empty() {
                regex::RegexSet::empty()
            } else {
                match regex::RegexSet::new(patterns) {
                    Ok(set) => set,
                    Err(e) => {
                        warn!(
                            server,
                            tool,
                            trace_id,
                            error = %e,
                            "Failed to compile forbidden_patterns for tool contract — skipping pattern check"
                        );
                        regex::RegexSet::empty()
                    }
                }
            };

            let contract = crate::security::response_contract::ToolResponseContract {
                max_bytes: effective_max_bytes,
                forbidden_patterns,
                action_mode: effective_action_mode,
            };

            if let Some(violation) = contract.validate(&text) {
                warn!(
                    server,
                    tool,
                    trace_id,
                    reason = violation.reason,
                    detail = %violation.detail,
                    "Response contract violation"
                );
                if violation.should_block {
                    return Err(Error::json_rpc(
                        -32603,
                        format!(
                            "Tool '{tool}' on server '{server}' response blocked by contract gate: \
                             {} — {}",
                            violation.reason, violation.detail
                        ),
                    ));
                }
                if let Some(obj) = result.as_object_mut() {
                    obj.insert(
                        "_contract_violation".to_string(),
                        serde_json::Value::Bool(true),
                    );
                    obj.insert(
                        "_contract_reason".to_string(),
                        serde_json::Value::String(violation.reason.to_string()),
                    );
                }
            }
        }
        Ok(())
    }

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
        let provenance = CallerProvenance::classify(caller.credential_principal);
        let caller_proof = CallerProof::new(verified_identity, provenance);

        // Capture once, before any authorization input is read. A bump after
        // this strands the insert under the epoch this call was authorized
        // in. A second load at the write site is the 4.g race.
        let policy_epoch = self.policy_epoch.load(Ordering::Acquire);

        let server = extract_required_str(args, "server")?;
        let tool = extract_required_str(args, "tool")?;

        if !caller
            .signing
            .is_some_and(|context| context.prepared_for(server, tool))
        {
            self.check_invocation_policy(args, session_id, caller)?;
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
        let projection_key_suffix =
            crate::projection::projection_key_suffix(self.projection_mode, session_id);

        tracing::Span::current().record("trace_id", trace_id);

        if self.kill_switch.is_killed(server) {
            return Err(Error::json_rpc(
                -32000,
                format!("Server '{server}' is currently disabled by operator kill switch"),
            ));
        }

        {
            let cap_cfg = self.capability_budget_config.read();
            if self
                .kill_switch
                .is_capability_disabled_with_cooldown(server, tool, cap_cfg.cooldown)
            {
                return Err(Error::json_rpc(
                    -32000,
                    format!(
                        "Capability '{tool}' on server '{server}' is temporarily disabled due to \
                         a high error rate. It will auto-recover after the cooldown period. \
                         Use gateway_list_disabled_capabilities to see all disabled capabilities."
                    ),
                ));
            }
        }

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
        let caller_credential = if let Some(idp_cfg) = self
            .backends
            .get(server)
            .and_then(|b| b.identity_propagation_config().cloned())
        {
            let resolved = self.resolve_caller_credential(server, &idp_cfg, verified_identity);
            self.with_connect_offer(resolved.await, verified_identity)
                .await?
        } else {
            self.refuse_unbound_account_backend(server)?;
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
            && self
                .backends
                .get(server)
                .is_some_and(|b| b.oauth_requires_per_user_isolation())
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
            caller.credential_principal,
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
                    // A refusal keeps its provenance across the replay as well
                    // as across the bridge boundary. Served as a generic error
                    // it would skip the delivery-refusal projection and count
                    // as a client failure — a retry could then open the circuit
                    // breaker on a client whose only fault was retrying a call
                    // the gateway itself refused.
                    if error
                        .get(crate::idempotency::FIREWALL_REFUSAL_MARKER)
                        .and_then(Value::as_bool)
                        == Some(true)
                    {
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
                        self.record_and_predict(session_id, &tool_key, caller.scope());
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
        if let Some(refusal) =
            self.undeclared_key_refusal(server, tool, &arguments, dispatch_binding.as_deref())
        {
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
        if !want_full
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
            && let Some(cached) = cache.get(&cache_key)
        {
            debug!(server, tool, trace_id, "Cache hit");
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
                reservation.complete(&cached);
            }
            let predictions = self.record_and_predict(session_id, &tool_key, caller.scope());
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
        let cost_warnings: Vec<String> = self.admit_spend(tool, api_key_name)?;

        // Derive a prompt_cache_key for OpenAI-compatible backends.
        // Priority: explicit _meta.prompt_cache_key from caller > session hash.
        let prompt_cache_key: Option<String> = args
            .get("_meta")
            .and_then(|m| m.get("prompt_cache_key"))
            .and_then(Value::as_str)
            .map(CacheKeyDeriver::from_header)
            .or_else(|| {
                session_id.map(|sid| {
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

        if let Some(execution) = caller.execution {
            execution.mark_dispatched();
        }
        // Boxed: the dispatch future is the largest thing this frame ever
        // holds, and inlining it puts `invoke_tool_traced` over
        // `clippy::large_futures` at every call site.
        let dispatch_result = Box::pin(self.accounted_dispatch(
            server,
            tool,
            arguments.clone(),
            &outbound_retry,
            prompt_cache_key.as_deref(),
            args.get("_meta"),
            want_full,
            session_id,
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
        ))
        .await;

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
                // The caller gets a tool result, but the audit record says
                // `error` with this code (D1-d.2: a backend failure).
                audit::note_dispatch_failure(&e);
                // Classify the error and convert to a structured tool-level
                // error response.  This keeps `isError + content + recovery`
                // in the tool result body rather than promoting to a JSON-RPC
                // protocol error, which gives the LLM actionable recovery
                // guidance without breaking the MCP framing.
                let (category, detail) = classify_dispatch_error(&e);
                let hint = recovery_for(
                    category,
                    RecoveryContext {
                        tool: Some(tool),
                        backend: Some(server),
                        detail: Some(&detail),
                        ..Default::default()
                    },
                );
                // Still record the error budget failure (already done above via
                // `record_error_budget`).  The idempotency reservation is left
                // for the commit below unless the refusal was pre-dispatch.
                attach_recovery(
                    json!({
                        "isError": true,
                        "content": [{"type": "text", "text": e.to_string()}],
                    }),
                    hint,
                )
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
        if !stopped_to_ask && let Some(reservation) = idem_reservation.as_mut() {
            reservation.commit(&withheld_side_effect());
        }

        // MRTR.9: a question the client never said it could answer is refused
        // where the backend's interim result is first seen — before a
        // continuation is minted and before the result is cached, so nothing
        // survives the refusal. Relaying it instead leaves the client holding
        // an `inputRequests` entry it has no handler for and the backend
        // holding an exchange that can never be completed.
        if let Some(interim) = &interim
            && let Some(refused) = interim.undeclared(caller.input_capabilities)
        {
            warn!(
                server,
                tool,
                trace_id,
                request_key = refused.key,
                method = refused.method,
                "Backend asked for input of a type the client did not declare"
            );
            return Err(undeclared_input_request(server, tool, &refused));
        }

        // MIK-7212.WIRE: a legacy client is asked here, in-band, instead of
        // being handed a continuation envelope it has no vocabulary for. A 2025
        // client cannot redeem one, so relaying it strands the exchange at both
        // ends — the client holds a token it cannot spend and the backend holds
        // a round nobody will finish.
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
                },
                caller.channel,
                session,
                caller.input_capabilities,
                pending,
                trace_id,
            ))
            .await;
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
                // carry `NoClientChannel` but declare `Declared::NONE`, so
                // `plan` refuses as `Refused` before any delivery is tried. A
                // stdio context that did fall through would mint, bound by its
                // process nonce (MIK-7570.STDIO.1).
                //
                // ponytail: `run` walks rounds internally and a session lost on
                // round two surfaces the same way, so the mint would replay
                // prompts already answered. Needs a progress signal out of
                // `run` to tell the two apart; not built, because no channel in
                // tree fails later than round one.
                Err(crate::gateway::input_bridge::BridgeError::Delivery {
                    error: crate::gateway::input_bridge::DeliveryError::NoSession,
                    ..
                }) => {}
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
                        // Built from the variant rather than spelled out, so the
                        // replayed refusal cannot drift from the live one.
                        let mut body = json!({
                            "code": Error::ResponseFirewallRefused.to_rpc_code(),
                            "message": Error::ResponseFirewallRefused.to_string(),
                        });
                        body[crate::idempotency::FIREWALL_REFUSAL_MARKER] = json!(true);
                        reservation.fail(&body);
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
                Err(error) => {
                    // A round that reached the backend may have acted, so its
                    // key must not be readmitted. `BackendFailed` is the only
                    // variant raised from the backend call itself; `NotAdmitted`
                    // was refused above the dispatch, and `Deadline`,
                    // `RequestBudgetExhausted`, `Refused`, `Delivery` and
                    // `RoundsExhausted` all leave the backend parked on a
                    // question that was never answered, and a backend that
                    // stopped to ask has not acted yet — the premise the `Ok`
                    // arm below rests on too. So their release-on-drop default
                    // still stands. A round that never left the gateway — no
                    // such backend, no such tool, an open circuit, a transport
                    // that never connected — is `NotAdmitted` rather than
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

        result = self.apply_response_gates(server, tool, api_key_name, trace_id, result)?;

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
            && cache.set(&cache_key, result.clone(), self.default_cache_ttl)
        {
            debug!(server, tool, trace_id, ttl = ?self.default_cache_ttl, "Cached result");
        }

        if let Some(reservation) = idem_reservation.as_mut()
            && reservation.complete(&result)
        {
            debug!(
                server,
                tool,
                key = reservation.key(),
                trace_id,
                "Idempotency entry marked completed"
            );
        }

        let predictions = self.record_and_predict(session_id, &tool_key, caller.scope());

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
        Ok(GuardedValue::sealed_by_guard(final_result))
    }

    /// Record an outcome against both backend and per-capability error budgets.
    fn record_error_budget(&self, server: &str, tool: &str, outcome: BudgetOutcome) {
        // A throttled backend is a working backend (GH #475). Recording it as
        // either sample distorts the failure rate the budgets exist to measure,
        // so the call returns before the config locks — a throttling burst
        // would otherwise contend on them to record nothing.
        if outcome == BudgetOutcome::IgnoredRateLimit {
            telemetry_metrics::counter!(
                "mcp_error_budget_suppressed_total",
                "server" => server.to_owned(),
                "reason" => "rate_limited"
            )
            .increment(1);
            debug!(
                server,
                tool, "Rate-limited response excluded from error budget accounting"
            );
            return;
        }
        let cfg = self.error_budget_config.read();
        let cap_cfg = self.capability_budget_config.read();
        if outcome == BudgetOutcome::Success {
            self.kill_switch
                .record_success(server, cfg.window_size, cfg.window_duration);
            self.kill_switch
                .record_capability_success(server, tool, &cap_cfg);
        } else {
            let auto_killed = self.kill_switch.record_failure(
                server,
                cfg.window_size,
                cfg.window_duration,
                cfg.threshold,
                cfg.min_samples,
            );
            let cap_disabled = self
                .kill_switch
                .record_capability_failure(server, tool, &cap_cfg);
            if auto_killed {
                warn!(server, "Server auto-killed by error budget exhaustion");
            }
            if cap_disabled {
                warn!(
                    server,
                    tool, "Capability auto-disabled by per-capability error budget"
                );
            }
        }
    }

    /// Record the session transition and return predictions for the current tool.
    ///
    /// Side-effects:
    /// - Records `session_id → tool_key` in the `TransitionTracker`.
    /// - If a `ToolRegistry` is attached, triggers schema prefetching for the
    ///   top-N predicted successors (see [`crate::tool_registry::ToolRegistry::prefetch_after`]).
    pub(super) fn record_and_predict(
        &self,
        session_id: Option<&str>,
        tool_key: &str,
        scope: super::InvokeScope<'_>,
    ) -> Vec<Value> {
        let Some(tracker) = self.get_transition_tracker() else {
            return Vec::new();
        };
        let Some(sid) = session_id else {
            return Vec::new();
        };

        tracker.record_transition(sid, tool_key);

        // Warm registry schemas for predicted-next tools (no-op when no registry).
        if let Some(registry) = self.get_tool_registry() {
            registry.prefetch_after(tool_key, &tracker, 0.20, 2);
        }

        // The tracker is global, so a transition another caller taught it can
        // name a tool this caller may not reach. Only admitted `server:tool`
        // keys are returned; an unparsable key is dropped (A3).
        tracker
            .predict_next(tool_key, 0.30, 3)
            .into_iter()
            .filter(|p| {
                p.tool.split_once(':').is_some_and(|(server, tool)| {
                    self.may_invoke(server, tool, scope, session_id).is_ok()
                })
            })
            .map(|p| json!({"tool": p.tool, "confidence": p.confidence}))
            .collect()
    }

    pub(super) fn grant_subject_from_api_key(api_key_name: Option<&str>) -> Option<GrantSubject> {
        api_key_name
            .filter(|name| !name.is_empty())
            .map(|name| GrantSubject::new("api_key", name, Some(name.to_string())))
    }

    fn apply_context_integrity(
        &self,
        server: &str,
        tool: &str,
        api_key_name: Option<&str>,
        trace_id: &str,
        result: Value,
    ) -> Value {
        let mut provenance = ContextProvenance::tool_result(
            server,
            tool,
            trace_id,
            ContextTrustBoundary::RemoteToolOutput,
        );
        provenance.subject = api_key_name.map(str::to_string);
        provenance.origin = Some(format!("{server}:{tool}"));

        let (read_only, destructive) = self.capability_context_flags(server, tool);
        let mut input = ContextIntegrityInput::read_only_tool_result(provenance, result.clone());
        input.read_only = read_only;
        input.destructive = destructive;
        input.action_risk = if destructive {
            ContextActionRisk::High
        } else if read_only {
            ContextActionRisk::Low
        } else {
            ContextActionRisk::Medium
        };

        let evaluation = self.context_integrity_kernel.read().evaluate(input);
        if evaluation.classification.findings.is_empty()
            && evaluation.policy.would_decision == ContextIntegrityDecisionKind::Allow
        {
            return result;
        }

        let delivered = if evaluation.policy.enforcement_applied {
            Self::context_integrity_delivered_result(&evaluation, &result)
        } else {
            result
        };
        Self::attach_context_integrity_metadata(delivered, &evaluation)
    }

    fn capability_context_flags(&self, server: &str, tool: &str) -> (bool, bool) {
        if let Some(capabilities) = self.get_capabilities()
            && server == capabilities.name
            && let Some(capability) = capabilities.get(tool)
        {
            let read_only = capability.metadata.read_only;
            let destructive = capability.metadata.destructive.unwrap_or(!read_only);
            return (read_only, destructive);
        }

        (false, false)
    }

    fn context_integrity_delivered_result(
        evaluation: &ContextIntegrityEvaluation,
        original: &Value,
    ) -> Value {
        let Some(delivered) = evaluation.transformed.delivered.clone() else {
            return json!({
                "isError": true,
                "content": [{
                    "type": "text",
                    "text": format!(
                        "Tool result withheld by ContextIntegrityKernel: {}",
                        evaluation.policy.rationale
                    )
                }]
            });
        };

        let text = delivered
            .as_str()
            .map_or_else(|| delivered.to_string(), str::to_string);
        let content = json!([{"type": "text", "text": text}]);

        // Rebuild rather than clone the backend's result. The kernel has just
        // judged this payload untrusted, so any field carried across is one
        // enforcement never inspected -- `_meta` is free-form and a compromised
        // backend can hang anything off it.
        //
        // The one thing that must survive is the fact that this is an interim
        // round, not a finished call. `resultType` is the discriminator and
        // `requestState` the handle. A handle without its discriminator is a
        // result that lies -- a live continuation token on a payload claiming
        // to be finished -- so the handle never crosses alone. The reverse is
        // not a lie but a narrowing: a round this gateway cannot parse keeps
        // its discriminator and loses its handle, so the caller learns the
        // exchange is unfinished without being handed a token nothing here
        // understood. `InputRequired` owns that parse, so ask it rather than
        // copying field names: a handle only crosses when the protocol type
        // says it is one.
        //
        // The questions themselves (`inputRequests`) do NOT cross as structure.
        // Note what that does and does not buy: `Strip` renders the whole
        // envelope into the delivered text, so the question text reaches the
        // caller regardless. What is withheld is a machine-actionable copy of
        // uninspected backend JSON, not the attacker's words.
        //
        // That leaves the caller holding a handle and no structured questions,
        // which is a deliberate narrowing and not a settled policy. The wider
        // choice -- carry the questions, or refuse the round outright with no
        // handle at all -- changes what enforcement means for an unfinished
        // exchange and is the operator's to make. Tracked in the v4.0.0
        // release notes as an open decision; until it is made, the conservative
        // reading applies: the exchange is known to continue, and nothing the
        // kernel judged untrusted crosses as structure.
        // `resultType` and `isError` describe the round. Their VALUES cross
        // untouched -- an unrecognized round type is still a round type, and
        // filtering by value is what turns a future protocol revision into a
        // completed call. Their TYPES do not: the protocol says one is a
        // string and the other a boolean, and anything else is not a
        // description this gateway can pass on. It cannot be dropped, because
        // a dropped discriminator reads as a finished success; it cannot be
        // cloned, because an object in a scalar field is uninspected backend
        // structure crossing the very boundary this transform exists to hold.
        // So a malformed round is refused outright: the caller learns the
        // backend replied badly and gets nothing it could act on.
        let result_type = original.get("resultType");
        let is_error = original.get("isError");
        let malformed = result_type.is_some_and(|value| !value.is_string())
            || is_error.is_some_and(|value| !value.is_boolean());
        if malformed {
            return json!({
                "content": [{
                    "type": "text",
                    "text": "The backend returned a malformed result: `resultType`                              must be a string and `isError` a boolean. The response                              was refused rather than delivered."
                }],
                "isError": true,
            });
        }
        let mut envelope = serde_json::Map::new();
        for (field, value) in [("resultType", result_type), ("isError", is_error)] {
            if let Some(value) = value {
                envelope.insert(field.to_string(), value.clone());
            }
        }
        // The handle is gated on the protocol type rather than on the field
        // name: `InputRequired` owns that parse, so a `requestState` crosses
        // only when the payload really is an input-required round.
        if let Some(request_state) =
            InputRequired::from_result(original).and_then(|interim| interim.request_state)
        {
            envelope.insert("requestState".to_string(), Value::String(request_state));
        }
        envelope.insert("content".to_string(), content);
        envelope.insert("structuredContent".to_string(), delivered);
        Value::Object(envelope)
    }

    fn attach_context_integrity_metadata(
        mut result: Value,
        evaluation: &ContextIntegrityEvaluation,
    ) -> Value {
        let metadata = json!({
            "schema_version": &evaluation.schema_version,
            "content_sha256": &evaluation.content_sha256,
            "provenance": &evaluation.provenance,
            "classification": &evaluation.classification,
            "policy": &evaluation.policy,
            "audit": &evaluation.audit,
        });

        if let Some(obj) = result.as_object_mut() {
            obj.insert("_context_integrity".to_string(), metadata);
            result
        } else {
            json!({
                "structuredContent": result,
                "_context_integrity": metadata
            })
        }
    }

    /// Resolve the per-user propagation headers for a backend by name, for the
    /// direct backend route (`/mcp/{name}`) which does not go through
    /// `dispatch_to_backend` (MIK-6704). Returns the empty vec when the backend
    /// is not propagation-configured (unchanged static path); fail-closed `Err`
    /// for a `required` backend with no identity/strategy.
    pub async fn resolve_propagation_headers(
        &self,
        server: &str,
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
    ) -> Result<Vec<(String, String)>> {
        Ok(self
            .resolve_propagation_credential(server, verified_identity)
            .await?
            .0)
    }

    /// Like [`Self::resolve_propagation_headers`] but also returns the caller's
    /// stable identity binding (MIK-6784), so the direct backend route can
    /// partition upstream `MCP-Session-Id` state per identity. The binding is
    /// `None` for a non-propagation backend (unchanged static path).
    ///
    /// # Errors
    ///
    /// Fail-closed `Err` for a `required` backend with no identity/strategy —
    /// same contract as [`Self::resolve_propagation_headers`].
    pub async fn resolve_propagation_credential(
        &self,
        server: &str,
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
    ) -> Result<(Vec<(String, String)>, Option<String>)> {
        let Some(idp_cfg) = self
            .backends
            .get(server)
            .and_then(|b| b.identity_propagation_config().cloned())
        else {
            self.refuse_unbound_account_backend(server)?;
            return Ok((Vec::new(), None));
        };
        let cred = self
            .resolve_caller_credential(server, &idp_cfg, verified_identity)
            .await?;
        Ok((cred.headers, cred.cache_binding))
    }

    /// Fail closed for a backend that names an `accounts.descriptors` entry but
    /// reached dispatch with no compiled propagation configuration.
    ///
    /// Startup compiles a bound backend's descriptor into its effective
    /// `identity_propagation` before the backend is constructed, so the only
    /// way to observe this state is a registration rebuilt from the raw config
    /// (a hot reload) that lost the binding. Dispatching then would send the
    /// call with no per-user credential at all — the exact silent downgrade the
    /// account reference exists to prevent — so it is refused instead.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] naming the backend and its descriptor reference.
    fn refuse_unbound_account_backend(&self, server: &str) -> Result<()> {
        let account = self
            .backends
            .get(server)
            .and_then(|b| b.account_descriptor_id().map(str::to_string));
        match account {
            Some(account) => Err(Error::Config(format!(
                "backend '{server}' is bound to account '{account}' but no account strategy is \
                 installed for it; refusing to dispatch without the account holder's credential"
            ))),
            None => Ok(()),
        }
    }

    /// Resolve the per-user identity-propagation credential for a backend
    /// configured with `identity_propagation` (MIK-6704 / ADR-007). This is the
    /// single identity gate: minting, fail-closed enforcement, and the cache
    /// binding are decided once here, then reused for the cache key AND dispatch.
    ///
    /// Fail-closed for a `required` backend: returns `Err` — never a
    /// static-credential fallback — when there is no verified identity, no
    /// propagation strategy wired, the strategy refuses, or a minted header does
    /// not parse. For a non-required backend, a mint failure degrades to the
    /// empty credential (no headers, no binding → shared cache key, best-effort).
    async fn resolve_caller_credential(
        &self,
        server: &str,
        idp_cfg: &crate::identity_propagation::IdentityPropagationConfig,
        verified_identity: Option<&crate::key_server::oidc::VerifiedIdentity>,
    ) -> Result<CallerCredential> {
        use crate::identity_propagation::BackendDescriptor;

        // Audit context (MIK-6740, IDP4): every mint and every fail-closed
        // refusal on THIS route is recorded, identically to the direct backend
        // route. Only subject/backend/audience/reason reach the log — never the
        // minted credential bytes.
        let audit_logger = self.transparency_logger.as_ref();
        let subject_id = crate::identity_propagation::audit_subject(verified_identity);
        let audience = idp_cfg.audience.as_str();

        let vault = idp_cfg.strategy == crate::identity_propagation::PropagationStrategyKind::Vault;
        let refuse = async |msg: String| -> Result<CallerCredential> {
            if idp_cfg.required || vault {
                // The request is already being refused on identity-propagation
                // grounds; an audit-write failure here does not change that
                // outcome (unlike the mint path below, which is fail-closed on
                // the audit write itself) — but it must not be silently
                // dropped, so it is logged.
                Self::audit_refused_credential(audit_logger, &subject_id, server, audience, &msg)
                    .await;
                Err(Error::Config(format!(
                    "identity propagation required for backend '{server}' but {msg}"
                )))
            } else {
                // Best-effort: non-required backend proceeds with static creds.
                // This is the static-credential fallback (IDP.5), not a mint or
                // a fail-closed refusal, so — like the direct route's
                // `Ok(empty)` branch — it is intentionally not audited.
                Ok(CallerCredential::default())
            }
        };

        // Vault is installed only for a compiled account-bound backend. A raw
        // declaration cannot borrow a global strategy, even when optional.
        let account_bound = self
            .backends
            .get(server)
            .is_some_and(|backend| backend.account_descriptor_id().is_some());
        if vault && !account_bound {
            return refuse(
                "raw Vault identity propagation requires an account descriptor".to_string(),
            )
            .await;
        }

        // MIK-6710: refuse BEFORE minting when this backend's transport cannot
        // carry `extra_headers` on the wire (stdio, websocket) — otherwise a
        // `required` backend would mint successfully here and then silently
        // run unauthenticated once `request_with_headers` drops the credential.
        //
        // A missing registry entry defaults to "capable": every real caller
        // resolves `idp_cfg` FROM the registered backend, so a `Some(idp_cfg)`
        // guarantees the backend exists in production; "not found" only happens
        // in unit tests against a fabricated config, and a genuinely absent
        // backend fails downstream at dispatch regardless.
        let transport_capable = self
            .backends
            .get(server)
            .is_none_or(|b| b.transport_carries_identity_headers());
        if let Err(msg) = crate::identity_propagation::ensure_transport_carries_identity_headers(
            idp_cfg.required,
            transport_capable,
        ) {
            return refuse(msg).await;
        }

        let Some(identity) = verified_identity else {
            return refuse("the request carries no verified end-user identity".to_string()).await;
        };
        // An explicit account reference requires its own installed strategy.
        // A missing or stale install must never borrow an unrelated global
        // strategy. Descriptorless callers retain their existing behavior.
        let strategy = if account_bound {
            self.backend_identity_strategy(server)
        } else {
            self.backend_identity_strategy(server)
                .or_else(|| self.identity_propagation.read().clone())
        };
        let Some(strategy) = strategy else {
            return refuse("no identity-propagation strategy is configured".to_string()).await;
        };

        let descriptor = BackendDescriptor {
            id: server.to_string(),
            audience: idp_cfg.audience.clone(),
            token_exchange_endpoint: idp_cfg.token_exchange_endpoint.clone(),
            token_exchange_scope: idp_cfg.token_exchange_scope.clone(),
        };
        match strategy.propagate(identity, &descriptor).await {
            Ok(cred) => {
                // Validate every header parses BEFORE dispatch, so an invalid
                // minted credential fails closed rather than silently letting the
                // static Authorization through (MIK-6734 review carry-forward).
                for (k, v) in &cred.headers {
                    if k.parse::<reqwest::header::HeaderName>().is_err()
                        || v.parse::<reqwest::header::HeaderValue>().is_err()
                    {
                        return refuse(format!("minted credential header '{k}' is invalid")).await;
                    }
                }
                // cache_binding distinguishes user AND audience (collision-safe),
                // so per-user results cache in isolation instead of being dropped
                // (IDP.8 — replaces the earlier blanket cache bypass).
                if !cred.headers.is_empty() {
                    Self::audit_minted_credential(
                        server,
                        idp_cfg,
                        audit_logger,
                        &subject_id,
                        audience,
                    )
                    .await?;
                }
                Ok(CallerCredential {
                    headers: cred.headers,
                    cache_binding: Some(cred.cache_binding),
                })
            }
            Err(e) => refuse(format!("credential minting failed: {e}"))
                .await
                .map_err(|refused| {
                    let backend = self.backends.get(server);
                    let account_id = backend.as_deref().and_then(|b| b.account_descriptor_id());
                    crate::personal_accounts::refusal::mark(refused, &e, account_id)
                }),
        }
    }

    /// Record an `idp_refuse`. The request is refused on identity-propagation
    /// grounds either way, so a failed write is logged, never dropped.
    async fn audit_refused_credential(
        audit_logger: Option<&Arc<crate::security::TransparencyLogger>>,
        subject_id: &str,
        server: &str,
        audience: &str,
        msg: &str,
    ) {
        if let Err(audit_err) = crate::identity_propagation::audit_identity_propagation(
            audit_logger,
            "idp_refuse",
            subject_id,
            server,
            Some(audience),
            Some(msg),
        )
        .await
        {
            tracing::warn!(
                server,
                error = %audit_err,
                "identity-propagation refuse audit write failed"
            );
        }
    }

    /// Fail-closed hardening: a minted credential must never reach the caller
    /// without a durable audit record, so an audit-write failure here aborts
    /// the mint instead of letting it proceed. Split out of
    /// [`Self::resolve_caller_credential`] purely to keep that function under
    /// the line budget — logic and ordering are unchanged.
    ///
    /// Operator-misconfig fail-OPEN guard: the audit helper treats `logger =
    /// None` (transparency log disabled) as a no-op `Ok(())`. On a `required`
    /// backend that would let a minted per-user credential go on the wire
    /// with NO audit record — the "no mint without a durable audit record"
    /// guarantee silently evaporating via misconfiguration. When propagation
    /// is REQUIRED but no transparency log is configured, fail closed on the
    /// SAME path as an audit-write failure rather than mint blind.
    /// (Non-required backends keep the `None -> Ok(())` best-effort
    /// behavior — a mint there is not covered by the durable-record
    /// guarantee.)
    async fn audit_minted_credential(
        server: &str,
        idp_cfg: &crate::identity_propagation::IdentityPropagationConfig,
        audit_logger: Option<&Arc<crate::security::TransparencyLogger>>,
        subject_id: &str,
        audience: &str,
    ) -> Result<()> {
        if idp_cfg.required && audit_logger.is_none() {
            return Err(Error::Internal(format!(
                "identity-propagation is required for backend '{server}' but no \
                 transparency log is configured; refusing to mint a per-user \
                 credential without a durable audit record"
            )));
        }
        if let Err(audit_err) = crate::identity_propagation::audit_identity_propagation(
            audit_logger,
            "idp_mint",
            subject_id,
            server,
            Some(audience),
            None,
        )
        .await
        {
            // CWE-209: `audit_err` can carry the transparency-log filesystem
            // path / IO detail. Keep it in the server log only; return a
            // generic client-facing message so the sensitive detail never
            // reaches the JSON-RPC caller (mirrors the direct route in
            // backend_handlers.rs).
            tracing::warn!(
                server,
                error = %audit_err,
                "identity-propagation mint audit write failed"
            );
            return Err(Error::Internal(format!(
                "identity-propagation audit unavailable for backend '{server}'"
            )));
        }
        Ok(())
    }

    /// Resolve the account credential a CAPABILITY tool needs, before any
    /// cache is consulted.
    ///
    /// `Ok(None)` means there is nothing to resolve on this route: the target
    /// is not the capability backend, the tool is not one of its capabilities,
    /// the capability names no account, or the account is an explicit `shared`
    /// descriptor whose static credential path is preserved unchanged. Every
    /// other outcome is either a credential minted for the verified caller by
    /// the ONE shared registry — the same instance the executor rechecks
    /// against — or a refusal that returns before the response cache is read.
    ///
    /// The reference read here is the capability's PRIMARY `auth`, which is the
    /// same `auth` the executor injects at egress; nothing here re-derives it
    /// from a provider name or a backend name.
    ///
    /// # Errors
    ///
    /// Every refusal from
    /// [`crate::identity_propagation::AccountStrategyRegistry::resolve`].
    async fn resolve_capability_account_credential(
        &self,
        server: &str,
        tool: &str,
        caller: CallerProof<'_>,
    ) -> Result<Option<Arc<crate::identity_propagation::PreparedAccountCredential>>> {
        use crate::identity_propagation::AccountCredential;

        let Some(capabilities) = self.get_capabilities() else {
            return Ok(None);
        };
        if server != capabilities.name {
            return Ok(None);
        }
        let Some(definition) = capabilities.get(tool) else {
            return Ok(None);
        };
        let Some(account) = definition.auth.account.as_deref() else {
            return Ok(None);
        };
        match self
            .account_strategies
            .resolve(account, &definition.auth.key, caller)
            .await?
        {
            AccountCredential::Legacy => Ok(None),
            AccountCredential::Prepared(prepared) => Ok(Some(prepared)),
        }
    }

    /// Admits one backend call against the configured spend budget.
    ///
    /// Per dispatch, not per `gateway_invoke`: a bridged exchange makes one
    /// backend call per round, and a budget checked only at the first would let
    /// a backend that keeps asking spend past the operator's limit.
    ///
    /// Returns the warnings to inject post-dispatch; blocks with JSON-RPC
    /// -32003 carrying the enforcer's own reason.
    #[cfg(feature = "cost-governance")]
    fn admit_spend(&self, tool: &str, api_key_name: Option<&str>) -> Result<Vec<String>> {
        let Some(ref enforcer) = self.budget_enforcer else {
            return Ok(Vec::new());
        };
        let result = enforcer.check(tool, api_key_name);
        if !result.allowed {
            return Err(Error::json_rpc(
                -32003,
                result
                    .block_reason
                    .unwrap_or_else(|| "Budget exceeded".to_string()),
            ));
        }
        Ok(result.warnings)
    }

    /// MIK-7570.SCHEMA.1 (R2): the `isError` result refusing a call to an MCP
    /// backend whose arguments carry keys the tool's schema does not declare.
    ///
    /// Runs on the arguments as the caller sent them, before secret injection,
    /// so a gateway-injected credential is never mistaken for an invented key.
    /// Capabilities are skipped: their executor validates after injection.
    fn undeclared_key_refusal(
        &self,
        server: &str,
        tool: &str,
        arguments: &Value,
        identity_key: Option<&str>,
    ) -> Option<Value> {
        if self
            .get_capabilities()
            .is_some_and(|cap| server == cap.name && cap.has_capability(tool))
        {
            return None;
        }
        let text =
            self.backends
                .get(server)?
                .undeclared_key_refusal(identity_key, tool, arguments)?;
        Some(json!({ "content": [{ "type": "text", "text": text }], "isError": true }))
    }

    /// Dispatch one round to the backend and meter it.
    ///
    /// Holds every emission that must fire once per backend call: the
    /// invocation counter, the latency histogram, the prompt-cache token
    /// record, the error budget, the cost tracker and the daily spend
    /// accumulator. A bridged retry round is a real call — it takes latency
    /// and spends budget exactly as the round that opened the exchange did —
    /// so metering left behind at a single call site would make every round
    /// after the first invisible.
    ///
    /// The spend gate is deliberately NOT here either, though it is also per
    /// call. It runs in `admit_spend`, above the point where a retry handle is
    /// redeemed; moving it below that redemption would burn a continuation on
    /// a call the budget refuses. Each caller of this function admits its own
    /// round first.
    #[allow(clippy::too_many_arguments)]
    async fn accounted_dispatch(
        &self,
        server: &str,
        tool: &str,
        arguments: Value,
        outbound_retry: &OutboundRetry,
        prompt_cache_key: Option<&str>,
        inbound_meta: Option<&Value>,
        want_full: bool,
        session_id: Option<&str>,
        caller_identity: Option<&GrantSubject>,
        // The VERIFIED end-user identity, carried for the capability route
        // whose account boundary is inside the executor. Pass-through only.
        caller_proof: CallerProof<'_>,
        propagated_headers: &[(String, String)],
        cache_binding: Option<&str>,
        // The capability route's account credential, resolved once above the
        // response cache and carried down unchanged. `None` for every MCP
        // backend and for a capability with no account reference.
        account_credential: Option<Arc<crate::identity_propagation::PreparedAccountCredential>>,
        api_key_name: Option<&str>,
        trace_id: &str,
        policy_epoch: u64,
        protocol_revision: Option<&str>,
        routing_profile: &str,
        scope: super::InvokeScope<'_>,
    ) -> Result<Value> {
        let dispatch_start = Instant::now();
        let dispatch_result = self
            .dispatch_to_backend(
                server,
                tool,
                arguments,
                outbound_retry,
                prompt_cache_key,
                inbound_meta,
                want_full,
                session_id,
                caller_identity,
                caller_proof,
                propagated_headers,
                cache_binding,
                account_credential,
                policy_epoch,
                protocol_revision,
                routing_profile,
                scope,
            )
            .await;
        let dispatch_latency = dispatch_start.elapsed();
        telemetry_metrics::counter!(
            "mcp_tool_invocations_total",
            "server" => server.to_owned(),
            "status" => if dispatch_result.is_ok() { "ok" } else { "error" }
        )
        .increment(1);
        telemetry_metrics::histogram!(
            "mcp_tool_invocation_duration_seconds",
            "server" => server.to_owned()
        )
        .record(dispatch_latency.as_secs_f64());

        // Record prompt-cached tokens from the backend response (if any)
        if let Ok(ref response) = dispatch_result {
            let cached_tokens = extract_cached_tokens(response);
            if cached_tokens > 0
                && let Some(ref stats) = self.stats
            {
                stats.record_cached_tokens(server, session_id, cached_tokens);
                debug!(
                    server,
                    tool, cached_tokens, trace_id, "Prompt cache hit recorded"
                );
            }
        }

        self.record_error_budget(server, tool, BudgetOutcome::of(&dispatch_result));

        // Record cost for successful calls (token count estimated at 0 for non-LLM tools).
        if dispatch_result.is_ok()
            && let Some(sid) = session_id
        {
            self.cost_tracker.record(
                sid,
                api_key_name,
                server,
                tool,
                0, // token_count: 0 for backend tool calls (no model inference)
                crate::cost_accounting::DEFAULT_PRICE_PER_MILLION,
            );
        }

        // === POST-INVOKE: BudgetEnforcer cost recording ===
        //
        // Record actual spend for per-tool and global daily accumulators.
        // Only on success — the call actually incurred the cost.
        #[cfg(feature = "cost-governance")]
        if dispatch_result.is_ok()
            && let Some(ref enforcer) = self.budget_enforcer
        {
            let cost = enforcer.registry.cost_for(tool);
            enforcer.record_spend(tool, api_key_name, cost);
        }

        dispatch_result
    }

    /// Dispatch a `tools/call` to the capability backend or an MCP backend.
    ///
    /// Applies secret injection before forwarding. When `prompt_cache_key` is
    /// `Some`, it is injected into the request `_meta` field so that
    /// OpenAI-compatible backends can use it for prompt caching.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)] // Coherent dispatch unit; identity-propagation enforcement inline
    async fn dispatch_to_backend(
        &self,
        server: &str,
        tool: &str,
        arguments: Value,
        // What a multi-round-trip retry carries beside `arguments` (MRTR.1).
        // Empty for a fresh call, which is every call that is not a retry.
        outbound_retry: &OutboundRetry,
        prompt_cache_key: Option<&str>,
        // The caller's own `_meta`, read but never relayed wholesale: only the
        // propagable trace context survives the hop (see `build_outbound_meta`).
        inbound_meta: Option<&Value>,
        want_full: bool,
        session_id: Option<&str>,
        // Identity that reaches the capability executor. The grant that admits
        // it was decided at the authorization chokepoint, so nothing here
        // re-decides it — this is the value the call is made *with*, not the
        // one it is checked against.
        caller_identity: Option<&GrantSubject>,
        // What the request PROVED about its caller, for the capability route
        // whose account boundary is inside the executor. Pass-through only.
        caller_proof: CallerProof<'_>,
        // Pre-resolved per-user propagation headers (empty = none). Resolved
        // once in `invoke_tool_traced` so the cache key and this dispatch share
        // one credential (MIK-6734); dispatch never mints.
        propagated_headers: &[(String, String)],
        // Caller's stable identity binding (MIK-6784). Transport uses it to
        // partition upstream `MCP-Session-Id` state; the capability executor
        // copies the same already-resolved string into the inner cache key.
        // `None` → shared default bucket / public namespace.
        identity_key: Option<&str>,
        // Resolved before the outer response cache, rechecked against the same
        // registry inside the executor before the inner cache and before
        // egress. Never minted here.
        account_credential: Option<Arc<crate::identity_propagation::PreparedAccountCredential>>,
        policy_epoch: u64,
        protocol_revision: Option<&str>,
        routing_profile: &str,
        scope: super::InvokeScope<'_>,
    ) -> Result<Value> {
        let injection = self.secret_injector.inject(server, tool, arguments)?;
        let arguments = injection.arguments;

        if let Some(cap) = self.get_capabilities()
            && server == cap.name
            && cap.has_capability(tool)
        {
            // The grant was decided at the authorization chokepoint, above the
            // caches. The definition is resolved again here only for the
            // response transform below.
            let cap_def = cap
                .get(tool)
                .ok_or_else(|| Error::Config(format!("Capability not found: {tool}")))?;
            let result = call_capability_tool_with_identity(
                &cap,
                tool,
                arguments,
                crate::capability::CapabilityExecutionContext {
                    caller_identity: caller_identity.cloned(),
                    allow_loopback_egress: false,
                    policy_epoch: Some(policy_epoch),
                    protocol_revision: protocol_revision.map(str::to_owned),
                    routing_profile: Some(routing_profile.to_owned()),
                    cache_binding: identity_key.map(str::to_owned),
                    // Threaded untouched, never synthesised. `caller_identity`
                    // above is a `GrantSubject` whose authority is not an OAuth
                    // issuer, so a key built from it would bind a person the
                    // gateway never authenticated.
                    verified_identity: caller_proof.verified().cloned().map(Arc::new),
                    caller_provenance: caller_proof.provenance(),
                    // Carried, not re-resolved: the executor rechecks it
                    // against the same registry before its own cache lookup
                    // and again before egress.
                    account_credential,
                },
            )
            .await?;
            let mut response = serde_json::to_value(result)?;

            // Apply per-capability response_transform when configured.
            //
            // The transform pipeline (project, rename, hide, etc.) operates on
            // the *capability payload*, not the MCP envelope. Without unwrapping
            // first, `transform.project: [issue]` for a Linear mutation would
            // search for an "issue" key at the top of `{content, structuredContent,
            // isError}`, find nothing, and silently return `{}`. See bug report:
            // https://github.com/MikkoParkkola/mcp-gateway/issues/167.
            //
            // `_full: true` (stripped earlier in invoke_tool_traced) bypasses
            // projection entirely.
            if !want_full && !cap_def.response_transform.is_empty() {
                let t = ResponseTransform::new(&cap_def.response_transform);
                let inner =
                    extract_output_validation_target(&response).unwrap_or_else(|| response.clone());
                let inner_populated = json_is_populated(&inner);
                let transformed = t.transform_result(tool, inner).await?;
                if inner_populated && !json_is_populated(&transformed) {
                    // Fail-fast (observability): projection emptied a populated
                    // payload — the spec likely names fields absent from this
                    // response. We still apply the projection (it may be a
                    // privacy/allowlist boundary, so we must NOT fall back to
                    // the full response and risk leaking dropped fields). The
                    // warning surfaces the misconfiguration; callers who want
                    // the unprojected payload pass `_full: true`.
                    tracing::warn!(
                        server = server,
                        tool = tool,
                        "response_transform produced an empty payload; returning projected result (pass _full:true to bypass projection)"
                    );
                }
                response = apply_validated_output(&response, transformed);
            }

            let output_schema =
                (!cap_def.schema.output.is_null()).then(|| cap_def.schema.output.clone());

            let validated = enforce_output_schema(server, tool, response, output_schema.as_ref());

            // Canonical projection (MIK-3534), applied last — after
            // response_transform (so `_raw` cannot re-expose a redacted field)
            // and after schema validation (the projected `{actor, …, _raw}`
            // shape would not satisfy a backend output schema). Rides the same
            // `!want_full` gate as response_transform, so the response cache and
            // idempotency layers inherit correctness: a non-`_full` caller
            // caches the projected shape, a `_full` caller bypasses both.
            //
            // The rollout gate (MIK-5877) decides whether projection runs at
            // all: `off` (default) never projects — a declared spec changes no
            // contract; `on` always projects; `experimental` projects only the
            // treatment arm of a sticky per-session A/B split.
            let decision = crate::projection::projection_decision(self.projection_mode, session_id);
            let spec_present = cap_def.projection.is_some();
            let final_result = if decision.project
                && let Some(spec) = cap_def.projection.as_ref()
            {
                apply_capability_projection(validated, spec, want_full)
            } else {
                validated
            };

            // A/B telemetry (MIK-5877, PROJ-ROLLOUT.3): one structured event per
            // eligible invocation so the experiment is measurable. No-op outside
            // `experimental` mode / spec-less tools.
            if let Some(rec) = crate::projection::ab_classification(
                self.projection_mode,
                session_id,
                want_full,
                spec_present,
            ) {
                emit_projection_ab_event(session_id, server, tool, rec, &final_result);
            }
            return Ok(final_result);
        }

        let backend = self
            .backends
            .get(server)
            .ok_or_else(|| Error::BackendNotFound(server.to_string()))?;

        // A "did you mean?" hint off THIS CALLER'S slot (MIK-7334.CATALOGUE.1):
        // the shared one holds a catalogue this caller was never shown once a
        // `stateless` backend lists per caller. Stale-tolerant; we still dispatch.
        let cached_names = backend.get_cached_tool_names_for(identity_key);
        let tool_is_cached = cached_names.iter().any(|n| n == tool);

        // Build request params. `_meta` is one object, so one writer owns it:
        // the caller's propagable trace context and this hop's cache key are
        // merged, or the field is absent entirely (design §3.4a).
        let mut params = json!({ "name": tool, "arguments": arguments });
        if let Some(meta) = build_outbound_meta(inbound_meta, prompt_cache_key)
            && let Value::Object(map) = &mut params
        {
            map.insert("_meta".to_string(), meta);
        }
        outbound_retry.apply(&mut params);

        // End-user identity propagation (MIK-6704 / ADR-007) and per-identity
        // upstream session partitioning (MIK-6784). The per-user credential was
        // resolved (and fail-closed enforced) once upstream in
        // `invoke_tool_traced`; here we simply attach the pre-resolved headers
        // plus the caller's identity key via `request_with_headers` (per-request,
        // never on the shared transport — tenant isolation, IDP.3). Only when
        // there are neither headers nor an identity key do we take the unchanged
        // static path (shared default session bucket).
        // The upstream-task leg, and the ONLY one. It is a different transport
        // entry point on the same dispatch, reached after every gate above —
        // kill switch, capability cooldown, `_full`/`_claim` stripping,
        // idempotency, authorization, secret injection — has already run. A
        // parallel submission path would be a second dispatcher with a
        // different set of gates, which is exactly what this funnel exists to
        // prevent.
        //
        // Armed only by the task worker, for exactly this `(server, tool)`, and
        // sent exactly once: a retried task-augmented call is a second upstream
        // job this gateway would not hold the handle for.
        let submission = crate::gateway::meta_mcp::upstream::armed_submission(server, tool);
        let response = match &submission {
            Some(_) => {
                backend
                    .request_with_task_capability(
                        "tools/call",
                        Some(params),
                        propagated_headers,
                        identity_key,
                    )
                    .await?
            }
            None if propagated_headers.is_empty() && identity_key.is_none() => {
                backend.request("tools/call", Some(params)).await?
            }
            None => {
                backend
                    .request_with_headers(
                        "tools/call",
                        Some(params),
                        propagated_headers,
                        identity_key,
                    )
                    .await?
            }
        };

        if let Some(error) = response.error {
            // When we have cached names and the tool wasn't in them, enrich
            // the error with Levenshtein-based suggestions.
            let message = if !cached_names.is_empty() && !tool_is_cached {
                // Drawn only from names this caller could invoke (A3).
                let candidates: Vec<&str> = cached_names
                    .iter()
                    .map(String::as_str)
                    .filter(|name| self.may_invoke(server, name, scope, session_id).is_ok())
                    .collect();
                match did_you_mean(tool, &candidates, 3, 3) {
                    Some(hint) => format!("Tool '{tool}' not found on server '{server}'. {hint}"),
                    None => format!(
                        "Tool '{tool}' not found on server '{server}'. {}",
                        error.message
                    ),
                }
            } else {
                error.message
            };
            return Err(Error::JsonRpc {
                code: error.code,
                message,
                data: error.data,
            });
        }

        let result = response.result.unwrap_or(json!(null));
        // The RAW reply, here and nowhere else: this value has not been through
        // projection, the contract gate or any shaping, so a `resultType:
        // "task"` in it is the peer's own envelope and never one this gateway
        // stamped on its own answer.
        if let Some(submission) = &submission {
            submission.offer(&result);
        }
        let output_schema = self
            .get_tool_registry()
            .and_then(|registry| registry.get(&format!("{server}:{tool}")))
            .and_then(|entry| entry.tool.output_schema)
            .or_else(|| {
                backend
                    .get_cached_tool_for(identity_key, tool)
                    .and_then(|cached| cached.output_schema)
            });

        Ok(enforce_output_schema(
            server,
            tool,
            result,
            output_schema.as_ref(),
        ))
    }

    // ========================================================================
    // Operator control meta-tools
    // ========================================================================

    /// `gateway_cost_report` — per-session and per-API-key spend report.
    #[allow(
        unknown_lints,
        clippy::unnecessary_wraps,
        clippy::unused_async,
        clippy::unused_async_trait_impl
    )]
    pub(super) async fn get_cost_report(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    ) -> Result<Value> {
        let include_all_sessions = extract_bool_or(args, "include_all_sessions", false);
        let include_all_keys = extract_bool_or(args, "include_all_keys", false);

        // Both are documented in this tool's own schema as an admin view, and
        // were read straight from the arguments. Refusing beats quietly
        // narrowing the report: a caller that asked for every session and got
        // one has no way to tell that it was scoped rather than empty.
        if (include_all_sessions || include_all_keys) && !caller.is_admin {
            return Err(crate::Error::Config(
                "include_all_sessions and include_all_keys are admin views and require an \
                 admin credential"
                    .to_string(),
            ));
        }

        // Resolve target session. A non-admin caller may name only its own:
        // taking the argument in preference to the caller's session let any
        // client read any other client's spend by guessing or observing an id.
        let requested = extract_optional_str(args, "session_id");
        if let Some(requested) = requested
            && !caller.is_admin
            && Some(requested) != session_id
        {
            return Err(crate::Error::Config(
                "reporting on another session is an admin view and requires an admin \
                 credential"
                    .to_string(),
            ));
        }
        let target_session_id = requested.or(session_id);

        let session_report = if include_all_sessions {
            serde_json::to_value(self.cost_tracker.all_sessions()).unwrap_or(json!([]))
        } else if let Some(sid) = target_session_id {
            self.cost_tracker
                .session_snapshot(sid)
                .map(|s| serde_json::to_value(s).unwrap_or(json!(null)))
                .unwrap_or(json!(null))
        } else {
            json!(null)
        };

        let key_report = if include_all_keys {
            serde_json::to_value(self.cost_tracker.all_keys()).unwrap_or(json!([]))
        } else {
            json!(null)
        };

        // The gateway-wide total is every caller's spend combined, which is the
        // same cross-tenant view the explicit flags are gated on. Gating those
        // and leaving this open would have made the check cosmetic.
        let aggregate = if caller.is_admin {
            serde_json::to_value(self.cost_tracker.aggregate()).unwrap_or(json!(null))
        } else {
            json!(null)
        };

        Ok(json!({
            "session": session_report,
            "keys": key_report,
            "aggregate": aggregate,
        }))
    }

    /// `gateway_get_stats` — gateway statistics with per-backend error budget
    /// and circuit-breaker status.
    #[allow(unknown_lints, clippy::unused_async, clippy::unused_async_trait_impl)]
    pub(super) async fn get_stats(
        &self,
        _args: &Value,
        // The admin flag only decides whether cost figures are included, and
        // that block is feature-gated. Relaxed on the parameter itself, in
        // exactly the build where its one use disappears, so dropping that use
        // under the feature still warns and unrelated bindings stay linted.
        #[cfg_attr(not(feature = "cost-governance"), allow(unused_variables))]
        caller_is_admin: bool,
    ) -> Result<Value> {
        let stats = self
            .stats
            .as_ref()
            .ok_or_else(|| Error::json_rpc(-32603, "Statistics not enabled for this gateway"))?;

        let all_backends = self.backends.all();
        // Publish completeness: an unenumerated backend contributes 0.
        // A truncated drain publishes a lower bound, not a complete total.
        // List and flag under one guard, so a fill landing between the reads
        // cannot pair a truncated count with a clear flag.
        let mut tools_known = true;
        let mut total_tools: usize = 0;
        for b in &all_backends {
            let (tools, truncated) = b.cached_tools_snapshot_and_truncated();
            tools_known &= b.cached_tools_known() && !truncated;
            total_tools += tools.len();
        }
        if let Some(cap) = self.get_capabilities() {
            total_tools += cap.get_tools().len();
        }

        let snapshot = stats.snapshot(total_tools);
        let mut response = build_stats_response(&snapshot, tools_known);

        let safety: Vec<Value> = all_backends
            .iter()
            .map(|b| {
                let killed = self.kill_switch.is_killed(&b.name);
                let error_rate = self.kill_switch.error_rate(&b.name);
                let (successes, failures) = self.kill_switch.window_counts(&b.name);
                build_server_safety_status(&b.name, killed, error_rate, successes, failures)
            })
            .collect();

        let cb_stats: Vec<Value> = all_backends
            .iter()
            .map(|b| build_circuit_breaker_stats_json(&b.name, &b.circuit_breaker_stats()))
            .collect();

        if let Value::Object(ref mut map) = response {
            map.insert("server_safety".to_string(), Value::Array(safety));
            map.insert("circuit_breakers".to_string(), Value::Array(cb_stats));
        }

        // Cost governance is cross-tenant: budgets and spend for every caller.
        #[cfg(feature = "cost-governance")]
        let include_costs = caller_is_admin;
        #[cfg(feature = "cost-governance")]
        if let Some(ref enforcer) = self.budget_enforcer {
            let snap = enforcer.snapshot();
            let cost_section = json!({
                "global_daily_spend_usd": snap.global_daily_usd,
                "global_daily_limit_usd": snap.global_daily_limit,
                "tool_daily_spend": snap.tool_daily,
                "tool_daily_limits": snap.tool_limits,
                "key_daily_spend": snap.key_daily,
            });
            if include_costs && let Value::Object(ref mut map) = response {
                map.insert("cost_governance".to_string(), cost_section);
            }
            if let Some(ref registry) = self.cost_registry {
                let tool_costs = json!(registry.snapshot());
                if let Value::Object(ref mut map) = response {
                    map.insert("tool_costs".to_string(), tool_costs);
                }
            }
        }

        Ok(response)
    }

    /// `gateway_kill_server` — disable a backend via the operator kill switch.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn kill_server(&self, args: &Value) -> Result<Value> {
        let server = extract_required_str(args, "server")?;
        let was_already_killed = self.kill_switch.is_killed(server);
        self.kill_switch.kill(server);
        Ok(json!({
            "server": server,
            "status": "disabled",
            "was_already_killed": was_already_killed,
            "message": format!("Server '{server}' has been disabled by operator kill switch")
        }))
    }

    /// `gateway_revive_server` — re-enable a previously killed backend.
    ///
    /// Resets the error-budget window AND closes a tripped circuit breaker so
    /// the backend starts with a clean slate. The breaker reset is load-bearing
    /// (MIK-5983): the `CIRCUIT_OPEN` error message directs operators to this
    /// tool, so it must actually recover a breaker-tripped backend.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn revive_server(&self, args: &Value) -> Result<Value> {
        let server = extract_required_str(args, "server")?;
        let was_killed = self.kill_switch.is_killed(server);
        self.kill_switch.revive(server);

        let mut breaker_was_open = false;
        if let Some(backend) = self.backends.get(server) {
            breaker_was_open =
                backend.circuit_breaker_stats().state != crate::failsafe::CircuitState::Closed;
            backend.reset_circuit_breaker();
        }

        Ok(json!({
            "server": server,
            "status": "active",
            "was_killed": was_killed,
            "breaker_was_open": breaker_was_open,
            "message": format!("Server '{server}' has been re-enabled")
        }))
    }

    /// `gateway_list_disabled_capabilities` — list capabilities suspended by
    /// the per-capability error budget.
    #[allow(clippy::unnecessary_wraps)]
    /// Filtered by `may_invoke`: a caller learns why its own capability fails,
    /// never that another caller's exists (A3).
    pub(super) fn list_disabled_capabilities(
        &self,
        scope: super::InvokeScope<'_>,
        session_id: Option<&str>,
    ) -> Result<Value> {
        let cap_cfg = self.capability_budget_config.read();
        let disabled = self.kill_switch.disabled_capabilities(cap_cfg.cooldown);
        let entries: Vec<Value> = disabled
            .iter()
            .filter_map(|key| {
                let (backend, capability) = key.split_once(':')?;
                self.may_invoke(backend, capability, scope, session_id)
                    .ok()?;
                let error_rate = self.kill_switch.capability_error_rate(backend, capability);
                Some(json!({
                    "backend": backend,
                    "capability": capability,
                    "error_rate": error_rate,
                    "cooldown_seconds": cap_cfg.cooldown.as_secs(),
                }))
            })
            .collect();
        Ok(json!({
            "disabled_count": entries.len(),
            "disabled_capabilities": entries,
            "note": if entries.is_empty() {
                "No capabilities are currently disabled."
            } else {
                "Capabilities auto-recover after the cooldown period elapses."
            }
        }))
    }

    /// `gateway_reload_config` — trigger an immediate config reload from disk.
    pub(super) async fn reload_config(&self) -> Result<Value> {
        let ctx = self.get_reload_context().ok_or_else(|| {
            Error::json_rpc(-32603, "Config reload is not enabled on this gateway")
        })?;

        match ctx.reload_outcome().await {
            Ok(outcome) => Ok(json!({
                "status": "ok",
                "changes": outcome.changes,
                "restart_required": outcome.restart_required,
                "restart_reason": outcome.restart_reason,
            })),
            Err(e) => Err(Error::json_rpc(-32603, e)),
        }
    }

    /// `gateway_reload_capabilities` — re-read every YAML capability file from disk.
    ///
    /// Designed for the agent-self-development hot path: an agent has just
    /// authored or edited a capability YAML and wants it immediately callable
    /// without restarting the gateway. Mirrors the file-watcher hot-reload that
    /// already triggers on disk changes, but exposes it as an MCP tool the
    /// agent can call directly.
    pub(super) async fn reload_capabilities(&self) -> Result<Value> {
        let backend = {
            let guard = self.capabilities.read();
            guard.clone()
        };
        let backend = backend.ok_or_else(|| {
            Error::json_rpc(-32603, "Capability backend is not enabled on this gateway")
        })?;

        match backend.reload().await {
            Ok(total) => Ok(json!({
                "status": "ok",
                "backend": backend.name,
                "total_capabilities": total,
            })),
            Err(e) => Err(Error::json_rpc(-32603, format!("{e}"))),
        }
    }

    /// `gateway_webhook_status` — webhook endpoint status and delivery stats.
    #[allow(clippy::unnecessary_wraps)]
    pub(super) fn webhook_status(&self) -> Result<Value> {
        let registry = self.get_webhook_registry().ok_or_else(|| {
            Error::json_rpc(-32603, "Webhook receiver is not enabled on this gateway")
        })?;

        let endpoints = registry.read().list_endpoints();
        let total = endpoints.len();
        let total_received: u64 = endpoints.iter().map(|e| e.stats.received).sum();
        let total_delivered: u64 = endpoints.iter().map(|e| e.stats.delivered).sum();

        Ok(json!({
            "endpoints": endpoints,
            "total_endpoints": total,
            "total_received": total_received,
            "total_delivered": total_delivered
        }))
    }

    /// Set the playbook engine (replaces existing).
    #[allow(dead_code)]
    pub fn set_playbook_engine(&self, engine: PlaybookEngine) {
        *self.playbook_engine.write() = engine;
    }

    /// `gateway_run_playbook` — run a named playbook.
    pub(super) async fn run_playbook(
        &self,
        args: &Value,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    ) -> Result<Value> {
        self.refuse_unattested_plan()?;
        let name = extract_required_str(args, "name")?;
        let arguments = parse_tool_arguments(args)?;

        debug!(playbook = name, "Running playbook");

        let definition = if let Some(definition) = caller
            .execution
            .and_then(super::admission::SyncLease::playbook_definition)
        {
            definition.clone()
        } else {
            let engine = self.playbook_engine.read();
            engine
                .get(name)
                .cloned()
                .ok_or_else(|| Error::json_rpc(-32602, format!("Playbook not found: {name}")))?
        };

        let invoker = MetaMcpInvoker { meta: self, caller };

        let mut temp_engine = PlaybookEngine::new();
        temp_engine.register(definition);
        let result = temp_engine.execute(name, arguments, &invoker).await?;

        Ok(serde_json::to_value(&result).unwrap_or(json!(null)))
    }
}

// ============================================================================
// Recovery classification helpers
// ============================================================================

/// Map a dispatch [`Error`] to an [`ErrorCategory`] and a human-readable detail
/// string suitable for embedding in a [`RecoveryHint`].
fn classify_dispatch_error(error: &Error) -> (ErrorCategory, String) {
    match error {
        Error::CircuitOpen {
            backend,
            last_failure,
        } => (
            ErrorCategory::CircuitBreakerTrip,
            match last_failure {
                Some(reason) => {
                    format!(
                        "Circuit breaker is open for backend '{backend}'; last failure: {reason}"
                    )
                }
                None => format!("Circuit breaker is open for backend '{backend}'"),
            },
        ),
        Error::RateLimited(_) => (ErrorCategory::RateLimited, error.to_string()),
        Error::BackendNotFound(name) | Error::ToolNotFound(name) => {
            (ErrorCategory::NotFound, format!("Not found: '{name}'"))
        }
        Error::BackendTimeout(msg) => (ErrorCategory::Timeout, msg.clone()),
        Error::BackendUnavailable(msg) | Error::Transport(msg) | Error::TransportConnect(msg) => {
            (ErrorCategory::BackendError, msg.clone())
        }
        // Protocol errors carry upstream HTTP failures as their message
        // (e.g. "API returned 429 Too Many Requests"). Inspect the text so a
        // rate limit or transient 5xx is not mislabelled as a param error.
        Error::Protocol(msg) => (classify_from_detail(Some(msg)), msg.clone()),
        Error::JsonRpc { message, .. } => (ErrorCategory::BackendError, message.clone()),
        // A capability 429 arrives as a typed `Http` error and no longer says
        // "429" in its message, so the prose classifier above cannot see it.
        // Without this arm the hint silently degrades to `BackendError` and the
        // client is told to retry immediately (GH475.RL.10).
        Error::Http(e) if e.status() == Some(reqwest::StatusCode::TOO_MANY_REQUESTS) => {
            (ErrorCategory::RateLimited, error.to_string())
        }
        _ => (ErrorCategory::BackendError, error.to_string()),
    }
}

/// How a dispatch counts against the error budgets.
///
/// A `bool` cannot express the third case: an outcome that is neither a success
/// nor a failure and must leave the window untouched (GH #475).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BudgetOutcome {
    Success,
    Failure,
    /// Throttled: the backend answered "not so fast", or the gateway's own
    /// rate limiter refused before dispatch (F23). Neither is evidence about
    /// the backend's health, so neither is sampled.
    IgnoredRateLimit,
}

impl BudgetOutcome {
    /// Classify a dispatch result.
    ///
    /// Rate limiting is recognised through the same predicate the backend
    /// circuit breaker uses, so the two cannot disagree about what a throttled
    /// response is.
    ///
    /// MCP carries tool-level failures *inside* a successful response
    /// (`isError: true`), so a throttled backend can answer `Ok`. Reading only
    /// the `Result` shape would sample that as a healthy call and defeat RL.1
    /// for every backend that reports its 429 the protocol's own way.
    pub(super) fn of(result: &Result<Value>) -> Self {
        match result {
            Ok(response) => {
                let is_error = response
                    .get("isError")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                // Scanning the whole envelope is safe only because `isError`
                // gates it: on a successful result the same text is ordinary
                // payload and must not exempt anything.
                if is_error && crate::gateway::recovery::is_rate_limited(&response.to_string()) {
                    Self::IgnoredRateLimit
                } else {
                    // A non-rate-limit `isError: true` is a tool refusing a
                    // request, not a backend in poor health: a bad argument or
                    // a missing file would otherwise open a circuit on a
                    // backend that answered correctly every time. It is
                    // sampled as a success on purpose.
                    Self::Success
                }
            }
            // The gateway's own limiter refused: the backend was never asked.
            // Matched on the variant, not on its message (F23).
            Err(Error::RateLimited(_)) => Self::IgnoredRateLimit,
            Err(error) => {
                if crate::gateway::recovery::is_rate_limited(&error.to_string()) {
                    Self::IgnoredRateLimit
                } else {
                    Self::Failure
                }
            }
        }
    }
}

/// Infer an [`ErrorCategory`] from a backend error/detail string by scanning
/// for HTTP-status signals.
///
/// Capability backends (and the `Error::Protocol` variant) surface upstream
/// HTTP failures as free-text messages rather than typed errors. Without this,
/// a `429 Too Many Requests` is reported as `INVALID_PARAM` with a
/// "fix your parameters" hint — wrong and unactionable, since the call is
/// correct and merely needs a retry after backoff.
///
/// Matching is case-insensitive and conservative: anything that does not match
/// a known signal falls back to [`ErrorCategory::Validation`], preserving the
/// prior behaviour for genuine schema violations.
fn classify_from_detail(detail: Option<&str>) -> ErrorCategory {
    let Some(text) = detail else {
        return ErrorCategory::Validation;
    };
    let lower = text.to_ascii_lowercase();

    // Rate limiting — retryable after backoff, NOT a param error.
    //
    // Delegated to the shared predicate so this classifier and the backend
    // circuit breaker cannot disagree about what a rate-limit response is
    // (GH #475). The narrowing lives there, with its rationale.
    if crate::gateway::recovery::is_rate_limited(text) {
        return ErrorCategory::RateLimited;
    }

    // Timeouts / gateway-timeout — backend was reachable but slow.
    if lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("408")
        || lower.contains("504")
        || lower.contains("gateway timeout")
    {
        return ErrorCategory::Timeout;
    }

    // Transient server-side failures — safe to retry once.
    if lower.contains("500")
        || lower.contains("502")
        || lower.contains("503")
        || lower.contains("internal server error")
        || lower.contains("bad gateway")
        || lower.contains("service unavailable")
    {
        return ErrorCategory::BackendError;
    }

    ErrorCategory::Validation
}

// ============================================================================
// Tests — error classification
// ============================================================================

#[cfg(test)]
mod error_classification_tests {
    use super::classify_from_detail;
    use crate::gateway::recovery::{ErrorCategory, RecoveryContext, recovery_for};

    /// A typed 429 never reaches the prose classifier at all.
    ///
    /// `classify_dispatch_error` dispatches on the error VARIANT and only sends
    /// `Protocol` through `classify_from_detail`. GH475.RL.10 made a capability
    /// 429 an `Error::Http`, and although its `Display` still happens to say
    /// "429" nothing reads that text -- it fell through to `BackendError`, and
    /// the client was told to retry at once instead of backing off. The
    /// listener answers one request and is the only way to obtain a real
    /// `reqwest::Error` carrying a status.
    #[tokio::test]
    async fn a_typed_429_is_still_rate_limited() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut scratch = [0u8; 1024];
            let _ = socket.read(&mut scratch).await;
            let _ = socket
                .write_all(b"HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n")
                .await;
        });

        let response = reqwest::get(format!("http://{addr}/")).await.unwrap();
        let error = crate::Error::Http(response.error_for_status().unwrap_err().without_url());
        let (category, _) = super::classify_dispatch_error(&error);
        assert_eq!(
            category,
            ErrorCategory::RateLimited,
            "a typed 429 must keep the backoff hint the prose one earned"
        );
    }

    #[test]
    fn rate_limit_429_classified_as_rate_limited() {
        // The exact shape returned by archive.org through the REST provider.
        let detail = "Protocol error: API returned 429 Too Many Requests: \
                      <html><body><h1>429 Too Many Requests</h1></body></html>";
        let cat = classify_from_detail(Some(detail));
        assert!(matches!(cat, ErrorCategory::RateLimited));

        // And the resulting hint must be RATE_LIMITED + retryable, NOT
        // INVALID_PARAM with a "fix your params" suggestion.
        let hint = recovery_for(cat, RecoveryContext::default());
        assert_eq!(hint.error_code, "RATE_LIMITED");
        assert!(hint.retry, "rate-limited calls are retryable after backoff");
    }

    #[test]
    fn rate_limit_phrasings_all_match() {
        for s in [
            "rate limit exceeded",
            "Rate-Limit hit",
            "ratelimit reached",
            "request throttled by upstream",
            "HTTP 429",
        ] {
            assert!(
                matches!(classify_from_detail(Some(s)), ErrorCategory::RateLimited),
                "expected RateLimited for {s:?}"
            );
        }
    }

    #[test]
    fn timeout_signals_classified_as_timeout() {
        for s in [
            "request timeout",
            "connection timed out",
            "HTTP 504",
            "504 Gateway Timeout",
        ] {
            assert!(
                matches!(classify_from_detail(Some(s)), ErrorCategory::Timeout),
                "expected Timeout for {s:?}"
            );
        }
    }

    #[test]
    fn server_errors_classified_as_backend_error() {
        for s in [
            "500 Internal Server Error",
            "502 Bad Gateway",
            "503 Service Unavailable",
        ] {
            assert!(
                matches!(classify_from_detail(Some(s)), ErrorCategory::BackendError),
                "expected BackendError for {s:?}"
            );
        }
    }

    /// Row 16c - the client-facing category must not move when a status-carried
    /// refusal starts arriving as `Error::JsonRpc` instead of `Error::Transport`.
    /// Both already map to `BackendError`; this pins that, because the transport
    /// rows cannot reach this classifier.
    #[test]
    fn row_16c_a_json_rpc_refusal_and_a_transport_fault_share_one_category() {
        use super::classify_dispatch_error;
        use crate::Error;

        for error in [
            Error::json_rpc(-32601, "Method not found: server/discover"),
            Error::Transport("HTTP 404".to_string()),
        ] {
            assert!(
                matches!(
                    classify_dispatch_error(&error).0,
                    ErrorCategory::BackendError
                ),
                "expected BackendError for {error:?}"
            );
        }
    }

    #[test]
    fn genuine_validation_errors_default_to_validation() {
        // Schema/param errors must keep the prior behaviour.
        for s in [
            "missing required field 'url'",
            "invalid enum value for 'output'",
            "expected string, got integer",
        ] {
            assert!(
                matches!(classify_from_detail(Some(s)), ErrorCategory::Validation),
                "expected Validation for {s:?}"
            );
        }
        // No detail at all also defaults to Validation.
        assert!(matches!(
            classify_from_detail(None),
            ErrorCategory::Validation
        ));
    }
}

// ============================================================================
// Tests — response_transform wiring
// ============================================================================

#[cfg(test)]
mod response_transform_tests {
    use serde_json::json;

    use crate::capability::validate_output;
    use crate::projection::schema::{ActorSpec, ProjectionSpec, SubjectSpec};
    use crate::provider::Transform as _;
    use crate::provider::transforms::ResponseTransform;
    use crate::transform::{RedactRule, TransformConfig};

    use super::{apply_capability_projection, enforce_output_schema};

    /// Prove the component used by `dispatch_to_backend`: given a non-empty
    /// `response_transform` in a capability definition, `ResponseTransform`
    /// strips all fields not listed in `project`.
    #[tokio::test]
    async fn response_transform_project_strips_unlisted_fields() {
        // GIVEN: a response_transform that keeps only "id" and "name"
        let config = TransformConfig {
            project: vec!["id".to_string(), "name".to_string()],
            ..Default::default()
        };
        let transform = ResponseTransform::new(&config);

        // AND: a raw tool response value with extra fields
        let raw = json!({
            "id": "abc",
            "name": "Alice",
            "internal_token": "secret",
            "noise": 42
        });

        // WHEN: applying the transform (as dispatch_to_backend would)
        let result = transform.transform_result("my_tool", raw).await.unwrap();

        // THEN: only projected fields remain
        assert_eq!(result.get("id"), Some(&json!("abc")));
        assert_eq!(result.get("name"), Some(&json!("Alice")));
        assert!(
            result.get("internal_token").is_none() || result["internal_token"].is_null(),
            "internal_token should be stripped"
        );
        assert!(
            result.get("noise").is_none() || result["noise"].is_null(),
            "noise should be stripped"
        );
    }

    /// Prove that an empty `response_transform` is a no-op: the raw response
    /// passes through completely unchanged.
    #[tokio::test]
    async fn response_transform_noop_when_config_is_empty() {
        // GIVEN: empty (default) transform config
        let config = TransformConfig::default();
        assert!(config.is_empty(), "default config must be empty");
        let transform = ResponseTransform::new(&config);

        // AND: a response with various fields
        let raw = json!({
            "content": [{"type": "text", "text": "hello"}],
            "is_error": false,
            "extra": "field"
        });

        // WHEN: transforming
        let result = transform
            .transform_result("tool", raw.clone())
            .await
            .unwrap();

        // THEN: result is identical to input
        assert_eq!(result, raw);
    }

    /// Prove redact patterns fire on all string values recursively.
    #[tokio::test]
    async fn response_transform_redact_replaces_sensitive_patterns() {
        // GIVEN: redact rule for credit card numbers
        let config = TransformConfig {
            redact: vec![RedactRule {
                pattern: r"\b\d{4}-\d{4}-\d{4}-\d{4}\b".to_string(),
                replacement: "[CC_REDACTED]".to_string(),
            }],
            ..Default::default()
        };
        let transform = ResponseTransform::new(&config);

        // AND: a response containing a card number in a nested field
        let raw = json!({
            "user": "Alice",
            "payment": {
                "card": "1234-5678-9012-3456",
                "valid": true
            }
        });

        // WHEN: transforming
        let result = transform
            .transform_result("billing_tool", raw)
            .await
            .unwrap();

        // THEN: the card number is redacted everywhere
        let card_val = result["payment"]["card"].as_str().unwrap();
        assert_eq!(card_val, "[CC_REDACTED]");
        // Non-sensitive fields are untouched
        assert_eq!(result["user"], json!("Alice"));
    }

    // ------------------------------------------------------------------
    // MIK-3534: canonical projection wiring (apply_capability_projection)
    // ------------------------------------------------------------------

    /// LEAK GUARD: projection runs *after* `response_transform`, so the
    /// preserved `_raw` is built from the already-redacted payload. A field
    /// redacted by `response_transform` must not reappear anywhere — including
    /// under `_raw`. This is the assertion that closes the prior concern about
    /// projection re-exposing redacted data.
    #[tokio::test]
    async fn projection_after_redaction_keeps_raw_redacted() {
        // GIVEN: response_transform redacts a card number...
        let rt = ResponseTransform::new(&TransformConfig {
            redact: vec![RedactRule {
                pattern: r"\b\d{4}-\d{4}-\d{4}-\d{4}\b".to_string(),
                replacement: "[CC_REDACTED]".to_string(),
            }],
            ..Default::default()
        });
        // ...AND the capability also declares a projection spec.
        let spec = ProjectionSpec {
            subject: Some(SubjectSpec {
                title: Some("user".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let inner = json!({"user": "Alice", "card": "1234-5678-9012-3456"});

        // WHEN: dispatch applies response_transform FIRST...
        let transformed = rt.transform_result("billing", inner).await.unwrap();
        // ...THEN canonical projection (bare value — no MCP envelope here).
        let out = apply_capability_projection(transformed, &spec, false);

        // THEN: the canonical bucket is built from the redacted payload
        assert_eq!(out["subject"]["title"], json!("Alice"));
        // AND: _raw preserves the payload with the card already redacted
        assert_eq!(out["_raw"]["card"], json!("[CC_REDACTED]"));
        // AND: the sensitive value appears NOWHERE in the output
        let serialized = serde_json::to_string(&out).unwrap();
        assert!(
            !serialized.contains("1234-5678"),
            "redacted value leaked through projection: {serialized}"
        );
    }

    /// `_full: true` bypasses projection entirely (the same gate that
    /// `response_transform` rides), returning the unprojected payload.
    #[test]
    fn projection_want_full_bypasses() {
        let spec = ProjectionSpec {
            subject: Some(SubjectSpec {
                title: Some("user".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let raw = json!({"user": "Alice", "extra": 1});
        let out = apply_capability_projection(raw.clone(), &spec, true);
        assert_eq!(
            out, raw,
            "_full must return the unprojected payload unchanged"
        );
    }

    /// Fail-fast: a spec that resolves no fields leaves the payload untouched
    /// (no `_raw` wrapper), inheriting `engine::project`'s contract.
    #[test]
    fn projection_fail_fast_passthrough_when_nothing_maps() {
        let spec = ProjectionSpec {
            actor: Some(ActorSpec {
                email: Some("nonexistent.path".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let raw = json!({"id": "x", "name": "y"});
        let out = apply_capability_projection(raw.clone(), &spec, false);
        assert_eq!(out, raw);
        assert!(
            out.get("_raw").is_none(),
            "no projection wrapper when nothing maps"
        );
    }

    /// Projection targets the INNER capability payload inside an MCP envelope
    /// (`structuredContent`), not the outer envelope — guards bug #167.
    #[test]
    fn projection_targets_inner_payload_inside_mcp_envelope() {
        let spec = ProjectionSpec {
            subject: Some(SubjectSpec {
                title: Some("issue.title".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let envelope = json!({
            "content": [{"type": "text", "text": "{\"issue\":{\"title\":\"Fix bug\"}}"}],
            "structuredContent": {"issue": {"title": "Fix bug"}},
            "isError": false
        });
        let out = apply_capability_projection(envelope, &spec, false);
        // The projected canonical view lives in structuredContent, not the
        // outer envelope.
        assert_eq!(
            out["structuredContent"]["subject"]["title"],
            json!("Fix bug")
        );
        assert_eq!(
            out["structuredContent"]["_raw"]["issue"]["title"],
            json!("Fix bug")
        );
    }

    /// Fail-fast on a single-text-content MCP envelope whose text is NOT JSON:
    /// projection resolves nothing, so the envelope must pass through unchanged.
    /// Re-wrapping would clobber the human-readable text with a JSON dump of the
    /// envelope — this is the regression guard for that path.
    #[test]
    fn projection_fail_fast_leaves_text_envelope_untouched() {
        let spec = ProjectionSpec {
            subject: Some(SubjectSpec {
                id: Some("issue.id".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let envelope = json!({
            "content": [{"type": "text", "text": "Issue ISS-1 created"}],
            "isError": false
        });
        let out = apply_capability_projection(envelope.clone(), &spec, false);
        assert_eq!(
            out, envelope,
            "non-matching spec must pass the text envelope through untouched"
        );
    }

    /// An error envelope is never projected — even when the spec would match the
    /// inner payload — so error text stays legible for the recovery classifier.
    #[test]
    fn projection_skips_error_envelopes() {
        let spec = ProjectionSpec {
            subject: Some(SubjectSpec {
                title: Some("issue.title".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let envelope = json!({
            "structuredContent": {"issue": {"title": "boom"}},
            "content": [{"type": "text", "text": "error: boom"}],
            "isError": true
        });
        let out = apply_capability_projection(envelope.clone(), &spec, false);
        assert_eq!(out, envelope, "error envelopes must not be projected");
    }

    // MIK-7212.MRTR.2a: a backend's own `requestState` must not reach the
    // client verbatim. The mint that replaces it (`invoke.rs:1909-1937`)
    // rewrites the top-level field only, and it runs *after* the dispatch path
    // that calls `enforce_output_schema`. So if schema enforcement republishes
    // the whole envelope under `structuredContent`, the backend's string
    // survives the mint in a second location.
    #[test]
    fn mrtr_2a_enforce_output_schema_does_not_republish_backend_request_state() {
        // An interim envelope as a backend sends it: a human-readable prompt in
        // `content` (not JSON, so there is no validation target to extract) and
        // the backend's own opaque `requestState` alongside it.
        let envelope = json!({
            "content": [{"type": "text", "text": "Which account should I use?"}],
            "requestState": "backend-opaque-state-abc123"
        });
        let schema = json!({"type": "object"});

        let result = enforce_output_schema("demo", "ask", envelope, Some(&schema));

        let republished = result
            .get("structuredContent")
            .and_then(|s| s.get("requestState"))
            .and_then(|v| v.as_str());
        assert_eq!(
            republished, None,
            "backend requestState republished under structuredContent: {result:#}"
        );

        // The second channel: `apply_validated_output` also rewrites a single
        // text item with a dump of whatever it validated, so an envelope
        // republished into `content[0].text` leaks the same string in prose.
        let rendered = result.pointer("/content/0/text").and_then(|v| v.as_str());
        assert_eq!(
            rendered,
            Some("Which account should I use?"),
            "backend requestState republished into content[0].text: {result:#}"
        );

        // Returning the envelope UNCHANGED is the contract the guard rests on,
        // not merely the absence of the two leaks above.
        assert_eq!(
            result,
            json!({
                "content": [{"type": "text", "text": "Which account should I use?"}],
                "requestState": "backend-opaque-state-abc123"
            }),
            "an envelope with no extractable payload was not returned unchanged"
        );

        // The other way to have nothing extractable: more than one content
        // item. `extract_output_validation_target` requires exactly one, so a
        // multi-item envelope takes the same arm and must be equally untouched.
        let multi = json!({
            "content": [
                {"type": "text", "text": "Which account should I use?"},
                {"type": "text", "text": "personal or work"}
            ],
            "requestState": "backend-opaque-state-abc123"
        });

        assert_eq!(
            enforce_output_schema("demo", "ask", multi.clone(), Some(&schema)),
            multi,
            "a multi-item envelope was not returned unchanged"
        );
    }

    // The other half of the predicate: a BARE payload is not an envelope just
    // because it carries a field called `content`, and it must still be
    // validated against the tool's schema rather than passed through.
    #[test]
    fn enforce_output_schema_validates_a_bare_payload_with_a_content_field() {
        let payload = json!({"content": "a string, not an array of content items"});
        let schema = json!({
            "type": "object",
            "properties": {"content": {"type": "string"}},
            "required": ["content"]
        });

        let result = enforce_output_schema("demo", "describe", payload.clone(), Some(&schema));

        assert_eq!(
            result, payload,
            "a bare payload is its own validation target and coerces to itself"
        );
    }

    #[test]
    fn enforce_output_schema_accepts_valid_result() {
        let schema = json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "count": { "type": "integer" }
            },
            "required": ["id", "count"]
        });

        let result = enforce_output_schema(
            "demo",
            "search",
            json!({"id": "abc", "count": 2}),
            Some(&schema),
        );

        assert_eq!(result["id"], json!("abc"));
        assert_eq!(result["count"], json!(2));
    }

    #[test]
    fn enforce_output_schema_passes_through_unexpected_fields_advisory() {
        // Output-schema mismatch is advisory for proxied tools: extra fields
        // from a real upstream API must NOT break the call. The result passes
        // through and structuredContent is still populated (with the extras).
        let schema = json!({
            "type": "object",
            "properties": {
                "data": { "type": "string" }
            },
            "required": ["data"]
        });

        let result = enforce_output_schema(
            "demo",
            "get_data",
            json!({"data": "ok", "extra": "value"}),
            Some(&schema),
        );

        // The raw payload (including the extra field) is preserved.
        assert_eq!(result.get("data").and_then(|v| v.as_str()), Some("ok"));
        assert_eq!(result.get("extra").and_then(|v| v.as_str()), Some("value"));
    }

    #[test]
    fn enforce_output_schema_validates_structured_content_inside_mcp_result() {
        let schema = json!({
            "type": "object",
            "properties": {
                "issue": {
                    "type": "object",
                    "properties": {
                        "id": { "type": "string" }
                    },
                    "required": ["id"]
                }
            },
            "required": ["issue"]
        });

        let result = enforce_output_schema(
            "fulcrum",
            "linear_get_issue",
            json!({
                "content": [{
                    "type": "text",
                    "text": "{\"issue\":{\"id\":\"abc\"}}"
                }],
                "structuredContent": { "issue": { "id": "abc" } },
                "isError": false
            }),
            Some(&schema),
        );

        assert_eq!(result["structuredContent"]["issue"]["id"], json!("abc"));
        assert_eq!(
            result["content"][0]["text"],
            json!("{\n  \"issue\": {\n    \"id\": \"abc\"\n  }\n}")
        );
    }

    #[test]
    fn enforce_output_schema_skips_mcp_error_envelopes() {
        let schema = json!({
            "type": "object",
            "properties": {
                "issue": { "type": "object" }
            }
        });

        let result = enforce_output_schema(
            "fulcrum",
            "linear_get_issue",
            json!({
                "content": [{
                    "type": "text",
                    "text": "bad input"
                }],
                "isError": true
            }),
            Some(&schema),
        );

        assert_eq!(result["isError"], json!(true));
        assert_eq!(result["content"][0]["text"], json!("bad input"));
    }

    // Minor 10 (b) — MIK-6865.SCHEMA.1: a scalar or bare-array
    // `structuredContent` must survive `enforce_output_schema` unchanged when
    // the declared `outputSchema` itself is non-object (`type: string`,
    // `type: array`). Every other fixture in this file declares
    // `type: object`; this is the clause none of them exercise.
    #[test]
    fn ac_schema_10b_scalar_structured_content_survives_enforce_output_schema() {
        let schema = json!({ "type": "string" });

        // The discriminating assertion. `enforce_output_schema` is advisory on
        // mismatch (see its else arm) and returns the payload either way, so
        // the survival check below passes whether the scalar validated or was
        // rejected and waved through. Only this one fails if support for a
        // non-object `outputSchema` regresses.
        let validation = validate_output(&json!("hello"), &schema);
        assert!(
            validation.is_valid(),
            "a scalar structuredContent must validate against a type: string outputSchema, not merely survive: {}",
            validation.format_output_error(&schema)
        );

        let result = enforce_output_schema(
            "demo",
            "echo",
            json!({
                "content": [{"type": "text", "text": "hello"}],
                "structuredContent": "hello",
                "isError": false
            }),
            Some(&schema),
        );

        assert_eq!(result["structuredContent"], json!("hello"));
    }

    #[test]
    fn ac_schema_10b_bare_array_structured_content_survives_enforce_output_schema() {
        let schema = json!({ "type": "array", "items": { "type": "string" } });

        let validation = validate_output(&json!(["a", "b"]), &schema);
        assert!(
            validation.is_valid(),
            "a bare-array structuredContent must validate against a type: array outputSchema, not merely survive: {}",
            validation.format_output_error(&schema)
        );

        let result = enforce_output_schema(
            "demo",
            "list_things",
            json!({
                "content": [{"type": "text", "text": "[\"a\",\"b\"]"}],
                "structuredContent": ["a", "b"],
                "isError": false
            }),
            Some(&schema),
        );

        assert_eq!(result["structuredContent"], json!(["a", "b"]));
    }

    #[tokio::test]
    async fn response_transform_runs_before_output_validation() {
        let transform = ResponseTransform::new(&TransformConfig {
            project: vec!["id".to_string()],
            ..Default::default()
        });
        let raw = json!({
            "id": "abc",
            "internal_token": "secret"
        });
        let transformed = transform.transform_result("my_tool", raw).await.unwrap();
        let schema = json!({
            "type": "object",
            "properties": {
                "id": { "type": "string" }
            },
            "required": ["id"]
        });

        let result = enforce_output_schema("demo", "my_tool", transformed, Some(&schema));

        assert_eq!(result, json!({"id": "abc"}));
    }

    /// Verify `TransformConfig::is_empty` returns expected values.
    #[test]
    fn transform_config_is_empty_tracks_all_fields() {
        // Default is empty
        assert!(TransformConfig::default().is_empty());

        // project non-empty
        assert!(
            !TransformConfig {
                project: vec!["x".to_string()],
                ..Default::default()
            }
            .is_empty()
        );

        // rename non-empty
        assert!(
            !TransformConfig {
                rename: [("a".to_string(), "b".to_string())].into(),
                ..Default::default()
            }
            .is_empty()
        );

        // redact non-empty
        assert!(
            !TransformConfig {
                redact: vec![RedactRule {
                    pattern: "x".to_string(),
                    replacement: "y".to_string(),
                }],
                ..Default::default()
            }
            .is_empty()
        );
    }

    /// `json_is_populated` truth table — the basis of the fail-fast guard.
    #[test]
    fn json_is_populated_truth_table() {
        use super::json_is_populated;
        assert!(!json_is_populated(&json!(null)));
        assert!(!json_is_populated(&json!({})));
        assert!(!json_is_populated(&json!([])));
        assert!(json_is_populated(&json!({"id": 1})));
        assert!(json_is_populated(&json!([1])));
        assert!(json_is_populated(&json!("x")));
        assert!(json_is_populated(&json!(0)));
        assert!(json_is_populated(&json!(false)));
    }

    /// Fail-fast trigger: projecting to a field absent from the response
    /// empties it. `json_is_populated` returns false, so `dispatch_to_backend`
    /// logs a warning (and still applies the projection — it never falls back
    /// to the unprojected payload, which could leak dropped fields). Callers
    /// pass `_full: true` to bypass projection (MIK-3533).
    #[tokio::test]
    async fn projection_to_absent_field_empties_payload_and_triggers_failsafe() {
        use super::json_is_populated;
        let config = TransformConfig {
            project: vec!["nonexistent_field".to_string()],
            ..Default::default()
        };
        let transform = ResponseTransform::new(&config);
        let raw = json!({ "id": "abc", "name": "Alice" });

        assert!(json_is_populated(&raw), "raw payload is populated");
        let transformed = transform.transform_result("tool", raw).await.unwrap();
        assert!(
            !json_is_populated(&transformed),
            "projecting to an absent field empties the payload -> warning logged"
        );
    }

    /// Healthy projection keeps real fields populated, so the fail-fast guard
    /// does NOT fire and the projected response is used.
    #[tokio::test]
    async fn projection_to_present_field_stays_populated() {
        use super::json_is_populated;
        let config = TransformConfig {
            project: vec!["id".to_string()],
            ..Default::default()
        };
        let transform = ResponseTransform::new(&config);
        let raw = json!({ "id": "abc", "name": "Alice", "secret": "x" });

        let transformed = transform.transform_result("tool", raw).await.unwrap();
        assert!(
            json_is_populated(&transformed),
            "a projection that keeps a present field stays populated"
        );
        assert_eq!(transformed.get("id"), Some(&json!("abc")));
    }
}

#[cfg(test)]
mod identity_propagation_enforcement_tests {
    /// The permissive authorizer these tests hand out.
    static ALLOW_ALL_INVOKE: crate::gateway::authz::AllowAll = crate::gateway::authz::AllowAll;

    use std::sync::Arc;

    use serde_json::{Value, json};

    use crate::backend::BackendRegistry;
    use crate::gateway::meta_mcp::MetaMcp;
    use crate::gateway::oauth::GatewayKeyPair;
    use crate::identity_propagation::{
        IdentityPropagationConfig, PropagationStrategyKind, SessionMode, SignedAssertionStrategy,
        TokenExchangeStrategy,
    };
    use crate::key_server::oidc::VerifiedIdentity;

    fn meta_with_strategy() -> MetaMcp {
        let m = MetaMcp::new(Arc::new(BackendRegistry::new()));
        let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
        m.set_identity_propagation(Arc::new(SignedAssertionStrategy::new(key, 300)));
        m
    }

    fn idp_cfg(required: bool) -> IdentityPropagationConfig {
        IdentityPropagationConfig {
            strategy: PropagationStrategyKind::SignedAssertion,
            audience: "https://memory.internal".to_string(),
            required,
            session_mode: SessionMode::Stateless,
            token_exchange_endpoint: None,
            token_exchange_scope: None,
        }
    }

    fn identity() -> VerifiedIdentity {
        VerifiedIdentity {
            subject: "alice".to_string(),
            email: "alice@corp".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://idp".to_string(),
        }
    }

    // MIK-6740 IDP4.1/4.2 — the Meta-MCP `gateway_invoke` route audits every
    // mint and every fail-closed refusal into the transparency log, identically
    // to the direct backend route. Regression guard for the gap where only the
    // direct route audited: a mint/refuse on the primary invoke path used to
    // leave no audit entry at all.
    #[tokio::test]
    async fn gateway_invoke_route_audits_mint_and_refuse() {
        use tempfile::NamedTempFile;

        use crate::security::TransparencyLogger;
        use crate::security::transparency_log::TransparencyLogConfig;

        let file = NamedTempFile::new().expect("tempfile");
        let cfg = Arc::new(TransparencyLogConfig {
            enabled: true,
            path: file.path().to_string_lossy().to_string(),
            key_id: "test".to_string(),
            ..TransparencyLogConfig::default()
        });
        let logger = Arc::new(TransparencyLogger::open(cfg).expect("logger opens"));

        let mut m = meta_with_strategy();
        m.enable_transparency_log(Arc::clone(&logger));

        // Successful mint -> idp_mint entry.
        let cred = m
            .resolve_caller_credential("memory", &idp_cfg(true), Some(&identity()))
            .await
            .expect("mint ok");
        let minted_value = cred.headers[0].1.clone();

        // Required + no identity -> fail-closed refuse -> idp_refuse entry.
        m.resolve_caller_credential("memory", &idp_cfg(true), None)
            .await
            .expect_err("must refuse");

        let raw = std::fs::read_to_string(file.path()).expect("read log");
        assert!(
            raw.contains("idp_mint"),
            "mint on the gateway_invoke route must be audited: {raw}"
        );
        assert!(
            raw.contains("idp_refuse"),
            "fail-closed refusal on the gateway_invoke route must be audited: {raw}"
        );
        // Redaction: the minted credential value must never reach the log.
        let token = minted_value
            .strip_prefix("Bearer ")
            .unwrap_or(&minted_value);
        assert!(
            !raw.contains(token),
            "the minted credential must never appear in the transparency log"
        );
    }

    // Header-capturing transport: records the per-request headers dispatch
    // attaches, so a test can assert the propagated credential reached the wire.
    type CapturedHeaders = Arc<parking_lot::Mutex<Vec<(String, String)>>>;
    // Records the identity key dispatch threads for upstream session
    // partitioning (MIK-6784), so a test can assert distinct identities produce
    // distinct keys.
    type CapturedIdentityKeys = Arc<parking_lot::Mutex<Vec<Option<String>>>>;

    struct CapturingTransport {
        captured: CapturedHeaders,
        captured_identity: CapturedIdentityKeys,
    }

    #[async_trait::async_trait]
    impl crate::transport::Transport for CapturingTransport {
        async fn request(
            &self,
            _method: &str,
            _params: Option<Value>,
        ) -> crate::Result<crate::protocol::JsonRpcResponse> {
            Ok(crate::protocol::JsonRpcResponse::success(
                crate::protocol::RequestId::Number(1),
                json!({"content": [{"type": "text", "text": "ok"}]}),
            ))
        }
        async fn request_with_headers(
            &self,
            _method: &str,
            _params: Option<Value>,
            extra_headers: &[(String, String)],
            identity_key: Option<&str>,
            _resend: crate::transport::ResendPermission,
        ) -> crate::Result<crate::protocol::JsonRpcResponse> {
            *self.captured.lock() = extra_headers.to_vec();
            self.captured_identity
                .lock()
                .push(identity_key.map(str::to_string));
            self.request(_method, _params).await
        }
        async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
            Ok(())
        }
        fn is_connected(&self) -> bool {
            true
        }
        async fn close(&self) -> crate::Result<()> {
            Ok(())
        }
    }

    // Build a MetaMcp whose registry has one identity-required HTTP backend
    // ("mem") wired to a header-capturing transport, plus the signed-assertion
    // strategy. Returns the meta and the shared capture buffer.
    fn meta_with_capturing_backend() -> (MetaMcp, CapturedHeaders) {
        let (m, captured, _identity) = meta_with_capturing_backend_full();
        (m, captured)
    }

    /// A transparency logger backed by a leaked tempfile — kept alive for the
    /// whole test process so a `required`-backend mint has a durable audit sink
    /// (without one, the MIK-6740 fail-closed guard aborts the mint). Leaking is
    /// fine in a unit test: the file is reclaimed when the process exits.
    fn leaked_test_transparency_logger() -> Arc<crate::security::TransparencyLogger> {
        use crate::security::TransparencyLogger;
        use crate::security::transparency_log::TransparencyLogConfig;

        let file = tempfile::NamedTempFile::new().expect("tempfile");
        let path = file.path().to_string_lossy().to_string();
        std::mem::forget(file); // keep the on-disk file alive for the test
        let cfg = Arc::new(TransparencyLogConfig {
            enabled: true,
            path,
            key_id: "test".to_string(),
            ..TransparencyLogConfig::default()
        });
        Arc::new(TransparencyLogger::open(cfg).expect("logger opens"))
    }

    /// Like [`meta_with_capturing_backend`] but also exposes the buffer of
    /// identity keys the transport received (MIK-6784). Wires a transparency log
    /// so a `required`-backend mint succeeds (the MIK-6740 fail-closed guard
    /// aborts a required mint when no audit sink is configured).
    fn meta_with_capturing_backend_full() -> (MetaMcp, CapturedHeaders, CapturedIdentityKeys) {
        build_capturing_backend(true)
    }

    /// Like [`meta_with_capturing_backend`] but with NO transparency log wired,
    /// so a `required`-backend mint must fail closed (MIK-6740 operator-misconfig
    /// guard).
    fn meta_with_capturing_backend_no_log() -> (MetaMcp, CapturedHeaders) {
        let (m, captured, _identity) = build_capturing_backend(false);
        (m, captured)
    }

    fn build_capturing_backend(
        with_transparency_log: bool,
    ) -> (MetaMcp, CapturedHeaders, CapturedIdentityKeys) {
        use crate::backend::Backend;
        use crate::config::{BackendConfig, TransportConfig};

        let registry = Arc::new(BackendRegistry::new());
        let config = BackendConfig {
            transport: TransportConfig::Http {
                http_url: "https://mem.internal/mcp".to_string(),
                streamable_http: true,
                protocol_version: None,
            },
            identity_propagation: Some(idp_cfg(true)),
            ..BackendConfig::default()
        };
        let backend = Arc::new(Backend::new(
            "mem",
            config,
            &crate::config::FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        ));
        let captured = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let captured_identity = Arc::new(parking_lot::Mutex::new(Vec::new()));
        backend.set_transport_for_test(Arc::new(CapturingTransport {
            captured: Arc::clone(&captured),
            captured_identity: Arc::clone(&captured_identity),
        }));
        let _ = registry.register(backend);

        let mut m = MetaMcp::new(registry);
        let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
        m.set_identity_propagation(Arc::new(SignedAssertionStrategy::new(key, 300)));
        if with_transparency_log {
            m.enable_transparency_log(leaked_test_transparency_logger());
        }
        (m, captured, captured_identity)
    }

    /// A backend that asks once and then completes.
    ///
    /// Stateful on purpose: a stub returning the same interim twice makes the
    /// bridge spin to `RoundsExhausted`, which would pass for "the bridge ran"
    /// without proving the retry carried the answer anywhere.
    /// How `AskOnceTransport` answers the round that follows the question.
    enum RetryRound {
        Completes,
        Fails,
        NeverReaches,
    }

    struct AskOnceTransport {
        calls: Arc<parking_lot::Mutex<Vec<Value>>>,
        retry_round: RetryRound,
    }

    #[async_trait::async_trait]
    impl crate::transport::Transport for AskOnceTransport {
        async fn request(
            &self,
            _method: &str,
            params: Option<Value>,
        ) -> crate::Result<crate::protocol::JsonRpcResponse> {
            let round = {
                let mut calls = self.calls.lock();
                calls.push(params.unwrap_or(Value::Null));
                calls.len()
            };
            if round > 1 {
                match self.retry_round {
                    RetryRound::Completes => {}
                    RetryRound::Fails => {
                        return Err(crate::Error::JsonRpc {
                            code: -32000,
                            message: "the backend failed the bridged retry".to_string(),
                            data: None,
                        });
                    }
                    RetryRound::NeverReaches => {
                        return Err(crate::Error::TransportConnect(
                            "the bridged retry never left the gateway".to_string(),
                        ));
                    }
                }
            }
            let body = if round == 1 {
                json!({
                    "resultType": "input_required",
                    "inputRequests": {"q1": {"method": "roots/list"}},
                    "requestState": "backend-state-1",
                })
            } else {
                json!({"content": [{"type": "text", "text": "completed"}]})
            };
            Ok(crate::protocol::JsonRpcResponse::success(
                crate::protocol::RequestId::Number(1),
                body,
            ))
        }
        async fn request_with_headers(
            &self,
            method: &str,
            params: Option<Value>,
            _extra_headers: &[(String, String)],
            _identity_key: Option<&str>,
            _resend: crate::transport::ResendPermission,
        ) -> crate::Result<crate::protocol::JsonRpcResponse> {
            self.request(method, params).await
        }
        async fn notify(&self, _method: &str, _params: Option<Value>) -> crate::Result<()> {
            Ok(())
        }
        fn is_connected(&self) -> bool {
            true
        }
        async fn close(&self) -> crate::Result<()> {
            Ok(())
        }
    }

    /// A legacy client that answers whatever the bridge puts to it.
    struct AnsweringClient {
        asked: Arc<parking_lot::Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl crate::gateway::input_bridge::ClientChannel for AnsweringClient {
        async fn send_request(
            &self,
            _session_id: &str,
            _id: &str,
            method: &str,
            _params: Option<Value>,
        ) -> std::result::Result<Value, crate::gateway::input_bridge::DeliveryError> {
            self.asked.lock().push(method.to_string());
            // A whole JSON-RPC reply, not a bare body: the bridge reads the
            // `result` member off the frame the client put on the wire.
            Ok(json!({"jsonrpc": "2.0", "result": {"roots": []}}))
        }
    }

    /// A `MetaMcp` with one plain backend that asks once and then completes.
    fn meta_that_asks_once(
        retry_round: RetryRound,
    ) -> (MetaMcp, Arc<parking_lot::Mutex<Vec<Value>>>) {
        use crate::backend::Backend;
        use crate::config::{BackendConfig, TransportConfig};

        let registry = Arc::new(BackendRegistry::new());
        let config = BackendConfig {
            transport: TransportConfig::Http {
                http_url: "https://asks.internal/mcp".to_string(),
                streamable_http: true,
                protocol_version: None,
            },
            ..BackendConfig::default()
        };
        let backend = Arc::new(Backend::new(
            "asks",
            config,
            &crate::config::FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        ));
        let calls = Arc::new(parking_lot::Mutex::new(Vec::new()));
        backend.set_transport_for_test(Arc::new(AskOnceTransport {
            calls: Arc::clone(&calls),
            retry_round,
        }));
        let _ = registry.register(backend);
        (MetaMcp::new(registry), calls)
    }

    // MIK-7212.MRTR.7a/7b on the production path. `tests/mik_7212_mrtr7_bridge_acs.rs`
    // constructs `InputBridge` itself, so it stays green when `invoke_tool_traced`
    // stops building one — which is what the reconcile merge did, unnoticed. This
    // test enters through `invoke_tool_traced`: with no bridge on that path the
    // legacy caller is handed a continuation envelope and the backend is called once.
    #[tokio::test]
    async fn legacy_caller_is_asked_in_band_and_the_backend_is_retried() {
        let (m, calls) = meta_that_asks_once(RetryRound::Completes);
        let asked = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let channel = AnsweringClient {
            asked: Arc::clone(&asked),
        };
        let declared = crate::protocol::meta::classify_request(
            Some(&json!({"_meta": {
                crate::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
                crate::protocol::meta::KEY_CLIENT_CAPABILITIES: {"roots": {}},
            }})),
            None,
        )
        .declared_capabilities();
        let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
            task: None,
            signing: None,
            execution: None,
            credential_principal: None,
            authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
            credential_kind: crate::security::audit::CredentialKind::None,
            is_modern: false,
            protocol_revision: None,
            authorizer: &ALLOW_ALL_INVOKE,
            stdio_nonce: None,
            verified_identity: None,
            api_key_name: None,
            agent_id: None,
            agent_declared: None,
            grant_subject: None,
            is_admin: false,
            input_capabilities: declared,
            retry: &crate::protocol::mrtr::NO_RETRY,
            confirmation:
                crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
            era: crate::protocol::meta::Era::Legacy,
            channel: &channel,
        };
        let args = json!({"server": "asks", "tool": "ask", "arguments": {}});
        m.invoke_tool_traced(&args, Some("session-1"), &caller, "trace-1")
            .await
            .expect("the bridged exchange completes");

        // MRTR.7a: the equivalent legacy request reached the client in band.
        assert_eq!(
            asked.lock().as_slice(),
            ["roots/list".to_string()],
            "the legacy client was never asked, so the bridge is not on the invoke path"
        );
        // MRTR.7b: the backend was retried, carrying the answer and its own state.
        let calls = calls.lock().clone();
        assert_eq!(calls.len(), 2, "the backend was not retried: {calls:?}");
        let retry = calls[1].to_string();
        assert!(
            retry.contains("backend-state-1"),
            "the retry dropped the backend's requestState: {retry}"
        );
        assert!(
            retry.contains("q1"),
            "the retry carried no answer for the question asked: {retry}"
        );
    }

    // A bridged round that fails after the backend was reached must not free the
    // idempotency key. The first dispatch already happened — the interim is what
    // opened the exchange — so the release-on-drop default answers a duplicate
    // submission by running the side effect a second time.
    #[tokio::test]
    async fn a_failed_bridged_retry_does_not_free_the_idempotency_key() {
        let (mut m, calls) = meta_that_asks_once(RetryRound::Fails);
        m.enable_idempotency(
            Arc::new(crate::idempotency::IdempotencyCache::new()),
            std::time::Duration::from_secs(60),
        );
        let asked = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let channel = AnsweringClient {
            asked: Arc::clone(&asked),
        };
        let declared = crate::protocol::meta::classify_request(
            Some(&json!({"_meta": {
                crate::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
                crate::protocol::meta::KEY_CLIENT_CAPABILITIES: {"roots": {}},
            }})),
            None,
        )
        .declared_capabilities();
        let retry = crate::protocol::mrtr::RetryFields {
            input_responses: None,
            request_state: None,
            idempotency_key: Some("key-1".to_string()),
            malformed: Vec::new(),
            attestation: None,
        };
        let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
            task: None,
            signing: None,
            execution: None,
            credential_principal: None,
            authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
            credential_kind: crate::security::audit::CredentialKind::None,
            is_modern: false,
            protocol_revision: None,
            authorizer: &ALLOW_ALL_INVOKE,
            stdio_nonce: None,
            verified_identity: None,
            api_key_name: None,
            agent_id: None,
            agent_declared: None,
            grant_subject: None,
            is_admin: false,
            input_capabilities: declared,
            retry: &retry,
            confirmation:
                crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
            era: crate::protocol::meta::Era::Legacy,
            channel: &channel,
        };
        let args = json!({"server": "asks", "tool": "ask", "arguments": {}});

        let first = m
            .invoke_tool_traced(&args, Some("session-1"), &caller, "trace-1")
            .await;
        assert!(first.is_err(), "the bridged retry was supposed to fail");
        let dispatched = calls.lock().len();
        assert_eq!(dispatched, 2, "the backend was not retried: {dispatched}");

        let second = m
            .invoke_tool_traced(&args, Some("session-1"), &caller, "trace-2")
            .await;
        assert_eq!(
            calls.lock().len(),
            dispatched,
            "the key was freed after a round that may have acted, so the duplicate re-executed"
        );
        let served = second
            .expect("the duplicate is served from the cache")
            .into_inner();
        assert!(
            served.to_string().contains("outcome is unknown"),
            "the duplicate was served something other than the uncertainty marker: {served}"
        );
        assert_eq!(
            served.get("isError").and_then(Value::as_bool),
            Some(true),
            "a round that may have acted must replay as a failure, not a success: {served}"
        );
    }

    // The mirror image: a bridged round refused before it left the gateway —
    // no such backend, no such tool, an open circuit, a transport that never
    // connected — provably did not act, so its key must be readmitted. Marking
    // it executed would strand the caller on an operation that never ran.
    #[tokio::test]
    async fn a_bridged_retry_refused_before_dispatch_frees_the_idempotency_key() {
        let (mut m, calls) = meta_that_asks_once(RetryRound::NeverReaches);
        m.enable_idempotency(
            Arc::new(crate::idempotency::IdempotencyCache::new()),
            std::time::Duration::from_secs(60),
        );
        let asked = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let channel = AnsweringClient {
            asked: Arc::clone(&asked),
        };
        let declared = crate::protocol::meta::classify_request(
            Some(&json!({"_meta": {
                crate::protocol::meta::KEY_PROTOCOL_VERSION: "2026-07-28",
                crate::protocol::meta::KEY_CLIENT_CAPABILITIES: {"roots": {}},
            }})),
            None,
        )
        .declared_capabilities();
        let retry = crate::protocol::mrtr::RetryFields {
            input_responses: None,
            request_state: None,
            idempotency_key: Some("key-1".to_string()),
            malformed: Vec::new(),
            attestation: None,
        };
        let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
            task: None,
            signing: None,
            execution: None,
            credential_principal: None,
            authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
            credential_kind: crate::security::audit::CredentialKind::None,
            is_modern: false,
            protocol_revision: None,
            authorizer: &ALLOW_ALL_INVOKE,
            stdio_nonce: None,
            verified_identity: None,
            api_key_name: None,
            agent_id: None,
            agent_declared: None,
            grant_subject: None,
            is_admin: false,
            input_capabilities: declared,
            retry: &retry,
            confirmation:
                crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
            era: crate::protocol::meta::Era::Legacy,
            channel: &channel,
        };
        let args = json!({"server": "asks", "tool": "ask", "arguments": {}});

        let first = m
            .invoke_tool_traced(&args, Some("session-1"), &caller, "trace-1")
            .await;
        assert!(first.is_err(), "the bridged retry was supposed to fail");
        let dispatched = calls.lock().len();
        assert_eq!(dispatched, 2, "the backend was not retried: {dispatched}");

        let second = m
            .invoke_tool_traced(&args, Some("session-1"), &caller, "trace-2")
            .await;
        drop(second);
        assert!(
            calls.lock().len() > dispatched,
            "the key stayed settled after a round that provably did not act, so the caller \
             cannot retry an operation that never ran"
        );
    }

    // IDP.1 end-to-end via Code Mode (gateway_execute): an identified caller reaches an
    // identity-required backend WITH its per-user Bearer credential on the wire.
    // Regression guard for the review finding that Code Mode dropped verified_identity.
    #[tokio::test]
    async fn code_mode_execute_propagates_identity_to_backend() {
        let (m, captured) = meta_with_capturing_backend();
        let id = identity();
        m.seed_caller_slot_for_test("mem", &id).await;
        let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
            task: None,
            signing: None,
            execution: None,
            credential_principal: None,
            authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
            credential_kind: crate::security::audit::CredentialKind::None,
            is_modern: false,
            protocol_revision: None,
            authorizer: &ALLOW_ALL_INVOKE,
            stdio_nonce: None,
            verified_identity: Some(&id),
            api_key_name: None,
            agent_id: None,
            agent_declared: None,
            grant_subject: None,
            is_admin: false,
            input_capabilities: crate::protocol::meta::Declared::NONE,
            retry: &crate::protocol::mrtr::NO_RETRY,
            confirmation:
                crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
            era: crate::protocol::meta::Era::Legacy,
            channel: &crate::gateway::input_bridge::NoClientChannel,
        };
        let args = json!({ "tool": "mem:read", "arguments": {} });
        m.code_mode_execute(&args, Some("s1"), &caller)
            .await
            .expect("code-mode execute ok");

        let headers = captured.lock().clone();
        let auth = headers.iter().find(|(k, _)| k == "Authorization");
        assert!(
            auth.is_some_and(|(_, v)| v.starts_with("Bearer ")),
            "Code Mode must propagate the per-user Bearer credential; got {headers:?}"
        );
    }

    // Fail-closed still holds through Code Mode: a required backend with NO
    // verified identity refuses at resolve, before dispatch.
    #[tokio::test]
    async fn code_mode_execute_fails_closed_without_identity() {
        let (m, _captured) = meta_with_capturing_backend();
        let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
            task: None,
            signing: None,
            execution: None,
            credential_principal: None,
            authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
            credential_kind: crate::security::audit::CredentialKind::None,
            is_modern: false,
            protocol_revision: None,
            authorizer: &ALLOW_ALL_INVOKE,
            api_key_name: None,
            agent_id: None,
            agent_declared: None,
            grant_subject: None,
            stdio_nonce: None,
            verified_identity: None,
            is_admin: false,
            input_capabilities: crate::protocol::meta::Declared::NONE,
            retry: &crate::protocol::mrtr::NO_RETRY,
            confirmation:
                crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
            era: crate::protocol::meta::Era::Legacy,
            channel: &crate::gateway::input_bridge::NoClientChannel,
        };
        let args = json!({ "tool": "mem:read", "arguments": {} });
        let err = m
            .code_mode_execute(&args, Some("s1"), &caller)
            .await
            .expect_err("must refuse without identity");
        assert!(
            err.to_string().contains("required"),
            "fail-closed error: {err}"
        );
    }

    // MIK-6740 operator-misconfig fail-OPEN guard (caller-level, end-to-end
    // through Code Mode): a `required` backend whose credential mints
    // successfully but whose transparency log is UNCONFIGURED must fail closed —
    // the mint aborts with an error AND no per-user header reaches the backend
    // transport. Without the guard, the audit helper's `None -> Ok(())` no-op
    // would let the credential go on the wire with zero audit record.
    #[tokio::test]
    async fn required_mint_without_transparency_log_fails_closed() {
        // The propagation-succeeds fixture with NO transparency log wired.
        let (m, captured) = meta_with_capturing_backend_no_log();
        let id = identity();
        m.seed_caller_slot_for_test("mem", &id).await;
        let caller = crate::gateway::meta_mcp::MetaMcpCallerContext {
            task: None,
            signing: None,
            execution: None,
            credential_principal: None,
            authentication: crate::gateway::meta_mcp::Authentication::Anonymous,
            credential_kind: crate::security::audit::CredentialKind::None,
            is_modern: false,
            protocol_revision: None,
            authorizer: &ALLOW_ALL_INVOKE,
            stdio_nonce: None,
            verified_identity: Some(&id),
            api_key_name: None,
            agent_id: None,
            agent_declared: None,
            grant_subject: None,
            is_admin: false,
            input_capabilities: crate::protocol::meta::Declared::NONE,
            retry: &crate::protocol::mrtr::NO_RETRY,
            confirmation:
                crate::gateway::destructive_confirmation::ConfirmationChannel::Unavailable,
            era: crate::protocol::meta::Era::Legacy,
            channel: &crate::gateway::input_bridge::NoClientChannel,
        };
        let args = json!({ "tool": "mem:read", "arguments": {} });
        let err = m
            .code_mode_execute(&args, Some("s1"), &caller)
            .await
            .expect_err("required mint with no audit sink must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("transparency log") || msg.contains("audit"),
            "fail-closed error must cite the missing audit sink: {msg}"
        );
        // The security property: no per-user credential reached the wire.
        assert!(
            captured.lock().is_empty(),
            "no per-user header must reach the backend when the mint fails closed; \
             got {:?}",
            captured.lock()
        );
    }

    // CWE-209 (PR #355 codex re-review): when a required mint SUCCEEDS but the
    // mint audit-write FAILS, the branch must fail closed AND return a GENERIC
    // client-facing error — never interpolate the underlying transparency-log
    // error (`PropagationError::AuditFailed`, which wraps the append IO error /
    // filesystem detail) into the caller-visible string. This drives a genuine
    // audit-write failure through `resolve_caller_credential` and asserts the
    // returned `Error::Internal` carries only the generic message.
    //
    // Failure-injection mirrors
    // `identity_propagation::tests::audit_fail_closed::mint_write_failure_is_fail_closed`:
    // POSIX checks file permissions only at `open(2)`, so a real write failure
    // is forced with process-wide `RLIMIT_FSIZE=0` (every write -> `EFBIG`) in a
    // re-exec'd CHILD process. `open()` writes nothing so it still succeeds;
    // in-memory minting still succeeds; only the audit append fails. Unix-only.
    #[cfg(unix)]
    #[test]
    fn mint_audit_write_failure_returns_generic_error_no_leak() {
        const ENV_VAR: &str = "IDP_INVOKE_AUDIT_FSIZE_CHILD_PATH";
        const MARK_OK: &str = "MINT_AUDIT_ERROR_WAS_GENERIC";
        const TEST_PATH: &str = "gateway::meta_mcp::invoke::identity_propagation_enforcement_tests::mint_audit_write_failure_returns_generic_error_no_leak";

        if std::env::var(ENV_VAR).is_ok() {
            // Child: RLIMIT_FSIZE=0 is already active (parent shell wrapper), so
            // the transparency-log append write fails while the in-memory mint
            // succeeds — exercising exactly the fixed mint-audit-failure branch.
            use crate::security::TransparencyLogger;
            use crate::security::transparency_log::TransparencyLogConfig;

            let path = std::env::var(ENV_VAR).expect("child path env var");
            let cfg = Arc::new(TransparencyLogConfig {
                enabled: true,
                path,
                key_id: "test".to_string(),
                ..TransparencyLogConfig::default()
            });
            let logger = Arc::new(
                TransparencyLogger::open(cfg).expect("open() writes nothing, must succeed"),
            );
            let mut m = meta_with_strategy();
            m.enable_transparency_log(logger);

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("current-thread runtime");
            let err = rt.block_on(async {
                m.resolve_caller_credential("memory", &idp_cfg(true), Some(&identity()))
                    .await
                    .expect_err("required mint whose audit write fails must fail closed")
            });
            let msg = err.to_string();

            // Fail-closed preserved: still an Internal error (mint aborted).
            assert!(
                matches!(err, crate::Error::Internal(_)),
                "mint-audit failure must fail closed as Internal: {err}"
            );
            // Generic client-facing message (backend name is a non-sensitive id).
            assert!(
                msg.contains("audit unavailable") && msg.contains("memory"),
                "must return the generic audit-unavailable message: {msg}"
            );
            // The pre-fix leak: none of the underlying transparency-log /
            // AuditFailed detail may reach the caller-visible string.
            for leaked in [
                "transparency-log write failed",
                "audit write failed",
                "action 'idp_mint'",
                "File too large",
                "os error",
            ] {
                assert!(
                    !msg.contains(leaked),
                    "client-facing mint-audit error must not leak {leaked:?}: {msg}"
                );
            }
            println!("{MARK_OK}");
            return;
        }

        // Parent: re-exec this exact test under RLIMIT_FSIZE=0 and assert on
        // what the child observed. `trap '' XFSZ` ignores SIGXFSZ (whose default
        // disposition would kill the child) so the write returns `Err` instead.
        let exe = std::env::current_exe().expect("current test binary path");
        let file = tempfile::NamedTempFile::new().expect("tempfile");
        let path = file.path().to_string_lossy().to_string();
        let script =
            format!("ulimit -f 0; trap '' XFSZ; exec \"$0\" '{TEST_PATH}' --exact --nocapture");
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .arg(&exe)
            .env(ENV_VAR, &path)
            .output()
            .expect("spawn fsize-limited child process");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(MARK_OK),
            "child did not confirm a generic (non-leaking) mint-audit error \
             (status={:?}, stdout={stdout}, stderr={})",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        // The child must also EXIT cleanly: a child that prints the marker and
        // then aborts (panic/abort after the observation) must not read as a
        // pass. Mirrors the two sibling fail-closed subprocess tests.
        assert!(
            output.status.success(),
            "child printed the marker but did not exit successfully \
             (status={:?}, stderr={})",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    async fn mints_bearer_credential_for_identity() {
        let mut m = meta_with_strategy();
        // A `required` mint needs a durable audit sink (MIK-6740 fail-closed).
        m.enable_transparency_log(leaked_test_transparency_logger());
        let cred = m
            .resolve_caller_credential("memory", &idp_cfg(true), Some(&identity()))
            .await
            .expect("mint ok");
        assert_eq!(cred.headers.len(), 1);
        assert_eq!(cred.headers[0].0, "Authorization");
        assert!(cred.headers[0].1.starts_with("Bearer "));
        // IDP.8 — a cache binding is produced so per-user results cache isolated.
        assert!(cred.cache_binding.is_some());
    }

    // IDP.8 — distinct identities produce distinct cache bindings, so two users
    // calling the same tool with the same arguments cannot collide in the cache.
    #[tokio::test]
    async fn distinct_identities_get_distinct_cache_bindings() {
        let mut m = meta_with_strategy();
        // A `required` mint needs a durable audit sink (MIK-6740 fail-closed).
        m.enable_transparency_log(leaked_test_transparency_logger());
        let alice = m
            .resolve_caller_credential("memory", &idp_cfg(true), Some(&identity()))
            .await
            .expect("alice")
            .cache_binding;
        let bob_identity = VerifiedIdentity {
            subject: "bob".to_string(),
            email: "bob@corp".to_string(),
            name: None,
            groups: vec![],
            issuer: "https://idp".to_string(),
        };
        let bob = m
            .resolve_caller_credential("memory", &idp_cfg(true), Some(&bob_identity))
            .await
            .expect("bob")
            .cache_binding;
        assert!(alice.is_some() && bob.is_some());
        assert_ne!(alice, bob, "per-user cache bindings must differ");
    }

    // IDP.2 — fail-closed: a REQUIRED backend with no verified identity refuses
    // (never falls back to the static credential).
    #[tokio::test]
    async fn required_backend_without_identity_fails_closed() {
        let m = meta_with_strategy();
        let err = m
            .resolve_caller_credential("memory", &idp_cfg(true), None)
            .await
            .expect_err("must refuse");
        assert!(
            err.to_string().contains("required"),
            "fail-closed error: {err}"
        );
    }

    // IDP.2 — fail-closed: a REQUIRED backend with no strategy wired refuses.
    #[tokio::test]
    async fn required_backend_without_strategy_fails_closed() {
        let m = MetaMcp::new(Arc::new(BackendRegistry::new())); // no strategy set
        let err = m
            .resolve_caller_credential("memory", &idp_cfg(true), Some(&identity()))
            .await
            .expect_err("must refuse");
        assert!(
            err.to_string().contains("required"),
            "fail-closed error: {err}"
        );
    }

    // MIK-6710 — fail-closed: a REQUIRED backend registered on a stdio
    // transport (which cannot carry `extra_headers` on the wire) refuses
    // BEFORE minting, even with a verified identity and a working strategy —
    // never mints a credential that `request_with_headers` would silently
    // drop, leaving the backend to run unauthenticated.
    #[tokio::test]
    async fn required_backend_on_stdio_transport_fails_closed_before_mint() {
        use crate::backend::Backend;
        use crate::config::{BackendConfig, TransportConfig};

        let registry = Arc::new(BackendRegistry::new());
        let config = BackendConfig {
            transport: TransportConfig::Stdio {
                command: "true".to_string(),
                cwd: None,
                protocol_version: None,
            },
            identity_propagation: Some(idp_cfg(true)),
            ..BackendConfig::default()
        };
        let backend = Arc::new(Backend::new(
            "stdio-mem",
            config,
            &crate::config::FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        ));
        let _ = registry.register(backend);

        let m = MetaMcp::new(registry);
        let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
        m.set_identity_propagation(Arc::new(SignedAssertionStrategy::new(key, 300)));

        let err = m
            .resolve_caller_credential("stdio-mem", &idp_cfg(true), Some(&identity()))
            .await
            .expect_err("stdio transport cannot carry identity headers; must refuse");
        assert!(err.to_string().contains("MIK-6710"), "error: {err}");
    }

    // A non-required backend on a stdio transport is unaffected by MIK-6710 —
    // best-effort, matching the existing non-required fallback. (A
    // non-required backend WITH a verified identity and a working strategy
    // still mints normally regardless of transport capability — the
    // transport gate only ever refuses a `required` backend; this test
    // exercises the identity-absent fallback, which is the case where a
    // non-required backend legitimately produces no headers.)
    #[tokio::test]
    async fn optional_backend_on_stdio_transport_yields_no_headers() {
        use crate::backend::Backend;
        use crate::config::{BackendConfig, TransportConfig};

        let registry = Arc::new(BackendRegistry::new());
        let config = BackendConfig {
            transport: TransportConfig::Stdio {
                command: "true".to_string(),
                cwd: None,
                protocol_version: None,
            },
            identity_propagation: Some(idp_cfg(false)),
            ..BackendConfig::default()
        };
        let backend = Arc::new(Backend::new(
            "stdio-mem-optional",
            config,
            &crate::config::FailsafeConfig::default(),
            std::time::Duration::from_secs(60),
        ));
        let _ = registry.register(backend);

        let m = MetaMcp::new(registry);
        let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
        m.set_identity_propagation(Arc::new(SignedAssertionStrategy::new(key, 300)));

        let cred = m
            .resolve_caller_credential("stdio-mem-optional", &idp_cfg(false), None)
            .await
            .expect("optional backend proceeds despite incapable transport");
        assert!(cred.headers.is_empty());
    }

    // A NON-required backend without identity degrades to the empty credential
    // (best-effort; no headers, no binding → shared cache key, IDP.5).
    #[tokio::test]
    async fn optional_backend_without_identity_yields_no_headers() {
        let m = meta_with_strategy();
        let cred = m
            .resolve_caller_credential("memory", &idp_cfg(false), None)
            .await
            .expect("optional ok");
        assert!(cred.headers.is_empty());
        assert!(cred.cache_binding.is_none());
    }

    // Direct backend route (/mcp/{name}) — resolve_propagation_headers mints the
    // per-user credential for a propagation-configured backend so the direct
    // passthrough carries it too (MIK-6734 review finding 4).
    #[tokio::test]
    async fn direct_route_resolves_bearer_for_identity() {
        let (m, _captured) = meta_with_capturing_backend();
        let headers = m
            .resolve_propagation_headers("mem", Some(&identity()))
            .await
            .expect("resolve ok");
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "Authorization" && v.starts_with("Bearer ")),
            "direct route must resolve the per-user Bearer credential: {headers:?}"
        );
    }

    // Direct route fails closed for a required backend with no identity — never
    // forwards with only the static credential.
    #[tokio::test]
    async fn direct_route_fails_closed_without_identity() {
        let (m, _captured) = meta_with_capturing_backend();
        let err = m
            .resolve_propagation_headers("mem", None)
            .await
            .expect_err("must refuse");
        assert!(
            err.to_string().contains("required"),
            "fail-closed error: {err}"
        );
    }

    // Direct route to a backend with no identity_propagation config is unchanged
    // (empty headers → static path).
    #[tokio::test]
    async fn direct_route_unconfigured_backend_yields_no_headers() {
        let (m, _captured) = meta_with_capturing_backend();
        let headers = m
            .resolve_propagation_headers("no-such-backend", Some(&identity()))
            .await
            .expect("resolve ok");
        assert!(headers.is_empty());
    }

    // MIK-6729 review M2 — the wired path: `resolve_caller_credential` MUST
    // copy `idp_cfg.token_exchange_endpoint`/`token_exchange_scope` into the
    // `BackendDescriptor` it hands to the installed strategy. Installs the
    // TokenExchangeStrategy the exact same way the production Gateway startup
    // match arm does (`gateway::server::mod` — `TokenExchangeStrategy::new` +
    // `meta_mcp.set_identity_propagation`), so this test exercises the real
    // wired path, not a hand-rolled stand-in.
    //
    // No live STS is available in-test, so this asserts the FAILURE MODE
    // instead of a minted token: an unreachable endpoint must fail with a
    // network/exchange error ("token-exchange request failed"), never with
    // `Misconfigured("... no token_exchange_endpoint configured ...")`. The
    // `Misconfigured` message is `TokenExchangeStrategy::propagate`'s first
    // check, reached ONLY when the descriptor's `token_exchange_endpoint` is
    // `None` — i.e. exactly what happens if invoke.rs's two wiring lines
    // (`token_exchange_endpoint`/`token_exchange_scope` copy into
    // `BackendDescriptor`) are deleted. Verified live (MIK-6729 review): with
    // those two lines removed, this test fails because the error message
    // becomes "... no token_exchange_endpoint configured (MIK-6729)" instead
    // of "token-exchange request failed"; every OLD test in this module still
    // passes, because none of them exercise a `TokenExchange` strategy.
    fn meta_with_token_exchange_strategy() -> MetaMcp {
        // Mirrors gateway::server::mod's
        // `Some(PropagationStrategyKind::TokenExchange) => { ... }` install
        // arm verbatim (same constructor, same `set_identity_propagation`
        // call) without needing a full `Config`/`Gateway::start`.
        let m = MetaMcp::new(Arc::new(BackendRegistry::new()));
        let key = Arc::new(GatewayKeyPair::generate().expect("keygen"));
        m.set_identity_propagation(Arc::new(TokenExchangeStrategy::new(key, 300)));
        m
    }

    fn token_exchange_idp_cfg() -> IdentityPropagationConfig {
        IdentityPropagationConfig {
            strategy: PropagationStrategyKind::TokenExchange,
            audience: "https://mail.internal".to_string(),
            required: true,
            session_mode: SessionMode::PerUser,
            // Port 0 is never reachable / instantly refused by the OS —
            // deterministic network failure, same technique as
            // `token_exchange::tests::unreachable_endpoint_is_refused`.
            token_exchange_endpoint: Some("https://127.0.0.1:0/token".to_string()),
            token_exchange_scope: Some("mail.read".to_string()),
        }
    }

    #[tokio::test]
    async fn resolve_caller_credential_wires_token_exchange_endpoint_and_scope() {
        let m = meta_with_token_exchange_strategy();
        let err = m
            .resolve_caller_credential("mail", &token_exchange_idp_cfg(), Some(&identity()))
            .await
            .expect_err("unreachable token-exchange endpoint must fail closed");
        let msg = err.to_string();
        assert!(
            !msg.contains("no identity-propagation strategy"),
            "strategy must be installed: {msg}"
        );
        assert!(
            !msg.contains("token_exchange_endpoint configured"),
            "if this fires, invoke.rs stopped wiring \
             token_exchange_endpoint/token_exchange_scope into BackendDescriptor \
             (MIK-6729 review M2): {msg}"
        );
        assert!(
            msg.contains("token-exchange request failed"),
            "must fail as a network/exchange error (proving the endpoint WAS \
             wired into the descriptor), not a Misconfigured short-circuit: {msg}"
        );
    }
}

#[cfg(test)]
mod error_budget_tests;

#[cfg(test)]
mod circuit_open_hint_tests;

#[cfg(test)]
mod session_fp_tests;

#[cfg(test)]
mod response_cache_error_tests;

#[cfg(test)]
mod ask_expiry_budget_tests;
