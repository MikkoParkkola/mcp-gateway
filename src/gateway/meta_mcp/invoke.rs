//! Tool invocation, dispatch, and operator-control handlers.
//!
//! Implements `gateway_invoke` (with idempotency and error-budget tracking),
//! `gateway_get_stats`, `gateway_kill_server`, `gateway_revive_server`,
//! `gateway_list_disabled_capabilities`, `gateway_reload_config`,
//! `gateway_webhook_status`, and `gateway_run_playbook`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::cache::ResponseCache;
use crate::capability::validate_output;
#[cfg(feature = "cost-governance")]
use crate::cost_accounting::suggestions;
use crate::hashing::{canonical_json, sha256_hex};
use crate::idempotency::{GuardOutcome, enforce};
use crate::playbook::PlaybookEngine;
use crate::provider::Transform as _;
use crate::provider::transforms::ResponseTransform;
use crate::security::validate_tool_name;
use crate::{Error, Result};

use super::super::meta_mcp_helpers::{
    build_circuit_breaker_stats_json, build_server_safety_status, build_stats_response,
    did_you_mean, extract_bool_or, extract_optional_str, extract_price_per_million,
    extract_required_str, parse_tool_arguments,
};
use super::super::recovery::{ErrorCategory, RecoveryContext, attach_recovery, recovery_for};
use super::super::trace;
use super::MetaMcp;
use super::prompt_cache::{CacheKeyDeriver, extract_cached_tokens, inject_cache_key};
use super::support::{
    MetaMcpInvoker, augment_with_predictions, augment_with_trace, resolve_idempotency_key,
};

fn enforce_output_schema(
    server: &str,
    tool: &str,
    result: Value,
    output_schema: Option<&Value>,
) -> Result<Value> {
    let Some(schema) = output_schema else {
        return Ok(result);
    };

    if result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(result);
    }

    let validation_target =
        extract_output_validation_target(&result).unwrap_or_else(|| result.clone());
    let validation = validate_output(&validation_target, schema);
    if validation.is_valid() {
        Ok(apply_validated_output(&result, validation.coerced))
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
        Ok(apply_validated_output(&result, validation_target))
    }
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

fn apply_validated_output(result: &Value, validated: Value) -> Value {
    let Some(obj) = result.as_object() else {
        return validated;
    };
    if !(obj.contains_key("content") || obj.contains_key("structuredContent")) {
        return validated;
    }

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
        session_id = session_id.unwrap_or("none"),
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

/// Monotonically increasing request counter for load-balanced cache key slot selection.
///
/// Global across all backends; overflow wraps (u64 → effectively infinite for our purposes).
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);

impl MetaMcp {
    /// Validate the per-action attestation token presented on a
    /// `gateway_invoke` call (MIK-5223, B1-IDENT).
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
    pub(super) fn check_attestation(&self, args: &Value, agent_id: Option<&str>) -> Result<()> {
        let Some(validator) = self.attestation_validator.as_ref() else {
            return Ok(());
        };
        let token = args.get("attestation").and_then(Value::as_str);
        // The requested action is the tool being invoked: the token's capability
        // allow-list must grant it (MIK-6163). Missing tool → empty action,
        // which only a "*" wildcard token can satisfy (fail-closed). The
        // authenticity checks still run first, so a forged/expired token is
        // rejected on those grounds regardless of capability.
        let requested = args.get("tool").and_then(Value::as_str).unwrap_or_default();
        match validator.validate_boundary_call(
            token,
            "gateway_invoke",
            Some(requested),
            chrono::Utc::now(),
        ) {
            Ok(_claims) => Ok(()),
            Err(rejection) => match self.attestation_mode {
                crate::attestation::AttestationMode::Enforce => Err(Error::json_rpc(
                    -32002,
                    format!("Attestation rejected at gateway_invoke: {rejection}"),
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

    /// `gateway_invoke` — invoke a tool on a backend with full tracing, caching,
    /// idempotency, error-budget tracking, and predictive prefetch.
    ///
    /// `agent_id` identifies the calling agent for audit logging (OWASP ASI03).
    pub(super) async fn invoke_tool(
        &self,
        args: &Value,
        session_id: Option<&str>,
        api_key_name: Option<&str>,
        agent_id: Option<&str>,
    ) -> Result<Value> {
        let trace_id = trace::generate();
        let trace_id_clone = trace_id.clone();
        trace::with_trace_id(trace_id, async move {
            self.invoke_tool_traced(args, session_id, api_key_name, agent_id, &trace_id_clone)
                .await
        })
        .await
    }

    /// Inner implementation executed within a trace-ID scope.
    #[allow(clippy::too_many_lines)] // Complex dispatch logic; splitting further harms readability
    async fn invoke_tool_traced(
        &self,
        args: &Value,
        session_id: Option<&str>,
        api_key_name: Option<&str>,
        agent_id: Option<&str>,
        trace_id: &str,
    ) -> Result<Value> {
        let server = extract_required_str(args, "server")?;
        let tool = extract_required_str(args, "tool")?;
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

        // MIK-5877: in `experimental` mode the projected (treatment) and raw
        // (control) arms must NOT share response-cache / idempotency entries, or
        // one arm's shape would be served to the other (the key is otherwise
        // just server:tool:hash(args)). Suffix both keys with the arm so each
        // arm is isolated while still deduping within itself — preserving
        // idempotency's double-execution protection per arm. `off`/`on` add no
        // suffix, so their keys are byte-identical to before.
        let projection_key_suffix =
            crate::projection::projection_key_suffix(self.projection_mode, session_id);

        // === PRE-INVOKE: Compute request hash for transparency log ============
        //
        // Computed eagerly here so the hash covers the raw arguments before any
        // secret injection or transformation.  Zero-cost when the logger is None.
        let request_hash = if self.transparency_logger.is_some() {
            format!(
                "sha256:{}",
                sha256_hex(canonical_json(&arguments).as_bytes())
            )
        } else {
            String::new()
        };

        // Validate tool name syntax before any work — prevents session corruption
        // from malformed names injected by compromised backend servers.
        if let Err(reason) = validate_tool_name(tool) {
            return Err(Error::Protocol(format!(
                "Invalid tool name '{tool}': {reason}"
            )));
        }

        // === PRE-INVOKE: Nonce replay protection (ADR-001, OWASP ASI07) ===
        //
        // Check and register the request nonce before any dispatch work so that
        // replayed requests are rejected cheaply without touching the backend.
        let request_nonce = args.get("nonce").and_then(Value::as_str);
        if let Some(ref nonce_store) = self.nonce_store {
            match request_nonce {
                Some(nonce) => nonce_store.check_and_register(nonce)?,
                None if self.require_nonce => {
                    return Err(Error::json_rpc(
                        -32001,
                        "Nonce required when message signing is enforced",
                    ));
                }
                None => {} // backward-compatible: nonce is optional by default
            }
        }

        tracing::Span::current().record("trace_id", trace_id);

        // === PRE-INVOKE: Per-action attestation (MIK-5223, B1-IDENT) ======
        //
        // Zero-cost no-op unless a validator was attached via
        // `with_attestation`. The token is presented in the top-level
        // `attestation` field of the call. In observe mode validation is
        // audited but never blocks; in enforce mode a missing/invalid token
        // fails the call closed. The clock is the gateway's trusted clock,
        // never a caller-supplied timestamp.
        self.check_attestation(args, agent_id)?;

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
        if let Err(msg) = profile.check(server, tool) {
            return Err(Error::Protocol(msg));
        }

        let tool_key = format!("{server}:{tool}");

        // `_full` requests bypass idempotency and response caching entirely.
        // A `_full` call returns a different (unprojected) payload than the
        // cached/projected result, so sharing a key would let one shape leak
        // into the other (a non-`_full` caller could hit a cached full payload
        // and receive fields the projection was meant to drop). A `_full` call
        // is therefore always a fresh, uncached dispatch.
        let idem_key = if want_full {
            None
        } else {
            resolve_idempotency_key(
                args,
                server,
                tool,
                &arguments,
                self.idempotency_cache.as_ref(),
            )
            .map(|k| {
                if projection_key_suffix.is_empty() {
                    k
                } else {
                    format!("{k}{projection_key_suffix}")
                }
            })
        };

        if let (Some(idem_cache), Some(key)) = (&self.idempotency_cache, &idem_key) {
            match enforce(idem_cache, key)? {
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
                    let predictions = self.record_and_predict(session_id, &tool_key);
                    return Ok(augment_with_trace(
                        augment_with_predictions(cached, predictions),
                        trace_id,
                    ));
                }
                GuardOutcome::Proceed => {
                    debug!(
                        server,
                        tool, key, trace_id, "Idempotency key registered as in-flight"
                    );
                }
            }
        }

        if !want_full && let Some(ref cache) = self.cache {
            let cache_key = {
                let base = ResponseCache::build_key(server, tool, &arguments);
                if projection_key_suffix.is_empty() {
                    base
                } else {
                    format!("{base}{projection_key_suffix}")
                }
            };
            if let Some(cached) = cache.get(&cache_key) {
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
                if let (Some(idem_cache), Some(key)) = (&self.idempotency_cache, &idem_key) {
                    idem_cache.mark_completed(key, cached.clone());
                }
                let predictions = self.record_and_predict(session_id, &tool_key);
                return Ok(augment_with_trace(
                    augment_with_predictions(cached, predictions),
                    trace_id,
                ));
            }
        }

        if let Some(ref stats) = self.stats {
            stats.record_invocation(server, tool);
        }
        if let Some(ref ranker) = self.ranker {
            ranker.record_use(server, tool);
        }

        // === OWASP ASI03: per-agent identity audit log ===
        //
        // Every tool invocation records the agent_id (or "anonymous") as a
        // structured tracing field so audit tooling can correlate invocations
        // back to the calling agent without post-processing.
        let agent_label = agent_id.unwrap_or("anonymous");
        tracing::info!(
            agent_id = %agent_label,
            server   = %server,
            tool     = %tool,
            trace_id = %trace_id,
            "tool invoked"
        );
        debug!(server, tool, trace_id, "Invoking tool");

        // === PRE-INVOKE: Cost governance budget check ===
        //
        // Returns the warnings to inject post-dispatch and blocks when the
        // budget is exceeded (returns JSON-RPC -32003 error).
        #[cfg(feature = "cost-governance")]
        let cost_warnings: Vec<String> = if let Some(ref enforcer) = self.budget_enforcer {
            let result = enforcer.check(tool, api_key_name);
            if !result.allowed {
                return Err(Error::json_rpc(
                    -32003,
                    result
                        .block_reason
                        .unwrap_or_else(|| "Budget exceeded".to_string()),
                ));
            }
            result.warnings
        } else {
            Vec::new()
        };

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

        let dispatch_start = Instant::now();
        let dispatch_result = self
            .dispatch_to_backend(
                server,
                tool,
                arguments.clone(),
                prompt_cache_key.as_deref(),
                want_full,
                session_id,
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

        self.record_error_budget(server, tool, dispatch_result.is_ok());

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
                if let (Some(idem_cache), Some(key)) = (&self.idempotency_cache, &idem_key) {
                    idem_cache.remove(key);
                }
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
                // `record_error_budget`).  Idempotency key was cleaned up above.
                attach_recovery(
                    json!({
                        "isError": true,
                        "content": [{"type": "text", "text": e.to_string()}],
                    }),
                    hint,
                )
            }
        };

        // === POST-INVOKE: Response contract gate (issue #133, D1) ===
        //
        // Validates the response against the per-tool contract declared in
        // config.  Default-deny (fail_closed=true) can block responses from
        // tools with no declared contract.
        //
        // Runs BEFORE D2 anomaly screening so contract violations abort early.
        if let Some(ref contract_cfg) = self.response_contract {
            let text = crate::security::response_inspect::extract_text_from_result(&result);
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
                let patterns: &[String] =
                    tool_entry.map_or(&[], |e| e.forbidden_patterns.as_slice());

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
        }

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

        if !want_full && let Some(ref cache) = self.cache {
            let cache_key = {
                let base = ResponseCache::build_key(server, tool, &arguments);
                if projection_key_suffix.is_empty() {
                    base
                } else {
                    format!("{base}{projection_key_suffix}")
                }
            };
            cache.set(&cache_key, result.clone(), self.default_cache_ttl);
            debug!(server, tool, trace_id, ttl = ?self.default_cache_ttl, "Cached result");
        }

        if let (Some(idem_cache), Some(key)) = (&self.idempotency_cache, &idem_key) {
            idem_cache.mark_completed(key, result.clone());
            debug!(
                server,
                tool, key, trace_id, "Idempotency entry marked completed"
            );
        }

        let predictions = self.record_and_predict(session_id, &tool_key);

        // SEP-1862 dynamic promotion: auto-surface this tool in the session's
        // tools/list after a successful invocation so the LLM can call it
        // directly next time without going through gateway_invoke.
        #[cfg(feature = "spec-preview")]
        if let Some(sid) = session_id {
            self.promote_tool_for_session(sid, &tool_key);
        }

        // === POST-INVOKE: Transparency log (issue #133, D3) ==================
        //
        // Commit the request+response pair to the hash-chain log AFTER all
        // post-processing so `result` reflects what the caller actually receives.
        // Failures are non-fatal — we log a warning but never abort the invocation.
        if let Some(ref tl) = self.transparency_logger {
            let response_hash =
                format!("sha256:{}", sha256_hex(canonical_json(&result).as_bytes()));
            let caller = api_key_name.unwrap_or("anonymous");
            let sid = session_id.unwrap_or("unknown");
            if let Err(e) =
                tl.log_invocation(sid, caller, server, tool, &request_hash, &response_hash)
            {
                warn!(
                    server,
                    tool,
                    trace_id,
                    error = %e,
                    "Transparency log write failed (non-fatal)"
                );
            }
        }

        // === POST-INVOKE: Response signing (ADR-001, OWASP ASI07) ===
        //
        // Sign the assembled response after all post-processing (cost warnings,
        // security findings, trace augmentation).  The MAC covers the full
        // response body so consumers can detect any tampering.
        let mut final_result =
            augment_with_trace(augment_with_predictions(result, predictions), trace_id);
        if let Some(ref signer) = self.message_signer {
            final_result = signer.sign_response(final_result, request_nonce);
        }

        Ok(final_result)
    }

    /// Record success/failure against both backend and per-capability error budgets.
    fn record_error_budget(&self, server: &str, tool: &str, success: bool) {
        let cfg = self.error_budget_config.read();
        let cap_cfg = self.capability_budget_config.read();
        if success {
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

        tracker
            .predict_next(tool_key, 0.30, 3)
            .into_iter()
            .map(|p| json!({"tool": p.tool, "confidence": p.confidence}))
            .collect()
    }

    /// Dispatch a `tools/call` to the capability backend or an MCP backend.
    ///
    /// Applies secret injection before forwarding. When `prompt_cache_key` is
    /// `Some`, it is injected into the request `_meta` field so that
    /// OpenAI-compatible backends can use it for prompt caching.
    async fn dispatch_to_backend(
        &self,
        server: &str,
        tool: &str,
        arguments: Value,
        prompt_cache_key: Option<&str>,
        want_full: bool,
        session_id: Option<&str>,
    ) -> Result<Value> {
        let injection = self.secret_injector.inject(server, tool, arguments)?;
        let arguments = injection.arguments;

        if let Some(cap) = self.get_capabilities()
            && server == cap.name
            && cap.has_capability(tool)
        {
            let result = cap.call_tool(tool, arguments).await?;
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
            if !want_full
                && let Some(cap_def) = cap.get(tool)
                && !cap_def.response_transform.is_empty()
            {
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

            let cap_def = cap.get(tool);
            let output_schema = cap_def
                .as_ref()
                .and_then(|c| (!c.schema.output.is_null()).then(|| c.schema.output.clone()));

            let validated = enforce_output_schema(server, tool, response, output_schema.as_ref())?;

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
            let spec_present = cap_def.as_ref().is_some_and(|c| c.projection.is_some());
            let final_result = if decision.project
                && let Some(cap_def) = cap_def.as_ref()
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

        // Eagerly check the cached tool list for a "did you mean?" hint.
        // Only fires when the cache is populated and the tool is not found there.
        // We still dispatch to the backend in case the cache is stale.
        let cached_names = backend.get_cached_tool_names();
        let tool_is_cached = cached_names.iter().any(|n| n == tool);

        // Build request params, injecting cache key into _meta when present.
        let base_params = json!({ "name": tool, "arguments": arguments });
        let params = match prompt_cache_key {
            Some(key) => inject_cache_key(Some(base_params), key),
            None => base_params,
        };

        let response = backend.request("tools/call", Some(params)).await?;

        if let Some(error) = response.error {
            // When we have cached names and the tool wasn't in them, enrich
            // the error with Levenshtein-based suggestions.
            let message = if !cached_names.is_empty() && !tool_is_cached {
                let candidates: Vec<&str> = cached_names.iter().map(String::as_str).collect();
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
        let output_schema = self
            .get_tool_registry()
            .and_then(|registry| registry.get(&format!("{server}:{tool}")))
            .and_then(|entry| entry.tool.output_schema)
            .or_else(|| {
                backend
                    .get_cached_tool(tool)
                    .and_then(|cached| cached.output_schema)
            });

        enforce_output_schema(server, tool, result, output_schema.as_ref())
    }

    // ========================================================================
    // Operator control meta-tools
    // ========================================================================

    /// `gateway_cost_report` — per-session and per-API-key spend report.
    #[allow(clippy::unnecessary_wraps, clippy::unused_async)]
    pub(super) async fn get_cost_report(
        &self,
        args: &Value,
        session_id: Option<&str>,
    ) -> Result<Value> {
        let include_all_sessions = extract_bool_or(args, "include_all_sessions", false);
        let include_all_keys = extract_bool_or(args, "include_all_keys", false);

        // Resolve target session (explicit arg or current session)
        let target_session_id = extract_optional_str(args, "session_id").or(session_id);

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

        let aggregate = serde_json::to_value(self.cost_tracker.aggregate()).unwrap_or(json!(null));

        Ok(json!({
            "session": session_report,
            "keys": key_report,
            "aggregate": aggregate,
        }))
    }

    /// `gateway_get_stats` — gateway statistics with per-backend error budget
    /// and circuit-breaker status.
    #[allow(clippy::unused_async)]
    pub(super) async fn get_stats(&self, args: &Value) -> Result<Value> {
        let price_per_million = extract_price_per_million(args);

        let stats = self
            .stats
            .as_ref()
            .ok_or_else(|| Error::json_rpc(-32603, "Statistics not enabled for this gateway"))?;

        let mut total_tools: usize = self
            .backends
            .all()
            .iter()
            .map(|b| b.cached_tools_count())
            .sum();
        if let Some(cap) = self.get_capabilities() {
            total_tools += cap.get_tools().len();
        }

        let snapshot = stats.snapshot(total_tools);
        let mut response = build_stats_response(&snapshot, price_per_million);

        let all_backends = self.backends.all();

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

        // Inject cost governance section when enabled
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
            if let Value::Object(ref mut map) = response {
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
    pub(super) fn list_disabled_capabilities(&self) -> Result<Value> {
        let cap_cfg = self.capability_budget_config.read();
        let disabled = self.kill_switch.disabled_capabilities(cap_cfg.cooldown);
        let entries: Vec<Value> = disabled
            .iter()
            .filter_map(|key| {
                let (backend, capability) = key.split_once(':')?;
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
    pub(super) async fn run_playbook(&self, args: &Value) -> Result<Value> {
        let name = extract_required_str(args, "name")?;
        let arguments = parse_tool_arguments(args)?;

        debug!(playbook = name, "Running playbook");

        let definition = {
            let engine = self.playbook_engine.read();
            engine
                .get(name)
                .cloned()
                .ok_or_else(|| Error::json_rpc(-32602, format!("Playbook not found: {name}")))?
        };

        let invoker = MetaMcpInvoker { meta: self };

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
        Error::CircuitOpen(backend) => (
            ErrorCategory::CircuitBreakerTrip,
            format!("Circuit breaker is open for backend '{backend}'"),
        ),
        Error::BackendNotFound(name) | Error::ToolNotFound(name) => {
            (ErrorCategory::NotFound, format!("Not found: '{name}'"))
        }
        Error::BackendTimeout(msg) => (ErrorCategory::Timeout, msg.clone()),
        Error::BackendUnavailable(msg) | Error::Transport(msg) => {
            (ErrorCategory::BackendError, msg.clone())
        }
        // Protocol errors carry upstream HTTP failures as their message
        // (e.g. "API returned 429 Too Many Requests"). Inspect the text so a
        // rate limit or transient 5xx is not mislabelled as a param error.
        Error::Protocol(msg) => (classify_from_detail(Some(msg)), msg.clone()),
        Error::JsonRpc { message, .. } => (ErrorCategory::BackendError, message.clone()),
        _ => (ErrorCategory::BackendError, error.to_string()),
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
    if lower.contains("429")
        || lower.contains("too many requests")
        || lower.contains("rate limit")
        || lower.contains("rate-limit")
        || lower.contains("ratelimit")
        || lower.contains("throttl")
    {
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
        )
        .expect("schema-valid result should pass");

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
        )
        .expect("extra fields are advisory, not fatal");

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
        )
        .expect("structuredContent should be validated, not the MCP envelope");

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
        )
        .expect("tool-error MCP envelope should bypass output validation");

        assert_eq!(result["isError"], json!(true));
        assert_eq!(result["content"][0]["text"], json!("bad input"));
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

        let result = enforce_output_schema("demo", "my_tool", transformed, Some(&schema))
            .expect("post-transform result should satisfy schema");

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
