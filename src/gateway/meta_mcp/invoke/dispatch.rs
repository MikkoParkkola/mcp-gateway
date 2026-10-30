// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Spend admission and dispatch to the backend.

use std::sync::Arc;
use std::time::Instant;

use serde_json::{Value, json};
use tracing::debug;

use super::enforce_output_schema;
use super::output_shape::apply_validated_output;
use super::r2_check::miss_with_hint;
use super::{dispatch_guards, relay};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp::prompt_cache::extract_cached_tokens;
use crate::identity_grants::GrantSubject;
use crate::identity_propagation::CallerProof;
use crate::provider::Transform as _;
use crate::provider::transforms::ResponseTransform;
use crate::{Error, Result};

use super::{
    OutboundRetry, apply_capability_projection, call_capability_tool_with_identity,
    emit_projection_ab_event, json_is_populated,
};

impl MetaMcp {
    /// Admits one backend call against the configured spend budget.
    ///
    /// Per dispatch, not per `gateway_invoke`: a bridged exchange makes one
    /// backend call per round, and a budget checked only at the first would let
    /// a backend that keeps asking spend past the operator's limit.
    ///
    /// Returns the [`dispatch_guards::Admission`]: the warnings to inject
    /// post-dispatch and the reservation on the call's cost, to be kept until
    /// the spend is recorded. Blocks with JSON-RPC -32003 carrying the
    /// enforcer's own reason.
    #[cfg(feature = "cost-governance")]
    pub(super) fn admit_spend(
        &self,
        tool: &str,
        // The per-key cost name (`BackendCall::cost_key`), never a display name.
        cost_key: Option<&str>,
    ) -> Result<dispatch_guards::Admission> {
        let Some(ref enforcer) = self.budget_enforcer else {
            return Ok(dispatch_guards::Admission::default());
        };
        let result = enforcer.check(tool, cost_key);
        if !result.allowed {
            return Err(Error::gateway_refused(
                -32003,
                result
                    .block_reason
                    .unwrap_or_else(|| "Budget exceeded".to_string()),
            ));
        }
        Ok(dispatch_guards::Admission::new(
            result.warnings,
            result.hold,
        ))
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
    pub(super) async fn accounted_dispatch(
        &self,
        server: &str,
        tool: &str,
        arguments: Value,
        outbound_retry: &OutboundRetry,
        prompt_cache_key: Option<&str>,
        inbound_meta: Option<&Value>,
        want_full: bool,
        session_id: Option<&str>,
        // Who the A/B arm keys on (`MetaMcpCallerContext::experiment_key`).
        arm_key: Option<&str>,
        caller_identity: Option<&GrantSubject>,
        // The VERIFIED end-user identity, carried for the capability route
        // whose account boundary is inside the executor, and the credential
        // owner key that names an MCP child (MIK-7825). Pass-through only.
        (caller_proof, credential_owner): (CallerProof<'_>, Option<&str>),
        propagated_headers: &crate::transport::LentCredential,
        cache_binding: Option<&str>,
        // The capability route's account credential, resolved once above the
        // response cache and carried down unchanged. `None` for every MCP
        // backend and for a capability with no account reference.
        account_credential: super::propagation::DispatchAccount,
        // The per-key cost name (`MetaMcpCallerContext::cost_key`): the
        // only name this function uses, for the spend it settles (MIK-8507).
        cost_key: Option<&str>,
        trace_id: &str,
        policy_epoch: u64,
        protocol_revision: Option<&str>,
        routing_profile: &str,
        scope: super::super::InvokeScope<'_>,
        // The backend the call was judged on; `None` for the capability route.
        captured: Option<Arc<crate::backend::Backend>>,
        chain: &super::super::response_security::chain_receipt::ChainSlot,
        // The call's admission: its reservation is settled with the spend.
        admission: &dispatch_guards::Admission,
        // MIK-8137 b1 (MX): proof this send passed the chokepoint. Only
        // `chokepoint()` can make one, so a send that skipped it does not
        // compile.
        _permit: super::chokepoint::Permit,
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
                arm_key,
                caller_identity,
                (caller_proof, credential_owner),
                propagated_headers,
                cache_binding,
                account_credential,
                policy_epoch,
                protocol_revision,
                routing_profile,
                scope,
                captured,
                chain,
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
                stats.record_cached_tokens(server, cached_tokens);
                debug!(
                    server,
                    tool, cached_tokens, trace_id, "Prompt cache hit recorded"
                );
            }
        }

        self.account_dispatch(
            &dispatch_guards::BackendCall {
                server,
                tool,
                session_id,
                // `account_dispatch` reads only `cost_key`.
                api_key_name: None,
                cost_key,
                trace_id,
                // On a session-less call `arm_key` is the non-empty caller key or None
                // (`experiment_key`): the key the caller's own report reads.
                caller_key: arm_key,
            },
            dispatch_guards::DirectOutcome::of(&dispatch_result),
            admission,
        );

        dispatch_result
    }

    /// Dispatch a `tools/call` to the capability backend or an MCP backend.
    ///
    /// Applies secret injection before forwarding. When `prompt_cache_key` is
    /// `Some`, it is injected into the request `_meta` field so that
    /// OpenAI-compatible backends can use it for prompt caching.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_lines)] // Coherent dispatch unit; identity-propagation enforcement inline
    pub(super) async fn dispatch_to_backend(
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
        // Who the A/B arm keys on (`MetaMcpCallerContext::experiment_key`):
        // `None` is the control shape and no A/B event (G4).
        arm_key: Option<&str>,
        // Identity that reaches the capability executor. The grant that admits
        // it was decided at the authorization chokepoint, so nothing here
        // re-decides it — this is the value the call is made *with*, not the
        // one it is checked against.
        caller_identity: Option<&GrantSubject>,
        // What the request PROVED about its caller, for the capability route
        // whose account boundary is inside the executor, and the credential
        // owner key (`support::credential_owner`). Pass-through only.
        (caller_proof, credential_owner): (CallerProof<'_>, Option<&str>),
        // Pre-resolved per-user propagation headers (empty = none). Resolved
        // once in `invoke_tool_traced` so the cache key and this dispatch share
        // one credential (MIK-6734); dispatch never mints.
        propagated_headers: &crate::transport::LentCredential,
        // Caller's stable identity binding (MIK-6784). Transport uses it to
        // partition upstream `MCP-Session-Id` state; the capability executor
        // copies the same already-resolved string into the inner cache key.
        // `None` → shared default bucket / public namespace.
        identity_key: Option<&str>,
        // Resolved before the outer response cache, rechecked against the same
        // registry inside the executor before the inner cache and before
        // egress. Never minted here.
        account_credential: super::propagation::DispatchAccount,
        policy_epoch: u64,
        protocol_revision: Option<&str>,
        routing_profile: &str,
        scope: super::super::InvokeScope<'_>,
        // The backend the call was judged on; `None` for the capability route.
        captured: Option<Arc<crate::backend::Backend>>,
        chain: &super::super::response_security::chain_receipt::ChainSlot,
    ) -> Result<Value> {
        // The grant was decided at the authorization chokepoint, above the
        // caches. The definition is resolved again here only for the response
        // transform below, in one lookup so a reload cannot split it (#2236).
        // Only a call judged on no registry backend takes the capability
        // route: one judged on a backend is never sent to a same-named
        // capability (resolve refuses that clash; this holds if a backend is
        // registered between resolve and here).
        if captured.is_none()
            && let Some(cap) = self.get_capabilities()
            && server == cap.name
            && let Some(cap_def) = cap.get(tool)
        {
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
                    account_credential: account_credential.credential,
                    account_resolution: crate::capability::AccountResolution::ByCaller(
                        account_credential.reference,
                    ),
                    mcp_generation: None,
                    credential_principal: credential_owner.map(str::to_owned),
                },
            )
            .await?;
            let mut response = serde_json::to_value(result)?;
            // The transform and the output schema below are written against
            // the declared shape, so a root published under `items` (MIK-7959)
            // is read without it and wrapped again after projection. Validating
            // the published object instead would rewrite the text content into
            // the wrapped shape.
            let wrapped =
                crate::capability::unwrap_published_output(&cap_def.schema.output, &mut response);

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
                let inner = crate::protocol::tool_result_payload(&response)
                    .unwrap_or_else(|| response.clone());
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
            // treatment arm of an A/B split sticky per caller key.
            let decision = crate::projection::projection_decision(self.projection_mode, arm_key);
            let spec_present = cap_def.projection.is_some();
            let mut final_result = if decision.project
                && let Some(spec) = cap_def.projection.as_ref()
            {
                apply_capability_projection(validated, spec, want_full)
            } else {
                validated
            };
            // After projection, whose field paths name the declared shape.
            if wrapped {
                crate::capability::rewrap_published_output(&mut final_result);
            }

            // A/B telemetry (MIK-5877, PROJ-ROLLOUT.3): one structured event per
            // eligible invocation so the experiment is measurable. No-op outside
            // `experimental` mode / spec-less tools.
            if let Some(key) = arm_key
                && let Some(rec) = crate::projection::ab_classification(
                    self.projection_mode,
                    Some(key),
                    want_full,
                    spec_present,
                )
            {
                // Keyed: the caller key ends in a stored principal (MIK-8697).
                let caller = crate::gateway::record_principal::record_owner(key, self.record_key());
                emit_projection_ab_event(session_id, &caller, server, tool, rec, &final_result);
            }
            return Ok(final_result);
        }

        // The backend the call was judged on, not a second lookup by name a
        // reload may have answered differently (MIK-7810). None: not found.
        let backend = captured.ok_or_else(|| Error::BackendNotFound(server.to_string()))?;

        // A "did you mean?" hint off THIS CALLER'S slot (MIK-7334.CATALOGUE.1):
        // the shared one holds a catalogue this caller was never shown once a
        // `stateless` backend lists per caller. Stale-tolerant; we still dispatch.
        let cached_names = backend.get_cached_tool_names_for(identity_key);
        let tool_is_cached = cached_names.iter().any(|n| n == tool);

        // Build request params. `_meta` is one object, so one writer owns it:
        // the caller's propagable trace context and this hop's cache key are
        // merged, or the field is absent entirely (design §3.4a).
        let (meta, key) = (inbound_meta, prompt_cache_key);
        let mut params = relay::outbound_params(tool, arguments, meta, key, outbound_retry);
        // ASI07 inc3: a chained backend gets this dispatch's own challenge.
        let chained = backend.chain_policy();
        let challenge = self.chain_challenge(chained.0, &mut params)?;

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
                    .request_with_task_capability_lent(
                        "tools/call",
                        Some(params),
                        propagated_headers.clone(),
                        identity_key,
                    )
                    .await?
            }
            None if propagated_headers.headers.is_empty() && identity_key.is_none() => {
                backend.request("tools/call", Some(params)).await?
            }
            None => {
                backend
                    .request_with_headers_lent(
                        "tools/call",
                        Some(params),
                        propagated_headers.clone(),
                        identity_key,
                    )
                    .await?
            }
        };

        if let Some(error) = response.error {
            // When we have cached names and the tool wasn't in them, enrich
            // the error with Levenshtein-based suggestions.
            let message = if !cached_names.is_empty() && !tool_is_cached {
                let tools = backend.get_cached_tools_snapshot_for(identity_key);
                let candidates =
                    self.miss_hint_pool((&cached_names, &tools), server, (scope, session_id));
                miss_with_hint(server, tool, &candidates, &error.message)
            } else {
                error.message
            };
            return Err(Error::JsonRpc {
                code: error.code,
                message,
                data: error.data,
            });
        }

        let withheld = response.ingress_withheld;
        let mut result = response.result.unwrap_or(json!(null));
        // Raw receipt (inc3 R1): verify before anything reads the reply.
        // A refused receipt is the delivered refusal of the backend's answer.
        self.chain_receive(
            chained,
            (
                &mut result,
                withheld
                    .as_deref()
                    .map(crate::protocol::reserved_members::Withheld::members),
            ),
            challenge.as_deref(),
            chain,
        )
        .inspect_err(|_| crate::gateway::delivery_facts::refused_while_vouched())?;
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
                    .with_cached_tool_for(identity_key, tool, |cached| cached.output_schema.clone())
                    .flatten()
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
}

impl MetaMcp {
    /// A name that is both a registry backend and the attached capability
    /// backend is refused, at resolve, before any credential, replay, key or
    /// cache: the checks judge the backend, and the capability would answer.
    /// Unscoped and name-only, so no caller's view can hide either route.
    pub(super) fn refuse_name_clash(&self, server: &str) -> Result<()> {
        if let Some(cap) = self.get_capabilities()
            && cap.name == server
            && self
                .scoped(crate::gateway::authz::BackendGrant::Unscoped)
                .scoped_get(server)
                .is_some()
        {
            return Err(ambiguous_backend(server, None));
        }
        Ok(())
    }
}

/// The refusal of a name that is both a registry backend and the capability
/// backend (see [`Error::AmbiguousBackend`]). `rule` names the policy rule
/// covering the call, when one does.
pub(super) fn ambiguous_backend(server: &str, rule: Option<&str>) -> Error {
    tracing::warn!(
        server,
        "refused: the name is both a configured backend and the capability backend"
    );
    Error::AmbiguousBackend {
        server: server.to_owned(),
        rule: rule.map(str::to_owned),
    }
}
