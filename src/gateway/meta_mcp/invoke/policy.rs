// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Invocation policy, attestation and response gates.

use serde_json::Value;
use tracing::warn;

use super::guarded::GuardedValue;
use super::{audit, dispatch_guards};
use crate::gateway::authz::{Authorize as _, Emit};
use crate::gateway::meta_mcp::MetaMcp;
use crate::gateway::meta_mcp_helpers::extract_required_str;
use crate::gateway::trace;
use crate::security::validate_tool_name;
use crate::{Error, Result};

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
        // S1 (kill switch, capability disable, session profile) is shared with
        // the per-backend route; every admission path reaches it through here.
        self.admit_target(&dispatch_guards::BackendCall {
            server,
            tool,
            session_id,
            api_key_name: None,
            trace_id: "",
            caller_key: None,
        })?;
        // #2445: a withheld tool is refused here, ahead of every replay layer.
        let backend = self.backends.get(server);
        match backend.and_then(|b| b.blocked_tool_refusal(None, tool)) {
            Some(refusal) => Err(Error::Protocol(refusal)),
            None => Ok(()),
        }
    }

    pub(in crate::gateway::meta_mcp) fn authorize_invocation(
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
        // The admin-capability rule is refused and audited like the authorizer.
        let refusal = authorizer
            .authorize(target)
            .map_err(|e| Error::Forbidden {
                code: e.code,
                status: e.status.as_u16(),
                message: e.message,
            })
            .and_then(|()| self.admin_capability_rule(server, tool, caller.is_admin));
        if let Err(e) = refusal {
            let (transport, name) = (authorizer.transport(), authorizer.caller_name());
            crate::gateway::authz::audit_refusal(transport, name, server, tool, &e.to_string());
            return Err(e);
        }
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
        // A clock before 1970 can judge no expiry: the token is treated as an
        // expired one, refused under enforce and logged under observe
        // (MIK-8202). Nothing is dated on it, so the audit ring is not written.
        let verdict = match crate::clock::utc_now() {
            Ok(now) => validator.validate_boundary_call(token, boundary, required, now),
            Err(clock) => Err(
                crate::attestation::validator::AttestationRejection::Expired {
                    expires_at: format!("a time that cannot be read: {clock}"),
                },
            ),
        };
        match verdict {
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
    pub(in crate::gateway::meta_mcp) fn refuse_unattested_plan(&self) -> Result<()> {
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
    pub(in crate::gateway::meta_mcp) async fn invoke_tool_in_slot(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    ) -> Result<Value> {
        let sourced = self.invoke_tool_sourced(args, session_id, caller).await;
        sourced.map(|sourced| sourced.0)
    }

    /// [`Self::invoke_tool`] plus the result's chain eligibility (A3) and its
    /// upstream chain outcome (inc3 D4).
    pub(in crate::gateway::meta_mcp) async fn invoke_tool_sourced(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
    ) -> Result<super::super::response_security::Sourced> {
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
            // MIN.2: read in a scope of its own, counted for the request only
            // when the call delivered (design §4.4).
            let ((result, notes), reading) = crate::security::tenant_reads::with_dispatch_reads(
                audit::with_dispatch_scope(traced),
            )
            .await;
            let responded = notes.responded();
            // Single delivery boundary: unwrap the guard-sealed result.
            let (result, source, upstream) = match result.map(GuardedValue::into_parts) {
                Ok((value, source, upstream)) => (Ok(value), source, upstream),
                Err(error) => (Err(error), crate::protocol::ChainSource::NotEligible, None),
            };
            // One record per call, refusals and failures included (D1-d).
            let audited = self
                .audit_invocation(args, session_id, caller, &trace_id_clone, result, notes)
                .await;
            // Only a delivered call counts: its own reading, and the tenants its
            // arguments name when a backend answered it, with or without a log.
            if audited.is_ok() {
                self.note_delivered_reading(args, reading, responded);
            }
            audited.map(|value| (value, source, upstream))
        })
        .await
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
    pub(in crate::gateway::meta_mcp) fn apply_response_gates(
        &self,
        server: &str,
        tool: &str,
        api_key_name: Option<&str>,
        trace_id: &str,
        result: Value,
    ) -> Result<Value> {
        let gated = self.apply_response_gates_effect(server, tool, api_key_name, trace_id, result);
        gated.map(|(value, _)| value)
    }

    /// [`Self::apply_response_gates`] plus whether a gate replaced or
    /// transformed the result (A3 R2'). Only this gateway may put a signature
    /// chain on a result, so any backend-sent chain is stripped first.
    pub(in crate::gateway::meta_mcp) fn apply_response_gates_effect(
        &self,
        server: &str,
        tool: &str,
        api_key_name: Option<&str>,
        trace_id: &str,
        mut result: Value,
    ) -> Result<(Value, super::super::response_security::GateEffect)> {
        crate::security::signature_chain::strip_chain(&mut result);
        let (mut result, raw_read) = audit::noted_response(self, result);
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
                    super::gateway_writes::note(
                        super::gateway_writes::Layer::Value,
                        &["_security_findings"],
                        &result,
                    );
                }
            }
        }

        let delivered = self.apply_context_integrity(server, tool, api_key_name, trace_id, result);
        // MIN.2: past every gate, so this dispatch's raw reading counts.
        crate::security::tenant_reads::note_attribution(raw_read);
        Ok(delivered)
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
    pub(super) fn apply_response_contract_gate(
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
            super::gateway_writes::note_contract(result);
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
                super::gateway_writes::note_contract(result);
            }
        }
        Ok(())
    }
}
