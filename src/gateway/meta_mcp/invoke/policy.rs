// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Invocation policy, attestation and response gates.

use crate::error::rpc_codes::INTERNAL_ERROR;
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
        crate::gateway::meta_mcp::visible::memo::refuse_withheld(server, tool)?;
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
        // MIK-8439/8475: on a per-user backend or an account-bearing
        // capability the error-rate check names the tool, so it waits for the
        // credential step; a caller with no view meets the account's answer
        // there first.
        let call = dispatch_guards::BackendCall {
            server,
            tool,
            session_id,
            api_key_name: None,
            cost_key: None,
            trace_id: "",
            caller_key: None,
        };
        let view = self.scoped(caller.scope().authorizer.backend_grant());
        if self.defers_error_rate_cooldown(&view, server, tool) {
            self.admit_named_target(&call)
        } else {
            self.admit_target(&call)
        }
        .map_err(|refusal| self.withheld_as_undefined((server, tool), session_id, refusal))?;
        // #2445: a withheld tool is refused here, ahead of every replay layer.
        let backend = self
            .scoped(caller.scope().authorizer.backend_grant())
            .scoped_get(server);
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
        // consulted. And the router builds its own target from the same
        // arguments (`judged_arguments`), so a policy that one day reads them
        // cannot give the two layers two answers.
        // `{}` and not `Null`: the router's own target builder defaults a
        // missing inner `arguments` to an empty object, and two gates that see
        // different targets are two gates that can disagree.
        // The arguments as dispatched (a JSON-string form parsed), the same
        // value the router's target builder judges (MIK-8137 b1).
        let judged = crate::gateway::authz::judged_arguments(args);
        let target = crate::gateway::authz::ToolTarget {
            server,
            tool,
            arguments: &judged,
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
                crate::attestation::AttestationMode::Enforce => Err(Error::gateway_refused(
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
            return Err(Error::gateway_refused(
                -32002,
                "Attestation rejected: multi-step plans carry no attestation in 4.0.0; \
                 call each tool with its own token",
            ));
        }
        Ok(())
    }

    /// [`Self::invoke_tool`] plus the result's chain eligibility (A3) and its
    /// upstream chain outcome (inc3 D4), or the lift's already-shaped stored
    /// answer, delivered unchanged (MIK-8392 STORED.2 D8). The invocation
    /// runs under `trace_id`, which the caller keeps for the answer's
    /// delivery record.
    pub(in crate::gateway::meta_mcp) async fn invoke_tool_sourced(
        &self,
        args: &Value,
        session_id: Option<&str>,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        trace_id: String,
    ) -> Result<super::SourcedOutcome> {
        // D1-f: a degraded audit log refuses before dispatch, after one probe.
        if let Some(log) = &self.transparency_logger
            && let Err(refused) = log.admit().await
        {
            self.count_call(
                args.get("server")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
                args.get("tool").and_then(Value::as_str),
                &crate::security::audit::AuditWho::from_caller(caller),
                crate::counters::Outcome::AdmissionRefused,
                None,
            );
            return Err(refused);
        }
        let trace_id_clone = trace_id.clone();
        // An in-process call has no request memo of its own: one per call, so
        // a refusal's code reaches its one record (MIK-8361). A request's
        // memo, when there is one, is kept.
        let traced = trace::with_trace_id(trace_id, async move {
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
            // The lift's already-shaped answer skips the live path below:
            // `audit_replay` recorded it, exactly once, and the stored frame
            // is delivered as is, never re-wrapped (D8).
            let result = match result {
                Ok(super::TracedOutcome::Stored(response)) => {
                    return Ok(super::SourcedOutcome::Stored(response));
                }
                Ok(super::TracedOutcome::Live(guarded)) => Ok(guarded),
                Err(error) => Err(error),
            };
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
            audited.map(|value| super::SourcedOutcome::Live((value, source, upstream)))
        });
        crate::gateway::meta_mcp::visible::memo::with_visibility_memo(traced).await
    }

    /// The one invocation record for a chain resume refused because its
    /// pending step's backend is absent for a scoped key (MIK-8387 S6). It
    /// never dispatches: the caller's `requestState` is still unredeemed here.
    /// It runs the frame [`Self::invoke_tool_sourced`] does (log admission, a
    /// trace id, a request memo) and the same writer, so all three cells get
    /// one record and one failure policy: `denied -32003` for an out-of-scope
    /// name, the not-found outcome for an unregistered one, and the log's
    /// write error when it fails closed.
    pub(in crate::gateway::meta_mcp) async fn record_absent_step(
        &self,
        (server, tool, arguments): (&str, &str, &Value),
        session_id: Option<&str>,
        caller: &crate::gateway::meta_mcp::MetaMcpCallerContext<'_>,
        absence: Option<crate::gateway::meta_mcp::scoped_backends::Absence>,
    ) -> Error {
        if let Some(log) = &self.transparency_logger
            && let Err(refused) = log.admit().await
        {
            self.count_call(
                server,
                Some(tool),
                &crate::security::audit::AuditWho::from_caller(caller),
                crate::counters::Outcome::AdmissionRefused,
                None,
            );
            return refused;
        }
        let args = serde_json::json!({"server": server, "tool": tool, "arguments": arguments});
        let trace_id = trace::generate();
        let recorded_trace = trace_id.clone();
        let recorded = trace::with_trace_id(trace_id, async move {
            if absence == Some(crate::gateway::meta_mcp::scoped_backends::Absence::OutOfScope) {
                crate::gateway::meta_mcp::visible::memo::note_denial_code(server, tool, -32003);
            }
            let missing = Err(Error::BackendNotFound(server.to_owned()));
            self.audit_invocation(
                &args,
                session_id,
                caller,
                &recorded_trace,
                missing,
                audit::DispatchNotes::default(),
            )
            .await
        });
        match crate::gateway::meta_mcp::visible::memo::with_visibility_memo(recorded).await {
            Err(error) => error,
            Ok(_) => Error::BackendNotFound(server.to_owned()),
        }
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
        self.apply_response_contract_gate(server, tool, trace_id, &mut result)
            .map_err(crate::gateway::delivery_facts::refused)?;

        // === POST-INVOKE: Response content inspection (issue #133, D2) ===
        //
        // Scan the backend response for secrets, exfiltration URLs, code
        // injection patterns, and suspicious encoding.
        //
        // Observe mode (default, `action_mode = false`): logs findings and
        // annotates the result with `_security_findings`.
        // Action mode (`action_mode = true`): blocks any response with a
        // HIGH/CRITICAL finding, returning a security error to the caller.
        let text = crate::security::response_inspect::extract_text_from_result(&result);
        let findings = self
            .inspect_backend_text(
                (server, tool, trace_id),
                &text,
                crate::gateway::delivery_facts::Part::Result,
            )
            .map_err(crate::gateway::delivery_facts::refused)?;
        if !findings.is_empty() {
            super::gateway_writes::insert_noted(
                super::gateway_writes::Layer::Value,
                &["_security_findings"],
                &mut result,
                serde_json::to_value(&findings).unwrap_or_default(),
            );
        }

        // A follow-up question the content gate enforces on ends the call
        // (MIK-8325): the gates judged the backend's question unsafe to show,
        // so it is refused, never resumed and never answered with a handle to
        // an exchange the caller cannot see. Strip, Summarize, Quarantine and
        // Deny alike; a round the gate let through is unchanged.
        let round = crate::protocol::mrtr::InputRequired::claims_input_required(&result);
        let delivered = self.apply_context_integrity(server, tool, api_key_name, trace_id, result);
        // MIN.2: past every gate, so this dispatch's raw reading counts.
        crate::security::tenant_reads::note_attribution(raw_read);
        if round
            && matches!(
                delivered.1,
                super::super::response_security::GateEffect::Enforced
                    | super::super::response_security::GateEffect::Withheld
            )
        {
            return Err(Error::ResponseFirewallRefused);
        }
        Ok(delivered)
    }

    /// D2 content inspection of a backend answer's text, shared by a result
    /// and a backend error (MIK-8139) so their screening cannot diverge:
    /// findings are logged and returned; in action mode a HIGH/CRITICAL
    /// finding refuses the answer.
    pub(in crate::gateway::meta_mcp) fn inspect_backend_text(
        &self,
        (server, tool, trace_id): (&str, &str, &str),
        text: &str,
        part: crate::gateway::delivery_facts::Part,
    ) -> Result<Vec<crate::security::response_inspect::Finding>> {
        use crate::security::response_inspect::ResponseInspectionMode;
        // Off (`enabled: false`): nothing inspected, logged, annotated or
        // blocked here, whatever `action_mode` says.
        if text.is_empty() || self.response_inspection == ResponseInspectionMode::Off {
            return Ok(Vec::new());
        }
        #[cfg(test)]
        crate::test_classification_count::note("d2_inspection", text);
        let inspection = crate::security::response_inspect::inspect_response(
            text,
            self.response_inspection == ResponseInspectionMode::Action,
        );
        // This delivery's findings, written before the block decision so a
        // blocked answer keeps the finding that blocked it. The
        // inspector ran on this answer, and that alone marks it scanned: a
        // gate that skips the inspector must return before this point.
        crate::gateway::delivery_facts::scanned();
        for finding in &inspection.findings {
            let kind = format!("inspect:{}", finding.category);
            crate::gateway::delivery_facts::found(kind, finding.severity, part);
        }
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
                INTERNAL_ERROR,
                format!(
                    "Tool '{tool}' on server '{server}' returned a response blocked \
                     by anomaly screening (HIGH/CRITICAL security finding detected). \
                     See gateway logs for details."
                ),
            ));
        }
        Ok(inspection.findings)
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
                    INTERNAL_ERROR,
                    format!(
                        "Tool '{tool}' on server '{server}' response blocked by contract gate: \
                         no contract declared and fail_closed is enabled."
                    ),
                ));
            }
            super::gateway_writes::write_contract(result, "no_contract_declared".to_string());
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
                        INTERNAL_ERROR,
                        format!(
                            "Tool '{tool}' on server '{server}' response blocked by contract gate: \
                             {} — {}",
                            violation.reason, violation.detail
                        ),
                    ));
                }
                super::gateway_writes::write_contract(result, violation.reason.to_string());
            }
        }
        Ok(())
    }
}
