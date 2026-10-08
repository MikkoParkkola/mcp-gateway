// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Error budgets, transition predictions and context integrity.

use serde_json::{Value, json};
use tracing::{debug, warn};

use super::{audit, withheld_evidence};
use crate::context_integrity::{
    ContextActionRisk, ContextIntegrityDecisionKind, ContextIntegrityEvaluation,
    ContextIntegrityInput, ContextProvenance, ContextTrustBoundary,
};
use crate::gateway::meta_mcp::MetaMcp;
use crate::identity_grants::GrantSubject;
use crate::protocol::mrtr::InputRequired;

use super::BudgetOutcome;

impl MetaMcp {
    /// Record an outcome against both backend and per-capability error budgets.
    pub(super) fn record_error_budget(&self, server: &str, tool: &str, outcome: BudgetOutcome) {
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

    /// Record the caller's transition and return predictions for the current tool.
    ///
    /// `key` is [`super::super::MetaMcpCallerContext::experiment_key`]: `None` (any
    /// keyless caller, stdio included) records nothing and is served no hints (G4).
    ///
    /// Side-effects:
    /// - Records `key → tool_key` in the `TransitionTracker`.
    /// - If a `ToolRegistry` is attached, triggers schema prefetching for the
    ///   top-N predicted successors (see [`crate::tool_registry::ToolRegistry::prefetch_after`]).
    pub(in crate::gateway::meta_mcp) fn record_and_predict(
        &self,
        // The session the visibility check reads (routing profile), and the
        // key the transition is recorded under.
        session_id: Option<&str>,
        key: Option<&str>,
        tool_key: &str,
        scope: super::super::InvokeScope<'_>,
    ) -> Vec<Value> {
        let Some(tracker) = self.get_transition_tracker() else {
            return Vec::new();
        };
        let Some(sid) = key else {
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

    pub(in crate::gateway::meta_mcp) fn grant_subject_from_api_key(
        api_key_name: Option<&str>,
    ) -> Option<GrantSubject> {
        api_key_name
            .filter(|name| !name.is_empty())
            .map(|name| GrantSubject::new("api_key", name, Some(name.to_string())))
    }

    pub(super) fn apply_context_integrity(
        &self,
        server: &str,
        tool: &str,
        api_key_name: Option<&str>,
        trace_id: &str,
        result: Value,
    ) -> (Value, super::super::response_security::GateEffect) {
        use super::super::response_security::GateEffect;
        let mut provenance = ContextProvenance::tool_result(
            server,
            tool,
            trace_id,
            ContextTrustBoundary::RemoteToolOutput,
        );
        provenance.subject = api_key_name.map(str::to_string);
        provenance.origin = Some(format!("{server}:{tool}"));

        let (read_only, destructive) = self.capability_context_flags(server, tool);
        // MIK-7994: the continuation the gateway minted is its own token, not
        // backend output, so it is not judged and Strip never renders it into
        // the delivered text. A backend's own `requestState` is judged as
        // ever: only a member the gateway still owns is left out. The handle
        // still crosses: it is read from `result` itself.
        let mut judged = result.clone();
        if super::gateway_writes::owns(
            super::gateway_writes::Layer::Value,
            super::gateway_writes::REQUEST_STATE,
            &result,
        ) && let Some(map) = judged.as_object_mut()
        {
            map.remove("requestState");
        }
        let mut input = ContextIntegrityInput::read_only_tool_result(provenance, judged);
        input.read_only = read_only;
        input.destructive = destructive;
        input.action_risk = if destructive {
            ContextActionRisk::High
        } else if read_only {
            ContextActionRisk::Low
        } else {
            ContextActionRisk::Medium
        };

        let evaluation = audit::noted_classes(self.context_integrity_kernel.read().evaluate(input));
        if evaluation.classification.findings.is_empty()
            && evaluation.policy.would_decision == ContextIntegrityDecisionKind::Allow
        {
            return (result, GateEffect::PassedThrough);
        }

        let (delivered, effect) = if evaluation.policy.enforcement_applied {
            let delivered = Self::context_integrity_delivered_result(&evaluation, &result);
            (delivered, GateEffect::Enforced)
        } else {
            (result, GateEffect::PassedThrough)
        };
        (
            Self::attach_context_integrity_metadata(delivered, &evaluation),
            effect,
        )
    }

    pub(super) fn capability_context_flags(&self, server: &str, tool: &str) -> (bool, bool) {
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

    pub(super) fn context_integrity_delivered_result(
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

    pub(super) fn attach_context_integrity_metadata(
        mut result: Value,
        evaluation: &ContextIntegrityEvaluation,
    ) -> Value {
        let metadata = json!({
            "schema_version": &evaluation.schema_version,
            "content_sha256": &evaluation.content_sha256,
            "provenance": &evaluation.provenance,
            "classification": withheld_evidence::delivered(evaluation),
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
}
