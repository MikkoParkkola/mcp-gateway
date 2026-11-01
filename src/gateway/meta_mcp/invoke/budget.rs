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
use crate::gateway::delivery_facts::ResponseEffect;
use crate::gateway::meta_mcp::MetaMcp;
use crate::identity_grants::GrantSubject;

use super::BudgetOutcome;

/// Whether enforcement withheld the backend's answer, from what
/// [`MetaMcp::context_integrity_delivered_result`] says it did: `None` is a
/// whole withhold and `Refused` a malformed round, both withheld; every other
/// effect delivered the answer. Exhaustive, so a new effect must be placed.
fn withheld_by(effect: Option<ResponseEffect>) -> bool {
    match effect {
        None | Some(ResponseEffect::Refused) => true,
        Some(ResponseEffect::Delivered | ResponseEffect::Annotated | ResponseEffect::Rewritten) => {
            false
        }
    }
}

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
                p.tool
                    .split_once(':')
                    .is_some_and(|(server, tool)| self.shows_name(server, tool, scope, session_id))
            })
            .map(|p| json!({"tool": p.tool, "confidence": p.confidence}))
            .collect()
    }

    /// The identity-grant fallback subject for `grant_key`: only an API key's
    /// name may be passed (MIK-8518); every other credential passes `None`.
    pub(in crate::gateway) fn grant_subject_from_api_key(
        grant_key: Option<&str>,
    ) -> Option<GrantSubject> {
        grant_key.and_then(|name| GrantSubject::checked("api_key", name, Some(name.to_string())))
    }

    /// Whether the kernel enforces on `carrier`. Notes no data classes: the
    /// egress scan's check is not the call's classification, and a replay
    /// has none (MIK-7116.MIN.1).
    pub(super) fn context_integrity_enforces(
        &self,
        (server, tool): (&str, &str),
        api_key_name: Option<&str>,
        trace_id: &str,
        carrier: &Value,
    ) -> bool {
        let input = self.context_integrity_input((server, tool), api_key_name, trace_id, carrier);
        let evaluation = self.context_integrity_kernel.read().evaluate(input);
        let clean = evaluation.classification.findings.is_empty()
            && evaluation.policy.would_decision == ContextIntegrityDecisionKind::Allow;
        !clean && evaluation.policy.enforcement_applied
    }

    fn context_integrity_input(
        &self,
        (server, tool): (&str, &str),
        api_key_name: Option<&str>,
        trace_id: &str,
        result: &Value,
    ) -> ContextIntegrityInput {
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
            result,
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
        input
    }

    pub(super) fn apply_context_integrity(
        &self,
        server: &str,
        tool: &str,
        api_key_name: Option<&str>,
        trace_id: &str,
        result: Value,
    ) -> (Value, super::super::response_security::GateEffect) {
        let (value, effect, _) =
            self.context_integrity_outcome(server, tool, api_key_name, trace_id, result);
        (value, effect)
    }

    /// [`Self::apply_context_integrity`], plus whether enforcement withheld the
    /// result outright. Only the caller that delivers the result notes that as
    /// a refusal; a classification of a copy notes nothing.
    pub(super) fn context_integrity_outcome(
        &self,
        server: &str,
        tool: &str,
        api_key_name: Option<&str>,
        trace_id: &str,
        result: Value,
    ) -> (Value, super::super::response_security::GateEffect, bool) {
        use super::super::response_security::GateEffect;
        let input = self.context_integrity_input((server, tool), api_key_name, trace_id, &result);
        let evaluation = audit::noted_classes(self.context_integrity_kernel.read().evaluate(input));
        if evaluation.classification.findings.is_empty()
            && evaluation.policy.would_decision == ContextIntegrityDecisionKind::Allow
        {
            return (result, GateEffect::PassedThrough, false);
        }

        let (delivered, effect, withheld) = if evaluation.policy.enforcement_applied {
            // A rebuilt round is raised here; a malformed round and a whole
            // withhold are both Withheld, raised once where they are delivered.
            let (delivered, rebuilt) =
                Self::context_integrity_delivered_result(&evaluation, &result);
            let effect = match rebuilt {
                Some(ResponseEffect::Rewritten) => {
                    crate::gateway::delivery_facts::raise(ResponseEffect::Rewritten);
                    GateEffect::Enforced
                }
                _ => GateEffect::Withheld,
            };
            (delivered, effect, withheld_by(rebuilt))
        } else {
            (result, GateEffect::PassedThrough, false)
        };
        (
            Self::attach_context_integrity_metadata(delivered, &evaluation),
            effect,
            withheld,
        )
    }

    /// The read-only and destructive flags of `server`'s `tool` when it is a
    /// capability the caller sees. A provider hidden from the caller has none,
    /// as an unregistered name has none, so its answer's integrity audit
    /// cannot tell the two apart.
    pub(super) fn capability_context_flags(&self, server: &str, tool: &str) -> (bool, bool) {
        if let Some(capabilities) = self.caller_capabilities()
            && server == capabilities.name
            && let Some(capability) = capabilities.get(tool)
        {
            let read_only = capability.metadata.read_only;
            let destructive = capability.metadata.destructive.unwrap_or(!read_only);
            return (read_only, destructive);
        }

        (false, false)
    }

    /// The answer enforcement delivers, and what that did to the backend's:
    /// `Rewritten` for a rebuild, `Refused` for a malformed round, and `None`
    /// for a whole withhold, whose refusal is raised where the withheld
    /// answer is delivered.
    pub(super) fn context_integrity_delivered_result(
        evaluation: &ContextIntegrityEvaluation,
        original: &Value,
    ) -> (Value, Option<ResponseEffect>) {
        let Some(delivered) = evaluation.transformed.delivered.clone() else {
            let withheld = json!({
                "isError": true,
                "content": [{
                    "type": "text",
                    "text": format!(
                        "Tool result withheld by ContextIntegrityKernel: {}",
                        evaluation.policy.rationale
                    )
                }]
            });
            return (withheld, None);
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
        // An enforced input round is rebuilt here but never delivered: the
        // response gates refuse it (MIK-8325, decision (i) in
        // the 4.0.0 decision docket), so the rebuild carries no
        // continuation handle and no question (`inputRequests`).
        //
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
            let refused = json!({
                "content": [{
                    "type": "text",
                    "text": "The backend returned a malformed result: `resultType`                              must be a string and `isError` a boolean. The response                              was refused rather than delivered."
                }],
                "isError": true,
            });
            return (refused, Some(ResponseEffect::Refused));
        }
        let mut envelope = serde_json::Map::new();
        for (field, value) in [("resultType", result_type), ("isError", is_error)] {
            if let Some(value) = value {
                envelope.insert(field.to_string(), value.clone());
            }
        }
        envelope.insert("content".to_string(), content);
        envelope.insert("structuredContent".to_string(), delivered);
        (Value::Object(envelope), Some(ResponseEffect::Rewritten))
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

        // A counted member written outside `note`: noting it would strip the
        // verdict from the staged receipt copy, which relay detection reads.
        if let Some(obj) = result.as_object_mut() {
            obj.insert("_context_integrity".to_string(), metadata);
            crate::gateway::delivery_facts::raise(ResponseEffect::Annotated);
            result
        } else {
            // A scalar has no member to carry the verdict: the gateway wraps
            // it, which changes the bytes delivered.
            crate::gateway::delivery_facts::raise(ResponseEffect::Rewritten);
            json!({
                "structuredContent": result,
                "_context_integrity": metadata
            })
        }
    }
}

#[cfg(test)]
mod withheld_by_tests {
    use super::{ResponseEffect, withheld_by};

    #[test]
    fn a_whole_withhold_is_withheld() {
        assert!(withheld_by(None));
    }

    #[test]
    fn a_refused_round_is_withheld() {
        assert!(withheld_by(Some(ResponseEffect::Refused)));
    }

    #[test]
    fn a_rewritten_answer_is_delivered() {
        assert!(!withheld_by(Some(ResponseEffect::Rewritten)));
    }

    #[test]
    fn an_annotated_answer_is_delivered() {
        assert!(!withheld_by(Some(ResponseEffect::Annotated)));
    }

    #[test]
    fn an_untouched_answer_is_delivered() {
        assert!(!withheld_by(Some(ResponseEffect::Delivered)));
    }
}
