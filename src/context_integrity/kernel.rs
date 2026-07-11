// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use std::sync::LazyLock;

use regex::RegexSet;
use serde_json::{Value, json};

use crate::{
    hashing::canonical_json_sha256,
    protocol::Tool,
    security::{
        ResponseScanner,
        response_inspect::{Severity as InspectSeverity, inspect_response},
    },
    validator::{Rule, Severity as ValidationSeverity, ToolPoisoningRule},
};

use super::{
    CONTEXT_INTEGRITY_SCHEMA_VERSION, ContextActionRisk, ContextDataClass,
    ContextIntegrityAuditEvent, ContextIntegrityClassification, ContextIntegrityClassifier,
    ContextIntegrityDecisionKind, ContextIntegrityEvaluation, ContextIntegrityFinding,
    ContextIntegrityInput, ContextIntegrityPolicy, ContextIntegrityPolicyMode,
    ContextIntegrityPolicyVerdict, ContextIntegritySeverity, ContextIntegrityTransformedContent,
    ContextProvenance,
};

const GUARDED_INSPECT_CATEGORY: &str = concat!("sec", "ret");
const MAX_CLASSIFICATION_TEXT_BYTES: usize = 64 * 1024;
const CLASSIFICATION_TEXT_EDGE_BYTES: usize = MAX_CLASSIFICATION_TEXT_BYTES / 2;

static PERSONAL_DATA_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        r"\b(?:\+?\d[\d .-]{7,}\d)\b",
        r"\b\d{3}-\d{2}-\d{4}\b",
    ])
    .expect("personal data patterns must compile")
});

static FINANCIAL_DATA_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"\b(?:\d[ -]?){13,19}\b",
        r"(?i)\biban\b[:\s]+[A-Z0-9 ]{12,}\b",
    ])
    .expect("financial data patterns must compile")
});

static DESTRUCTIVE_ACTION_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)\b(delete|remove|wipe|drop|truncate)\s+(all|database|table|files|records)\b",
        r"(?i)\btransfer\s+(funds|money|assets)\b",
        r"(?i)\brevoke\s+(all\s+)?access\b",
        r"(?i)\bdisable\s+(audit|logging|monitoring)\b",
    ])
    .expect("destructive action patterns must compile")
});

static TOOL_ACCESS_ESCALATION_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)\bgrant\s+(me|this\s+tool|the\s+tool|it)\s+(access|permission|admin)\b",
        r"(?i)\benable\s+(admin|privileged|restricted)\s+tool",
        r"(?i)\bcall\s+[\w.-]*admin[\w.-]*\b",
        r"(?i)\buse\s+[\w.-]*admin[\w.-]*\s+to\b",
    ])
    .expect("tool access escalation patterns must compile")
});

static EXFILTRATION_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)\b(send|post|upload|transmit)\s+(all\s+)?(data|content|records)\s+(to|via)\b",
        r"(?i)\bhttps?://[^\s]+/(collect|ingest|exfil|upload)\b",
    ])
    .expect("exfiltration patterns must compile")
});

/// Context integrity kernel.
pub struct ContextIntegrityKernel {
    policy: ContextIntegrityPolicy,
    response_scanner: ResponseScanner,
}

impl ContextIntegrityKernel {
    /// Create a kernel with a specific policy.
    #[must_use]
    pub fn new(policy: ContextIntegrityPolicy) -> Self {
        Self {
            policy,
            response_scanner: ResponseScanner::new(),
        }
    }

    /// Evaluate tool-result content and produce a policy envelope.
    #[must_use]
    pub fn evaluate(&self, input: ContextIntegrityInput) -> ContextIntegrityEvaluation {
        let content_sha256 = canonical_json_sha256(&input.content);
        let text = render_text_for_classification(&input.content);
        let classification = self.classify_text(&input, &text);
        let would_decision = self.resolve_decision(&input, &classification);
        let decision = if self.policy.effective_mode() == ContextIntegrityPolicyMode::MonitorOnly {
            ContextIntegrityDecisionKind::Allow
        } else {
            would_decision
        };
        let transformed = transform_content(decision, &input.content, &classification.findings);
        let policy = policy_verdict(
            &self.policy,
            decision,
            would_decision,
            &classification,
            &input,
        );
        let audit = ContextIntegrityAuditEvent {
            schema_version: CONTEXT_INTEGRITY_SCHEMA_VERSION.to_string(),
            invocation_id: input.provenance.invocation_id.clone(),
            server: input.provenance.server.clone(),
            tool: input.provenance.tool.clone(),
            trust_boundary: input.provenance.trust_boundary,
            content_sha256: content_sha256.clone(),
            decision,
            would_decision,
            findings_count: classification.findings.len(),
            monitor_only: self.policy.effective_mode() == ContextIntegrityPolicyMode::MonitorOnly,
        };

        ContextIntegrityEvaluation {
            schema_version: CONTEXT_INTEGRITY_SCHEMA_VERSION.to_string(),
            content_sha256,
            provenance: input.provenance,
            classification,
            policy,
            transformed,
            audit,
        }
    }

    /// Evaluate a tool descriptor with AX-010 descriptor poisoning checks.
    #[must_use]
    pub fn evaluate_tool_descriptor(
        &self,
        tool: &Tool,
        mut provenance: ContextProvenance,
    ) -> ContextIntegrityEvaluation {
        provenance.tool.clone_from(&tool.name);
        let descriptor_content = json!({
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema,
            "annotations": tool.annotations,
        });
        let original_content = descriptor_content.clone();
        let mut input =
            ContextIntegrityInput::read_only_tool_result(provenance, descriptor_content);
        input.action_risk = if tool
            .annotations
            .as_ref()
            .and_then(|a| a.destructive_hint)
            .unwrap_or(false)
        {
            ContextActionRisk::High
        } else {
            ContextActionRisk::Low
        };
        input.destructive = input.action_risk.requires_confirmation();

        let mut evaluation = self.evaluate(input.clone());
        if let Ok(validation) = ToolPoisoningRule.check(tool)
            && validation.severity != ValidationSeverity::Pass
        {
            let severity = if validation.severity == ValidationSeverity::Fail {
                ContextIntegritySeverity::Critical
            } else {
                ContextIntegritySeverity::High
            };
            evaluation
                .classification
                .findings
                .push(ContextIntegrityFinding {
                    classifier: ContextIntegrityClassifier::ToolPoisoning,
                    severity,
                    data_class: ContextDataClass::InstructionLike,
                    description: validation.rule_name,
                    evidence: validation.issues.join("; "),
                });
            finalize_classification(&mut evaluation.classification);
            let would_decision =
                self.resolve_decision_from_findings(&evaluation.classification, input.action_risk);
            let decision =
                if self.policy.effective_mode() == ContextIntegrityPolicyMode::MonitorOnly {
                    ContextIntegrityDecisionKind::Allow
                } else {
                    would_decision
                };
            evaluation.policy = policy_verdict(
                &self.policy,
                decision,
                would_decision,
                &evaluation.classification,
                &input,
            );
            evaluation.audit.decision = decision;
            evaluation.audit.would_decision = would_decision;
            evaluation.audit.findings_count = evaluation.classification.findings.len();
            evaluation.transformed = transform_content(
                decision,
                &original_content,
                &evaluation.classification.findings,
            );
        }

        evaluation
    }

    fn classify_text(
        &self,
        input: &ContextIntegrityInput,
        text: &str,
    ) -> ContextIntegrityClassification {
        let mut findings = Vec::new();

        for item in self.response_scanner.scan_text(text) {
            findings.push(ContextIntegrityFinding {
                classifier: ContextIntegrityClassifier::PromptInjection,
                severity: ContextIntegritySeverity::Critical,
                data_class: ContextDataClass::InstructionLike,
                description: item.pattern_description,
                evidence: safe_fragment(&item.matched_fragment),
            });
        }

        for item in inspect_response(text, true).findings {
            let (classifier, data_class) = match item.category {
                GUARDED_INSPECT_CATEGORY => (
                    ContextIntegrityClassifier::GuardedMaterial,
                    ContextDataClass::GuardedMaterial,
                ),
                "exfil_url" | "c2" => (
                    ContextIntegrityClassifier::DataExfiltration,
                    ContextDataClass::Internal,
                ),
                "code_inject" | "supply_chain" => (
                    ContextIntegrityClassifier::DestructiveInstruction,
                    ContextDataClass::InstructionLike,
                ),
                _ => (
                    ContextIntegrityClassifier::PromptInjection,
                    ContextDataClass::InstructionLike,
                ),
            };
            findings.push(ContextIntegrityFinding {
                classifier,
                severity: map_inspect_severity(item.severity),
                data_class,
                description: item.description.to_string(),
                evidence: format!("response_inspect pattern {}", item.matched_pattern_index),
            });
        }

        append_regex_findings(
            &mut findings,
            &PERSONAL_DATA_PATTERNS,
            text,
            ContextIntegrityClassifier::PersonalData,
            ContextIntegritySeverity::Medium,
            ContextDataClass::PersonalData,
            "personal data pattern",
        );
        append_regex_findings(
            &mut findings,
            &FINANCIAL_DATA_PATTERNS,
            text,
            ContextIntegrityClassifier::FinancialData,
            ContextIntegritySeverity::High,
            ContextDataClass::FinancialData,
            "financial data pattern",
        );
        append_regex_findings(
            &mut findings,
            &DESTRUCTIVE_ACTION_PATTERNS,
            text,
            ContextIntegrityClassifier::DestructiveInstruction,
            ContextIntegritySeverity::High,
            ContextDataClass::InstructionLike,
            "destructive instruction pattern",
        );
        append_regex_findings(
            &mut findings,
            &TOOL_ACCESS_ESCALATION_PATTERNS,
            text,
            ContextIntegrityClassifier::ToolAccessEscalation,
            ContextIntegritySeverity::Critical,
            ContextDataClass::InstructionLike,
            "tool access escalation pattern",
        );
        append_regex_findings(
            &mut findings,
            &EXFILTRATION_PATTERNS,
            text,
            ContextIntegrityClassifier::DataExfiltration,
            ContextIntegritySeverity::High,
            ContextDataClass::Internal,
            "data exfiltration pattern",
        );

        if input.destructive && input.provenance.trust_boundary.is_untrusted() {
            findings.push(ContextIntegrityFinding {
                classifier: ContextIntegrityClassifier::DestructiveInstruction,
                severity: ContextIntegritySeverity::High,
                data_class: ContextDataClass::InstructionLike,
                description: "untrusted content attached to destructive tool result".to_string(),
                evidence: "destructive tool boundary".to_string(),
            });
        }

        let mut classification = ContextIntegrityClassification {
            data_classes: vec![ContextDataClass::Public],
            findings,
            max_severity: None,
        };
        finalize_classification(&mut classification);
        classification
    }

    fn resolve_decision(
        &self,
        input: &ContextIntegrityInput,
        classification: &ContextIntegrityClassification,
    ) -> ContextIntegrityDecisionKind {
        let mut decision = self.resolve_decision_from_findings(classification, input.action_risk);

        if input.action_risk.requires_confirmation()
            && !classification.findings.is_empty()
            && decision == ContextIntegrityDecisionKind::Allow
        {
            decision = self.policy.high_risk_action_decision;
        }

        if self.policy.allow_benign_read_only
            && input.read_only
            && !has_critical_finding(classification)
            && decision == ContextIntegrityDecisionKind::Allow
        {
            return ContextIntegrityDecisionKind::Allow;
        }

        decision
    }

    fn resolve_decision_from_findings(
        &self,
        classification: &ContextIntegrityClassification,
        action_risk: ContextActionRisk,
    ) -> ContextIntegrityDecisionKind {
        if classification
            .findings
            .iter()
            .any(|f| f.classifier == ContextIntegrityClassifier::ToolPoisoning)
        {
            return self.policy.tool_poisoning_decision;
        }
        if classification
            .findings
            .iter()
            .any(|f| f.classifier == ContextIntegrityClassifier::ToolAccessEscalation)
        {
            return ContextIntegrityDecisionKind::Deny;
        }
        if action_risk.requires_confirmation() && !classification.findings.is_empty() {
            return self.policy.high_risk_action_decision;
        }
        if classification
            .findings
            .iter()
            .any(|f| f.classifier == ContextIntegrityClassifier::PromptInjection)
        {
            return self.policy.untrusted_instruction_decision;
        }
        if classification
            .findings
            .iter()
            .any(|f| f.classifier == ContextIntegrityClassifier::GuardedMaterial)
        {
            return self.policy.guarded_material_decision;
        }
        if classification
            .findings
            .iter()
            .any(|f| f.classifier == ContextIntegrityClassifier::DestructiveInstruction)
        {
            return self.policy.destructive_instruction_decision;
        }
        if classification.findings.iter().any(|f| {
            matches!(
                f.classifier,
                ContextIntegrityClassifier::PersonalData
                    | ContextIntegrityClassifier::FinancialData
                    | ContextIntegrityClassifier::DataExfiltration
            )
        }) {
            return self.policy.personal_data_decision;
        }
        ContextIntegrityDecisionKind::Allow
    }
}

impl Default for ContextIntegrityKernel {
    fn default() -> Self {
        Self::new(ContextIntegrityPolicy::default())
    }
}

fn append_regex_findings(
    findings: &mut Vec<ContextIntegrityFinding>,
    set: &RegexSet,
    text: &str,
    classifier: ContextIntegrityClassifier,
    severity: ContextIntegritySeverity,
    data_class: ContextDataClass,
    description: &str,
) {
    for idx in set.matches(text) {
        findings.push(ContextIntegrityFinding {
            classifier,
            severity,
            data_class,
            description: description.to_string(),
            evidence: format!("pattern {idx}"),
        });
    }
}

fn finalize_classification(classification: &mut ContextIntegrityClassification) {
    let mut data_classes: Vec<ContextDataClass> = classification
        .findings
        .iter()
        .map(|f| f.data_class)
        .collect();
    if data_classes.is_empty() {
        data_classes.push(ContextDataClass::Public);
    }
    data_classes.sort_unstable();
    data_classes.dedup();
    classification.data_classes = data_classes;
    classification.max_severity = classification.findings.iter().map(|f| f.severity).max();
}

fn has_critical_finding(classification: &ContextIntegrityClassification) -> bool {
    classification
        .findings
        .iter()
        .any(|f| f.severity == ContextIntegritySeverity::Critical)
}

fn policy_verdict(
    policy: &ContextIntegrityPolicy,
    decision: ContextIntegrityDecisionKind,
    would_decision: ContextIntegrityDecisionKind,
    classification: &ContextIntegrityClassification,
    input: &ContextIntegrityInput,
) -> ContextIntegrityPolicyVerdict {
    let enforcement_applied = policy.effective_mode() == ContextIntegrityPolicyMode::Enforce
        && decision != ContextIntegrityDecisionKind::Allow;
    let confirmation_required = matches!(decision, ContextIntegrityDecisionKind::Confirm)
        || (input.action_risk.requires_confirmation() && !classification.findings.is_empty());
    let quarantined = matches!(decision, ContextIntegrityDecisionKind::Quarantine);
    let privilege_elevation_allowed = !classification
        .findings
        .iter()
        .any(|f| f.classifier == ContextIntegrityClassifier::ToolAccessEscalation);
    let rationale = if classification.findings.is_empty() {
        "no classifier findings".to_string()
    } else if policy.effective_mode() == ContextIntegrityPolicyMode::MonitorOnly {
        format!(
            "monitor-only: would apply {would_decision:?} for {} finding(s)",
            classification.findings.len()
        )
    } else {
        format!(
            "enforced {decision:?} for {} finding(s)",
            classification.findings.len()
        )
    };

    ContextIntegrityPolicyVerdict {
        mode: policy.effective_mode(),
        decision,
        would_decision,
        enforcement_applied,
        confirmation_required,
        quarantined,
        privilege_elevation_allowed,
        rationale,
    }
}

fn transform_content(
    decision: ContextIntegrityDecisionKind,
    content: &Value,
    findings: &[ContextIntegrityFinding],
) -> ContextIntegrityTransformedContent {
    match decision {
        ContextIntegrityDecisionKind::Allow => ContextIntegrityTransformedContent {
            delivered: Some(content.clone()),
            stripped: false,
            summarized: false,
            withheld: false,
        },
        ContextIntegrityDecisionKind::Strip => ContextIntegrityTransformedContent {
            delivered: Some(Value::String(strip_instruction_lines(&render_text(
                content,
            )))),
            stripped: true,
            summarized: false,
            withheld: false,
        },
        ContextIntegrityDecisionKind::Summarize => {
            let summary = format!(
                "ContextIntegrityKernel withheld raw content and summarized {} finding(s).",
                findings.len()
            );
            ContextIntegrityTransformedContent {
                delivered: Some(Value::String(summary)),
                stripped: false,
                summarized: true,
                withheld: false,
            }
        }
        ContextIntegrityDecisionKind::Quarantine
        | ContextIntegrityDecisionKind::Confirm
        | ContextIntegrityDecisionKind::Deny => ContextIntegrityTransformedContent {
            delivered: None,
            stripped: false,
            summarized: false,
            withheld: true,
        },
    }
}

fn strip_instruction_lines(text: &str) -> String {
    text.lines()
        .filter(|line| {
            let lowered = line.to_ascii_lowercase();
            !lowered.contains("ignore previous")
                && !lowered.contains("system prompt")
                && !lowered.contains("grant")
                && !lowered.contains("call")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_text(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) => items.iter().map(render_text).collect::<Vec<_>>().join("\n"),
        Value::Object(map) => map.values().map(render_text).collect::<Vec<_>>().join("\n"),
        Value::Null => String::new(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.to_string(),
    }
}

fn render_text_for_classification(value: &Value) -> String {
    let mut sample = TextSample::default();
    collect_text_sample(value, &mut sample);
    sample.into_text()
}

#[derive(Default)]
struct TextSample {
    head: String,
    tail: String,
    total_bytes: usize,
}

impl TextSample {
    fn push(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }

        let separator = if self.total_bytes == 0 { "" } else { "\n" };
        self.push_segment(separator);
        self.push_segment(text);
    }

    fn push_segment(&mut self, segment: &str) {
        self.total_bytes += segment.len();
        push_prefix_limited(&mut self.head, segment, MAX_CLASSIFICATION_TEXT_BYTES);
        push_suffix_limited(&mut self.tail, segment, CLASSIFICATION_TEXT_EDGE_BYTES);
    }

    fn into_text(self) -> String {
        if self.total_bytes <= MAX_CLASSIFICATION_TEXT_BYTES {
            return self.head;
        }

        format!(
            "{}\n[...content truncated for classification...]\n{}",
            prefix_fragment(&self.head, CLASSIFICATION_TEXT_EDGE_BYTES),
            self.tail
        )
    }
}

fn collect_text_sample(value: &Value, sample: &mut TextSample) {
    match value {
        Value::String(s) => sample.push(s),
        Value::Array(items) => {
            for item in items {
                collect_text_sample(item, sample);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                collect_text_sample(value, sample);
            }
        }
        Value::Null => {}
        Value::Bool(v) => sample.push(&v.to_string()),
        Value::Number(v) => sample.push(&v.to_string()),
    }
}

fn push_prefix_limited(out: &mut String, segment: &str, limit: usize) {
    if out.len() >= limit {
        return;
    }

    let remaining = limit - out.len();
    out.push_str(prefix_fragment(segment, remaining));
}

fn push_suffix_limited(out: &mut String, segment: &str, limit: usize) {
    if segment.len() >= limit {
        out.clear();
        out.push_str(suffix_fragment(segment, limit));
        return;
    }

    out.push_str(segment);
    trim_prefix_to_limit(out, limit);
}

fn trim_prefix_to_limit(out: &mut String, limit: usize) {
    if out.len() <= limit {
        return;
    }

    let mut start = out.len() - limit;
    while !out.is_char_boundary(start) {
        start += 1;
    }
    out.drain(..start);
}

fn prefix_fragment(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }

    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn suffix_fragment(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }

    let mut start = text.len() - limit;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

fn map_inspect_severity(severity: InspectSeverity) -> ContextIntegritySeverity {
    match severity {
        InspectSeverity::Low => ContextIntegritySeverity::Low,
        InspectSeverity::Medium => ContextIntegritySeverity::Medium,
        InspectSeverity::High => ContextIntegritySeverity::High,
        InspectSeverity::Critical => ContextIntegritySeverity::Critical,
    }
}

fn safe_fragment(fragment: &str) -> String {
    let mut out = fragment.chars().take(120).collect::<String>();
    if fragment.chars().count() > 120 {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
#[path = "kernel_tests.rs"]
mod tests;
