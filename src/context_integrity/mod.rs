// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Context integrity kernel for tool-result boundary protection.
//!
//! The kernel classifies gateway-routed tool output before that output is
//! promoted into privileged agent context. It records provenance, trust
//! boundary, classifier evidence, policy decisions, and monitor-only rollout
//! metadata on risky live dispatch results before they are cached, signed, or
//! returned to the caller.

use serde::{Deserialize, Serialize};
use serde_json::Value;

mod kernel;
pub use kernel::ContextIntegrityKernel;

/// Version marker for serialized context-integrity evaluations.
pub const CONTEXT_INTEGRITY_SCHEMA_VERSION: &str = "context_integrity.v1";

/// Trust boundary assigned to the content entering the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextTrustBoundary {
    /// Gateway-authored metadata or locally generated policy content.
    GatewayTrusted,
    /// Output from a local server controlled by the operator.
    LocalToolOutput,
    /// Output from a remote MCP server or remote HTTP API.
    RemoteToolOutput,
    /// User-provided content that has not been independently trusted.
    UserProvided,
    /// Boundary could not be determined.
    Unknown,
}

impl ContextTrustBoundary {
    fn is_untrusted(self) -> bool {
        matches!(
            self,
            Self::RemoteToolOutput | Self::UserProvided | Self::Unknown
        )
    }
}

/// Coarse data class inferred from result content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextDataClass {
    /// Public or benign content.
    Public,
    /// Internal business content.
    Internal,
    /// Personal data such as contact identifiers.
    PersonalData,
    /// Financial identifiers or payment-like material.
    FinancialData,
    /// Health-related material.
    HealthData,
    /// Protected access material.
    GuardedMaterial,
    /// Instruction-like content that can steer an agent.
    InstructionLike,
    /// Data class could not be determined.
    Unknown,
}

/// Risk of the downstream action associated with this result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextActionRisk {
    /// Read-only or presentation-only action.
    Low,
    /// Reversible action or minor side effect.
    Medium,
    /// Privileged, mutating, or externally visible action.
    High,
    /// Irreversible, destructive, or broad-permission action.
    Critical,
}

impl ContextActionRisk {
    fn requires_confirmation(self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

/// Operating mode for the kernel policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextIntegrityPolicyMode {
    /// Evaluate and emit evidence, but deliver content as if allowed.
    MonitorOnly,
    /// Apply the resolved policy decision to delivered content.
    Enforce,
}

/// Named policy preset for common rollout modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextIntegrityPolicyPreset {
    /// Local developer mode: monitor-only with gentle would-strip defaults.
    LocalDeveloper,
    /// Shared team mode: enforce baseline protection with confirmation gates.
    TeamShared,
    /// Enterprise strict mode: enforce stronger handling for guarded material.
    EnterpriseStrict,
    /// Audit-only mode: record evidence without changing delivered content.
    AuditOnly,
}

/// Policy decision supported by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextIntegrityDecisionKind {
    /// Deliver content unchanged.
    Allow,
    /// Remove instruction-like lines and deliver the remaining text.
    Strip,
    /// Replace content with a short non-instructional summary.
    Summarize,
    /// Hold content in quarantine and deliver nothing downstream.
    Quarantine,
    /// Require a human or policy confirmation before delivery.
    Confirm,
    /// Deny delivery.
    Deny,
}

/// Classifier that produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextIntegrityClassifier {
    /// Existing prompt-injection scanner matched instruction takeover content.
    PromptInjection,
    /// Existing response inspector matched protected access material.
    GuardedMaterial,
    /// Local regex matched personal data.
    PersonalData,
    /// Local regex matched financial material.
    FinancialData,
    /// Local regex matched destructive action instructions.
    DestructiveInstruction,
    /// Local regex matched an attempted tool-permission escalation.
    ToolAccessEscalation,
    /// Existing AX-010 validator matched poisoned tool descriptor content.
    ToolPoisoning,
    /// Local regex matched exfiltration-shaped content.
    DataExfiltration,
}

/// Severity assigned to a context-integrity finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextIntegritySeverity {
    /// Informational evidence.
    Low,
    /// Suspicious but not independently blocking.
    Medium,
    /// Likely unsafe for automatic privileged promotion.
    High,
    /// Deterministic block-worthy evidence.
    Critical,
}

/// Provenance for the content evaluated by the kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextProvenance {
    /// Gateway server or backend identifier.
    pub server: String,
    /// Tool name or logical producer.
    pub tool: String,
    /// Invocation identifier supplied by the gateway or caller.
    pub invocation_id: String,
    /// Actor or grant subject associated with the invocation, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Trust boundary assigned before classification.
    pub trust_boundary: ContextTrustBoundary,
    /// Digest of the associated `TrustCard`, when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_card_digest: Option<String>,
    /// Human-readable origin label for audit correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
}

impl ContextProvenance {
    /// Construct provenance for a tool result.
    #[must_use]
    pub fn tool_result(
        server: impl Into<String>,
        tool: impl Into<String>,
        invocation_id: impl Into<String>,
        trust_boundary: ContextTrustBoundary,
    ) -> Self {
        Self {
            server: server.into(),
            tool: tool.into(),
            invocation_id: invocation_id.into(),
            subject: None,
            trust_boundary,
            trust_card_digest: None,
            origin: None,
        }
    }
}

/// Input passed into the context-integrity kernel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextIntegrityInput {
    /// Provenance for this content.
    pub provenance: ContextProvenance,
    /// Raw tool result or descriptor-derived content.
    pub content: Value,
    /// Risk of the downstream action that may consume this content.
    pub action_risk: ContextActionRisk,
    /// Whether the originating tool declares read-only behavior.
    pub read_only: bool,
    /// Whether the originating tool declares destructive behavior.
    pub destructive: bool,
}

impl ContextIntegrityInput {
    /// Construct a read-only tool-result input.
    #[must_use]
    pub fn read_only_tool_result(provenance: ContextProvenance, content: Value) -> Self {
        Self {
            provenance,
            content,
            action_risk: ContextActionRisk::Low,
            read_only: true,
            destructive: false,
        }
    }
}

/// Policy thresholds and action mapping for context integrity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextIntegrityPolicy {
    /// Monitor-only or enforcing mode.
    pub mode: ContextIntegrityPolicyMode,
    /// Decision for prompt-injection findings from untrusted boundaries.
    pub untrusted_instruction_decision: ContextIntegrityDecisionKind,
    /// Decision for protected access material.
    pub guarded_material_decision: ContextIntegrityDecisionKind,
    /// Decision for personal data in otherwise benign content.
    pub personal_data_decision: ContextIntegrityDecisionKind,
    /// Decision for destructive instructions.
    pub destructive_instruction_decision: ContextIntegrityDecisionKind,
    /// Decision for poisoned tool descriptors.
    pub tool_poisoning_decision: ContextIntegrityDecisionKind,
    /// Decision for high-risk actions with any unsafe finding.
    pub high_risk_action_decision: ContextIntegrityDecisionKind,
    /// Whether read-only content without critical findings is allowed.
    pub allow_benign_read_only: bool,
    /// When `true`, the render guard is non-bypassable: it refuses to run in a
    /// purely advisory `MonitorOnly` mode and treats its effective mode as
    /// `Enforce`. A "guard" that only observes is not a guard — this flag makes
    /// that property explicit and uncircumventable at the chokepoint.
    pub non_bypassable: bool,
}

impl ContextIntegrityPolicy {
    /// The mode actually applied. When [`non_bypassable`](Self::non_bypassable)
    /// is set, a configured `MonitorOnly` is upgraded to `Enforce` so the guard
    /// cannot be silently reduced to advisory tagging.
    #[must_use]
    pub const fn effective_mode(&self) -> ContextIntegrityPolicyMode {
        if self.non_bypassable {
            ContextIntegrityPolicyMode::Enforce
        } else {
            self.mode
        }
    }
}

impl ContextIntegrityPolicy {
    /// Default monitor-only policy for safe rollout.
    #[must_use]
    pub const fn monitor_only() -> Self {
        Self {
            mode: ContextIntegrityPolicyMode::MonitorOnly,
            untrusted_instruction_decision: ContextIntegrityDecisionKind::Quarantine,
            guarded_material_decision: ContextIntegrityDecisionKind::Strip,
            personal_data_decision: ContextIntegrityDecisionKind::Summarize,
            destructive_instruction_decision: ContextIntegrityDecisionKind::Confirm,
            tool_poisoning_decision: ContextIntegrityDecisionKind::Deny,
            high_risk_action_decision: ContextIntegrityDecisionKind::Confirm,
            allow_benign_read_only: true,
            non_bypassable: false,
        }
    }

    /// Enforcing baseline policy for tests and opt-in deployments.
    #[must_use]
    pub const fn enforcing_baseline() -> Self {
        Self {
            mode: ContextIntegrityPolicyMode::Enforce,
            ..Self::monitor_only()
        }
    }

    /// Compile a named preset into an explicit policy.
    #[must_use]
    pub const fn from_preset(preset: ContextIntegrityPolicyPreset) -> Self {
        match preset {
            ContextIntegrityPolicyPreset::LocalDeveloper => Self {
                mode: ContextIntegrityPolicyMode::MonitorOnly,
                untrusted_instruction_decision: ContextIntegrityDecisionKind::Strip,
                guarded_material_decision: ContextIntegrityDecisionKind::Summarize,
                personal_data_decision: ContextIntegrityDecisionKind::Summarize,
                destructive_instruction_decision: ContextIntegrityDecisionKind::Confirm,
                tool_poisoning_decision: ContextIntegrityDecisionKind::Deny,
                high_risk_action_decision: ContextIntegrityDecisionKind::Confirm,
                allow_benign_read_only: true,
                non_bypassable: false,
            },
            ContextIntegrityPolicyPreset::TeamShared => Self::enforcing_baseline(),
            ContextIntegrityPolicyPreset::EnterpriseStrict => Self {
                mode: ContextIntegrityPolicyMode::Enforce,
                untrusted_instruction_decision: ContextIntegrityDecisionKind::Quarantine,
                guarded_material_decision: ContextIntegrityDecisionKind::Deny,
                personal_data_decision: ContextIntegrityDecisionKind::Confirm,
                destructive_instruction_decision: ContextIntegrityDecisionKind::Confirm,
                tool_poisoning_decision: ContextIntegrityDecisionKind::Deny,
                high_risk_action_decision: ContextIntegrityDecisionKind::Confirm,
                allow_benign_read_only: true,
                non_bypassable: false,
            },
            ContextIntegrityPolicyPreset::AuditOnly => Self::monitor_only(),
        }
    }
}

impl Default for ContextIntegrityPolicy {
    fn default() -> Self {
        Self::monitor_only()
    }
}

/// A single classifier finding with audit-safe evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextIntegrityFinding {
    /// Classifier that produced the finding.
    pub classifier: ContextIntegrityClassifier,
    /// Finding severity.
    pub severity: ContextIntegritySeverity,
    /// Data class associated with the finding.
    pub data_class: ContextDataClass,
    /// Human-readable description.
    pub description: String,
    /// Audit-safe evidence, never intended to hold the full raw result.
    pub evidence: String,
}

/// Aggregated classification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextIntegrityClassification {
    /// Data classes inferred for the content.
    pub data_classes: Vec<ContextDataClass>,
    /// Classifier findings.
    pub findings: Vec<ContextIntegrityFinding>,
    /// Highest severity in `findings`, or `None` when clean.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_severity: Option<ContextIntegritySeverity>,
}

/// Policy verdict emitted for the evaluated content.
#[allow(clippy::struct_excessive_bools)] // Serialized policy flags are independent audit facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextIntegrityPolicyVerdict {
    /// Policy mode used for evaluation.
    pub mode: ContextIntegrityPolicyMode,
    /// Effective decision after monitor-only override, if any.
    pub decision: ContextIntegrityDecisionKind,
    /// Decision that would apply in enforcing mode.
    pub would_decision: ContextIntegrityDecisionKind,
    /// Whether enforcement changed delivered content.
    pub enforcement_applied: bool,
    /// Whether explicit confirmation is required before delivery or action.
    pub confirmation_required: bool,
    /// Whether content was quarantined.
    pub quarantined: bool,
    /// Whether the content may elevate grants or tool access.
    pub privilege_elevation_allowed: bool,
    /// Short rationale for the decision.
    pub rationale: String,
}

/// Transformed content produced by a policy decision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextIntegrityTransformedContent {
    /// Content delivered downstream after policy application, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delivered: Option<Value>,
    /// Whether instruction-like text was stripped.
    pub stripped: bool,
    /// Whether the delivered content is a summary.
    pub summarized: bool,
    /// Whether the original content is withheld.
    pub withheld: bool,
}

/// Audit event for downstream logs or evidence export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextIntegrityAuditEvent {
    /// Schema version for audit event consumers.
    pub schema_version: String,
    /// Invocation identifier.
    pub invocation_id: String,
    /// Server identifier.
    pub server: String,
    /// Tool identifier.
    pub tool: String,
    /// Trust boundary assigned to content.
    pub trust_boundary: ContextTrustBoundary,
    /// SHA-256 digest of canonical JSON input content.
    pub content_sha256: String,
    /// Effective decision.
    pub decision: ContextIntegrityDecisionKind,
    /// Enforcing-mode decision.
    pub would_decision: ContextIntegrityDecisionKind,
    /// Number of findings.
    pub findings_count: usize,
    /// Whether monitor-only mode overrode enforcement.
    pub monitor_only: bool,
}

/// Full kernel evaluation output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextIntegrityEvaluation {
    /// Evaluation schema version.
    pub schema_version: String,
    /// Content digest for correlation without replaying raw content.
    pub content_sha256: String,
    /// Provenance evaluated by the kernel.
    pub provenance: ContextProvenance,
    /// Classification evidence.
    pub classification: ContextIntegrityClassification,
    /// Policy verdict.
    pub policy: ContextIntegrityPolicyVerdict,
    /// Transformed content after policy application.
    pub transformed: ContextIntegrityTransformedContent,
    /// Audit event for evidence export.
    pub audit: ContextIntegrityAuditEvent,
}

impl ContextIntegrityEvaluation {
    /// Build a human-readable explanation for this policy decision.
    #[must_use]
    pub fn explain(&self) -> ContextIntegrityDecisionExplanation {
        let reason = if self.classification.findings.is_empty() {
            "No context-integrity findings were detected.".to_string()
        } else {
            format!(
                "{} finding(s) drove a {:?} policy decision.",
                self.classification.findings.len(),
                self.policy.would_decision
            )
        };
        let source_evidence = self
            .classification
            .findings
            .iter()
            .map(|finding| {
                format!(
                    "{:?}: {} ({})",
                    finding.classifier, finding.description, finding.evidence
                )
            })
            .collect();
        let action_taken = match self.policy.decision {
            ContextIntegrityDecisionKind::Allow => {
                if self.audit.monitor_only && self.policy.would_decision != self.policy.decision {
                    format!(
                        "Monitor-only mode delivered content but recorded would-apply {:?}.",
                        self.policy.would_decision
                    )
                } else {
                    "Delivered content unchanged.".to_string()
                }
            }
            ContextIntegrityDecisionKind::Strip => {
                "Removed instruction-like lines before delivery.".to_string()
            }
            ContextIntegrityDecisionKind::Summarize => {
                "Withheld raw content and delivered a short summary.".to_string()
            }
            ContextIntegrityDecisionKind::Quarantine => {
                "Withheld content for quarantine review.".to_string()
            }
            ContextIntegrityDecisionKind::Confirm => {
                "Withheld content until explicit confirmation.".to_string()
            }
            ContextIntegrityDecisionKind::Deny => "Denied content delivery.".to_string(),
        };
        let safe_next_step = if self.policy.confirmation_required {
            "Ask a human to review the evidence before using this content.".to_string()
        } else if self.audit.monitor_only && self.policy.would_decision != self.policy.decision {
            "Review monitor-only evidence before enabling enforcement.".to_string()
        } else if self.classification.findings.is_empty() {
            "No action needed.".to_string()
        } else {
            "Review the evidence and adjust local policy only with an audit trail.".to_string()
        };
        let confirmation_reason = if self.policy.confirmation_required {
            Some(
                "Confirmation is reserved for exceptions, ambiguous high-risk content, destructive follow-up, or private data exposure."
                    .to_string(),
            )
        } else {
            None
        };

        ContextIntegrityDecisionExplanation {
            reason,
            source_evidence,
            action_taken,
            safe_next_step,
            confirmation_reason,
        }
    }
}

/// Plain-language explanation for a context-integrity decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextIntegrityDecisionExplanation {
    /// Summary reason for the decision.
    pub reason: String,
    /// Audit-safe source evidence snippets.
    pub source_evidence: Vec<String>,
    /// Action taken by the policy.
    pub action_taken: String,
    /// Safe next step for the operator or agent.
    pub safe_next_step: String,
    /// Why confirmation was required, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_reason: Option<String>,
}

/// Feedback scope for context-integrity tuning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextIntegrityFeedbackScope {
    /// Tune only the local policy or local fixture set.
    LocalOnly,
    /// Route through enterprise review before any policy weakening.
    EnterprisePolicy,
}

/// Feedback kind for a classifier finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextIntegrityFeedbackKind {
    /// Finding was too strict for the local workflow.
    FalsePositive,
    /// Finding was useful and should remain active.
    TruePositive,
}

/// Feedback disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextIntegrityFeedbackDisposition {
    /// Local policy may be tuned with audit evidence.
    TuneLocalPolicy,
    /// Enterprise policy change needs explicit review.
    RequireEnterpriseReview,
    /// No policy weakening is recommended.
    NoPolicyChange,
}

/// Feedback request for context-integrity findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextIntegrityFeedback {
    /// Classifier receiving feedback.
    pub classifier: ContextIntegrityClassifier,
    /// Feedback kind.
    pub kind: ContextIntegrityFeedbackKind,
    /// Feedback scope.
    pub scope: ContextIntegrityFeedbackScope,
    /// Operator-facing reason.
    pub reason: String,
}

impl ContextIntegrityFeedback {
    /// Return the safe disposition for this feedback.
    #[must_use]
    pub fn disposition(&self) -> ContextIntegrityFeedbackDisposition {
        match (self.kind, self.scope) {
            (
                ContextIntegrityFeedbackKind::FalsePositive,
                ContextIntegrityFeedbackScope::LocalOnly,
            ) => ContextIntegrityFeedbackDisposition::TuneLocalPolicy,
            (
                ContextIntegrityFeedbackKind::FalsePositive,
                ContextIntegrityFeedbackScope::EnterprisePolicy,
            ) => ContextIntegrityFeedbackDisposition::RequireEnterpriseReview,
            (ContextIntegrityFeedbackKind::TruePositive, _) => {
                ContextIntegrityFeedbackDisposition::NoPolicyChange
            }
        }
    }
}
