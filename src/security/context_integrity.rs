// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Context Integrity Kernel for prompt, tool, and data-boundary protection (MIK-6559).
//!
//! Classifies tool results, applies policy decisions, and emits audit evidence
//! before responses reach the client/agent. Benign read-only workflows are
//! pass-through by default in monitor mode; suspicious or high-risk content
//! can be stripped, summarized, quarantined, confirmed, or denied with
//! machine-readable evidence.
//!
//! # Architecture
//!
//! 1. **Classifiers** scan tool result text for threat categories (prompt
//!    injection, secrets, PII, destructive instructions, exfiltration/C2,
//!    tool-poisoning markers).
//! 2. **Policy engine** evaluates classifier findings against trust boundary,
//!    tool annotations, and severity to produce a [`PolicyDecision`] with
//!    one of six actions: allow, strip, summarize, quarantine, confirm, deny.
//! 3. **Kernel** assembles [`ContextIntegrityMetadata`] and serializes it under
//!    `_context_integrity` — never replacing normal MCP `content`/`structuredContent`.

use std::sync::LazyLock;

use regex::RegexSet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;

use crate::security::response_inspect::Severity;
use crate::security::response_scanner::ResponseScanner;

// ---------------------------------------------------------------------------
// Core types (AC.1)
// ---------------------------------------------------------------------------

/// Provenance descriptor attached to each tool result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentProvenance {
    /// Result originates from a verified remote backend with signed provenance.
    VerifiedRemote,
    /// Result from a configured but unsigned remote backend.
    UnverifiedRemote,
    /// Result from a local stdio backend.
    Local,
    /// Provenance could not be determined.
    Unknown,
}

/// Trust boundary classification for the tool result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustBoundary {
    /// Internal / fully-trusted backend.
    Internal,
    /// External backend with verified provenance.
    ExternalVerified,
    /// External backend without verified provenance.
    ExternalUnverified,
    /// Trust boundary could not be determined.
    Unknown,
}

/// Data classification for the tool result content.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    /// Public or non-sensitive data.
    Public,
    /// Internal / operational data.
    Internal,
    /// Confidential or sensitive data detected.
    Confidential,
    /// Classification not determined.
    Unknown,
}

/// Finding category detected by classifiers (AC.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// Indirect prompt injection attempt.
    PromptInjection,
    /// Secret or API token leak.
    Secret,
    /// Personally identifiable information.
    Pii,
    /// Destructive or action-oriented instructions.
    DestructiveAction,
    /// Exfiltration or C2 URL.
    ExfiltrationC2,
    /// MCP tool-poisoning or rug-pull marker.
    ToolPoisoning,
}

/// Severity level for a classifier finding.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ClassifierSeverity {
    /// Informational — never blocks.
    Low,
    /// Suspicious pattern.
    Medium,
    /// Likely malicious.
    High,
    /// Confirmed threat.
    Critical,
}

/// A single classifier finding with redacted evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifierFinding {
    /// Category of the finding.
    pub category: FindingCategory,
    /// Severity level.
    pub severity: ClassifierSeverity,
    /// Name of the detector that matched.
    pub matched_detector: String,
    /// Redacted snippet (never contains raw secrets).
    pub evidence: String,
}

/// Policy decision action (AC.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyDecision {
    /// Allow the response as-is.
    Allow,
    /// Strip the dangerous content from the response.
    Strip,
    /// Summarize the response without dangerous details.
    Summarize,
    /// Quarantine the response for human review.
    Quarantine,
    /// Require explicit confirmation before proceeding.
    Confirm,
    /// Deny the response entirely.
    Deny,
}

/// Operational mode for the context integrity kernel (AC.5).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IntegrityMode {
    /// Monitor-only: emit audit evidence but never block.
    Monitor,
    /// Enforce: apply policy decisions (block/transform).
    Enforce,
}

/// Policy decision with action and mode (AC.1, AC.3, AC.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecisionResult {
    /// The policy decision action.
    pub action: PolicyDecision,
    /// The operational mode at decision time.
    pub mode: IntegrityMode,
    /// Human-readable reason for the decision.
    pub reason: String,
}

/// Complete context-integrity metadata attached to every tool result (AC.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextIntegrityMetadata {
    /// Provenance of the tool result content.
    pub provenance: ContentProvenance,
    /// Trust boundary classification.
    pub trust_boundary: TrustBoundary,
    /// Data classification.
    pub data_class: DataClass,
    /// Classifier findings.
    pub findings: Vec<ClassifierFinding>,
    /// Policy decision.
    pub policy: PolicyDecisionResult,
    /// Stable evidence ID (UUID v4).
    pub evidence_id: String,
}

// ---------------------------------------------------------------------------
// Classifier regex patterns (AC.2)
// ---------------------------------------------------------------------------

// PII patterns
static PII_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        r"(?i)\b(?:SSN|social\s+security)\s*(?:#|number|no\.?)?\s*:?\s*\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
        r"(?i)\b(?:credit\s+card|card\s+number|cc\s*#?)\s*:?\s*\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        r"(?i)\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
    ])
    .expect("PII patterns must compile")
});

// Destructive action patterns
static DESTRUCTIVE_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)\b(?:rm\s+-rf|rm\s+-fr|rm\s+-r)\s+/",
        r"(?i)\b(?:DROP|TRUNCATE|DELETE\s+FROM)\s+\w+",
        r"(?i)\b(?:format\s+[a-z]:|diskpart|fdisk)\b",
        r"(?i)\b(?:shutdown|reboot|init\s+0|poweroff)\b",
        r"(?i)\bchmod\s+777\b",
        r"(?i)\b(?:sudo\s+)?rm\s+-(?:rf?)\s+\S+",
    ])
    .expect("Destructive patterns must compile")
});

// Tool-poisoning / rug-pull markers
static TOOL_POISONING_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>",
        r"(?i)<\|?(?:system|assistant|user|im_start|im_end)\|?>",
        r"(?i)IMPORTANT:\s*(?:ignore|override|disregard)",
        r"(?i)new\s+system\s+prompt\s*:",
        r"(?i)system\s*:\s*you\s+are",
        r"(?i)you\s+are\s+now\s+(?:a\s+)?(?:DAN|jailbroken|unrestricted)",
        r"(?i)\[TOOL_UPDATE\]|\[SCHEMA_CHANGE\]|\[OVERRIDE\]",
    ])
    .expect("Tool-poisoning patterns must compile")
});

// Privileged instruction override patterns (AC.4)
static PRIVILEGED_OVERRIDE_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)ignore\s+(all\s+)?previous\s+instructions",
        r"(?i)disregard\s+(all\s+)?previous\s+(instructions?|context|rules)",
        r"(?i)forget\s+(all\s+)?(your|previous)\s+(instructions?|rules|context)",
        r"(?i)override\s+(all\s+)?previous\s+(instructions?|constraints)",
        r"(?i)you\s+are\s+now\s+(?:a\s+)?(?:DAN|jailbroken|unrestricted)",
        r"(?i)new\s+(?:system\s+)?(?:prompt|instruction|directive)",
        r"(?i)system\s*:\s*you\s+are",
        r"(?i)<\|?(?:system|assistant)\|?>",
        r"(?i)\[INST\].*\[/INST\]",
    ])
    .expect("Privileged override patterns must compile")
});

// Self-granted tool access patterns (AC.4)
static SELF_GRANT_PATTERNS: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        r"(?i)(?:call|invoke|execute|run)\s+(?:the\s+)?(?:tool|function)\s+[\w_]+",
        r"(?i)(?:grant|allow|enable|approve)\s+(?:access|permission)\s+(?:to|for)\s+[\w_]+",
        r"(?i)you\s+(?:now\s+)?have\s+(?:full\s+)?access\s+to\s+(?:all\s+)?tools?",
        r"(?i)approved\s+(?:for|by)\s+(?:system|admin|root)",
        r"(?i)(?:use|call)\s+(?:the\s+)?(?:tool|function)\s+\w+\s+(?:to|with)",
    ])
    .expect("Self-grant patterns must compile")
});

// ---------------------------------------------------------------------------
// ContextIntegrityKernel
// ---------------------------------------------------------------------------

/// The Context Integrity Kernel classifies tool results and applies policy.
///
/// Thread-safe and reusable across invocations.
pub struct ContextIntegrityKernel {
    /// Prompt injection scanner (reuses existing ResponseScanner).
    scanner: ResponseScanner,
    /// Operational mode.
    mode: IntegrityMode,
    /// Whether the kernel is enabled.
    enabled: bool,
    /// Severity threshold for enforce-mode deny.
    deny_threshold: ClassifierSeverity,
    /// Severity threshold for enforce-mode quarantine.
    quarantine_threshold: ClassifierSeverity,
}

impl ContextIntegrityKernel {
    /// Create a new kernel from configuration.
    #[must_use]
    pub fn new(mode: IntegrityMode, enabled: bool) -> Self {
        Self {
            scanner: ResponseScanner::new(),
            mode,
            enabled,
            deny_threshold: ClassifierSeverity::Critical,
            quarantine_threshold: ClassifierSeverity::High,
        }
    }

    /// Create a kernel with custom severity thresholds.
    #[must_use]
    pub fn with_thresholds(
        mode: IntegrityMode,
        enabled: bool,
        deny_threshold: ClassifierSeverity,
        quarantine_threshold: ClassifierSeverity,
    ) -> Self {
        Self {
            scanner: ResponseScanner::new(),
            mode,
            enabled,
            deny_threshold,
            quarantine_threshold,
        }
    }

    /// Whether the kernel is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The current operational mode.
    #[must_use]
    pub fn mode(&self) -> IntegrityMode {
        self.mode
    }

    /// Classify a tool result and return findings (AC.2).
    ///
    /// Scans for: prompt injection, secrets, PII, destructive actions,
    /// exfiltration/C2, and tool-poisoning markers.
    #[must_use]
    pub fn classify(&self, text: &str) -> Vec<ClassifierFinding> {
        if text.is_empty() {
            return Vec::new();
        }

        let mut findings = Vec::new();

        // 1. Prompt injection (reuse existing scanner)
        let injection_matches = self.scanner.scan_text(text);
        for m in &injection_matches {
            findings.push(ClassifierFinding {
                category: FindingCategory::PromptInjection,
                severity: ClassifierSeverity::Critical,
                matched_detector: m.pattern_description.clone(),
                evidence: redact_snippet(&m.matched_fragment),
            });
        }

        // 2. Secrets (reuse existing response_inspect patterns indirectly)
        let secret_findings = classify_secrets(text);
        findings.extend(secret_findings);

        // 3. PII
        for idx in PII_PATTERNS.matches(text) {
            findings.push(ClassifierFinding {
                category: FindingCategory::Pii,
                severity: ClassifierSeverity::Medium,
                matched_detector: format!("pii_pattern_{idx}"),
                evidence: redact_snippet(text),
            });
        }

        // 4. Destructive actions
        for idx in DESTRUCTIVE_PATTERNS.matches(text) {
            findings.push(ClassifierFinding {
                category: FindingCategory::DestructiveAction,
                severity: ClassifierSeverity::High,
                matched_detector: format!("destructive_pattern_{idx}"),
                evidence: redact_snippet(text),
            });
        }

        // 5. Exfiltration/C2 (covered by prompt injection scanner patterns)
        for m in &injection_matches {
            if m.pattern_description.contains("exfiltration")
                || m.pattern_description.contains("Exfiltration")
                || m.pattern_description.contains("outbound HTTP")
            {
                findings.push(ClassifierFinding {
                    category: FindingCategory::ExfiltrationC2,
                    severity: ClassifierSeverity::High,
                    matched_detector: m.pattern_description.clone(),
                    evidence: redact_snippet(&m.matched_fragment),
                });
            }
        }

        // 6. Tool-poisoning / rug-pull markers
        for idx in TOOL_POISONING_PATTERNS.matches(text) {
            findings.push(ClassifierFinding {
                category: FindingCategory::ToolPoisoning,
                severity: ClassifierSeverity::High,
                matched_detector: format!("tool_poisoning_pattern_{idx}"),
                evidence: redact_snippet(text),
            });
        }

        findings
    }

    /// Evaluate the policy decision based on findings, trust boundary, and tool annotations (AC.3, AC.5).
    #[must_use]
    pub fn evaluate(
        &self,
        findings: &[ClassifierFinding],
        trust_boundary: &TrustBoundary,
        is_read_only: bool,
    ) -> PolicyDecisionResult {
        if !self.enabled {
            return PolicyDecisionResult {
                action: PolicyDecision::Allow,
                mode: self.mode,
                reason: "context_integrity_disabled".to_string(),
            };
        }

        // No findings → allow
        if findings.is_empty() {
            return PolicyDecisionResult {
                action: PolicyDecision::Allow,
                mode: self.mode,
                reason: if is_read_only {
                    "benign_read_only_no_findings".to_string()
                } else {
                    "no_findings".to_string()
                },
            };
        }

        let max_severity = findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(ClassifierSeverity::Low);

        // In monitor mode, never block — just audit
        if self.mode == IntegrityMode::Monitor {
            let action = if is_read_only && max_severity <= ClassifierSeverity::Low {
                PolicyDecision::Allow
            } else {
                PolicyDecision::Allow // monitor mode: always allow but audit
            };
            return PolicyDecisionResult {
                action,
                mode: self.mode,
                reason: format!(
                    "monitor_mode_max_severity_{:?}_findings_{}",
                    max_severity,
                    findings.len()
                ),
            };
        }

        // Enforce mode — apply thresholds
        if max_severity >= self.deny_threshold {
            return PolicyDecisionResult {
                action: PolicyDecision::Deny,
                mode: self.mode,
                reason: format!("critical_severity_deny_threshold_met_findings_{}", findings.len()),
            };
        }

        if max_severity >= self.quarantine_threshold {
            // Untrusted external + high severity → quarantine
            if matches!(
                trust_boundary,
                TrustBoundary::ExternalUnverified | TrustBoundary::Unknown
            ) {
                return PolicyDecisionResult {
                    action: PolicyDecision::Quarantine,
                    mode: self.mode,
                    reason: format!(
                        "high_severity_untrusted_boundary_{:?}_findings_{}",
                        trust_boundary,
                        findings.len()
                    ),
                };
            }
            // Trusted boundary + high severity → strip
            return PolicyDecisionResult {
                action: PolicyDecision::Strip,
                mode: self.mode,
                reason: format!("high_severity_trusted_boundary_findings_{}", findings.len()),
            };
        }

        // Medium severity → confirm
        if max_severity >= ClassifierSeverity::Medium {
            return PolicyDecisionResult {
                action: PolicyDecision::Confirm,
                mode: self.mode,
                reason: format!("medium_severity_confirm_findings_{}", findings.len()),
            };
        }

        // Low severity → allow with audit
        PolicyDecisionResult {
            action: PolicyDecision::Allow,
            mode: self.mode,
            reason: format!("low_severity_allow_findings_{}", findings.len()),
        }
    }

    /// Process a complete tool result: classify, evaluate, and return metadata (AC.1).
    ///
    /// Returns `None` when the kernel is disabled.
    #[must_use]
    pub fn process(
        &self,
        text: &str,
        provenance: ContentProvenance,
        trust_boundary: TrustBoundary,
        is_read_only: bool,
    ) -> Option<ContextIntegrityMetadata> {
        if !self.enabled {
            return None;
        }

        let findings = self.classify(text);
        let data_class = infer_data_class(&findings);
        let policy = self.evaluate(&findings, &trust_boundary, is_read_only);

        let evidence_id = uuid::Uuid::new_v4().to_string();

        let metadata = ContextIntegrityMetadata {
            provenance,
            trust_boundary,
            data_class,
            findings,
            policy,
            evidence_id,
        };

        info!(
            evidence_id = %metadata.evidence_id,
            action = ?metadata.policy.action,
            mode = ?metadata.policy.mode,
            finding_count = metadata.findings.len(),
            "context_integrity_decision"
        );

        Some(metadata)
    }

    /// Apply the policy decision to a result value.
    ///
    /// In monitor mode, the original payload is preserved and `_context_integrity`
    /// metadata is attached. In enforce mode, the payload may be transformed
    /// (stripped, quarantined, denied) based on the decision.
    ///
    /// Returns the (possibly transformed) result value.
    pub fn apply(
        &self,
        result: &mut Value,
        metadata: &ContextIntegrityMetadata,
    ) -> Result<(), String> {
        // Always attach metadata under _context_integrity (never replaces content)
        if let Some(obj) = result.as_object_mut() {
            obj.insert(
                "_context_integrity".to_string(),
                serde_json::to_value(metadata).unwrap_or_default(),
            );
        }

        // In monitor mode, never transform
        if self.mode == IntegrityMode::Monitor {
            return Ok(());
        }

        // Enforce mode: apply decision
        match metadata.policy.action {
            PolicyDecision::Allow | PolicyDecision::Confirm => Ok(()),
            PolicyDecision::Strip => {
                if let Some(obj) = result.as_object_mut() {
                    // Redact dangerous content from text fields
                    if let Some(content) = obj.get_mut("content").and_then(|c| c.as_array_mut()) {
                        for item in content.iter_mut() {
                            if let Some(t) = item.get_mut("text").and_then(|t| t.as_str()) {
                                let stripped = strip_dangerous_content(t);
                                *item.get_mut("text").unwrap() = Value::String(stripped);
                            }
                        }
                    }
                }
                Ok(())
            }
            PolicyDecision::Summarize => {
                if let Some(obj) = result.as_object_mut() {
                    if let Some(content) = obj.get_mut("content").and_then(|c| c.as_array_mut()) {
                        for item in content.iter_mut() {
                            if let Some(t) = item.get_mut("text").and_then(|t| t.as_str()) {
                                let summarized = summarize_dangerous_content(t);
                                *item.get_mut("text").unwrap() = Value::String(summarized);
                            }
                        }
                    }
                }
                Ok(())
            }
            PolicyDecision::Quarantine => {
                if let Some(obj) = result.as_object_mut() {
                    obj.insert(
                        "_quarantined".to_string(),
                        Value::Bool(true),
                    );
                }
                Ok(())
            }
            PolicyDecision::Deny => Err(format!(
                "context_integrity_denied: {}",
                metadata.policy.reason
            )),
        }
    }

    /// Check if text contains privileged instruction override attempts (AC.4).
    #[must_use]
    pub fn detect_privileged_override(&self, text: &str) -> Vec<ClassifierFinding> {
        let mut findings = Vec::new();

        for idx in PRIVILEGED_OVERRIDE_PATTERNS.matches(text) {
            findings.push(ClassifierFinding {
                category: FindingCategory::PromptInjection,
                severity: ClassifierSeverity::Critical,
                matched_detector: format!("privileged_override_pattern_{idx}"),
                evidence: redact_snippet(text),
            });
        }

        findings
    }

    /// Check if text contains self-granted tool access attempts (AC.4).
    #[must_use]
    pub fn detect_self_granted_access(&self, text: &str) -> Vec<ClassifierFinding> {
        let mut findings = Vec::new();

        for idx in SELF_GRANT_PATTERNS.matches(text) {
            findings.push(ClassifierFinding {
                category: FindingCategory::PromptInjection,
                severity: ClassifierSeverity::Critical,
                matched_detector: format!("self_grant_pattern_{idx}"),
                evidence: redact_snippet(text),
            });
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Redact a text snippet for evidence — never expose raw secrets.
fn redact_snippet(text: &str) -> String {
    let truncated = if text.len() > 80 { &text[..80] } else { text };
    // Mask potential secrets (long alphanumeric runs)
    let mut result = String::with_capacity(truncated.len());
    let mut run_len = 0u32;
    for ch in truncated.chars() {
        if ch.is_alphanumeric() || ch == '-' || ch == '_' {
            run_len += 1;
            if run_len > 8 {
                result.push('*');
            } else {
                result.push(ch);
            }
        } else {
            run_len = 0;
            result.push(ch);
        }
    }
    result
}

/// Strip dangerous content from text by removing lines matching attack patterns.
fn strip_dangerous_content(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    for line in text.lines() {
        let is_dangerous = PRIVILEGED_OVERRIDE_PATTERNS.is_match(line)
            || DESTRUCTIVE_PATTERNS.is_match(line)
            || SELF_GRANT_PATTERNS.is_match(line);
        if !is_dangerous {
            output.push_str(line);
            output.push('\n');
        }
    }
    output.trim_end().to_string()
}

/// Summarize dangerous content by replacing it with a placeholder.
fn summarize_dangerous_content(text: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut had_replacement = false;
    for line in text.lines() {
        let is_dangerous = PRIVILEGED_OVERRIDE_PATTERNS.is_match(line)
            || DESTRUCTIVE_PATTERNS.is_match(line)
            || SELF_GRANT_PATTERNS.is_match(line);
        if is_dangerous {
            if !had_replacement {
                output.push_str("[Content redacted by context integrity policy]\n");
                had_replacement = true;
            }
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    output.trim_end().to_string()
}

/// Classify secrets in text using regex patterns.
fn classify_secrets(text: &str) -> Vec<ClassifierFinding> {
    use crate::security::response_inspect;
    let inspection = response_inspect::inspect_response(text, false);
    inspection
        .findings
        .iter()
        .filter(|f| f.category == "secret")
        .map(|f| ClassifierFinding {
            category: FindingCategory::Secret,
            severity: match f.severity {
                Severity::Critical => ClassifierSeverity::Critical,
                Severity::High => ClassifierSeverity::High,
                Severity::Medium => ClassifierSeverity::Medium,
                Severity::Low => ClassifierSeverity::Low,
            },
            matched_detector: f.description.to_string(),
            evidence: "[REDACTED_SECRET]".to_string(),
        })
        .collect()
}

/// Infer data class from classifier findings.
fn infer_data_class(findings: &[ClassifierFinding]) -> DataClass {
    let has_secret = findings
        .iter()
        .any(|f| f.category == FindingCategory::Secret);
    let has_pii = findings.iter().any(|f| f.category == FindingCategory::Pii);

    if has_secret || has_pii {
        DataClass::Confidential
    } else if findings.is_empty() {
        DataClass::Public
    } else {
        DataClass::Internal
    }
}

/// Extract text content from a JSON tool result for classification.
#[must_use]
pub fn extract_text_from_result(value: &Value) -> String {
    crate::security::response_inspect::extract_text_from_result(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_classifies_clean_text() {
        let kernel = ContextIntegrityKernel::new(IntegrityMode::Monitor, true);
        let findings = kernel.classify("The weather in Helsinki is 5 degrees celsius.");
        assert!(findings.is_empty());
    }

    #[test]
    fn kernel_disabled_returns_none() {
        let kernel = ContextIntegrityKernel::new(IntegrityMode::Monitor, false);
        let result = kernel.process("test", ContentProvenance::Local, TrustBoundary::Internal, true);
        assert!(result.is_none());
    }

    #[test]
    fn redact_snippet_masks_long_runs() {
        let snippet = redact_snippet("sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345");
        assert!(snippet.contains("****"), "Long alphanumeric runs must be masked");
    }

    #[test]
    fn infer_data_class_confidential_for_secrets() {
        let findings = vec![ClassifierFinding {
            category: FindingCategory::Secret,
            severity: ClassifierSeverity::Critical,
            matched_detector: "test".to_string(),
            evidence: "[REDACTED]".to_string(),
        }];
        assert_eq!(infer_data_class(&findings), DataClass::Confidential);
    }
}
