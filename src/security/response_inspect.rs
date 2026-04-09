//! Response content inspection for MCP backend responses.
//!
//! Scans backend tool call results for secrets, prompt injection, and
//! exfiltration patterns before returning them to the client.
//!
//! Two modes: **Observe** (log only) and **Action** (block HIGH/CRITICAL).
//!
//! All patterns pre-compiled via [`regex::RegexSet`] for single-pass <1ms.

use std::sync::LazyLock;
use regex::RegexSet;
use serde::Serialize;

/// Severity level for an inspection finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// A single inspection finding.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub category: &'static str,
    pub severity: Severity,
    pub description: &'static str,
    pub matched_pattern_index: usize,
}

/// Result of inspecting a response.
#[derive(Debug, Clone, Serialize)]
pub struct InspectionResult {
    pub findings: Vec<Finding>,
    pub should_block: bool,
}

impl InspectionResult {
    #[must_use]
    pub fn clean() -> Self {
        Self { findings: Vec::new(), should_block: false }
    }

    #[must_use]
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }
}

// (regex, category, severity, description)
const PATTERNS: &[(&str, &str, Severity, &str)] = &[
    // Secrets
    (r"(?i)(sk-ant-|sk-proj-)[a-zA-Z0-9\-]{20,}", "secret", Severity::Critical, "Anthropic API key"),
    (r"AKIA[0-9A-Z]{16}", "secret", Severity::Critical, "AWS access key ID"),
    (r"(?i)ghp_[a-zA-Z0-9]{36}", "secret", Severity::Critical, "GitHub PAT"),
    (r"(?i)xox[bpors]-[a-zA-Z0-9\-]{10,}", "secret", Severity::High, "Slack token"),
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "secret", Severity::Critical, "Private key"),
    (r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]{20,}", "secret", Severity::High, "Bearer token"),
    // Injection
    (r"(?i)ignore\s+(all\s+)?previous\s+instructions", "injection", Severity::Critical, "Ignore previous instructions"),
    (r"(?i)you\s+are\s+now\s+(?:a|an)\s+", "injection", Severity::High, "Role override attempt"),
    (r"(?i)IMPORTANT:\s*disregard", "injection", Severity::High, "Disregard directive"),
    // Exfil / C2
    (r"(?i)https?://[a-z0-9\-]+\.(ngrok|serveo|localtunnel|lhr\.life)\.\w+", "exfil_url", Severity::High, "Tunnel service URL"),
    (r"169\.254\.169\.254|metadata\.google\.internal", "c2", Severity::Critical, "Cloud metadata SSRF"),
    // Encoding
    (r"(?i)base64\s*[=:]\s*[A-Za-z0-9+/]{100,}", "encoding", Severity::Medium, "Large base64 blob"),
];

static PATTERN_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    let patterns: Vec<&str> = PATTERNS.iter().map(|(p, _, _, _)| *p).collect();
    RegexSet::new(patterns).expect("All response inspection patterns must compile")
});

/// Inspect response text for security patterns.
///
/// `action_mode`: `true` = block on HIGH/CRITICAL; `false` = observe only.
#[must_use]
pub fn inspect_response(text: &str, action_mode: bool) -> InspectionResult {
    if text.is_empty() {
        return InspectionResult::clean();
    }

    let matches = PATTERN_SET.matches(text);
    if !matches.matched_any() {
        return InspectionResult::clean();
    }

    let mut findings = Vec::new();
    let mut should_block = false;

    for idx in matches.iter() {
        let (_, category, severity, description) = PATTERNS[idx];
        if action_mode && matches!(severity, Severity::High | Severity::Critical) {
            should_block = true;
        }
        findings.push(Finding {
            category, severity, description,
            matched_pattern_index: idx,
        });
    }

    InspectionResult { findings, should_block }
}

/// Extract text content from an MCP tool result JSON value.
pub fn extract_text_from_result(value: &serde_json::Value) -> String {
    let mut text = String::new();

    if let Some(content) = value.get("content").and_then(|c| c.as_array()) {
        for item in content {
            if let Some(t) = item.get("text").and_then(|t| t.as_str()) {
                text.push_str(t);
                text.push('\n');
            }
        }
    }

    if text.is_empty() {
        if let Some(t) = value.get("text").and_then(|t| t.as_str()) {
            text.push_str(t);
        }
    }

    if text.is_empty() {
        if let Some(r) = value.get("result") {
            text = r.to_string();
        }
    }

    text
}
