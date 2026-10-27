// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Firewall verdict predicates and the rule helpers that pick an action.

use super::{CompiledRule, Finding, FirewallAction, FirewallRule, FirewallVerdict, ScanType};
use crate::error::rpc_codes::INVALID_REQUEST;
use crate::security::Severity;

impl FirewallVerdict {
    /// Construct an unconditional allow verdict (used when scanning is disabled).
    pub(super) fn allow() -> Self {
        Self {
            allowed: true,
            action: FirewallAction::Allow,
            findings: Vec::new(),
            anomaly_score: None,
        }
    }

    /// Returns `true` when the block was triggered solely by anomaly detection
    /// (OWASP ASI10 — Rogue Agents), i.e. every blocking finding is a
    /// `SequenceAnomaly` at `Severity::High` or `Severity::Critical`.
    ///
    /// Callers should use JSON-RPC error code `-32002` for anomaly blocks to
    /// distinguish them from generic security blocks (`-32600`).
    pub fn is_anomaly_block(&self) -> bool {
        self.blocked_only_by(|_| false)
    }

    /// [`Self::is_anomaly_block`] widened to relay findings (OWASP ASI10,
    /// COLLUDE.1): every finding is a high or critical `SequenceAnomaly` or a
    /// `CollusionRelay`. Crate-internal so the public meaning stays put.
    pub(crate) fn is_asi10_block(&self) -> bool {
        self.blocked_only_by(|f| f.scan_type == ScanType::CollusionRelay)
    }

    /// The code and message a blocked request answers on every route: an
    /// ASI10 block (OWASP rogue agents) `-32002` "Anomaly detection blocked:
    /// …", any other block `-32600` "Firewall blocked: …". `None` when the
    /// verdict allows. One definition, so `/mcp`, `/mcp/{name}`, stdio and the
    /// dispatch chokepoint cannot word one refusal differently
    /// (route-check-parity P3). The HTTP status stays with each route.
    pub(crate) fn request_refusal(&self) -> Option<(i32, String)> {
        if self.allowed {
            return None;
        }
        let desc = self
            .findings
            .first()
            .map_or("Security firewall blocked this request", |f| {
                f.description.as_str()
            });
        Some(if self.is_asi10_block() {
            (-32002, format!("Anomaly detection blocked: {desc}"))
        } else {
            (INVALID_REQUEST, format!("Firewall blocked: {desc}"))
        })
    }

    /// Whether the finding a refusal words (the first) came from a content scan
    /// of the arguments, not from a stateful control. A stateful control's
    /// text carries counts and scores only; a content scan's names the
    /// argument and the pattern it matched.
    pub(crate) fn refusal_words_content(&self) -> bool {
        self.findings.first().is_some_and(|finding| {
            // Exhaustive on purpose: a new scan type must choose a side here.
            match finding.scan_type {
                ScanType::BudgetExceeded
                | ScanType::CrossTenantReach
                | ScanType::SequenceAnomaly
                | ScanType::CollusionRelay => false,
                ScanType::Credentials
                | ScanType::Pii
                | ScanType::PromptInjection
                | ScanType::ShellInjection
                | ScanType::PathTraversal
                | ScanType::SqlInjection
                | ScanType::MemoryPoisoning => true,
            }
        })
    }

    fn blocked_only_by(&self, also: impl Fn(&Finding) -> bool) -> bool {
        !self.allowed
            && !self.findings.is_empty()
            && self.findings.iter().all(|f| {
                (f.scan_type == ScanType::SequenceAnomaly && f.severity >= Severity::High)
                    || also(f)
            })
    }
}

// ─── Rule helpers ─────────────────────────────────────────────────────────────

pub(super) fn compile_rule(rule: &FirewallRule) -> CompiledRule {
    // The guarantee is the load: `FirewallConfig::validate` refuses an invalid
    // glob while the firewall is on. Should one get here anyway, it matches no
    // tool. That backstop fails safe for an `allow` rule and open for a `block`
    // rule, which is acceptable only because the load refusal comes first.
    let pattern = glob::Pattern::new(&rule.tool_match).ok();
    CompiledRule {
        pattern,
        action: rule.action,
        scans: rule.scan.clone(),
        reason: rule.reason.clone(),
    }
}

pub(super) fn rule_matches(rule: &CompiledRule, tool: &str) -> bool {
    rule.pattern.as_ref().is_some_and(|p| p.matches(tool))
}

/// The first rule whose glob covers `tool` and whose `scan` list holds
/// `scan_type`; an empty list holds every type.
pub(super) fn first_matching_rule_action(
    rules: &[CompiledRule],
    tool: &str,
    scan_type: ScanType,
) -> Option<FirewallAction> {
    rules
        .iter()
        .find(|rule| {
            rule_matches(rule, tool) && (rule.scans.is_empty() || rule.scans.contains(&scan_type))
        })
        .map(|rule| rule.action)
}

pub(super) const fn default_action_for_severity(severity: Severity) -> FirewallAction {
    match severity {
        Severity::Critical | Severity::High => FirewallAction::Block,
        Severity::Medium => FirewallAction::Warn,
        Severity::Low => FirewallAction::Allow,
    }
}

pub(super) const fn decide_firewall_action(
    matching_rule_action: Option<FirewallAction>,
    highest_severity: Option<Severity>,
) -> FirewallAction {
    match highest_severity {
        None => FirewallAction::Allow,
        Some(severity) => match matching_rule_action {
            Some(action) => action,
            None => default_action_for_severity(severity),
        },
    }
}
