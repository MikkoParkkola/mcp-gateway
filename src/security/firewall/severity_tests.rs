// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Finding severity: the firewall action table, the strongest-severity choice
//! and the serialized severity strings (MIK-8669).

use super::*;
use crate::security::Severity;

// ── MIK-8669 commit G guard tests: severity table ───────────────────────────

#[test]
fn severity_action_table_is_block_warn_allow() {
    assert_eq!(
        decide_firewall_action(None, Some(Severity::High)),
        FirewallAction::Block
    );
    assert_eq!(
        decide_firewall_action(None, Some(Severity::Medium)),
        FirewallAction::Warn
    );
    assert_eq!(
        decide_firewall_action(None, Some(Severity::Low)),
        FirewallAction::Allow
    );
    assert_eq!(decide_firewall_action(None, None), FirewallAction::Allow);
}

#[test]
fn matching_rule_overrides_severity_default() {
    assert_eq!(
        decide_firewall_action(Some(FirewallAction::Allow), Some(Severity::High)),
        FirewallAction::Allow
    );
    assert_eq!(
        decide_firewall_action(Some(FirewallAction::Block), Some(Severity::Low)),
        FirewallAction::Block
    );
}

#[test]
fn default_action_for_severity_is_block_warn_allow() {
    assert_eq!(
        super::verdict::default_action_for_severity(Severity::High),
        FirewallAction::Block
    );
    assert_eq!(
        super::verdict::default_action_for_severity(Severity::Medium),
        FirewallAction::Warn
    );
    assert_eq!(
        super::verdict::default_action_for_severity(Severity::Low),
        FirewallAction::Allow
    );
}

fn finding_at(severity: Severity) -> Finding {
    Finding {
        scan_type: ScanType::PromptInjection,
        severity,
        description: "guard fixture".to_string(),
        matched: "fixture".to_string(),
        location: FindingLocation::RequestArgs,
    }
}

#[test]
fn strongest_finding_severity_selects_highest_present() {
    let mixed = [
        finding_at(Severity::Low),
        finding_at(Severity::High),
        finding_at(Severity::Medium),
    ];
    assert_eq!(strongest_finding_severity(&mixed), Some(Severity::High));
    let low_medium = [finding_at(Severity::Low), finding_at(Severity::Medium)];
    assert_eq!(
        strongest_finding_severity(&low_medium),
        Some(Severity::Medium)
    );
    let low_only = [finding_at(Severity::Low)];
    assert_eq!(strongest_finding_severity(&low_only), Some(Severity::Low));
}

#[test]
fn strongest_finding_severity_is_none_for_no_findings() {
    let empty: &[Finding] = &[];
    assert_eq!(strongest_finding_severity(empty), None);
}

#[test]
fn finding_severity_serializes_to_snake_case_names() {
    for (severity, expected) in [
        (Severity::High, "high"),
        (Severity::Medium, "medium"),
        (Severity::Low, "low"),
    ] {
        let value = serde_json::to_value(finding_at(severity)).expect("finding must serialize");
        assert_eq!(
            value.get("severity").and_then(serde_json::Value::as_str),
            Some(expected)
        );
    }
}

// ── MIK-8669 commit C1: critical severity ───────────────────────────────────

#[test]
fn critical_severity_blocks_and_is_strongest() {
    assert_eq!(
        decide_firewall_action(None, Some(Severity::Critical)),
        FirewallAction::Block
    );
    assert_eq!(
        strongest_finding_severity(&[finding_at(Severity::High), finding_at(Severity::Critical)]),
        Some(Severity::Critical)
    );
}

#[test]
fn critical_anomaly_only_block_answers_32002() {
    let mut verdict = FirewallVerdict {
        allowed: false,
        action: FirewallAction::Block,
        findings: vec![Finding {
            scan_type: ScanType::SequenceAnomaly,
            severity: Severity::Critical,
            description: "the finding".into(),
            matched: String::new(),
            location: FindingLocation::SequenceAnomaly,
        }],
        anomaly_score: None,
    };
    assert_eq!(
        verdict.request_refusal(),
        Some((-32002, "Anomaly detection blocked: the finding".to_string()))
    );
    verdict.findings.push(Finding {
        scan_type: ScanType::PromptInjection,
        severity: Severity::High,
        description: "other finding".into(),
        matched: String::new(),
        location: FindingLocation::RequestArgs,
    });
    assert_eq!(
        verdict.request_refusal().map(|(code, _)| code),
        Some(-32600)
    );
}
