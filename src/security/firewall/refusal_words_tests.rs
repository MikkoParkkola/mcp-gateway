// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `FirewallVerdict::refusal_words_content`: which finding a step refusal is
//! neutralised for (MIK-8362). The first finding is the one a refusal words.

use super::*;
use crate::security::Severity;

fn finding(scan_type: ScanType) -> Finding {
    Finding {
        scan_type,
        severity: Severity::High,
        description: "d".to_string(),
        matched: "m".to_string(),
        location: FindingLocation::SequenceAnomaly,
    }
}

fn verdict(types: &[ScanType]) -> FirewallVerdict {
    FirewallVerdict {
        allowed: false,
        action: FirewallAction::Block,
        findings: types.iter().copied().map(finding).collect(),
        anomaly_score: None,
    }
}

#[test]
fn a_stateful_control_keeps_its_wording() {
    for stateful in [
        ScanType::BudgetExceeded,
        ScanType::CrossTenantReach,
        ScanType::SequenceAnomaly,
        ScanType::CollusionRelay,
    ] {
        assert!(
            !verdict(&[stateful]).refusal_words_content(),
            "{stateful:?}"
        );
    }
}

#[test]
fn a_content_scan_is_neutralised() {
    for content in [
        ScanType::Credentials,
        ScanType::Pii,
        ScanType::PromptInjection,
        ScanType::ShellInjection,
        ScanType::PathTraversal,
        ScanType::SqlInjection,
        ScanType::MemoryPoisoning,
    ] {
        assert!(verdict(&[content]).refusal_words_content(), "{content:?}");
    }
}

#[test]
fn the_first_finding_decides_a_mixed_verdict() {
    assert!(verdict(&[ScanType::ShellInjection, ScanType::BudgetExceeded]).refusal_words_content());
    assert!(
        !verdict(&[ScanType::BudgetExceeded, ScanType::ShellInjection]).refusal_words_content()
    );
    assert!(!verdict(&[]).refusal_words_content());
}
