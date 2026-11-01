// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The multi-target response rows: block and warn dominate in either target
//! order, the audit's target list is sorted and unique, and an empty target
//! list is refused. Moved from `response_tests.rs` for the file-size ceiling.

use super::audit::{assert_legacy_field_compatibility, capture_warnings};
use super::*;

/// MIK-7407.RESPONSE.3; FWR-07/08. Rules retain first-match semantics for
/// each tool, while one Block across any target cannot be downgraded.
#[test]
fn firewall_response_multitarget_block_dominates_in_both_orders() {
    for targets in [
        vec![target("alpha", "allowed"), target("zeta", "blocked")],
        vec![target("zeta", "blocked"), target("alpha", "allowed")],
    ] {
        let (firewall, _dir, path) = response_fixture(FirewallConfig {
            rules: vec![
                response_rule("allowed", FirewallAction::Allow),
                response_rule("blocked", FirewallAction::Block),
                response_rule("blocked", FirewallAction::Allow),
            ],
            ..FirewallConfig::default()
        });
        let mut response = json!({"text": INJECTION});
        let verdict = firewall
            .check_response_artifact(
                &mut response,
                &targets,
                &correlation(),
                ResponseArtifactKind::FinalResponse,
                ResponseMutationPolicy::Redact,
            )
            .expect("nonempty server-bound targets");
        assert!(
            !verdict.allowed,
            "a later target's Block must dominate an earlier Allow"
        );
        assert_eq!(verdict.action, FirewallAction::Block);
        assert_counts(&firewall, 1, 1, 1);
        let events = audit_entries(&path);
        assert_eq!(events.len(), 1);
        assert_response_event(
            &events[0],
            &correlation(),
            &targets,
            ResponseArtifactKind::FinalResponse,
            FirewallAction::Block,
        );
        assert_eq!(
            events[0]["policy_targets"],
            json!([
                {"server":"alpha", "tool":"allowed"}, {"server":"zeta", "tool":"blocked"}
            ])
        );
    }
}

/// MIK-7407.RESPONSE.3; FWR-07. Warn dominates Allow in either target order.
#[test]
fn firewall_response_multitarget_warn_dominates_allow_in_both_orders() {
    for targets in [
        vec![target("alpha", "allowed"), target("zeta", "warned")],
        vec![target("zeta", "warned"), target("alpha", "allowed")],
    ] {
        let (firewall, _dir, path) = response_fixture(FirewallConfig {
            rules: vec![
                response_rule("allowed", FirewallAction::Allow),
                response_rule("warned", FirewallAction::Warn),
            ],
            ..FirewallConfig::default()
        });
        let original = json!({"text": INJECTION});
        let mut response = original.clone();
        let verdict = firewall
            .check_response_artifact(
                &mut response,
                &targets,
                &correlation(),
                ResponseArtifactKind::FinalResponse,
                ResponseMutationPolicy::Redact,
            )
            .expect("nonempty targets");
        assert!(verdict.allowed);
        assert_eq!(verdict.action, FirewallAction::Warn);
        assert!(
            verdict
                .findings
                .iter()
                .any(|finding| finding.scan_type == ScanType::PromptInjection)
        );
        assert_eq!(response, original);
        assert_counts(&firewall, 1, 1, 1);
        let events = audit_entries(&path);
        assert_eq!(events.len(), 1);
        assert_response_event(
            &events[0],
            &correlation(),
            &targets,
            ResponseArtifactKind::FinalResponse,
            FirewallAction::Warn,
        );
    }
}

/// MIK-7407.RESPONSE.3/.4; FWR-14. Targets are canonical metadata of one
/// artifact, distinct from the external operation's safe correlation label.
#[test]
fn firewall_response_audit_targets_are_sorted_unique_and_external_label_preserved() {
    let (firewall, _dir, path) = response_fixture(FirewallConfig::default());
    let targets = vec![
        target("z", "b"),
        target("a", "z"),
        target("a", "a"),
        target("z", "a"),
        target("z", "b"),
    ];
    let mut response = json!({"text": "plain text"});
    let verdict = firewall
        .check_response_artifact(
            &mut response,
            &targets,
            &correlation(),
            ResponseArtifactKind::FinalResponse,
            ResponseMutationPolicy::Redact,
        )
        .expect("nonempty server-bound targets");
    assert!(verdict.allowed);
    assert_counts(&firewall, 1, 1, 1);
    let events = audit_entries(&path);
    assert_eq!(events.len(), 1);
    assert_response_event(
        &events[0],
        &correlation(),
        &targets,
        ResponseArtifactKind::FinalResponse,
        FirewallAction::Allow,
    );
    assert_eq!(
        events[0]["policy_targets"],
        json!([
            {"server":"a", "tool":"a"}, {"server":"a", "tool":"z"}, {"server":"z", "tool":"a"}, {"server":"z", "tool":"b"}
        ])
    );
    assert_legacy_field_compatibility(&events[0]);
}

/// MIK-7407.RESPONSE.3; FWR-16. An enabled caller with no bound policy
/// target is a wiring error, not permission to skip all rules.
#[test]
fn firewall_response_empty_targets_refuse_without_inspection_or_malformed_audit() {
    let (firewall, _dir, path) = response_fixture(FirewallConfig::default());
    let mut response = json!({"text": "even clean content needs a bound target"});
    let original = response.clone();
    let (result, warning) = capture_warnings(|| {
        firewall.check_response_artifact(
            &mut response,
            &[],
            &correlation(),
            ResponseArtifactKind::FinalResponse,
            ResponseMutationPolicy::Redact,
        )
    });
    assert_eq!(
        result.expect_err("empty targets must be a typed wiring error"),
        InvalidResponseTargets
    );
    assert!(
        warning.contains("WARN"),
        "invalid wiring must emit a diagnostic warning: {warning}"
    );
    assert!(
        warning.contains("response") && warning.contains("target"),
        "diagnostic identifies response-target wiring: {warning}"
    );
    assert!(!warning.contains("even clean content"));
    assert_eq!(response, original);
    assert_counts(&firewall, 0, 0, 0);
    assert!(audit_entries(&path).is_empty());
}
