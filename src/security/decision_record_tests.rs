// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8914.API2A.3/.4/.5/.7/.9: the decision object's reader contract.

use serde_json::{Value, json};

use super::{
    Decided, Decision, DecisionFinding, DecisionKind, Effect, FIELD, decision_evidence,
    findings_line, matches_rule, rule_line,
};

fn decision(kind: DecisionKind, rule_id: Option<&str>) -> Decision {
    Decision {
        v: 1,
        config_revision: Some("hmac-sha256:00aa".to_owned()),
        running_revision: None,
        pending_restart: Vec::new(),
        kind,
        rule_id: rule_id.map(str::to_owned),
        grant_id: None,
        findings: Some(Vec::new()),
        findings_truncated: false,
        effect: Some(Effect::Undeclared),
        decided: Decided::Fresh,
    }
}

fn record(decision: &Decision) -> Value {
    json!({ "counter": 7, "tool": "t", FIELD: serde_json::to_value(decision).unwrap() })
}

#[test]
fn api2a_3_an_old_record_reads_as_no_evidence_and_a_new_one_reads_back_exactly() {
    let old = json!({ "counter": 1, "tool": "t" });
    assert_eq!(decision_evidence(&old), None);
    let new = decision(DecisionKind::Firewall, Some("firewall:3f9a0c12be47"));
    assert_eq!(decision_evidence(&record(&new)), Some(new));
}

#[test]
fn api2a_3_a_malformed_decision_is_no_evidence_not_a_panic() {
    let bad = json!({ "counter": 1, FIELD: { "v": "one" } });
    assert_eq!(decision_evidence(&bad), None);
}

#[test]
fn api2a_4_matches_rule_is_exact() {
    let r = record(&decision(DecisionKind::Grant, Some("grant:aaaaaaaaaaaa")));
    assert!(matches_rule(&r, "grant:aaaaaaaaaaaa"));
    assert!(!matches_rule(&r, "grant:aaaaaaaaaaa"), "no prefix match");
    assert!(!matches_rule(&r, "firewall:aaaaaaaaaaaa"));
    let ruleless = record(&decision(DecisionKind::Ssrf, None));
    assert!(
        !matches_rule(&ruleless, ""),
        "an absent rule matches nothing"
    );
    assert!(!matches_rule(
        &json!({ "counter": 1 }),
        "grant:aaaaaaaaaaaa"
    ));
}

#[test]
fn api2a_7_a_check_without_a_rule_id_says_so_never_blank() {
    for kind in [
        DecisionKind::BackendScope,
        DecisionKind::ClientToolScope,
        DecisionKind::AgentScope,
        DecisionKind::Ssrf,
        DecisionKind::CostBudget,
        DecisionKind::AdminCapability,
        DecisionKind::RoutingProfile,
        DecisionKind::KillSwitch,
        DecisionKind::CapabilityDisabled,
        DecisionKind::DescriptorBlock,
        DecisionKind::Attestation,
        DecisionKind::ResponseGate,
        DecisionKind::Syntax,
        DecisionKind::Firewall,
    ] {
        assert_eq!(
            rule_line(&decision(kind, None)),
            "rule not recorded for this check",
            "{kind:?}"
        );
    }
    assert_eq!(
        rule_line(&decision(DecisionKind::DefaultAllow, None)),
        "allowed: no rule restricted this call"
    );
    assert_eq!(
        rule_line(&decision(DecisionKind::NotRedecided, None)),
        "not decided again for this call"
    );
    assert_eq!(
        rule_line(&decision(DecisionKind::Grant, Some("grant:aaaaaaaaaaaa"))),
        "decided by the rule named below"
    );
}

#[test]
fn api2a_9_findings_not_recorded_differs_from_none() {
    assert_eq!(
        findings_line(None),
        "findings not recorded by this gateway version"
    );
    let mut not_run = decision(DecisionKind::ToolPolicy, None);
    not_run.findings = None;
    assert_eq!(
        findings_line(Some(&not_run)),
        "findings not recorded by this gateway version"
    );
    let clean = decision(DecisionKind::ToolPolicy, None);
    assert_eq!(findings_line(Some(&clean)), "none");
    let mut found = decision(DecisionKind::Firewall, None);
    found.findings = Some(vec![DecisionFinding {
        scan_type: "prompt_injection".to_owned(),
        severity: "high".to_owned(),
        location: "arguments.query".to_owned(),
    }]);
    assert_eq!(findings_line(Some(&found)), "listed below");
}

#[test]
fn the_wire_names_are_the_agreed_ones() {
    let mut d = decision(DecisionKind::NotRedecided, None);
    d.decided = Decided::CacheHitNotRedecided;
    d.effect = Some(Effect::MayWrite);
    let v = serde_json::to_value(&d).unwrap();
    assert_eq!(v["v"], 1);
    assert_eq!(v["kind"], "not_redecided");
    assert_eq!(v["decided"], "cache_hit_not_redecided");
    assert_eq!(v["effect"], "may_write");
    assert!(v.get("rule_id").is_none(), "absent, not null");
    assert!(v.get("audit_required").is_none() && v.get("rollback_applies").is_none());
}
