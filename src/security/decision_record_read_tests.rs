// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Readers of the decision object (MIK-8914 API2A.3, .4, .5, .7, .9, .19).

use serde_json::{Value, json};

use super::read::{
    EVIDENCE_FIELDS, FLAGS_NOT_SET, NO_FINDINGS, NOT_RECORDED_BY_VERSION, NOT_RECORDED_FOR_CALL,
    RULE_NOT_RECORDED, UNDECLARED, decision_evidence, effect_line, findings_line, flags_line,
    matches_rule, rule_line,
};
use super::{Decided, Decision, DecisionFinding, DecisionKind, Effect, EffectSource};

/// A v2 decision with every field this version writes.
fn full() -> Decision {
    Decision {
        v: 2,
        config_revision: Some("rev-a".into()),
        running_revision: None,
        pending_restart: vec![],
        kind: DecisionKind::Grant,
        rule_id: Some("grant:abc".into()),
        grant_id: Some("g-dev".into()),
        request_findings: Some(vec![DecisionFinding {
            scan_type: "shell_injection".into(),
            severity: "high".into(),
            location: "request_args".into(),
        }]),
        request_findings_truncated: false,
        declared_effect: Some(Effect::ReadOnly),
        declared_effect_source: Some(EffectSource::ToolAnnotation),
        decided: Decided::Fresh,
    }
}

/// A recorded entry carrying `decision`, or no decision when `None`.
fn entry(decision: Option<&Decision>) -> Value {
    let mut e = json!({"kind": "invocation", "counter": 7});
    if let Some(d) = decision {
        e["decision"] = serde_json::to_value(d).expect("serialise");
    }
    e
}

#[test]
fn a_record_without_a_decision_reads_no_evidence() {
    assert_eq!(decision_evidence(&entry(None)), None);
}

#[test]
fn a_v2_record_reads_its_decision_evidence() {
    let d = full();
    assert_eq!(decision_evidence(&entry(Some(&d))), Some(d));
}

#[test]
fn matches_rule_returns_exactly_that_rules_records() {
    let rule = |id: Option<&str>| Decision {
        rule_id: id.map(str::to_owned),
        ..full()
    };
    let log = [
        entry(Some(&rule(Some("firewall:a")))),
        entry(Some(&rule(Some("firewall:b")))),
        entry(Some(&rule(Some("tool_policy:c")))),
        entry(Some(&rule(Some("firewall:b")))),
        entry(Some(&rule(None))),
        entry(None),
    ];
    let hits: Vec<usize> = log
        .iter()
        .enumerate()
        .filter(|(_, e)| matches_rule(e, "firewall:b"))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(hits, vec![1, 3]);
}

#[test]
fn a_kind_only_record_reads_rule_not_recorded() {
    let kind_only = Decision {
        rule_id: None,
        ..full()
    };
    assert_eq!(rule_line(&kind_only), Some(RULE_NOT_RECORDED));
    assert_eq!(RULE_NOT_RECORDED, "rule not recorded for this check");
    assert_eq!(rule_line(&full()), None);
}

#[test]
fn absent_flags_read_not_set_by_this_rule() {
    assert_eq!(flags_line(&full()), FLAGS_NOT_SET);
    assert_eq!(FLAGS_NOT_SET, "not set by this rule");
}

#[test]
fn findings_absent_on_a_v1_record_read_not_recorded_by_this_version() {
    let v1 = Decision {
        v: 1,
        request_findings: None,
        ..full()
    };
    assert_eq!(findings_line(&v1), Some(NOT_RECORDED_BY_VERSION));
    assert_eq!(
        NOT_RECORDED_BY_VERSION,
        "not recorded by this gateway version"
    );
}

#[test]
fn findings_absent_on_a_v2_record_read_not_recorded_for_this_call() {
    let v2 = Decision {
        request_findings: None,
        ..full()
    };
    assert_eq!(findings_line(&v2), Some(NOT_RECORDED_FOR_CALL));
    assert_eq!(NOT_RECORDED_FOR_CALL, "not recorded for this call");
}

#[test]
fn an_empty_findings_list_reads_none() {
    let clean = Decision {
        request_findings: Some(vec![]),
        ..full()
    };
    assert_eq!(findings_line(&clean), Some(NO_FINDINGS));
    assert_eq!(NO_FINDINGS, "none");
    assert_eq!(findings_line(&full()), None, "a list to show needs no line");
}

#[test]
fn effect_absent_on_a_v1_record_read_not_recorded_by_this_version() {
    let v1 = Decision {
        v: 1,
        declared_effect: None,
        declared_effect_source: None,
        ..full()
    };
    assert_eq!(effect_line(&v1), Some(NOT_RECORDED_BY_VERSION));
}

#[test]
fn effect_absent_on_a_v2_record_read_not_recorded_for_this_call() {
    let v2 = Decision {
        declared_effect: None,
        declared_effect_source: None,
        ..full()
    };
    assert_eq!(effect_line(&v2), Some(NOT_RECORDED_FOR_CALL));
}

#[test]
fn effect_undeclared_reads_the_tool_declared_no_effect() {
    let undeclared = Decision {
        declared_effect: Some(Effect::Undeclared),
        ..full()
    };
    assert_eq!(effect_line(&undeclared), Some(UNDECLARED));
    assert_eq!(UNDECLARED, "the tool declared no effect");
    assert_eq!(
        effect_line(&full()),
        None,
        "a declared read-only effect needs no line"
    );
}

#[test]
fn the_reader_field_names_are() {
    assert_eq!(
        EVIDENCE_FIELDS,
        ["kind", "rule", "grant", "flags", "findings", "effect"]
    );
}
