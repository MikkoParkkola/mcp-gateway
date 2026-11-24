// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8914.API2A.1: the decision object's wire shape.

use super::{Decided, Decision, DecisionKind, Effect};

fn decision(kind: DecisionKind, rule_id: Option<&str>) -> Decision {
    Decision {
        token: None,
        token_unavailable: false,
        v: 1,
        config_revision: Some("hmac-sha256:00aa".to_owned()),
        config_revision_capabilities: None,
        running_revision: None,
        pending_restart: Vec::new(),
        kind,
        rule_id: rule_id.map(str::to_owned),
        grant_id: None,
        request_findings: Some(Vec::new()),
        request_findings_truncated: false,
        declared_effect: Some(Effect::Undeclared),
        declared_effect_source: Some(super::EffectSource::ToolAnnotation),
        decided: Decided::Fresh,
    }
}

#[test]
fn the_wire_names_are_the_agreed_ones() {
    let mut d = decision(DecisionKind::NotRedecided, None);
    d.decided = Decided::CacheHitNotRedecided;
    d.declared_effect = Some(Effect::MayWrite);
    let v = serde_json::to_value(&d).unwrap();
    assert_eq!(v["v"], 1);
    assert_eq!(v["kind"], "not_redecided");
    assert_eq!(v["decided"], "cache_hit_not_redecided");
    assert_eq!(v["declared_effect"], "may_write");
    // One fact, one owner: what reached the caller is the delivery record's.
    for delivery_field in ["effect", "findings", "response_effect", "response_findings"] {
        assert!(
            v.get(delivery_field).is_none(),
            "{delivery_field} is not this object's"
        );
    }
    assert!(v.get("rule_id").is_none(), "absent, not null");
    assert!(v.get("audit_required").is_none() && v.get("rollback_applies").is_none());
}

/// The kind `noted` records for a call whose outcome is `outcome`.
fn recorded(noted: &super::Noted, outcome: crate::security::audit::AuditOutcome) -> DecisionKind {
    noted
        .decision(
            Decided::Fresh,
            super::Refused::of(outcome),
            None,
            crate::security::audit::CredentialKind::None,
        )
        .kind
}

#[test]
fn the_first_refusal_noted_is_the_one_recorded() {
    let mut noted = super::Noted::default();
    noted.refused(DecisionKind::ToolPolicy, None);
    noted.refused(DecisionKind::Firewall, None);
    let denied = crate::security::audit::AuditOutcome::Denied(-32003);
    assert_eq!(recorded(&noted, denied), DecisionKind::ToolPolicy);
}

#[test]
fn the_memo_kind_wins_over_a_later_note() {
    let mut noted = super::Noted::default();
    noted.refused(DecisionKind::Firewall, None);
    noted.refused_by_memo((DecisionKind::BackendScope, None));
    let denied = crate::security::audit::AuditOutcome::Denied(-32003);
    assert_eq!(recorded(&noted, denied), DecisionKind::BackendScope);
}

#[test]
fn an_allowed_call_with_no_note_is_a_default_allow() {
    let ok = crate::security::audit::AuditOutcome::Ok;
    assert_eq!(
        recorded(&super::Noted::default(), ok),
        DecisionKind::DefaultAllow
    );
    let replayed = super::Noted::not_redecided();
    assert_eq!(recorded(&replayed, ok), DecisionKind::NotRedecided);
}

/// MIK-8914.API2A.13: a refused call that noted no check fails every debug
/// build; a release build records `unrecorded`, never an allow.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "noted no check")]
fn a_refusal_that_noted_no_check_fails_the_guard() {
    let denied = crate::security::audit::AuditOutcome::Denied(-32001);
    let _ = recorded(&super::Noted::default(), denied);
}

/// The call and route scopes move a `Noted` in and out on every poll of the
/// call: it stays one pointer wide, and an allowed call that notes nothing
/// never boxes.
#[test]
fn noted_is_one_pointer_and_unboxed_until_a_note() {
    assert_eq!(
        std::mem::size_of::<super::Noted>(),
        std::mem::size_of::<usize>()
    );
    assert!(super::Noted::default().0.is_none());
    let mut noted = super::Noted::default();
    noted.refused(DecisionKind::Firewall, None);
    noted.refused(DecisionKind::Grant, None);
    assert_eq!(
        noted.refusal_pair().map(|(kind, _)| kind),
        Some(DecisionKind::Firewall)
    );
}

/// GUARD (canary, type half): a request finding enters the decision object as
/// exactly its scan type, severity and location. A finding's description and
/// matched text (the parts that can carry caller-supplied text) have no field
/// to land in; adding one fails this row.
#[test]
fn a_decision_finding_carries_no_description_or_match() {
    let finding = super::DecisionFinding {
        scan_type: "prompt_injection".to_owned(),
        severity: "high".to_owned(),
        location: "arguments".to_owned(),
    };
    let value = serde_json::to_value(&finding).expect("serialises");
    let keys: std::collections::BTreeSet<&str> = value
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        ["location", "scan_type", "severity"].into_iter().collect(),
        "{value}"
    );
}

fn bare_decision(coverage: &str) -> String {
    format!(
        r#"{{"v":2,"kind":"grant","decided":"fresh","config_revision_capabilities":{coverage}}}"#
    )
}

/// A record written without the field reads as absent and says capabilities
/// were not included. Partial names the directories that could be read.
/// Covered adds nothing.
#[test]
fn d1_absent_coverage_says_not_included_and_partial_names_the_directories() {
    use super::Coverage;
    use super::read::capabilities_line;

    for (variant, name) in [
        (Coverage::Covered, "covered"),
        (Coverage::NotLoaded, "not_loaded"),
        (Coverage::Partial, "partial"),
    ] {
        assert_eq!(
            serde_json::to_value(variant).expect("name"),
            serde_json::json!(name),
            "{name}"
        );
    }

    let absent: super::Decision =
        serde_json::from_str(r#"{"v":2,"kind":"grant","decided":"fresh"}"#)
            .expect("a record written before the field");
    assert_eq!(absent.config_revision_capabilities, None);
    assert_eq!(
        capabilities_line(absent.config_revision_capabilities),
        "capabilities not included",
        "no field"
    );
    assert_eq!(
        capabilities_line(Some(Coverage::NotLoaded)),
        "capabilities not included",
        "not_loaded"
    );

    let partial: super::Decision =
        serde_json::from_str(&bare_decision("\"partial\"")).expect("partial");
    assert_eq!(
        partial.config_revision_capabilities,
        Some(Coverage::Partial)
    );
    assert_eq!(
        capabilities_line(Some(Coverage::Partial)),
        "capabilities included from the directories that could be read"
    );
    assert_eq!(
        capabilities_line(Some(Coverage::Covered)),
        "",
        "covered adds nothing"
    );
}
