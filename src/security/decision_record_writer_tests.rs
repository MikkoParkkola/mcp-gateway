// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decision object's writer side: version 2 records,
//! and the declared effect noted independently of which check won.

use super::{DECISION_VERSION, Decided, DecisionKind, Effect, EffectSource, Noted, Refused};
use crate::security::audit::AuditOutcome;

fn allowed(noted: &Noted) -> super::Decision {
    noted.decision(Decided::Fresh, Refused::No, None)
}

#[test]
fn every_decision_this_version_writes_is_v_2() {
    assert_eq!(DECISION_VERSION, 2);
    let denied = AuditOutcome::Denied(-32003);
    let mut refused = Noted::default();
    refused.refused(DecisionKind::ToolPolicy, None);
    let cases = [
        allowed(&Noted::default()),
        refused.decision(Decided::Fresh, Refused::of(denied), None),
        Noted::not_redecided().decision(Decided::CacheHitNotRedecided, Refused::No, None),
        Noted::not_redecided().decision(Decided::Replayed, Refused::No, None),
    ];
    for d in cases {
        assert_eq!(d.v, 2, "{:?}", d.decided);
    }
}

#[test]
fn a_refusal_before_the_effect_is_read_omits_it() {
    let mut noted = Noted::default();
    noted.refused(DecisionKind::Syntax, None);
    let d = noted.decision(
        Decided::Fresh,
        Refused::of(AuditOutcome::Invalid(-32602)),
        None,
    );
    assert_eq!(d.declared_effect, None);
    assert_eq!(d.declared_effect_source, None);
}

#[test]
fn the_effect_is_kept_whichever_check_wins() {
    let mut noted = Noted::default();
    noted.note_effect(Effect::MayWrite, EffectSource::ToolAnnotation);
    noted.refused(DecisionKind::ToolPolicy, None);
    let refused = noted.decision(
        Decided::Fresh,
        Refused::of(AuditOutcome::Denied(-32003)),
        None,
    );
    assert_eq!(refused.declared_effect, Some(Effect::MayWrite));
    assert_eq!(
        refused.declared_effect_source,
        Some(EffectSource::ToolAnnotation)
    );
}

/// A cache hit is not decided again, but keeps the declared effect its
/// admission noted, with the effect's source.
#[test]
fn a_cache_hit_keeps_the_effect_its_admission_noted() {
    let mut noted = Noted::default();
    noted.note_effect(Effect::ReadOnly, EffectSource::CapabilityDefinition);
    let d = noted
        .as_not_redecided()
        .decision(Decided::CacheHitNotRedecided, Refused::No, None);
    assert_eq!(d.kind, DecisionKind::NotRedecided);
    assert_eq!(d.declared_effect, Some(Effect::ReadOnly));
    assert_eq!(
        d.declared_effect_source,
        Some(EffectSource::CapabilityDefinition)
    );
}

#[test]
fn the_effect_source_wire_names() {
    let mut noted = Noted::default();
    noted.note_effect(Effect::MayWrite, EffectSource::ToolAnnotation);
    let v = serde_json::to_value(allowed(&noted)).unwrap();
    assert_eq!(v["declared_effect"], "may_write");
    assert_eq!(v["declared_effect_source"], "tool_annotation");
    let none = serde_json::to_value(allowed(&Noted::default())).unwrap();
    assert!(
        none.get("declared_effect_source").is_none(),
        "absent with no effect"
    );
}

fn hit(scan_type: &str, severity: &str, location: &str) -> super::DecisionFinding {
    super::DecisionFinding {
        scan_type: scan_type.to_owned(),
        severity: severity.to_owned(),
        location: location.to_owned(),
    }
}

/// Distinct triples, numbered so a row can name which ones stayed.
fn numbered(n: usize) -> Vec<super::DecisionFinding> {
    (0..n)
        .map(|i| hit(&format!("scan{i}"), "high", "arguments"))
        .collect()
}

/// The record a fresh refusal with `outcome` writes.
fn refused_as(notes: &Noted, outcome: AuditOutcome) -> super::Decision {
    notes.decision(Decided::Fresh, Refused::of(outcome), None)
}

/// A scan that ran and raised nothing is written as an empty list, which
/// the reader tells apart from a scan that never ran.
#[test]
fn a_clean_scan_writes_an_empty_finding_list() {
    let mut clean = Noted::default();
    clean.note_request_findings(Vec::new());
    let record = allowed(&clean);
    assert_eq!(record.request_findings, Some(Vec::new()));
    assert!(!record.request_findings_truncated);
    let wire = serde_json::to_value(&record).unwrap();
    assert_eq!(wire["request_findings"], serde_json::json!([]));
}

/// A call refused before any scan ran has no findings field at all.
#[test]
fn a_call_refused_before_any_scan_has_no_findings_field() {
    let mut early = Noted::default();
    early.refused(DecisionKind::Syntax, None);
    let record = refused_as(&early, AuditOutcome::Invalid(-32602));
    assert_eq!(record.request_findings, None);
    let wire = serde_json::to_value(&record).unwrap();
    assert!(wire.get("request_findings").is_none(), "{wire}");
    assert!(wire.get("request_findings_truncated").is_none(), "{wire}");
}

/// Two scans of one call add up. A triple both raised is written once; a
/// triple that differs from it in any single part is a different finding.
#[test]
fn two_scans_add_up_and_share_a_triple_once() {
    let mut both = Noted::default();
    both.note_request_findings([hit("secret", "high", "arguments")]);
    both.note_request_findings([
        hit("secret", "high", "arguments"),
        hit("pii", "high", "arguments"),
        hit("secret", "medium", "arguments"),
        hit("secret", "high", "tool"),
    ]);
    let expected = vec![
        hit("secret", "high", "arguments"),
        hit("pii", "high", "arguments"),
        hit("secret", "medium", "arguments"),
        hit("secret", "high", "tool"),
    ];
    assert_eq!(allowed(&both).request_findings, Some(expected));
}

/// Sixteen distinct triples fit, even when repeats push the raw count past
/// sixteen: nothing is cut and nothing is marked.
#[test]
fn sixteen_distinct_triples_fit_with_repeats_among_them() {
    let all = numbered(16);
    let mut notes = Noted::default();
    notes.note_request_findings(all.iter().take(10).cloned());
    notes.note_request_findings(all.iter().cloned());
    let record = allowed(&notes);
    assert!(!record.request_findings_truncated);
    assert_eq!(record.request_findings, Some(all));
}

/// The seventeenth distinct triple is dropped and marks the record cut;
/// the sixteen kept are the first ones seen, in the order the scans saw them.
#[test]
fn a_seventeenth_distinct_triple_is_dropped_and_marked() {
    let all = numbered(17);
    let mut notes = Noted::default();
    notes.note_request_findings(all.iter().take(9).cloned());
    notes.note_request_findings(all.iter().skip(9).cloned());
    let record = allowed(&notes);
    assert!(record.request_findings_truncated);
    assert_eq!(record.request_findings, Some(all[..16].to_vec()));
    let wire = serde_json::to_value(&record).unwrap();
    assert_eq!(wire["request_findings_truncated"], true);
}

/// Findings are written whichever check decided: a refused call keeps what
/// the scans raised before the refusal.
#[test]
fn findings_are_kept_whichever_check_wins() {
    let mut blocked = Noted::default();
    blocked.note_request_findings([hit("secret", "high", "arguments")]);
    blocked.refused(DecisionKind::Firewall, None);
    let record = refused_as(&blocked, AuditOutcome::Denied(-32600));
    assert_eq!(
        record.request_findings,
        Some(vec![hit("secret", "high", "arguments")])
    );
}

/// A cache hit is not decided again but keeps the findings its admission's
/// scans noted, cut marker included.
#[test]
fn a_cache_hit_keeps_the_findings_its_admission_noted() {
    let mut admitted = Noted::default();
    admitted.note_request_findings(numbered(17));
    let hit_record =
        admitted
            .as_not_redecided()
            .decision(Decided::CacheHitNotRedecided, Refused::No, None);
    assert!(hit_record.request_findings_truncated);
    assert_eq!(hit_record.request_findings, Some(numbered(16)));
}
