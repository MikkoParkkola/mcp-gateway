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
