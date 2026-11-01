// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decision object's writer side (MIK-8914 API2A.2, .20, .22, .19):
//! version 2 records, ranked allow attribution, request findings and the
//! declared effect noted independently of which check won, and rule ids.

use serde_json::json;

use super::{
    AllowRank, DECISION_VERSION, Decided, DecisionFinding, DecisionKind, Effect, EffectSource,
    MAX_REQUEST_FINDINGS, Noted, RULE_ID_TAG, Refused, rule_id,
};
use crate::security::audit::AuditOutcome;

fn finding(scan_type: &str, severity: &str, location: &str) -> DecisionFinding {
    DecisionFinding {
        scan_type: scan_type.into(),
        severity: severity.into(),
        location: location.into(),
    }
}

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
fn a_refusal_before_the_firewall_omits_findings_and_effect() {
    let mut noted = Noted::default();
    noted.refused(DecisionKind::Syntax, None);
    let d = noted.decision(
        Decided::Fresh,
        Refused::of(AuditOutcome::Invalid(-32602)),
        None,
    );
    assert_eq!(d.request_findings, None, "absent, never Some(empty)");
    assert_eq!(d.declared_effect, None);
}

/// One fixture where every rank matches; the most specific wins, then each
/// winner is removed in turn (noted in reverse rank order to prove the rank,
/// not the note order, decides).
#[test]
fn attribution_ladder() {
    let ladder = [
        (
            DecisionKind::Firewall,
            AllowRank::FirewallSoftenedBlock,
            "firewall:soft",
            None,
        ),
        (
            DecisionKind::Grant,
            AllowRank::Grant,
            "grant:g1",
            Some("g-dev"),
        ),
        (DecisionKind::Mtls, AllowRank::MtlsRule, "mtls:m1", None),
        (
            DecisionKind::ToolPolicy,
            AllowRank::ToolPolicyEntry,
            "tool_policy:t1",
            None,
        ),
        (
            DecisionKind::Firewall,
            AllowRank::FirewallAllowRule,
            "firewall:allow",
            None,
        ),
    ];
    for winner in 0..ladder.len() {
        let mut noted = Noted::default();
        for (kind, rank, id, grant) in ladder[winner..].iter().rev() {
            noted.allowed_by(
                *kind,
                *rank,
                Some((*id).to_owned()),
                grant.map(str::to_owned),
            );
        }
        let d = allowed(&noted);
        let (kind, _, id, grant) = ladder[winner];
        assert_eq!(
            (d.kind, d.rule_id.as_deref()),
            (kind, Some(id)),
            "step {winner}"
        );
        assert_eq!(d.grant_id.as_deref(), grant, "step {winner}");
    }
    assert_eq!(allowed(&Noted::default()).kind, DecisionKind::DefaultAllow);
}

#[test]
fn a_matched_grant_records_its_grant_id_beside_its_rule_id() {
    let mut noted = Noted::default();
    noted.allowed_by(
        DecisionKind::Grant,
        AllowRank::Grant,
        Some("grant:keyed".into()),
        Some("g-dev".into()),
    );
    let d = allowed(&noted);
    assert_eq!(d.rule_id.as_deref(), Some("grant:keyed"));
    assert_eq!(d.grant_id.as_deref(), Some("g-dev"));
    assert_ne!(d.rule_id, d.grant_id);
}

#[test]
fn findings_and_effect_are_kept_whichever_check_wins() {
    let mut noted = Noted::default();
    noted.note_findings([finding("shell_injection", "high", "request_args")]);
    noted.note_effect(Effect::MayWrite, EffectSource::ToolAnnotation);
    noted.refused(DecisionKind::ToolPolicy, None);
    let refused = noted.decision(
        Decided::Fresh,
        Refused::of(AuditOutcome::Denied(-32003)),
        None,
    );
    assert_eq!(
        refused.request_findings,
        Some(vec![finding("shell_injection", "high", "request_args")])
    );
    assert_eq!(refused.declared_effect, Some(Effect::MayWrite));
}

#[test]
fn the_union_deduplicates_on_the_triple() {
    let mut noted = Noted::default();
    noted.note_findings([
        finding("shell_injection", "high", "request_args"),
        finding("path_traversal", "high", "request_args"),
    ]);
    noted.note_findings([
        finding("shell_injection", "high", "request_args"),
        finding("shell_injection", "medium", "request_args"),
        finding("shell_injection", "high", "sequence_anomaly"),
    ]);
    let d = allowed(&noted);
    assert_eq!(
        d.request_findings,
        Some(vec![
            finding("shell_injection", "high", "request_args"),
            finding("path_traversal", "high", "request_args"),
            finding("shell_injection", "medium", "request_args"),
            finding("shell_injection", "high", "sequence_anomaly"),
        ])
    );
}

/// The cap applies to the distinct union of both scans, in scan order.
#[test]
fn union_then_cap_on_one_fixture() {
    let distinct = |n: usize| (0..n).map(|i| finding(&format!("t{i}"), "high", "request_args"));
    // (a) 20 raw findings, 16 distinct: all kept, not truncated.
    let mut noted = Noted::default();
    noted.note_findings(distinct(10));
    noted.note_findings(distinct(16).skip(6).chain(distinct(4)));
    let d = allowed(&noted);
    assert_eq!(d.request_findings, Some(distinct(16).collect()));
    assert!(!d.request_findings_truncated);
    // (b) 17 distinct: the first 16 in scan order, truncated.
    let mut noted = Noted::default();
    noted.note_findings(distinct(9));
    noted.note_findings(distinct(17).skip(9));
    let d = allowed(&noted);
    assert_eq!(MAX_REQUEST_FINDINGS, 16);
    assert_eq!(d.request_findings, Some(distinct(16).collect()));
    assert!(d.request_findings_truncated);
}

/// An independent expected value: the kind, then the full-width HMAC under
/// the rule-id key of the definition's canonical JSON.
#[test]
fn rule_id_table() {
    let key = crate::gateway::record_principal::RecordPrincipalKey::from_text(&"k".repeat(32))
        .expect("key")
        .rule_id_key();
    let definition = json!({"match": "fs_*", "action": "block"});
    let expected = format!(
        "firewall:{}",
        crate::hashing::hmac_sha256_hex(
            &key,
            crate::hashing::canonical_json(&definition).as_bytes()
        )
    );
    let id = rule_id(DecisionKind::Firewall, &key, &definition);
    assert_eq!(id, expected);
    let hex = id.strip_prefix("firewall:").expect("kind prefix");
    assert_eq!(hex.len(), 64);
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    for kind in [
        DecisionKind::ToolPolicy,
        DecisionKind::Mtls,
        DecisionKind::Grant,
    ] {
        let id = rule_id(kind, &key, &definition);
        let prefix = serde_json::to_value(kind).unwrap();
        assert!(
            id.starts_with(&format!("{}:", prefix.as_str().unwrap())),
            "{id}"
        );
    }
    let edited = json!({"match": "fs_*", "action": "warn"});
    assert_ne!(rule_id(DecisionKind::Firewall, &key, &edited), id);
}

#[test]
fn the_rule_key_tag_is_not_the_revision_tag() {
    assert_eq!(RULE_ID_TAG, b"decision.rule_id.v1");
    assert_ne!(RULE_ID_TAG, crate::config_reload::revision::TAG);
    let key = crate::gateway::record_principal::RecordPrincipalKey::from_text(&"k".repeat(32))
        .expect("key");
    assert_ne!(key.rule_id_key(), key.config_revision_key());
}

#[test]
fn rule_ids_are_keyed() {
    let a = crate::gateway::record_principal::RecordPrincipalKey::from_text(&"a".repeat(32))
        .expect("key")
        .rule_id_key();
    let b = crate::gateway::record_principal::RecordPrincipalKey::from_text(&"b".repeat(32))
        .expect("key")
        .rule_id_key();
    let definition = json!({"match": "fs_*", "action": "block"});
    assert_ne!(
        rule_id(DecisionKind::Firewall, &a, &definition),
        rule_id(DecisionKind::Firewall, &b, &definition)
    );
}

/// A cache hit is not decided again, but keeps the findings and the declared
/// effect its admission noted, with the effect's source.
#[test]
fn a_cache_hit_keeps_the_effect_its_admission_noted() {
    let mut noted = Noted::default();
    noted.note_findings([finding("shell_injection", "high", "request_args")]);
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
    assert_eq!(
        d.request_findings,
        Some(vec![finding("shell_injection", "high", "request_args")])
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
