// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decision set's model rows: the access projection, the live-grant
//! closing check, health, snapshot and revision.

use chrono::{DateTime, Duration, TimeZone as _, Utc};

use super::{DecisionSet, Health, Source};
use crate::identity_grants::{
    GrantAgent, GrantAgentKey, GrantScope, GrantSubject, IdentityGrant, IdentityGrantAuditEvent,
    IdentityGrantDecisionReason,
};
use crate::security::ProofSource;

const KEY: [u8; 32] = [7; 32];
const AGENT: &str = "mtls:runner";

fn at(minute: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 28, 12, 0, 0).unwrap() + Duration::minutes(minute)
}

fn ready() -> DecisionSet {
    let mut set = DecisionSet::with_key(KEY);
    for source in [Source::Access, Source::ControlPlane, Source::Capability] {
        set.set_health(source, Health::Ready);
    }
    set
}

fn denial(capability: &str, reason: IdentityGrantDecisionReason, minute: i64) -> IdentityGrantAuditEvent {
    IdentityGrantAuditEvent {
        event: "identity_grant_decision".to_string(),
        timestamp: at(minute),
        allowed: false,
        reason,
        subject: Some(GrantSubject::new("https://idp.example", "alice", None)),
        agent_id: Some(AGENT.to_string()),
        capability: capability.to_string(),
        tool: None,
        scope: GrantScope::Execute,
        grant_id: None,
    }
}

fn missing(capability: &str, minute: i64) -> IdentityGrantAuditEvent {
    denial(capability, IdentityGrantDecisionReason::MissingGrant, minute)
}

fn grant(capability: &str, scope: GrantScope) -> IdentityGrant {
    IdentityGrant {
        grant_id: "g1".to_string(),
        subject: GrantSubject::new("https://idp.example", "alice", None),
        agent: GrantAgent::Exact(GrantAgentKey {
            source: ProofSource::MutualTls,
            id: "runner".to_string(),
        }),
        capability: capability.to_string(),
        tool: None,
        scope,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "test".to_string(),
        reason: "test".to_string(),
    }
}

fn count(set: &DecisionSet) -> usize {
    set.snapshot(true).expect("all sources ready").0
}

#[test]
fn a_missing_grant_with_a_proven_agent_opens_one_access_request() {
    let mut set = ready();
    set.note_denial(&missing("stripe.charges", 1));
    set.note_denial(&missing("stripe.refunds", 2));
    let list = set.list();
    assert_eq!(list.len(), 1, "one item per subject and agent: {list:?}");
    assert_eq!(list[0]["kind"], "access_request");
    assert_eq!(list[0]["scope"].as_array().map(Vec::len), Some(2));
}

#[test]
fn every_a1_exclusion_opens_nothing() {
    use IdentityGrantDecisionReason as R;
    let mut set = ready();
    for reason in [R::MissingIdentity, R::MissingOwner, R::OwnerMismatch, R::PublicCapability, R::SharedCapability, R::GrantMatched] {
        set.note_denial(&denial("stripe.charges", reason, 1));
    }
    let mut no_agent = missing("stripe.charges", 1);
    no_agent.agent_id = None;
    set.note_denial(&no_agent);
    let mut no_subject = missing("stripe.charges", 1);
    no_subject.subject = None;
    set.note_denial(&no_subject);
    // The positive control: the same set does open on a real missing grant.
    assert_eq!(count(&set), 0);
    set.note_denial(&missing("stripe.charges", 2));
    assert_eq!(count(&set), 1);
}

#[test]
fn a_newer_ui_decision_closes_and_a_newer_denial_reopens() {
    let mut set = ready();
    set.note_denial(&missing("stripe.charges", 1));
    set.note_ui_decision("https://idp.example", "alice", AGENT, "stripe.charges", at(2));
    assert_eq!(count(&set), 0);
    set.note_denial(&missing("stripe.charges", 3));
    assert_eq!(count(&set), 1);
}

#[test]
fn an_older_ui_decision_leaves_the_item_open() {
    let mut set = ready();
    set.note_denial(&missing("stripe.charges", 5));
    set.note_ui_decision("https://idp.example", "alice", AGENT, "stripe.charges", at(4));
    assert_eq!(count(&set), 1);
}

#[test]
fn a_covering_grant_closes_and_its_expiry_reopens() {
    let mut set = ready();
    set.note_denial(&missing("stripe.charges", 1));
    let mut row = grant("stripe.charges", GrantScope::Execute);
    row.expires_at = Some(at(10));
    set.set_grants(vec![row], at(2));
    assert_eq!(count(&set), 0, "a live covering row closes it");
    set.expire(at(11));
    assert_eq!(count(&set), 1, "the denial outlives the row that covered it");
}

#[test]
fn a_row_that_evaluate_would_not_match_leaves_the_item_open() {
    let other = GrantSubject::new("https://idp.example", "bob", None);
    let rows: Vec<(&str, IdentityGrant)> = vec![
        ("narrower scope", grant("stripe.charges", GrantScope::Read)),
        ("other capability", grant("stripe.refunds", GrantScope::Any)),
        ("other agent", IdentityGrant {
            agent: GrantAgent::Exact(GrantAgentKey { source: ProofSource::VerifiedJwtSubject, id: "runner".to_string() }),
            ..grant("stripe.charges", GrantScope::Any)
        }),
        ("other subject", IdentityGrant { subject: other.clone(), ..grant("stripe.charges", GrantScope::Any) }),
        ("other owner", IdentityGrant { owner: Some(other), ..grant("stripe.charges", GrantScope::Any) }),
        ("revoked", IdentityGrant { revoked_at: Some(at(0)), ..grant("stripe.charges", GrantScope::Any) }),
        ("other tool", IdentityGrant { tool: Some("refund".to_string()), ..grant("stripe.charges", GrantScope::Any) }),
    ];
    for (why, row) in rows {
        let mut set = ready();
        let mut note = missing("stripe.charges", 1);
        note.tool = Some("charge".to_string());
        set.note_denial(&note);
        set.set_grants(vec![row], at(2));
        assert_eq!(count(&set), 1, "{why}");
    }
}

#[test]
fn every_row_evaluate_would_match_closes_the_item() {
    let rows: Vec<(&str, IdentityGrant)> = vec![
        ("exact", grant("stripe.charges", GrantScope::Execute)),
        ("wider scope", grant("stripe.charges", GrantScope::Any)),
        ("any agent", IdentityGrant { agent: GrantAgent::Any, ..grant("stripe.charges", GrantScope::Execute) }),
        ("same owner", IdentityGrant {
            owner: Some(GrantSubject::new("https://idp.example", "alice", Some("label".to_string()))),
            ..grant("stripe.charges", GrantScope::Execute)
        }),
        ("same tool", IdentityGrant { tool: Some("charge".to_string()), ..grant("stripe.charges", GrantScope::Execute) }),
    ];
    for (why, row) in rows {
        let mut set = ready();
        let mut note = missing("stripe.charges", 1);
        note.tool = Some("charge".to_string());
        set.note_denial(&note);
        set.set_grants(vec![row], at(2));
        assert_eq!(count(&set), 0, "{why}");
    }
}

#[test]
fn snapshot_is_none_for_a_non_admin_and_while_a_source_is_unavailable() {
    let mut set = ready();
    assert_eq!(set.snapshot(true).map(|s| s.0), Some(0));
    assert_eq!(set.snapshot(false), None);
    set.set_health(Source::ControlPlane, Health::Unavailable);
    assert_eq!(set.snapshot(true), None);
    set.set_health(Source::ControlPlane, Health::Absent);
    assert_eq!(set.snapshot(true).map(|s| s.0), Some(0), "an absent source is not an error");
    assert_eq!(DecisionSet::with_key(KEY).snapshot(true), None, "sources start unavailable");
}

#[test]
fn revision_rises_on_open_close_and_field_change_and_not_on_a_no_op() {
    let mut set = ready();
    let rev = |set: &DecisionSet| set.snapshot(true).expect("ready").1;
    let r0 = rev(&set);
    set.note_denial(&missing("stripe.charges", 1));
    let r1 = rev(&set);
    assert!(r1 > r0, "open");
    set.note_denial(&missing("stripe.refunds", 2));
    let r2 = rev(&set);
    assert!(r2 > r1, "a scope entry added to an open item");
    set.expire(at(3));
    assert_eq!(rev(&set), r2, "nothing changed");
    set.note_ui_decision("https://idp.example", "alice", AGENT, "stripe.charges", at(4));
    set.note_ui_decision("https://idp.example", "alice", AGENT, "stripe.refunds", at(4));
    assert!(rev(&set) > r2, "close");
}

#[test]
fn folding_is_order_free_and_a_repeat_changes_nothing() {
    let denial_1 = missing("stripe.charges", 1);
    let denial_3 = missing("stripe.charges", 3);
    let apply = |order: &[u8]| {
        let mut set = ready();
        for step in order {
            match step {
                1 => set.note_denial(&denial_1),
                2 => set.note_ui_decision("https://idp.example", "alice", AGENT, "stripe.charges", at(2)),
                _ => set.note_denial(&denial_3),
            }
        }
        set.list()
    };
    let expected = apply(&[1, 2, 3]);
    assert_eq!(expected.len(), 1, "the newer denial reopens");
    for order in [[3, 2, 1], [2, 3, 1], [3, 1, 2], [1, 3, 2], [2, 1, 3]] {
        assert_eq!(apply(&order), expected, "{order:?}");
    }
    let mut once = ready();
    once.note_denial(&denial_1);
    once.note_ui_decision("https://idp.example", "alice", AGENT, "stripe.charges", at(2));
    once.note_ui_decision("https://idp.example", "alice", AGENT, "stripe.charges", at(2));
    once.note_denial(&denial_1);
    assert_eq!(count(&once), 0, "a replayed older denial cannot resurrect a declined request");
}

#[test]
fn eviction_closes_a_request_whose_newest_denial_is_past_the_edge() {
    let mut set = ready();
    set.note_denial(&missing("stripe.charges", 1));
    set.note_denial(&missing("stripe.refunds", 5));
    set.evict_before(at(3));
    let list = set.list();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["scope"].as_array().map(Vec::len), Some(1));
}
