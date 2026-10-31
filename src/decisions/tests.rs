// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The decision set's model rows: the access projection, the live-grant
//! closing check, health, snapshot and revision.

use chrono::{DateTime, Duration, TimeZone as _, Utc};

use super::{DecisionSet, Fold, Health, LogPos, Source, UiDecision};
use crate::identity_grants::{
    GrantAgent, GrantAgentKey, GrantScope, GrantSubject, IdentityGrant, IdentityGrantAuditEvent,
    IdentityGrantDecisionReason,
};
use crate::security::ProofSource;

const KEY: [u8; 32] = [7; 32];
const AGENT: &str = "mtls:runner";

fn at(minute: i64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 28, 12, 0, 0).unwrap()
        + Duration::try_minutes(minute).expect("a test minute is in range")
}

fn ready() -> DecisionSet {
    let mut set = DecisionSet::with_key(KEY);
    for source in [Source::Access, Source::ControlPlane, Source::Capability] {
        set.set_health(source, Health::Ready);
    }
    set.set_discovery(Vec::new(), Vec::new(), at(0));
    set
}

fn denial(
    capability: &str,
    reason: IdentityGrantDecisionReason,
    minute: i64,
) -> IdentityGrantAuditEvent {
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
    denial(
        capability,
        IdentityGrantDecisionReason::MissingGrant,
        minute,
    )
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

fn pos(log: Source, offset: u64) -> LogPos {
    LogPos {
        log,
        entry: format!("hash-{offset}"),
        counter: offset,
    }
}

/// Deliver a denial live at transparency-log offset `offset`.
fn deny(set: &mut DecisionSet, offset: u64, event: &IdentityGrantAuditEvent) {
    set.live(pos(Source::Access, offset), Fold::Denial(event.clone()));
}

fn decision(capability: &str, minute: i64) -> UiDecision {
    UiDecision {
        authority: "https://idp.example".to_string(),
        subject: "alice".to_string(),
        agent: AGENT.to_string(),
        capability: capability.to_string(),
        at: at(minute),
    }
}

/// Deliver a UI decision live at control-plane offset `offset`.
fn decide(set: &mut DecisionSet, offset: u64, capability: &str, minute: i64) {
    set.live(
        pos(Source::ControlPlane, offset),
        Fold::Decided(decision(capability, minute)),
    );
}

fn count(set: &DecisionSet) -> usize {
    set.snapshot().expect("all sources ready").0
}

#[test]
fn a_missing_grant_with_a_proven_agent_opens_one_access_request() {
    let mut set = ready();
    deny(&mut set, 101, &missing("stripe.charges", 1));
    deny(&mut set, 102, &missing("stripe.refunds", 2));
    let list = set.list();
    assert_eq!(list.len(), 1, "one item per subject and agent: {list:?}");
    assert_eq!(list[0]["kind"], "access_request");
    assert_eq!(list[0]["scope"].as_array().map(Vec::len), Some(2));
}

#[test]
fn every_a1_exclusion_opens_nothing() {
    use IdentityGrantDecisionReason as R;
    let mut set = ready();
    for (offset, reason) in [
        R::MissingIdentity,
        R::MissingOwner,
        R::OwnerMismatch,
        R::PublicCapability,
        R::SharedCapability,
        R::GrantMatched,
    ]
    .into_iter()
    .enumerate()
    {
        deny(
            &mut set,
            200 + offset as u64,
            &denial("stripe.charges", reason, 1),
        );
    }
    let mut no_agent = missing("stripe.charges", 1);
    no_agent.agent_id = None;
    deny(&mut set, 104, &no_agent);
    let mut no_subject = missing("stripe.charges", 1);
    no_subject.subject = None;
    deny(&mut set, 105, &no_subject);
    // The positive control: the same set does open on a real missing grant.
    assert_eq!(count(&set), 0);
    deny(&mut set, 106, &missing("stripe.charges", 2));
    assert_eq!(count(&set), 1);
}

#[test]
fn a_newer_ui_decision_closes_and_a_newer_denial_reopens() {
    let mut set = ready();
    deny(&mut set, 107, &missing("stripe.charges", 1));
    decide(&mut set, 121, "stripe.charges", 2);
    assert_eq!(count(&set), 0);
    deny(&mut set, 108, &missing("stripe.charges", 3));
    assert_eq!(count(&set), 1);
}

#[test]
fn an_older_ui_decision_leaves_the_item_open() {
    let mut set = ready();
    deny(&mut set, 109, &missing("stripe.charges", 5));
    decide(&mut set, 122, "stripe.charges", 4);
    assert_eq!(count(&set), 1);
}

#[test]
fn a_covering_grant_closes_and_its_expiry_reopens() {
    let mut set = ready();
    deny(&mut set, 110, &missing("stripe.charges", 1));
    assert_eq!(count(&set), 1, "open before the row");
    let mut row = grant("stripe.charges", GrantScope::Execute);
    row.expires_at = Some(at(10));
    set.set_grants(vec![row], at(2));
    assert_eq!(count(&set), 0, "a live covering row closes it");
    set.expire(at(11));
    assert_eq!(
        count(&set),
        1,
        "the denial outlives the row that covered it"
    );
}

#[test]
fn a_row_that_evaluate_would_not_match_leaves_the_item_open() {
    let other = GrantSubject::new("https://idp.example", "bob", None);
    let rows: Vec<(&str, IdentityGrant)> = vec![
        ("narrower scope", grant("stripe.charges", GrantScope::Read)),
        ("other capability", grant("stripe.refunds", GrantScope::Any)),
        (
            "other agent",
            IdentityGrant {
                agent: GrantAgent::Exact(GrantAgentKey {
                    source: ProofSource::VerifiedJwtSubject,
                    id: "runner".to_string(),
                }),
                ..grant("stripe.charges", GrantScope::Any)
            },
        ),
        (
            "other subject",
            IdentityGrant {
                subject: other.clone(),
                ..grant("stripe.charges", GrantScope::Any)
            },
        ),
        (
            "other owner",
            IdentityGrant {
                owner: Some(other),
                ..grant("stripe.charges", GrantScope::Any)
            },
        ),
        (
            "revoked",
            IdentityGrant {
                revoked_at: Some(at(0)),
                ..grant("stripe.charges", GrantScope::Any)
            },
        ),
        (
            "other tool",
            IdentityGrant {
                tool: Some("refund".to_string()),
                ..grant("stripe.charges", GrantScope::Any)
            },
        ),
    ];
    for (why, row) in rows {
        let mut set = ready();
        let mut note = missing("stripe.charges", 1);
        note.tool = Some("charge".to_string());
        deny(&mut set, 111, &note);
        assert_eq!(count(&set), 1, "{why}: open before the row");
        set.set_grants(vec![row], at(2));
        assert_eq!(count(&set), 1, "{why}");
    }
}

#[test]
fn every_row_evaluate_would_match_closes_the_item() {
    let rows: Vec<(&str, IdentityGrant)> = vec![
        ("exact", grant("stripe.charges", GrantScope::Execute)),
        ("wider scope", grant("stripe.charges", GrantScope::Any)),
        (
            "any agent",
            IdentityGrant {
                agent: GrantAgent::Any,
                ..grant("stripe.charges", GrantScope::Execute)
            },
        ),
        (
            "same owner",
            IdentityGrant {
                owner: Some(GrantSubject::new(
                    "https://idp.example",
                    "alice",
                    Some("label".to_string()),
                )),
                ..grant("stripe.charges", GrantScope::Execute)
            },
        ),
        (
            "same tool",
            IdentityGrant {
                tool: Some("charge".to_string()),
                ..grant("stripe.charges", GrantScope::Execute)
            },
        ),
    ];
    for (why, row) in rows {
        let mut set = ready();
        let mut note = missing("stripe.charges", 1);
        note.tool = Some("charge".to_string());
        deny(&mut set, 112, &note);
        assert_eq!(count(&set), 1, "{why}: open before the row");
        set.set_grants(vec![row], at(2));
        assert_eq!(count(&set), 0, "{why}");
    }
}

#[test]
fn snapshot_is_none_while_a_source_is_unavailable() {
    let mut set = ready();
    assert_eq!(set.snapshot().map(|s| s.0), Some(0));
    set.set_health(Source::ControlPlane, Health::Unavailable);
    assert_eq!(set.snapshot(), None);
    set.set_health(Source::ControlPlane, Health::Absent);
    assert_eq!(
        set.snapshot().map(|s| s.0),
        Some(0),
        "an absent source is not an error"
    );
    assert_eq!(
        DecisionSet::with_key(KEY).snapshot(),
        None,
        "sources start unavailable"
    );
}

#[test]
fn revision_rises_on_open_close_and_field_change_and_not_on_a_no_op() {
    let mut set = ready();
    let rev = |set: &DecisionSet| set.snapshot().expect("ready").1;
    let r0 = rev(&set);
    deny(&mut set, 113, &missing("stripe.charges", 1));
    let r1 = rev(&set);
    assert!(r1 > r0, "open");
    deny(&mut set, 114, &missing("stripe.refunds", 2));
    let r2 = rev(&set);
    assert!(r2 > r1, "a scope entry added to an open item");
    set.expire(at(3));
    assert_eq!(rev(&set), r2, "nothing changed");
    decide(&mut set, 123, "stripe.charges", 4);
    decide(&mut set, 124, "stripe.refunds", 4);
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
                1 => deny(&mut set, 115, &denial_1),
                2 => decide(&mut set, 125, "stripe.charges", 2),
                _ => deny(&mut set, 116, &denial_3),
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
    deny(&mut once, 117, &denial_1);
    decide(&mut once, 126, "stripe.charges", 2);
    decide(&mut once, 126, "stripe.charges", 2);
    deny(&mut once, 117, &denial_1);
    assert_eq!(
        count(&once),
        0,
        "a replayed older denial cannot resurrect a declined request"
    );
}

#[test]
fn eviction_closes_a_request_whose_refusals_left_the_log() {
    let mut set = ready();
    deny(&mut set, 119, &missing("stripe.charges", 1));
    // Timed before the other, but written after it: its record is kept.
    deny(&mut set, 120, &missing("stripe.refunds", 0));
    set.evict_before(120);
    let list = set.list();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["scope"].as_array().map(Vec::len), Some(1));
}

/// A set just built: every source unavailable until its replay finishes.
fn booting() -> DecisionSet {
    let mut set = DecisionSet::with_key(KEY);
    set.set_health(Source::Capability, Health::Absent);
    set.set_discovery(Vec::new(), Vec::new(), at(0));
    set
}

fn replay_all(set: &mut DecisionSet, logs_first: Source) {
    let denial = Fold::Denial(missing("stripe.charges", 1));
    let declined = Fold::Decided(decision("stripe.charges", 2));
    let later = Fold::Denial(missing("stripe.refunds", 3));
    let steps = [
        (Source::Access, vec![(1, denial), (2, later)]),
        (Source::ControlPlane, vec![(1, declined)]),
    ];
    let order: Vec<_> = if logs_first == Source::Access {
        steps.into_iter().collect()
    } else {
        steps.into_iter().rev().collect()
    };
    for (log, events) in order {
        for (offset, event) in events {
            set.replayed(pos(log, offset), event);
        }
        set.replay_done(log);
    }
}

#[test]
fn replaying_the_two_logs_in_either_order_gives_the_same_set() {
    let mut access_first = booting();
    replay_all(&mut access_first, Source::Access);
    let mut audit_first = booting();
    replay_all(&mut audit_first, Source::ControlPlane);
    assert_eq!(access_first.list(), audit_first.list());
    assert_eq!(
        access_first.list().len(),
        1,
        "refunds stays open, charges was declined"
    );
}

#[test]
fn an_admin_decline_does_not_come_back_after_a_restart() {
    for first in [Source::Access, Source::ControlPlane] {
        let mut set = booting();
        replay_all(&mut set, first);
        let list = set.list();
        assert_eq!(list.len(), 1, "{first:?}: refunds stays open: {list:?}");
        let scope = list[0]["scope"].as_array().expect("scope").clone();
        assert_eq!(scope.len(), 1, "{first:?}: {list:?}");
        assert_eq!(scope[0]["capability"], "stripe.refunds", "{first:?}");
    }
}

#[test]
fn an_event_seen_twice_is_applied_once() {
    let mut set = ready();
    let charge = missing("stripe.charges", 1);
    deny(&mut set, 1, &charge);
    deny(&mut set, 1, &charge);
    assert_eq!(set.list().len(), 1, "one request");
    assert_eq!(
        set.list()[0]["refused_calls"],
        1,
        "same position: one refusal"
    );
    deny(&mut set, 2, &charge);
    assert_eq!(
        set.list()[0]["refused_calls"],
        2,
        "a second position is a second refusal"
    );
}

#[test]
fn a_live_event_during_replay_is_neither_lost_nor_counted_twice() {
    let mut set = booting();
    set.replayed(
        pos(Source::Access, 1),
        Fold::Denial(missing("stripe.charges", 1)),
    );
    // Written after the cut-off: arrives only live.
    set.live(
        pos(Source::Access, 3),
        Fold::Denial(missing("stripe.charges", 3)),
    );
    // Written before the cut-off: arrives by both paths.
    set.live(
        pos(Source::Access, 2),
        Fold::Denial(missing("stripe.charges", 2)),
    );
    set.replayed(
        pos(Source::Access, 2),
        Fold::Denial(missing("stripe.charges", 2)),
    );
    assert_eq!(set.snapshot(), None, "held while the replay runs");
    set.replay_done(Source::Access);
    assert_eq!(
        set.snapshot(),
        None,
        "the control-plane replay is still running"
    );
    set.replay_done(Source::ControlPlane);
    assert_eq!(set.snapshot().map(|s| s.0), Some(1));
    assert_eq!(set.list()[0]["refused_calls"], 3);
}

fn change(path: &str, actual: &str, loaded_as: Option<&str>) -> super::CapabilityChange {
    super::CapabilityChange {
        file: path.to_string(),
        actual: actual.to_string(),
        loaded_as: loaded_as.map(str::to_string),
        content: "name: stripe.charges\ndescription: d\n".to_string(),
    }
}

#[test]
fn the_capability_source_is_unavailable_until_its_backend_reports() {
    let mut set = DecisionSet::with_key(KEY);
    set.set_health(Source::Access, Health::Ready);
    set.set_health(Source::ControlPlane, Health::Ready);
    set.set_discovery(Vec::new(), Vec::new(), at(0));
    assert_eq!(set.snapshot(), None);
    set.set_capability_changes(
        "caps",
        vec![change("/c/a.yaml", "h1", Some("stripe.charges"))],
        at(1),
    );
    assert_eq!(set.snapshot().map(|s| s.0), Some(1));
}

#[test]
fn an_access_request_waits_on_the_change_to_its_trusted_capability() {
    let mut set = ready();
    deny(&mut set, 1, &missing("stripe.charges", 1));
    // The changed bytes may claim any name; the link follows the trusted one.
    set.set_capability_changes(
        "caps",
        vec![change("/c/a.yaml", "h1", Some("stripe.charges"))],
        at(2),
    );
    let list = set.list();
    assert_eq!(list.len(), 2);
    assert_eq!(
        list[0]["kind"], "capability_changed",
        "the blocking item comes first"
    );
    assert_eq!(
        list[1]["waits_on"],
        serde_json::json!([list[0]["id"].clone()])
    );
}

#[test]
fn an_untrusted_change_blocks_nothing() {
    let mut set = ready();
    deny(&mut set, 1, &missing("stripe.charges", 1));
    set.set_capability_changes("caps", vec![change("/c/a.yaml", "h1", None)], at(2));
    let list = set.list();
    let access = list
        .iter()
        .find(|item| item["kind"] == "access_request")
        .expect("access item");
    assert_eq!(access["waits_on"], serde_json::json!([]));
}

#[test]
fn the_view_names_missing_and_partial_kinds_and_carries_the_snapshot_revision() {
    let mut set = ready();
    deny(&mut set, 1, &missing("stripe.charges", 1));
    let view = set.view().expect("ready");
    assert_eq!(view.missing_kinds, vec!["adopt"]);
    assert_eq!(view.partial_kinds, vec!["capability_changed"]);
    assert_eq!(Some((view.decisions.len(), view.revision)), set.snapshot());
    assert_eq!(DecisionSet::with_key(KEY).view(), None);
}

#[test]
fn no_name_or_text_from_changed_bytes_reaches_the_list() {
    const CANARY: &str = "Zq7canary";
    let content = format!(
        "name: tool{CANARY}\ndescription: desc{CANARY}\nschema:\n  input:\n    type: object\n    properties:\n      prop{CANARY}:\n        type: str{CANARY}\n        default: def{CANARY}\n        examples: [ex{CANARY}]\n        const: const{CANARY}\n    required: [prop{CANARY}]\n"
    );
    let mut set = ready();
    set.set_capability_changes(
        "caps",
        vec![super::CapabilityChange {
            content,
            ..change("/c/a.yaml", "h1", Some("stripe.charges"))
        }],
        at(1),
    );
    let view = set.view().expect("ready");
    assert_eq!(view.decisions.len(), 1, "the change is listed");
    let text = serde_json::to_string(&view.decisions).expect("serialize");
    assert!(!text.contains(CANARY), "{text}");
    assert!(
        text.contains("stripe.charges"),
        "the trusted name is shown: {text}"
    );
}

#[test]
fn a_changed_capability_carries_the_inferred_risk_class() {
    let mut set = ready();
    let content = "name: stripe_charges\ndescription: Charge a card\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://api.stripe.com\n      path: /v1/charges\n".to_string();
    set.set_capability_changes(
        "caps",
        vec![super::CapabilityChange {
            content,
            ..change("/c/a.yaml", "h1", Some("stripe_charges"))
        }],
        at(1),
    );
    let item = &set.list()[0];
    assert_eq!(item["scan_basis"], "inferred", "{item}");
    assert!(
        serde_json::from_value::<crate::trust::TrustRiskClass>(item["scan"].clone()).is_ok(),
        "the scan is a trust risk class: {item}"
    );

    let mut unparsed = ready();
    unparsed.set_capability_changes("caps", vec![change("/c/b.yaml", "h2", None)], at(1));
    let item = &unparsed.list()[0];
    assert_eq!(item["scan"], serde_json::Value::Null, "{item}");
    assert_eq!(item["scan_reason"], "unparsed", "{item}");
}

#[test]
fn scanning_a_changed_capability_makes_no_credential_lookup() {
    use crate::secrets::lookup_probe::calls;

    // Control: the probe counts a resolver call on this thread.
    let before = calls();
    let _ = crate::secrets::SecretResolver::new().resolve("{env.DECISIONS_PROBE_UNSET}");
    assert_eq!(calls(), before + 1, "the probe counts a lookup");

    let content = "name: probe_refs\ndescription: Holds references\nauth:\n  required: true\n  type: bearer\n  key: keychain:decisions-probe\nproviders:\n  primary:\n    service: rest\n    config:\n      base_url: https://{env.DECISIONS_PROBE_HOST}/v1\n      path: /items\n".to_string();
    let start = calls();
    let mut set = ready();
    set.set_capability_changes(
        "caps",
        vec![super::CapabilityChange {
            content,
            ..change("/c/a.yaml", "h1", Some("probe_refs"))
        }],
        at(1),
    );
    let item = &set.list()[0];
    assert!(!item["scan"].is_null(), "the scan parsed and ran: {item}");
    assert_eq!(calls(), start, "no secret or env reference was looked up");
}

#[test]
fn a_record_naming_no_one_reads_back_as_no_request() {
    let record = |authority: &str, subject: &str| {
        let serde_json::Value::Object(fields) = serde_json::json!({
            "kind": super::GRANT_DECISION_KIND,
            "timestamp": at(1).to_rfc3339(),
            "reason": "missing_grant",
            "capability": "stripe.charges",
            "scope": "execute",
            "agent_id": AGENT,
            "subject": {"authority": authority, "subject": subject},
        }) else {
            unreachable!("a JSON object literal")
        };
        fields
    };
    assert!(super::denial_from_record(&record("https://idp.example", "alice")).is_some());
    for (authority, subject) in [("", ""), ("https://idp.example", ""), ("", "alice")] {
        assert!(
            super::denial_from_record(&record(authority, subject)).is_none(),
            "({authority:?}, {subject:?}) names no one"
        );
    }
    let mut no_subject = record("", "");
    no_subject.remove("subject");
    assert!(super::denial_from_record(&no_subject).is_none());
}

#[test]
fn an_empty_subject_is_never_covered_by_a_grant() {
    let mut set = ready();
    let nobody = super::AccessKey {
        authority: String::new(),
        subject: String::new(),
        agent: AGENT.to_string(),
    };
    let requested = super::Requested {
        scope: Some(GrantScope::Execute),
        ..super::Requested::default()
    };
    // A row for the same empty subject: `GrantSubject::new` would match it.
    let row = IdentityGrant {
        subject: GrantSubject::new("", "", None),
        owner: None,
        ..grant("stripe.charges", GrantScope::Any)
    };
    set.set_grants(vec![row], at(2));
    assert!(!set.covered(&nobody, "stripe.charges", &requested));
}

#[test]
fn held_notes_are_bounded_and_a_lost_one_forces_another_replay() {
    let mut set = booting();
    set.replay_done(Source::ControlPlane);
    let over = super::HELD_CAP + 3;
    for n in 0..over {
        let capability = format!("cap.{n}");
        set.live(
            pos(Source::Access, n as u64),
            Fold::Denial(missing(&capability, 1)),
        );
    }
    assert_eq!(set.held.len(), super::HELD_CAP, "memory stays bounded");

    // The replay that was running did not see the dropped notes.
    assert!(!set.replay_done(Source::Access), "a lost note is not ready");
    assert_eq!(set.snapshot(), None, "never a count missing notes");

    // The next replay reads every note back from the log.
    for n in 0..over {
        let capability = format!("cap.{n}");
        set.replayed(
            pos(Source::Access, n as u64),
            Fold::Denial(missing(&capability, 1)),
        );
    }
    assert!(set.replay_done(Source::Access));
    assert_eq!(set.list()[0]["scope"].as_array().map(Vec::len), Some(over));
}

#[test]
fn a_lost_note_affects_only_its_own_log() {
    let mut set = booting();
    // A UI decision held for the control-plane log.
    set.live(
        pos(Source::ControlPlane, 1),
        Fold::Decided(decision("stripe.charges", 9)),
    );
    for n in 0..=super::HELD_CAP {
        let capability = format!("cap.{n}");
        set.live(
            pos(Source::Access, n as u64),
            Fold::Denial(missing(&capability, 1)),
        );
    }
    assert!(
        !set.replay_done(Source::Access),
        "the access log lost a note"
    );
    assert!(
        set.held
            .iter()
            .any(|(pos, _)| pos.log == Source::ControlPlane),
        "the other log's held event is kept"
    );
}

mod discovery;
