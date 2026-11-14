// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `audit verify` and `settle` hold each settle role to its fields: every
//! field missing or mistyped fails, and `settled_by` only on an outcome.

use serde_json::{Map, Value, json};

use super::pairing_tests::*;
use super::rotation_tests::{cfg, log_path};
use super::*;

pub(super) const STOPPED: &str = "config_write_delivery_stopped";

/// A pairing failure at `at` naming `rule` (a field rule), the chain passing.
pub(super) fn assert_field_fails(r: &VerifyResult, at: u64, rule: &str, what: &str) {
    assert!(!r.ok, "{what}: passed");
    assert_eq!(r.failed_check, FailedCheck::Pairing, "{what}");
    assert_eq!(
        r.error_at_counter,
        Some(at),
        "{what}: {:?}",
        r.error_message
    );
    let msg = r.error_message.as_deref().unwrap_or_default();
    assert!(msg.contains(rule), "{what}: {msg}");
}

/// `record` with `edit` applied: `None` removes the field.
pub(super) fn with_field(
    mut record: Map<String, Value>,
    field: &str,
    edit: Option<Value>,
) -> Map<String, Value> {
    match edit {
        Some(v) => record.insert(field.into(), v),
        None => record.remove(field),
    };
    record
}

/// (case, a role's well-formed record, field, edit, the rule it breaks)
type FieldCase = (
    &'static str,
    Map<String, Value>,
    &'static str,
    Option<Value>,
    &'static str,
);

/// Every role's fields, each missing or mistyped (step 3 section 2).
#[expect(
    clippy::too_many_lines,
    reason = "one table of every role's field cases reads as one"
)]
fn field_cases() -> Vec<FieldCase> {
    let intent = || rec(INTENT, "w-1", &json!({}));
    let by = |v: Value| json!({"intent_counter": 3, "settled_by": v});
    // (case, the role's well-formed record, field, edit, rule)
    vec![
        (
            "intent no token",
            intent(),
            "token",
            None,
            "field token missing",
        ),
        (
            "intent token number",
            intent(),
            "token",
            Some(json!(5)),
            "field token mistyped",
        ),
        (
            "intent token empty",
            intent(),
            "token",
            Some(json!("")),
            "field token mistyped",
        ),
        (
            "intent counter",
            intent(),
            "intent_counter",
            Some(json!(1)),
            "field intent_counter forbidden",
        ),
        (
            "recovery no settles",
            rec(RECOVERY, "r-1", &json!({"settles": "w-1"})),
            "settles",
            None,
            "field settles missing",
        ),
        (
            "recovery settles empty",
            rec(RECOVERY, "r-1", &json!({"settles": "w-1"})),
            "settles",
            Some(json!("")),
            "field settles mistyped",
        ),
        (
            "recovery counter",
            rec(RECOVERY, "r-1", &json!({"settles": "w-1"})),
            "intent_counter",
            Some(json!(3)),
            "field intent_counter forbidden",
        ),
        (
            "outcome no counter",
            dep(OUTCOME, "w-1", 3),
            "intent_counter",
            None,
            "field intent_counter missing",
        ),
        (
            "outcome counter text",
            dep(OUTCOME, "w-1", 3),
            "intent_counter",
            Some(json!("3")),
            "field intent_counter mistyped",
        ),
        (
            "outcome settled_by number",
            rec(OUTCOME, "w-1", &by(json!(5))),
            "kind",
            Some(json!("settle.save")),
            "field settled_by mistyped",
        ),
        (
            "outcome settled_by empty token",
            rec(
                OUTCOME,
                "w-1",
                &by(json!({"token": "", "intent_counter": 1})),
            ),
            "kind",
            Some(json!("settle.save")),
            "field settled_by.token mistyped",
        ),
        (
            "outcome settled_by no counter",
            rec(OUTCOME, "w-1", &by(json!({"token": "r-1"}))),
            "kind",
            Some(json!("settle.save")),
            "field settled_by.intent_counter missing",
        ),
        (
            "abandoned counter text",
            dep(ABANDONED, "w-1", 3),
            "intent_counter",
            Some(json!("3")),
            "field intent_counter mistyped",
        ),
        (
            "deferred no counter",
            dep(DEFERRED, "w-1", 3),
            "intent_counter",
            None,
            "field intent_counter missing",
        ),
        (
            "stopped counter negative",
            dep(STOPPED, "w-1", 3),
            "intent_counter",
            Some(json!(-1)),
            "field intent_counter mistyped",
        ),
    ]
}

#[test]
fn each_role_fails_on_each_field_missing_or_mistyped() {
    let intent = || rec(INTENT, "w-1", &json!({}));
    let by = |v: Value| json!({"intent_counter": 3, "settled_by": v});
    // (case, the role's well-formed record, field, edit, rule)
    let cases = field_cases();
    for (what, record, field, edit, rule) in cases {
        let intent_role = record["event"] == INTENT || record["event"] == RECOVERY;
        let bad = with_field(record, field, edit);
        let (records, at) = if intent_role {
            (vec![bad], 3)
        } else {
            (vec![intent(), bad], 4)
        };
        assert_field_fails(&verify_records(records), at, rule, what);
    }
    // Controls: each role's well-formed record passes, abandoned with no
    // intent_counter (never delivered) included.
    let ok = verify_records(vec![
        intent(),
        rec(RECOVERY, "r-1", &json!({"settles": "w-1"})),
        dep(DEFERRED, "w-1", 3),
        dep(STOPPED, "w-1", 3),
        rec(
            OUTCOME,
            "w-1",
            &by(json!({"token": "r-1", "intent_counter": 4})),
        ),
        rec(INTENT, "w-2", &json!({})),
        rec(ABANDONED, "w-2", &json!({})),
    ]);
    assert_paired(&ok, "well-formed roles");
}

#[tokio::test]
async fn settle_refuses_a_payload_that_breaks_its_roles_fields() {
    use super::settle::{FieldFault, FieldProblem, IntentKind, InvalidPayload, Role, Unsettled};
    use super::settle_tests::on_disk;
    use FieldProblem::{Forbidden, Missing, Mistyped};
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let l = std::sync::Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    let own = l.log_id();
    let save = Role::Intent(IntentKind::Save);
    let fault = |field: &'static str, problem| InvalidPayload::Field(FieldFault { field, problem });
    let by = json!({"token": "", "intent_counter": 1});
    let cases = [
        (
            "outcome no counter",
            "w-1",
            Role::Outcome,
            json!({}),
            fault("intent_counter", Missing),
        ),
        (
            "intent counter",
            "w-1",
            save,
            json!({"intent_counter": 3}),
            fault("intent_counter", Forbidden),
        ),
        (
            "recovery no settles",
            "r-1",
            Role::RecoveryIntent,
            json!({}),
            fault("settles", Missing),
        ),
        (
            "settled_by empty token",
            "w-1",
            Role::Outcome,
            json!({"intent_counter": 3, "settled_by": by}),
            fault("settled_by.token", Mistyped),
        ),
        ("empty token", "", save, json!({}), fault("token", Mistyped)),
        (
            "deferred counter text",
            "w-1",
            Role::Deferred,
            json!({"intent_counter": "3"}),
            fault("intent_counter", Mistyped),
        ),
    ];
    for (what, token, role, extra, want) in cases {
        let before = on_disk(&path);
        let got = l.settle(&own, token, role, payload(&extra)).await;
        assert!(
            matches!(&got, Err(Unsettled::Invalid(f)) if *f == want),
            "{what}: {got:?}"
        );
        assert!(on_disk(&path) == before, "{what}: appended");
    }
    // Controls: the same roles, well formed, settle.
    let controls = [
        (save, "w-1", json!({})),
        (Role::RecoveryIntent, "r-1", json!({"settles": "w-1"})),
        (Role::Deferred, "w-1", json!({"intent_counter": 3})),
        (Role::Outcome, "w-1", json!({"intent_counter": 3})),
    ];
    for (role, token, extra) in controls {
        let got = l.settle(&own, token, role, payload(&extra)).await;
        assert!(got.is_ok(), "{role:?}: {got:?}");
    }
}

#[tokio::test]
async fn settle_refuses_settled_by_on_every_role_but_outcome() {
    use super::settle::{FieldFault, FieldProblem, IntentKind, InvalidPayload, Role, Unsettled};
    let dir = crate::test_dir_keep::kept_tempdir();
    let path = log_path(&dir);
    let l = std::sync::Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    let own = l.log_id();
    let by = json!({"token": "r-1", "intent_counter": 1});
    let want = InvalidPayload::Field(FieldFault {
        field: "settled_by",
        problem: FieldProblem::Forbidden,
    });
    let roles = [
        (Role::Intent(IntentKind::Save), json!({"settled_by": by})),
        (
            Role::RecoveryIntent,
            json!({"settles": "w-1", "settled_by": by}),
        ),
        (Role::Abandoned, json!({"settled_by": by})),
        (
            Role::Deferred,
            json!({"intent_counter": 3, "settled_by": by}),
        ),
        (
            Role::DeliveryStopped,
            json!({"intent_counter": 3, "settled_by": by}),
        ),
    ];
    for (role, extra) in roles {
        let got = l.settle(&own, "w-1", role, payload(&extra)).await;
        assert!(
            matches!(&got, Err(Unsettled::Invalid(f)) if *f == want),
            "{role:?}: {got:?}"
        );
    }
    // Control: an outcome may carry it.
    let outcome = payload(&json!({"intent_counter": 3, "settled_by": by}));
    let got = l.settle(&own, "w-1", Role::Outcome, outcome).await;
    assert!(got.is_ok(), "{got:?}");
}

#[test]
fn verify_fails_settled_by_on_every_role_but_outcome() {
    let by = json!({"token": "r-1", "intent_counter": 4});
    let head = || {
        vec![
            rec(INTENT, "w-1", &json!({})),
            rec(RECOVERY, "r-1", &json!({"settles": "w-1"})),
        ]
    };
    let cases = [
        (
            "writer intent",
            rec(INTENT, "w-2", &json!({"settled_by": by})),
        ),
        (
            "recovery intent",
            rec(
                RECOVERY,
                "r-2",
                &json!({"settles": "w-1", "settled_by": by}),
            ),
        ),
        (
            "abandoned",
            rec(ABANDONED, "w-1", &json!({"settled_by": by})),
        ),
        (
            "deferred",
            rec(
                DEFERRED,
                "w-1",
                &json!({"intent_counter": 3, "settled_by": by}),
            ),
        ),
        (
            "stopped",
            rec(
                STOPPED,
                "w-1",
                &json!({"intent_counter": 3, "settled_by": by}),
            ),
        ),
    ];
    for (what, bad) in cases {
        let r = verify_records([head(), vec![bad]].concat());
        assert_field_fails(&r, 5, "field settled_by forbidden", what);
    }
    // Control: on an outcome it pairs.
    let ok = verify_records([head(), vec![settled("w-1", 3, "r-1", 4)]].concat());
    assert_paired(&ok, "outcome settled_by");
}

#[test]
fn every_role_fails_on_each_of_its_fields_missing_or_mistyped() {
    use FieldEdit::{Drop, Set};
    // (event, its well-formed extra fields, whether it is an intent)
    let mut roles: Vec<(&str, Value, bool)> = WRITER_INTENTS
        .iter()
        .map(|k| (*k, json!({}), true))
        .collect();
    roles.push((RECOVERY, json!({"settles": "w-0"}), true));
    roles.push((OUTCOME, json!({"intent_counter": 3}), false));
    roles.push((ABANDONED, json!({"intent_counter": 3}), false));
    roles.push((DEFERRED, json!({"intent_counter": 3}), false));
    roles.push((STOPPED, json!({"intent_counter": 3}), false));
    for (event, extra, intent_role) in roles {
        let mut edits = vec![
            ("token", Drop, "field token missing"),
            ("token", Set(json!(7)), "field token mistyped"),
            ("token", Set(json!("")), "field token mistyped"),
        ];
        if intent_role {
            edits.push((
                "intent_counter",
                Set(json!(3)),
                "field intent_counter forbidden",
            ));
        } else {
            edits.push((
                "intent_counter",
                Set(json!("3")),
                "field intent_counter mistyped",
            ));
            edits.push((
                "intent_counter",
                Set(json!(-1)),
                "field intent_counter mistyped",
            ));
            if event != ABANDONED {
                edits.push(("intent_counter", Drop, "field intent_counter missing"));
            }
        }
        if event == RECOVERY {
            edits.push(("settles", Drop, "field settles missing"));
            edits.push(("settles", Set(json!(7)), "field settles mistyped"));
            edits.push(("settles", Set(json!("")), "field settles mistyped"));
        }
        if event == OUTCOME {
            for (by, rule) in [
                (json!(5), "field settled_by mistyped"),
                (
                    json!({"intent_counter": 1}),
                    "field settled_by.token missing",
                ),
                (
                    json!({"token": 5, "intent_counter": 1}),
                    "field settled_by.token mistyped",
                ),
                (
                    json!({"token": "r-1"}),
                    "field settled_by.intent_counter missing",
                ),
                (
                    json!({"token": "r-1", "intent_counter": "1"}),
                    "field settled_by.intent_counter mistyped",
                ),
            ] {
                edits.push(("settled_by", Set(by), rule));
            }
        }
        for (field, edit, rule) in edits {
            let what = format!("{event} {field} {rule}");
            let bad = match edit {
                Drop => with_field(rec(event, "w-1", &extra), field, None),
                Set(v) => with_field(rec(event, "w-1", &extra), field, Some(v)),
            };
            let (records, at) = if intent_role {
                (vec![bad], 3)
            } else {
                (vec![rec(INTENT, "w-1", &json!({})), bad], 4)
            };
            assert_field_fails(&verify_records(records), at, rule, &what);
        }
    }
}

/// How the field sweep breaks a field.
enum FieldEdit {
    Drop,
    Set(Value),
}
