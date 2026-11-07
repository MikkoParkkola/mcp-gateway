// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `audit verify` pairs settle records: each row brackets its claim with a
//! case that needs a finding, so a verifier that pairs nothing fails it.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use super::identity_tests::rechain;
use super::rotation_tests::{cfg, lines, log_path};
use super::*;

pub(super) const INTENT: &str = "config_save_intent";
pub(super) const OUTCOME: &str = "config_write_outcome";
pub(super) const ABANDONED: &str = "config_write_abandoned";
pub(super) const DEFERRED: &str = "config_write_deferred";

/// A settle-shaped record: `event`, `token`, a prefixed `kind`, and `extra`.
pub(super) fn rec(event: &str, token: &str, extra: &Value) -> Map<String, Value> {
    let mut m = json!({"event": event, "token": token, "kind": "settle.save"});
    m.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    m.as_object().unwrap().clone()
}

/// A dependent of `token` naming the intent at `at`.
pub(super) fn dep(event: &str, token: &str, at: u64) -> Map<String, Value> {
    rec(event, token, &json!({"intent_counter": at}))
}

/// A fresh log (its open and identified records at counters 1 and 2) then
/// `records` from counter 3, re-chained, with `.hwm` at the tail.
pub(super) fn log_with(dir: &tempfile::TempDir, records: Vec<Map<String, Value>>) -> PathBuf {
    let path = log_path(dir);
    drop(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    let mut all: Vec<_> = lines(&path)
        .into_iter()
        .map(|v| v.as_object().unwrap().clone())
        .collect();
    assert_eq!(
        all.len(),
        2,
        "a fresh log holds its open and identified records"
    );
    all.extend(records);
    rechain(&path, all);
    path
}

pub(super) fn verified(path: &Path) -> VerifyResult {
    verify_segments(path, &cfg(path, 12, false), VerifyMode::Live).unwrap()
}

/// Verify `records` in a fresh log.
pub(super) fn verify_records(records: Vec<Map<String, Value>>) -> VerifyResult {
    let dir = tempfile::tempdir().unwrap();
    verified(&log_with(&dir, records))
}

/// Lines among `lines` that contain `needle`.
pub(super) fn count(lines: &[String], needle: &str) -> usize {
    lines.iter().filter(|l| l.contains(needle)).count()
}

pub(super) fn assert_paired(r: &VerifyResult, what: &str) {
    assert!(r.ok, "{what}: {:?} {:?}", r.error_message, r.warnings);
    assert!(r.error_at_counter.is_none(), "{what}");
}

/// A pairing failure (the chain passed) at `at`, naming `rule` and `token`.
pub(super) fn assert_fails(r: &VerifyResult, at: u64, rule: &str, token: &str) {
    assert!(!r.ok, "{rule}: passed");
    assert_eq!(r.failed_check, FailedCheck::Pairing, "{rule}");
    assert_eq!(
        r.error_at_counter,
        Some(at),
        "{rule}: {:?}",
        r.error_message
    );
    let msg = r.error_message.as_deref().unwrap_or_default();
    assert!(msg.contains(rule), "{rule}: {msg}");
    assert!(msg.contains(&format!("(token {token})")), "{token}: {msg}");
}

#[test]
fn equal_repeats_collapse_and_a_dependent_naming_the_second_pairs() {
    // GIVEN: one intent written twice, equal, and an outcome naming the
    // second; and (the bracket) another token's intent alone
    let r = verify_records(vec![
        rec(INTENT, "w-1", &json!({})),
        rec(INTENT, "w-1", &json!({})),
        dep(OUTCOME, "w-1", 4),
        rec(INTENT, "w-2", &json!({})),
    ]);

    // THEN: w-1 pairs with no warning; w-2 alone is interrupted
    assert_paired(&r, "collapsed repeats");
    assert_eq!(count(&r.warnings, "(token w-1)"), 0, "{:?}", r.warnings);
    assert_eq!(count(&r.warnings, "interrupted"), 1, "{:?}", r.warnings);
}

#[test]
fn a_dependent_naming_no_intent_of_its_token_and_role_fails() {
    const RULE: &str = "names no intent of its token at that counter";
    let note = || {
        json!({"event": "config_write_note"})
            .as_object()
            .unwrap()
            .clone()
    };
    // A counter between two equal repeats (a plain record sits there).
    let between = verify_records(vec![
        rec(INTENT, "w-1", &json!({})),
        note(),
        rec(INTENT, "w-1", &json!({})),
        dep(OUTCOME, "w-1", 4),
    ]);
    assert_fails(&between, 6, RULE, "w-1");
    // Another token's intent.
    let other_token = verify_records(vec![
        rec(INTENT, "w-1", &json!({})),
        rec(INTENT, "w-2", &json!({})),
        dep(OUTCOME, "w-1", 4),
    ]);
    assert_fails(&other_token, 5, RULE, "w-1");
    // Another role's record of the same token.
    let other_role = verify_records(vec![
        rec(INTENT, "w-1", &json!({})),
        dep(DEFERRED, "w-1", 3),
        dep(OUTCOME, "w-1", 4),
    ]);
    assert_fails(&other_role, 5, RULE, "w-1");
}

#[test]
fn an_intent_pairs_with_a_terminal_record_and_warns_without_one() {
    let intent = || rec(INTENT, "w-1", &json!({}));
    // Paired, no warning: outcome; abandoned; deferred then outcome.
    for (what, tail) in [
        ("outcome", vec![dep(OUTCOME, "w-1", 3)]),
        ("abandoned", vec![dep(ABANDONED, "w-1", 3)]),
        (
            "deferred then outcome",
            vec![dep(DEFERRED, "w-1", 3), dep(OUTCOME, "w-1", 3)],
        ),
    ] {
        let r = verify_records([vec![intent()], tail].concat());
        assert_paired(&r, what);
        assert_eq!(
            count(&r.warnings, "(token w-1)"),
            0,
            "{what}: {:?}",
            r.warnings
        );
    }
    // Deferred, no terminal: left to recovery.
    let deferred = verify_records(vec![intent(), dep(DEFERRED, "w-1", 3)]);
    assert!(deferred.ok, "{:?}", deferred.error_message);
    assert_eq!(
        count(&deferred.warnings, "left to recovery"),
        1,
        "{:?}",
        deferred.warnings
    );
    // Alone: interrupted.
    let alone = verify_records(vec![intent()]);
    assert!(alone.ok, "{:?}", alone.error_message);
    assert_eq!(
        count(&alone.warnings, "interrupted"),
        1,
        "{:?}",
        alone.warnings
    );
}

#[test]
fn a_token_and_role_with_two_different_records_fails() {
    const RULE: &str = "two different records for one token and role";
    let intent = || rec(INTENT, "w-1", &json!({}));
    let with = |event: &str, why: &str| {
        let mut r = dep(event, "w-1", 3);
        r.insert("reason".into(), why.into());
        r
    };
    let tagged = |why: &str| rec(INTENT, "w-1", &json!({"reason": why}));
    // (case, records with a differing repeat, the deciding counter)
    let cases = [
        ("intent", vec![tagged("a"), tagged("b")], 4),
        (
            "deferred",
            vec![
                intent(),
                with(DEFERRED, "a"),
                with(DEFERRED, "b"),
                dep(OUTCOME, "w-1", 3),
            ],
            5,
        ),
        (
            "outcome",
            vec![intent(), with(OUTCOME, "a"), with(OUTCOME, "b")],
            5,
        ),
        (
            "abandoned",
            vec![intent(), with(ABANDONED, "a"), with(ABANDONED, "b")],
            5,
        ),
        (
            "outcome vs abandoned",
            vec![intent(), with(OUTCOME, "a"), with(ABANDONED, "a")],
            5,
        ),
    ];
    for (what, records, at) in cases {
        let r = verify_records(records);
        assert!(!r.ok, "{what}: passed");
        assert_fails(&r, at, RULE, "w-1");
    }
    // Controls: the same shapes with equal repeats pair.
    let controls = [
        (
            "intent",
            vec![tagged("a"), tagged("a"), dep(OUTCOME, "w-1", 3)],
        ),
        (
            "deferred",
            vec![
                intent(),
                with(DEFERRED, "a"),
                with(DEFERRED, "a"),
                dep(OUTCOME, "w-1", 3),
            ],
        ),
        (
            "outcome",
            vec![intent(), with(OUTCOME, "a"), with(OUTCOME, "a")],
        ),
        (
            "abandoned",
            vec![intent(), with(ABANDONED, "a"), with(ABANDONED, "a")],
        ),
    ];
    for (what, records) in controls {
        assert_paired(&verify_records(records), what);
    }
}

#[test]
fn delivery_stopped_without_an_outcome_fails() {
    const STOPPED: &str = "config_write_delivery_stopped";
    let intent = || rec(INTENT, "w-1", &json!({}));
    let r = verify_records(vec![intent(), dep(STOPPED, "w-1", 3)]);
    assert_fails(&r, 4, "delivery stopped with no outcome", "w-1");
    // Control: with its outcome it pairs.
    let paired = verify_records(vec![
        intent(),
        dep(STOPPED, "w-1", 3),
        dep(OUTCOME, "w-1", 3),
    ]);
    assert_paired(&paired, "stopped then outcome");
}

#[tokio::test]
async fn two_equal_settles_of_one_intent_collapse() {
    use super::settle::{IntentKind, Role};
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let l = std::sync::Arc::new(TransparencyLogger::open(cfg(&path, 12, false)).unwrap());
    let own = l.log_id();
    let intent = || json!({"kind": "settle.save"}).as_object().unwrap().clone();
    let save = Role::Intent(IntentKind::Save);
    // GIVEN: one intent settled twice, equal, an outcome naming the second,
    // and (the bracket) another token's intent alone
    let first = l.settle(&own, "w-1", save, intent()).await.unwrap();
    let second = l.settle(&own, "w-1", save, intent()).await.unwrap();
    let outcome = json!({"kind": "settle.save", "intent_counter": second.counter});
    let outcome = outcome.as_object().unwrap().clone();
    l.settle(&own, "w-1", Role::Outcome, outcome).await.unwrap();
    l.settle(&own, "w-2", save, intent()).await.unwrap();
    drop(l);

    // The premise: the two records differ outside the caller's view.
    let all = lines(&path);
    let at = |c: u64| all.iter().find(|v| v["counter"] == c).unwrap().clone();
    let (a, b) = (at(first.counter), at(second.counter));
    for field in ["prev_entry_hash", "entry_hash", "trace_id"] {
        assert_ne!(a[field], b[field], "{field}");
    }

    // THEN: w-1 pairs with no warning; w-2 is interrupted
    let r = verified(&path);
    assert_paired(&r, "two settles");
    assert_eq!(count(&r.warnings, "(token w-1)"), 0, "{:?}", r.warnings);
    assert_eq!(count(&r.warnings, "interrupted"), 1, "{:?}", r.warnings);
}

pub(super) const RECOVERY: &str = "config_recovery_intent";

/// An outcome of `token` naming its intent at `at`, settled by the
/// recovery attempt `by` whose intent is at `by_at`.
pub(super) fn settled(token: &str, at: u64, by: &str, by_at: u64) -> Map<String, Value> {
    let by = json!({"token": by, "intent_counter": by_at});
    rec(
        OUTCOME,
        token,
        &json!({"intent_counter": at, "settled_by": by}),
    )
}

#[test]
fn settled_by_resolves_against_the_recovery_attempts_intents() {
    const RULE: &str = "settled_by names no intent";
    // GIVEN: w-1's intent (3) and the recovery attempt r-1's intent (4)
    let head = || {
        vec![
            rec(INTENT, "w-1", &json!({})),
            rec(RECOVERY, "r-1", &json!({"settles": "w-1"})),
        ]
    };
    // settled_by naming r-1's intent pairs, though its token is not w-1's.
    let ok = verify_records([head(), vec![settled("w-1", 3, "r-1", 4)]].concat());
    assert_paired(&ok, "settled by r-1's intent");
    // settled_by naming w-1's own intent under r-1's token fails: it is not
    // an intent of r-1.
    let own = verify_records([head(), vec![settled("w-1", 3, "r-1", 3)]].concat());
    assert_fails(&own, 5, RULE, "w-1");
    // settled_by naming a counter that holds no intent of r-1 fails.
    let none = verify_records([head(), vec![settled("w-1", 3, "r-1", 2)]].concat());
    assert_fails(&none, 5, RULE, "w-1");
}

fn payload(v: &Value) -> Map<String, Value> {
    let mut m = json!({"kind": "settle.save"});
    m.as_object_mut()
        .unwrap()
        .extend(v.as_object().unwrap().clone());
    m.as_object().unwrap().clone()
}

/// The counter of the oldest file's first record: the retention boundary.
fn boundary(path: &Path) -> u64 {
    let oldest = super::segments::list_segments(path)
        .unwrap()
        .first()
        .map_or_else(|| path.to_path_buf(), |s| s.path.clone());
    lines(&oldest)[0]["counter"].as_u64().unwrap()
}

/// A log whose intent of `w-old` expired by retention (its expiry record in
/// a newer segment), reopened so no more rotations happen: the logger, the
/// old intent's counter and the boundary.
async fn expired_log(path: &Path) -> (std::sync::Arc<TransparencyLogger>, u64, u64) {
    use super::settle::{IntentKind, Role};
    let l = std::sync::Arc::new(TransparencyLogger::open(cfg(path, 1, false)).unwrap());
    let save = Role::Intent(IntentKind::Save);
    let own = l.log_id();
    let old = l.settle(&own, "w-old", save, payload(&json!({})));
    let old = old.await.unwrap().counter;
    let mut i = 0;
    while super::segments::list_segments(path)
        .unwrap()
        .first()
        .is_none_or(|s| s.seq < 2)
    {
        super::rotation_tests::append(&l, i);
        i += 1;
        assert!(i < 3_000, "no expiry happened");
    }
    drop(l);
    let mut big = (*cfg(path, 1, false)).clone();
    big.rotation.max_segment_bytes = 1 << 20;
    let l = std::sync::Arc::new(TransparencyLogger::open(std::sync::Arc::new(big)).unwrap());
    let b = boundary(path);
    assert!(old < b, "the old intent expired: {old} >= {b}");
    let newer = super::segments::list_segments(path)
        .unwrap()
        .into_iter()
        .skip(1);
    let anchored = newer.map(|s| s.path).chain([path.to_path_buf()]).any(|f| {
        lines(&f)
            .iter()
            .any(|v| v["event"] == super::rotation::EV_EXPIRED)
    });
    assert!(anchored, "an expiry record sits in a newer file");
    (l, old, b)
}

/// Settle `role` of `token` with `extra`, returning its counter.
async fn put(
    l: &std::sync::Arc<TransparencyLogger>,
    token: &str,
    role: super::settle::Role,
    extra: &Value,
) -> u64 {
    let got = l.settle(&l.log_id(), token, role, payload(extra)).await;
    got.unwrap_or_else(|e| panic!("{e:?}")).counter
}

/// Verify `path` live and archive alike.
fn both_modes(path: &Path) -> [(VerifyMode, VerifyResult); 2] {
    [VerifyMode::Live, VerifyMode::Archive]
        .map(|m| (m, verify_segments(path, &cfg(path, 1, false), m).unwrap()))
}

#[tokio::test]
async fn dependents_below_at_and_above_the_boundary() {
    use super::settle::{IntentKind, Role};
    // Just below the boundary: an expired intent, an info line.
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let (l, _, b) = expired_log(&path).await;
    put(&l, "w-x", Role::Outcome, &json!({"intent_counter": b - 1})).await;
    drop(l);
    for (mode, r) in both_modes(&path) {
        assert!(r.ok, "{mode:?}: {:?}", r.error_message);
        assert_eq!(
            count(&r.notes, "intent expired"),
            1,
            "{mode:?}: {:?}",
            r.notes
        );
    }
    // At the boundary: in range, no intent there, so it fails.
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let (l, _, b) = expired_log(&path).await;
    let at = put(&l, "w-x", Role::Outcome, &json!({"intent_counter": b})).await;
    drop(l);
    for (mode, r) in both_modes(&path) {
        assert_fails(
            &r,
            at,
            "names no intent of its token at that counter",
            "w-x",
        );
        assert_eq!(count(&r.notes, "intent expired"), 0, "{mode:?}");
    }
    // Above it: an intent in range pairs, with no info line.
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let (l, _, _) = expired_log(&path).await;
    let i = put(&l, "w-in", Role::Intent(IntentKind::Save), &json!({})).await;
    put(&l, "w-in", Role::Outcome, &json!({"intent_counter": i})).await;
    drop(l);
    for (mode, r) in both_modes(&path) {
        assert_paired(&r, &format!("{mode:?} above"));
        assert_eq!(count(&r.notes, "intent expired"), 0, "{mode:?}");
    }
}

#[tokio::test]
async fn settled_by_below_the_boundary_is_expired_not_failed() {
    use super::settle::{IntentKind, Role};
    let dir = tempfile::tempdir().unwrap();
    let path = log_path(&dir);
    let (l, old, _) = expired_log(&path).await;
    // GIVEN: an outcome whose settled_by names w-old's expired intent
    let i = put(&l, "w-1", Role::Intent(IntentKind::Save), &json!({})).await;
    let by = json!({"token": "w-old", "intent_counter": old});
    put(
        &l,
        "w-1",
        Role::Outcome,
        &json!({"intent_counter": i, "settled_by": by}),
    )
    .await;
    drop(l);
    // THEN: it pairs, and settled_by is an info line, in both modes
    for (mode, r) in both_modes(&path) {
        assert_paired(&r, &format!("{mode:?}"));
        assert_eq!(
            count(&r.notes, "settled_by names an intent expired"),
            1,
            "{mode:?}: {:?}",
            r.notes
        );
    }
}

const STOPPED: &str = "config_write_delivery_stopped";

/// A pairing failure at `at` naming `rule` (a field rule), the chain passing.
fn assert_field_fails(r: &VerifyResult, at: u64, rule: &str, what: &str) {
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
fn with_field(
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
    let dir = tempfile::tempdir().unwrap();
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

/// A record with no settle prefix: today's writer, or a mismatch.
fn plain(v: &Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[test]
fn legacy_intents_are_counted_once_and_mismatched_records_warn_once() {
    // GIVEN: two legacy intents (no prefix), a settle intent, and two
    // mismatched records: a reserved event without the prefix naming the
    // intent, and the prefix on an event settle never writes
    let r = verify_records(vec![
        plain(&json!({"event": INTENT, "token": "old-1"})),
        plain(&json!({"event": RECOVERY, "token": "old-2"})),
        rec(INTENT, "w-1", &json!({})),
        plain(&json!({"event": OUTCOME, "token": "w-1", "intent_counter": 5})),
        rec("config_write_note", "w-2", &json!({})),
    ]);
    // THEN: one info line counts the legacy intents; one warning names the
    // mismatch; the mismatched outcome pairs nothing, so w-1 is interrupted
    assert!(r.ok, "{:?}", r.error_message);
    let legacy = "config intents written before outcome records existed; not paired";
    assert_eq!(count(&r.notes, legacy), 1, "{:?}", r.notes);
    assert_eq!(count(&r.notes, &format!("2 {legacy}")), 1, "{:?}", r.notes);
    assert_eq!(
        count(&r.warnings, "not a settle record"),
        1,
        "{:?}",
        r.warnings
    );
    assert_eq!(count(&r.warnings, "interrupted"), 1, "{:?}", r.warnings);
    assert_eq!(count(&r.warnings, "old-"), 0, "{:?}", r.warnings);
}

/// Edit the record at `counter` in place: its hash no longer matches.
fn tamper(path: &Path, counter: u64) {
    let mut all = lines(path);
    let at = all.iter().position(|v| v["counter"] == counter).unwrap();
    all[at]["note"] = "edited".into();
    let mut body = String::new();
    for v in &all {
        writeln!(body, "{v}").unwrap();
    }
    std::fs::write(path, body).unwrap();
}

#[test]
fn under_a_failed_chain_pairing_findings_are_unverified_warnings() {
    const STOPPED_RULE: &str = "delivery stopped with no outcome";
    let records = || {
        vec![
            rec(INTENT, "w-1", &json!({})),
            dep(STOPPED, "w-1", 3),
            plain(&json!({"event": "config_write_note"})),
        ]
    };
    // A streaming failure: the record at 5 edited after the pairing failure.
    let dir = tempfile::tempdir().unwrap();
    let streaming = log_with(&dir, records());
    tamper(&streaming, 5);
    // A tail-only failure: the chain intact, `.hwm` gone.
    let dir2 = tempfile::tempdir().unwrap();
    let tail = log_with(&dir2, records());
    std::fs::remove_file(super::segments::sibling(&tail, "hwm")).unwrap();
    for (what, path) in [("streaming", streaming), ("tail", tail)] {
        let r = verified(&path);
        // THEN: the chain verdict stands, and pairing only warns
        assert!(!r.ok, "{what}: passed");
        assert_eq!(r.failed_check, FailedCheck::Chain, "{what}");
        let msg = r.error_message.clone().unwrap_or_default();
        assert!(!msg.contains(STOPPED_RULE), "{what}: {msg}");
        let unverified = format!("unverified: {STOPPED_RULE}");
        assert_eq!(
            count(&r.warnings, &unverified),
            1,
            "{what}: {:?}",
            r.warnings
        );
    }
    // Control: untampered, the same records fail on pairing.
    assert_fails(&verify_records(records()), 4, STOPPED_RULE, "w-1");
}

#[test]
fn repeats_differing_only_in_time_fields_collapse() {
    // GIVEN: one intent written twice, differing only in `timestamp` and
    // `clock_invalid`, an outcome naming the second, and (the bracket)
    // another token's intent alone
    let r = verify_records(vec![
        rec(INTENT, "w-1", &json!({"timestamp": "2026-11-07T00:00:00Z"})),
        rec(
            INTENT,
            "w-1",
            &json!({"timestamp": "2026-11-07T00:00:01Z", "clock_invalid": true}),
        ),
        dep(OUTCOME, "w-1", 4),
        rec(INTENT, "w-2", &json!({})),
    ]);

    // THEN: w-1 pairs with no warning; w-2 alone is interrupted
    assert_paired(&r, "time fields only");
    assert_eq!(count(&r.warnings, "(token w-1)"), 0, "{:?}", r.warnings);
    assert_eq!(count(&r.warnings, "interrupted"), 1, "{:?}", r.warnings);
}

#[test]
fn a_mismatched_record_warning_names_its_file_by_position_not_path() {
    // GIVEN: a log holding one mismatched record
    let dir = tempfile::tempdir().unwrap();
    let path = log_with(&dir, vec![rec("config_write_note", "w-2", &json!({}))]);

    // WHEN: it is verified
    let r = verified(&path);

    // THEN: one warning, naming the file by its position, never its path
    let warned: Vec<&String> = r
        .warnings
        .iter()
        .filter(|w| w.contains("not a settle record"))
        .collect();
    assert_eq!(warned.len(), 1, "{:?}", r.warnings);
    let shown_dir = dir.path().display().to_string();
    assert!(!warned[0].contains(&shown_dir), "{}", warned[0]);
    assert!(!warned[0].contains("transparency.jsonl"), "{}", warned[0]);
    assert!(warned[0].contains("in file 1 ("), "{}", warned[0]);
}

/// The lookups one dependent costs (step 3 section 4): its own
/// `intent_counter`, and its `settled_by` when it has one.
const LOOKUPS_PER_DEPENDENT: usize = 2;

#[test]
fn intent_lookups_grow_with_the_dependents_not_their_square() {
    // GIVEN: a thousand tokens, each an intent, a recovery attempt's
    // intent, and an outcome naming both (its own intent and settled_by)
    const TOKENS: u64 = 1_000;
    let mut records = Vec::new();
    for i in 0..TOKENS {
        let (token, by) = (format!("w-{i}"), format!("r-{i}"));
        let at = 3 + 3 * i;
        records.push(rec(INTENT, &token, &json!({})));
        records.push(rec(RECOVERY, &by, &json!({"settles": token})));
        records.push(settled(&token, at, &by, at + 1));
    }
    let dependents = usize::try_from(TOKENS).unwrap();

    // WHEN: the log is verified, counting candidates the lookup examined
    super::verify::PROBES.with(|p| p.set(0));
    let r = verify_records(records);
    let probes = super::verify::PROBES.with(std::cell::Cell::get);

    // THEN: every outcome paired after at least one look each, and the
    // work stays within the lookups each dependent costs
    assert_paired(&r, "a thousand tokens");
    assert!(probes >= dependents, "the counter saw no lookups: {probes}");
    assert!(
        probes <= LOOKUPS_PER_DEPENDENT * dependents,
        "{probes} candidates for {dependents} dependents"
    );
}

#[tokio::test]
async fn settle_refuses_settled_by_on_every_role_but_outcome() {
    use super::settle::{FieldFault, FieldProblem, IntentKind, InvalidPayload, Role, Unsettled};
    let dir = tempfile::tempdir().unwrap();
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
fn records_after_the_first_failure_are_still_paired() {
    // GIVEN: a valid intent, an unrelated malformed record, then the
    // intent's outcome
    let malformed = with_field(dep(OUTCOME, "w-9", 3), "intent_counter", None);
    let r = verify_records(vec![
        rec(INTENT, "w-1", &json!({})),
        malformed,
        dep(OUTCOME, "w-1", 3),
    ]);

    // THEN: exactly the one failure, and no warning for the paired intent
    assert_field_fails(&r, 4, "field intent_counter missing", "malformed");
    assert_eq!(count(&r.warnings, "(token w-1)"), 0, "{:?}", r.warnings);
}
