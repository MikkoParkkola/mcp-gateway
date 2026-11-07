// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `audit verify` pairs settle records (MIK-9318 step 3, design
//! design-9318-step3-final.md section 7): each row brackets its claim with a
//! case that needs a finding, so a verifier that pairs nothing fails it.

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
    assert_eq!(all.len(), 2, "a fresh log holds its open and identified records");
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
    assert_eq!(r.error_at_counter, Some(at), "{rule}: {:?}", r.error_message);
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
    let note = || json!({"event": "config_write_note"}).as_object().unwrap().clone();
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
        ("deferred then outcome", vec![dep(DEFERRED, "w-1", 3), dep(OUTCOME, "w-1", 3)]),
    ] {
        let r = verify_records([vec![intent()], tail].concat());
        assert_paired(&r, what);
        assert_eq!(count(&r.warnings, "(token w-1)"), 0, "{what}: {:?}", r.warnings);
    }
    // Deferred, no terminal: left to recovery.
    let deferred = verify_records(vec![intent(), dep(DEFERRED, "w-1", 3)]);
    assert!(deferred.ok, "{:?}", deferred.error_message);
    assert_eq!(count(&deferred.warnings, "left to recovery"), 1, "{:?}", deferred.warnings);
    // Alone: interrupted.
    let alone = verify_records(vec![intent()]);
    assert!(alone.ok, "{:?}", alone.error_message);
    assert_eq!(count(&alone.warnings, "interrupted"), 1, "{:?}", alone.warnings);
}
