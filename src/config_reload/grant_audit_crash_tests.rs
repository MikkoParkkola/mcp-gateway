// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Grant-change auditor: append failures, gap marking and crash recovery
//! (MIK-7570.AUDIT.4, cells T6-T8b). Harness in `grant_audit_tests.rs`.

use std::sync::atomic::Ordering;

use super::grant_audit::{GrantAuditFault, Recorded};
use super::grant_audit_tests::{Fixture, add, revoke, row};
use crate::control_plane::GrantChangeVerb as V;

fn fail_appends_from(f: &Fixture, call: usize) {
    f.store.fail_from.store(call, Ordering::SeqCst);
}

fn heal(f: &Fixture) {
    f.store.fail_from.store(0, Ordering::SeqCst);
}

fn journal_ids(f: &Fixture) -> Vec<String> {
    f.event_ids()
        .into_iter()
        .filter(|id| id.starts_with("grant-journal:"))
        .collect()
}

fn assert_unique(f: &Fixture) {
    let ids = f.event_ids();
    let unique: std::collections::BTreeSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "duplicate record: {ids:?}");
}

/// T6 (auditor level): a failed append reports the change unrecorded and
/// marks the durable gap.
#[tokio::test]
async fn t6_failed_append_is_unrecorded_and_marks_the_gap() {
    let f = Fixture::new();
    f.cli(add(row("g1", "r"))).await;
    fail_appends_from(&f, 1);
    let got = f.reconcile().await.unwrap();
    assert!(matches!(got, Recorded::Unrecorded(_)), "{got:?}");
    assert_eq!(f.state_json()["gap"], serde_json::json!(true));
}

/// T7a + T7b: after a failed append and a restart, the gap is recorded even
/// with no mismatch, and a later direct edit reads as indeterminate.
#[tokio::test]
async fn t7_gap_is_recorded_and_edits_read_as_indeterminate() {
    let mut f = Fixture::new();
    f.cli(add(row("g1", "r"))).await;
    f.reconcile().await.unwrap();
    f.cli(revoke("g1")).await;
    fail_appends_from(&f, 2);
    f.reconcile().await.unwrap();
    heal(&f);
    f.restart();
    f.direct_write(vec![row("g1", "edited")]).await;
    f.reconcile().await.unwrap();

    let got = f.records();
    assert!(got.iter().any(|r| r.0 == V::Indeterminate), "{got:?}");
    assert!(
        !got.iter().any(|r| r.0 == V::OutOfBand),
        "a gap must not produce an exact out-of-band record: {got:?}"
    );
    assert_eq!(f.state_json()["gap"], serde_json::json!(false));
    assert_unique(&f);
}

/// T7c: recovering the old plan keeps the gap until a plan carrying the gap
/// record commits.
#[tokio::test]
async fn t7c_recovered_plan_keeps_the_gap() {
    let mut f = Fixture::new();
    f.cli(add(row("g1", "r"))).await;
    fail_appends_from(&f, 1);
    f.reconcile().await.unwrap();
    heal(&f);
    f.restart();
    *f.auditor.fault.lock() = Some(GrantAuditFault::AfterPlanWrite);
    let _ = f.reconcile().await;
    assert_eq!(f.state_json()["gap"], serde_json::json!(true));
    assert!(!f.records().iter().any(|r| r.0 == V::Indeterminate));
    f.restart();
    f.reconcile().await.unwrap();
    assert!(f.records().iter().any(|r| r.0 == V::Indeterminate));
    assert_eq!(f.state_json()["gap"], serde_json::json!(false));
    assert_eq!(journal_ids(&f).len(), 1);
    assert_unique(&f);
}

/// T8: a crash at each point of the plan boundary leaves every planned
/// record exactly once, in plan order, after recovery.
#[tokio::test]
async fn t8_every_crash_point_recovers_exactly_once() {
    let cases = [
        (GrantAuditFault::AfterPlanWrite, 3),
        (GrantAuditFault::AfterAppend(1), 3),
        (GrantAuditFault::BeforeCommit, 3),
        (GrantAuditFault::AfterAppend(300), 301),
    ];
    for (fault, entries) in cases {
        let mut f = Fixture::new();
        for i in 0..entries {
            f.cli(add(row(&format!("g{i:03}"), "r"))).await;
        }
        *f.auditor.fault.lock() = Some(fault);
        let _ = f.reconcile().await;
        f.restart();
        f.reconcile().await.unwrap();
        let got: Vec<_> = f.records().into_iter().map(|r| r.1).collect();
        let want: Vec<_> = (0..entries).map(|i| format!("g{i:03}")).collect();
        assert_eq!(got, want, "{fault:?}");
        assert_unique(&f);
    }
}

/// T8b: a failed commit write keeps the plan as a barrier: the next reload is
/// refused, nothing new is appended, and a restart records each id once.
#[tokio::test]
async fn t8b_failed_commit_is_a_barrier() {
    let mut f = Fixture::new();
    f.cli(add(row("g1", "r"))).await;
    *f.auditor.fault.lock() = Some(GrantAuditFault::CommitWrite);
    let _ = f.reconcile().await;
    let before = f.event_ids().len();
    f.cli(add(row("g2", "r"))).await;
    let refused = f.reconcile().await;
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(f.event_ids().len(), before);
    let snapshot = f.auditor.snapshot(&f.rows().await, chrono::Utc::now());
    assert!(snapshot.is_err(), "no snapshot while a plan is pending");
    f.restart();
    f.reconcile().await.unwrap();
    let got: Vec<_> = f.records().into_iter().map(|r| r.1).collect();
    assert_eq!(got, vec!["g1".to_string(), "g2".to_string()]);
    assert_unique(&f);
}

/// T3a + T3b (auditor level): one `loaded` per active grant, then a closing
/// record with the count, zero included.
#[tokio::test]
async fn t3_snapshot_records_active_grants_and_the_count() {
    let f = Fixture::new();
    let mut expired = row("g3", "r");
    expired.expires_at = Some("2001-01-01T00:00:00Z".parse().unwrap());
    let mut revoked = row("g4", "r");
    revoked.revoked_at = Some("2001-01-01T00:00:00Z".parse().unwrap());
    let rows = vec![row("g1", "r"), row("g2", "r"), expired, revoked];
    f.auditor.snapshot(&rows, chrono::Utc::now()).unwrap();
    let got = f.records();
    let loaded: Vec<_> = got
        .iter()
        .filter(|r| r.0 == V::Loaded)
        .map(|r| r.1.clone())
        .collect();
    assert_eq!(loaded, vec!["g1".to_string(), "g2".to_string()]);
    let events = f.store.events();
    let closing = events.last().unwrap().grant_change.clone().unwrap();
    assert_eq!(closing.verb, V::LoadedComplete);
    assert_eq!(closing.count, Some(2));
    let run = closing.run_id.clone().unwrap();
    assert!(
        events
            .iter()
            .all(|e| e.grant_change.as_ref().unwrap().run_id.as_deref() == Some(run.as_str()))
    );

    let empty = Fixture::new();
    empty.auditor.snapshot(&[], chrono::Utc::now()).unwrap();
    let only = empty.store.events();
    assert_eq!(only.len(), 1);
    assert_eq!(only[0].grant_change.clone().unwrap().count, Some(0));
}

/// T3c + T3d (auditor level): a failed `loaded` or closing append is an error.
#[tokio::test]
async fn t3cd_failed_snapshot_append_is_an_error() {
    for fail_at in [1, 3] {
        let f = Fixture::new();
        fail_appends_from(&f, fail_at);
        let rows = vec![row("g1", "r"), row("g2", "r")];
        assert!(
            f.auditor.snapshot(&rows, chrono::Utc::now()).is_err(),
            "{fail_at}"
        );
    }
}
