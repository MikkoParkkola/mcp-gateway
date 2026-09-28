// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Grant-change auditor: damaged journals, changed grant paths and the store
//! round trip (MIK-7570.AUDIT.4, cells T4g-T4k, T11).

use super::grant_audit::{GrantAuditFault, GrantAuditor, JournalRead};
use super::grant_audit_tests::{Fixture, add, row, upsert};
use crate::control_plane::GrantChangeVerb as V;
use crate::identity_grants::journal::{grant_digest, journal_path};

fn append_raw(f: &Fixture, bytes: &[u8]) {
    use std::io::Write as _;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(journal_path(&f.grants))
        .unwrap();
    file.write_all(bytes).unwrap();
}

/// T4g: a torn line followed by a valid entry yields one `indeterminate` and
/// the entry's own record; a second reconciliation adds nothing.
#[tokio::test]
async fn t4g_torn_line_then_entry() {
    let f = Fixture::new();
    f.cli(add(row("g1", "r"))).await;
    append_raw(&f, b"{\"torn\":\n");
    f.cli(add(row("g2", "r"))).await;
    f.reconcile().await.unwrap();
    let got = f.records();
    assert_eq!(
        got.iter().filter(|r| r.0 == V::Indeterminate).count(),
        1,
        "{got:?}"
    );
    assert!(got.iter().any(|r| r.0 == V::Add && r.1 == "g2"), "{got:?}");
    let n = got.len();
    f.reconcile().await.unwrap();
    assert_eq!(f.records().len(), n);
}

/// T4g: an unterminated final line waits; once completed it is recorded once.
#[tokio::test]
async fn t4g_unterminated_tail_waits() {
    let f = Fixture::new();
    f.cli(add(row("g1", "r"))).await;
    f.reconcile().await.unwrap();
    let bytes = std::fs::read(journal_path(&f.grants)).unwrap();
    let line = bytes.split(|b| *b == b'\n').next().unwrap().to_vec();
    // A second copy of the same line, minus its newline, with a fresh id.
    let text = String::from_utf8(line).unwrap();
    let id = serde_json::from_str::<serde_json::Value>(&text).unwrap()["entry_id"]
        .as_str()
        .unwrap()
        .to_string();
    // A consistent later entry: an identical `--replace` of the same row.
    let digest = serde_json::from_str::<serde_json::Value>(&text).unwrap()["digest"]
        .as_str()
        .unwrap()
        .to_string();
    let copy = text
        .replace(&id, "00000000-0000-4000-8000-000000000001")
        .replace("\"verb\":\"add\"", "\"verb\":\"replace\"")
        .replace(
            "\"prev_digest\":null",
            &format!("\"prev_digest\":\"{digest}\""),
        );
    assert_ne!(
        copy,
        text.replace(&id, "00000000-0000-4000-8000-000000000001")
    );
    append_raw(&f, copy.as_bytes());
    f.reconcile().await.unwrap();
    assert_eq!(f.records().len(), 1, "an unterminated line waits");
    append_raw(&f, b"\n");
    f.reconcile().await.unwrap();
    assert_eq!(f.records().len(), 2);
}

/// T4g: an unreadable journal records one `indeterminate`, keeps the
/// baseline, and CLI changes are recorded once it is readable again.
#[tokio::test]
async fn t4g_unreadable_journal_keeps_the_baseline() {
    let f = Fixture::new();
    f.cli(add(row("g1", "r"))).await;
    f.reconcile().await.unwrap();
    f.cli(add(row("g2", "r"))).await;
    let rows = f.rows().await;
    let unreadable = JournalRead::Unreadable("mode refused".into());
    for _ in 0..2 {
        let p = f.auditor.prepare(&rows, &unreadable).unwrap();
        f.auditor.record(p);
    }
    let got = f.records();
    assert_eq!(
        got.iter().filter(|r| r.0 == V::Indeterminate).count(),
        1,
        "{got:?}"
    );
    assert!(!got.iter().any(|r| r.0 == V::OutOfBand), "{got:?}");
    f.reconcile().await.unwrap();
    assert!(f.records().iter().any(|r| r.0 == V::Add && r.1 == "g2"));
    assert!(!f.records().iter().any(|r| r.0 == V::OutOfBand));
}

/// T4h: a journal replaced by a shorter one with a new entry: one
/// `indeterminate`, the new entry recorded, and neither repeated after a restart.
#[tokio::test]
async fn t4h_replaced_journal() {
    let mut f = Fixture::new();
    f.cli(add(row("g1", "r"))).await;
    f.cli(add(row("g2", "r"))).await;
    f.reconcile().await.unwrap();
    std::fs::remove_file(journal_path(&f.grants)).unwrap();
    f.cli(add(row("g3", "r"))).await;
    f.reconcile().await.unwrap();
    let got = f.records();
    assert_eq!(
        got.iter().filter(|r| r.0 == V::Indeterminate).count(),
        1,
        "{got:?}"
    );
    assert!(got.iter().any(|r| r.0 == V::Add && r.1 == "g3"));
    let n = got.len();
    f.reconcile().await.unwrap();
    f.restart();
    f.reconcile().await.unwrap();
    assert_eq!(f.records().len(), n);
}

/// T4i: two direct edits of one grant around a CLI change in one
/// reconciliation keep distinct ids, and survive a crash after one append.
#[tokio::test]
async fn t4i_two_edits_one_plan_distinct_ids() {
    let mut f = Fixture::new();
    f.cli(add(row("g1", "a"))).await;
    f.reconcile().await.unwrap();
    f.direct_write(vec![row("g1", "b")]).await;
    f.cli(upsert(row("g1", "c"), true)).await;
    f.direct_write(vec![row("g1", "d")]).await;
    *f.auditor.fault.lock() = Some(GrantAuditFault::AfterAppend(1));
    let _ = f.reconcile().await;
    f.restart();
    f.reconcile().await.unwrap();
    let oob: Vec<_> = f
        .records()
        .into_iter()
        .filter(|r| r.0 == V::OutOfBand)
        .collect();
    assert_eq!(oob.len(), 2, "{oob:?}");
    assert_eq!(oob[1].2, Some(grant_digest(&row("g1", "d"))));
    let ids = f.event_ids();
    let unique: std::collections::BTreeSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len());
}

/// T4k: state kept for another grant path is no baseline for this one.
#[tokio::test]
async fn t4k_state_for_another_path_is_no_baseline() {
    let f = Fixture::new();
    f.direct_write(vec![row("g1", "a")]).await;
    f.reconcile().await.unwrap();
    // Precondition: the first reconciliation committed a baseline holding g1,
    // so the zero below comes from ignoring it, not from never having one.
    assert!(
        f.state_json()["grants"]["g1"].is_string(),
        "{}",
        f.state_json()
    );
    let other = f.grants.with_file_name("other.yaml");
    std::fs::copy(&f.grants, &other).unwrap();
    std::fs::write(
        &other,
        std::fs::read_to_string(&other)
            .unwrap()
            .replace("reason: a", "reason: z"),
    )
    .unwrap();
    let auditor = GrantAuditor::new(f.store.clone(), &f.state_dir, &other);
    let rows = crate::identity_grants::read_identity_grants_file(&other)
        .await
        .unwrap()
        .grants;
    let p = auditor.prepare(&rows, &JournalRead::Missing).unwrap();
    auditor.record(p);
    assert!(
        !f.records().iter().any(|r| r.0 == V::OutOfBand),
        "{:?}",
        f.records()
    );
}
