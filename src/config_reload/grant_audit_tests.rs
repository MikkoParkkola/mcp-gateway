// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Grant-change auditor cells (MIK-7570.AUDIT.4), gateway half.
//!
//! Plan: `docs/design/2026-09-28-grant-change-journal-test-plan.md`. The
//! auditor is driven directly here; reload and startup wiring have their own
//! cells.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::grant_audit::{GrantAuditor, JournalRead, Recorded, STATE_FILE};
use crate::control_plane::store::{
    AuditFilter, AuditPage, ControlPlaneStore, InMemoryControlPlaneStore, StoreError, StoreResult,
};
use crate::control_plane::{
    ControlPlaneAction, ControlPlaneAuditEvent, ControlPlaneGrant, ControlPlanePolicy,
    GrantChangeVerb,
};
use crate::identity_grants::journal::{
    GrantChange, JournalVerb, apply_change, grant_digest, journal_path,
};
use crate::identity_grants::{
    GrantAgent, GrantScope, GrantSubject, IdentityGrant, IdentityGrantFile,
    read_identity_grants_file, write_identity_grants_file,
};

/// An in-memory store whose `append_audit` fails while `fail_from` is at or
/// below the call number (1-based); 0 means never.
#[derive(Default)]
pub(crate) struct FlakyStore {
    inner: InMemoryControlPlaneStore,
    calls: AtomicUsize,
    pub(crate) fail_from: AtomicUsize,
    /// When set, the grant epoch seen at the first failed append, plus one
    /// (0: no failure observed). Proves publish happened before the append.
    pub(super) watch_epoch: std::sync::OnceLock<Arc<std::sync::atomic::AtomicU64>>,
    pub(super) epoch_at_failure: std::sync::atomic::AtomicU64,
}

impl FlakyStore {
    pub(crate) fn events(&self) -> Vec<ControlPlaneAuditEvent> {
        let mut page = self
            .inner
            .read_audit(&AuditFilter::new(10_000))
            .expect("read");
        page.events.reverse();
        page.events
    }
}

impl ControlPlaneStore for FlakyStore {
    fn list_grants(&self) -> StoreResult<Vec<ControlPlaneGrant>> {
        self.inner.list_grants()
    }
    fn get_grant(&self, id: &str) -> StoreResult<Option<ControlPlaneGrant>> {
        self.inner.get_grant(id)
    }
    fn put_grant(&self, g: ControlPlaneGrant) -> StoreResult<()> {
        self.inner.put_grant(g)
    }
    fn delete_grant(&self, id: &str) -> StoreResult<()> {
        self.inner.delete_grant(id)
    }
    fn list_policies(&self) -> StoreResult<Vec<ControlPlanePolicy>> {
        self.inner.list_policies()
    }
    fn get_policy(&self, id: &str) -> StoreResult<Option<ControlPlanePolicy>> {
        self.inner.get_policy(id)
    }
    fn put_policy(&self, p: ControlPlanePolicy) -> StoreResult<()> {
        self.inner.put_policy(p)
    }
    fn delete_policy(&self, id: &str) -> StoreResult<()> {
        self.inner.delete_policy(id)
    }
    fn append_audit(&self, event: &ControlPlaneAuditEvent) -> StoreResult<()> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        let from = self.fail_from.load(Ordering::SeqCst);
        if from != 0 && n >= from {
            if let Some(epoch) = self.watch_epoch.get() {
                let seen = epoch.load(Ordering::SeqCst) + 1;
                let _ = self.epoch_at_failure.compare_exchange(
                    0,
                    seen,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
            }
            return Err(StoreError::Io(std::io::Error::other(
                "injected append failure",
            )));
        }
        self.inner.append_audit(event)
    }
    fn read_audit(&self, filter: &AuditFilter) -> StoreResult<AuditPage> {
        self.inner.read_audit(filter)
    }
}

/// A grant file, its journal, a store and a state directory; `restart`
/// drops every in-memory auditor state, as a crash would.
pub(super) struct Fixture {
    _dir: tempfile::TempDir,
    pub(super) grants: PathBuf,
    pub(super) state_dir: PathBuf,
    pub(super) store: Arc<FlakyStore>,
    pub(super) auditor: GrantAuditor,
}

impl Fixture {
    pub(super) fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let grants = dir.path().join("grants.yaml");
        let state_dir = dir.path().join("store");
        std::fs::create_dir_all(&state_dir).unwrap();
        let store = Arc::new(FlakyStore::default());
        let auditor = GrantAuditor::new(store.clone(), &state_dir, &grants);
        Self {
            _dir: dir,
            grants,
            state_dir,
            store,
            auditor,
        }
    }

    pub(super) fn restart(&mut self) {
        self.auditor = GrantAuditor::new(self.store.clone(), &self.state_dir, &self.grants);
    }

    pub(super) async fn cli(&self, change: GrantChange) {
        apply_change(&self.grants, true, change).await.unwrap();
    }

    pub(super) async fn direct_write(&self, rows: Vec<IdentityGrant>) {
        write_identity_grants_file(&self.grants, &IdentityGrantFile::new(rows))
            .await
            .unwrap();
    }

    pub(super) async fn rows(&self) -> Vec<IdentityGrant> {
        read_identity_grants_file(&self.grants)
            .await
            .map(|f| f.grants)
            .unwrap_or_default()
    }

    pub(super) fn journal(&self) -> JournalRead {
        match std::fs::read(journal_path(&self.grants)) {
            Ok(bytes) => JournalRead::Bytes(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => JournalRead::Missing,
            Err(e) => JournalRead::Unreadable(e.to_string()),
        }
    }

    /// One reconciliation as a reload runs it: prepare, (publish), record.
    pub(super) async fn reconcile(&self) -> Result<Recorded, String> {
        let rows = self.rows().await;
        let prepared = self
            .auditor
            .prepare(&rows, &self.journal())
            .map_err(|r| r.0)?;
        Ok(self.auditor.record(prepared))
    }

    /// `(verb, grant id or target, digest)` of every grant record, oldest first.
    pub(super) fn records(&self) -> Vec<(GrantChangeVerb, String, Option<String>)> {
        self.store
            .events()
            .into_iter()
            .map(|e| {
                assert_eq!(e.actor_id, "unknown", "{e:?}");
                assert_eq!(e.action, ControlPlaneAction::MutateGrant, "{e:?}");
                let change = e.grant_change.expect("grant record carries grant_change");
                (change.verb, e.target_id, change.digest)
            })
            .collect()
    }

    pub(super) fn event_ids(&self) -> Vec<String> {
        self.store
            .events()
            .into_iter()
            .map(|e| e.event_id)
            .collect()
    }

    pub(super) fn state_json(&self) -> serde_json::Value {
        let text = std::fs::read_to_string(self.state_dir.join(STATE_FILE)).unwrap_or_default();
        serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)
    }
}

pub(super) fn row(grant_id: &str, reason: &str) -> IdentityGrant {
    IdentityGrant {
        grant_id: grant_id.to_string(),
        subject: GrantSubject::new("api_key".to_string(), "alice".to_string(), None),
        agent: GrantAgent::Any,
        capability: "cap".to_string(),
        tool: None,
        scope: GrantScope::Read,
        owner: None,
        expires_at: None,
        revoked_at: None,
        provenance: "p".to_string(),
        reason: reason.to_string(),
    }
}

pub(super) fn add(new: IdentityGrant) -> GrantChange {
    upsert(new, false)
}

pub(super) fn upsert(new: IdentityGrant, replace: bool) -> GrantChange {
    Box::new(move |file: &mut IdentityGrantFile| {
        let existed = file.grants.iter().any(|g| g.grant_id == new.grant_id);
        if existed && !replace {
            return Err("exists".to_string());
        }
        file.grants.retain(|g| g.grant_id != new.grant_id);
        let id = new.grant_id.clone();
        file.grants.push(new);
        let verb = if existed {
            JournalVerb::Replace
        } else {
            JournalVerb::Add
        };
        Ok((verb, id))
    })
}

pub(super) fn revoke(grant_id: &str) -> GrantChange {
    let grant_id = grant_id.to_string();
    Box::new(move |file: &mut IdentityGrantFile| {
        let row = file
            .grants
            .iter_mut()
            .find(|g| g.grant_id == grant_id)
            .ok_or_else(|| "missing".to_string())?;
        row.revoked_at = Some("2026-06-29T14:00:00Z".parse().unwrap());
        Ok((JournalVerb::Revoke, grant_id))
    })
}

use GrantChangeVerb as V;

#[allow(clippy::unnecessary_wraps, reason = "records carry an optional digest")]
fn d(row: &IdentityGrant) -> Option<String> {
    Some(grant_digest(row))
}

/// T2a: an add then a revoke between two loads yields two records.
#[tokio::test]
async fn t2a_add_then_revoke_between_loads_yields_two_records() {
    let f = Fixture::new();
    f.cli(add(row("g1", "r"))).await;
    f.cli(revoke("g1")).await;
    let revoked = f.rows().await[0].clone();

    assert_eq!(f.reconcile().await, Ok(Recorded::All(2)));
    assert_eq!(
        f.records(),
        vec![
            (V::Add, "g1".into(), d(&row("g1", "r"))),
            (V::Revoke, "g1".into(), d(&revoked)),
        ]
    );
    let ids = f.event_ids();
    assert!(
        ids.iter().all(|id| id.starts_with("grant-journal:")),
        "{ids:?}"
    );
}

/// T2a fields: a journal record carries expiry, the CLI's clock and the OS hint.
#[tokio::test]
async fn t2a_journal_record_carries_the_entry_fields() {
    let f = Fixture::new();
    let mut r = row("g1", "r");
    r.expires_at = Some("2030-01-01T00:00:00Z".parse().unwrap());
    f.cli(add(r)).await;
    f.reconcile().await.unwrap();

    let events = f.store.events();
    let change = events[0].grant_change.clone().unwrap();
    assert_eq!(
        change.expires_at,
        Some("2030-01-01T00:00:00Z".parse().unwrap())
    );
    assert!(change.occurred_at.is_some());
    assert_eq!(events[0].target_id, "g1");
}

/// T2b: a second reconciliation with no change records nothing more.
#[tokio::test]
async fn t2b_repeated_reconciliation_never_duplicates() {
    let f = Fixture::new();
    f.cli(add(row("g1", "r"))).await;
    f.reconcile().await.unwrap();
    assert_eq!(f.records().len(), 1, "precondition: the add was recorded");
    f.reconcile().await.unwrap();
    assert_eq!(f.records().len(), 1);
}

/// T4a: a direct edit with no journal entry is out-of-band.
#[tokio::test]
async fn t4a_direct_edit_is_out_of_band() {
    let f = Fixture::new();
    f.cli(add(row("g1", "r"))).await;
    f.reconcile().await.unwrap();
    let edited = row("g1", "edited");
    f.direct_write(vec![edited.clone()]).await;
    f.reconcile().await.unwrap();

    assert_eq!(
        f.records().last().cloned(),
        Some((V::OutOfBand, "g1".into(), d(&edited)))
    );
}

/// T4b: a deleted row, and an empty `grants` list, are out-of-band per id.
#[tokio::test]
async fn t4b_deleted_rows_are_out_of_band() {
    let f = Fixture::new();
    f.cli(add(row("g1", "r"))).await;
    f.cli(add(row("g2", "r"))).await;
    f.reconcile().await.unwrap();
    f.direct_write(vec![row("g2", "r")]).await;
    f.reconcile().await.unwrap();
    assert_eq!(
        f.records().last().cloned(),
        Some((V::OutOfBand, "g1".into(), None))
    );
    f.direct_write(Vec::new()).await;
    f.reconcile().await.unwrap();
    assert_eq!(
        f.records().last().cloned(),
        Some((V::OutOfBand, "g2".into(), None))
    );
    assert_eq!(f.records().len(), 4);
}

/// T4d: a direct edit that a later CLI revoke overwrote is still seen.
#[tokio::test]
async fn t4d_edit_absorbed_by_a_cli_change_is_still_out_of_band() {
    let f = Fixture::new();
    f.cli(add(row("g1", "r"))).await;
    f.reconcile().await.unwrap();
    let edited = row("g1", "edited");
    f.direct_write(vec![edited.clone()]).await;
    f.cli(revoke("g1")).await;
    f.reconcile().await.unwrap();

    let got = f.records();
    assert_eq!(got.len(), 3, "{got:?}");
    assert_eq!(got[1], (V::OutOfBand, "g1".into(), d(&edited)));
    assert_eq!(got[2].0, V::Revoke);
}

/// T4e: the same transition repeated in later reconciliations is recorded
/// each time, under a fresh event id.
#[tokio::test]
async fn t4e_repeated_transitions_get_fresh_ids() {
    let f = Fixture::new();
    f.cli(add(row("g1", "a"))).await;
    f.reconcile().await.unwrap();
    for reason in ["b", "a", "b"] {
        f.direct_write(vec![row("g1", reason)]).await;
        f.reconcile().await.unwrap();
    }
    let oob = f
        .records()
        .into_iter()
        .filter(|r| r.0 == V::OutOfBand)
        .count();
    assert_eq!(oob, 3);
    let ids = f.event_ids();
    let unique: std::collections::BTreeSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "{ids:?}");
}

/// T4f + T4j: with no baseline, a journalled grant whose row differs is
/// out-of-band, but a first `revoke` of a grant that predates the journal is not.
#[tokio::test]
async fn t4f_t4j_no_baseline() {
    let f = Fixture::new();
    // g0 predates the journal; g1 is journalled, then edited directly.
    f.direct_write(vec![row("g0", "r")]).await;
    f.cli(add(row("g1", "r"))).await;
    f.cli(revoke("g0")).await;
    let rows = f.rows().await;
    let mut edited = rows.iter().find(|r| r.grant_id == "g1").unwrap().clone();
    edited.reason = "edited".into();
    let g0 = rows.iter().find(|r| r.grant_id == "g0").unwrap().clone();
    f.direct_write(vec![g0.clone(), edited.clone()]).await;

    f.reconcile().await.unwrap();
    let got = f.records();
    assert!(got.contains(&(V::Revoke, "g0".into(), d(&g0))), "{got:?}");
    assert!(
        got.contains(&(V::OutOfBand, "g1".into(), d(&edited))),
        "{got:?}"
    );
    assert!(
        !got.iter().any(|r| r.0 == V::OutOfBand && r.1 == "g0"),
        "{got:?}"
    );
}

/// T4l: a grant added outside the CLI after a baseline is out-of-band.
#[tokio::test]
async fn t4l_unjournalled_add_is_out_of_band() {
    let f = Fixture::new();
    f.cli(add(row("g1", "r"))).await;
    f.reconcile().await.unwrap();
    let mut rows = f.rows().await;
    rows.push(row("g2", "r"));
    f.direct_write(rows).await;
    f.reconcile().await.unwrap();
    assert_eq!(
        f.records().last().cloned(),
        Some((V::OutOfBand, "g2".into(), d(&row("g2", "r"))))
    );
}
