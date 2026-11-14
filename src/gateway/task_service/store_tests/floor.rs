// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The task store's restart floor adapter: its save, its outcome, and the
//! coordinator's run over it. Rows written before the adapter: against the stub,
//! which answers Ok and does nothing, every row here fails on its own
//! assertion. Real clock: the rows wait on real blocking writes.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::time::Instant;

use super::super::record::PreparedTask;
use super::super::store::floor::TaskFloor;
use super::super::store::gate::GateState;
use super::super::store::{CommitHook, StoreError, StoreWriteStage, TaskStore};
use super::OWNER;
use super::support::*;
use crate::gateway::restart_floor::{FloorAdapter, FloorFault};

const BUDGET: Duration = Duration::from_secs(30);

pub(super) fn floor(store: &TaskStore) -> TaskFloor {
    TaskFloor::new(store, BUDGET)
}

pub(super) fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

/// Run `future` to completion or fail the row by name.
pub(super) async fn within<T>(row: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), future)
        .await
        .unwrap_or_else(|elapsed| panic!("{row}: did not finish in time ({elapsed})"))
}

/// A hook that counts `stage`, failing it while `fail` is set.
pub(super) fn counting(stage: StoreWriteStage, fail: bool) -> (CommitHook, Arc<AtomicUsize>) {
    let seen = Arc::new(AtomicUsize::new(0));
    let hook: CommitHook = Arc::new({
        let seen = Arc::clone(&seen);
        move |at| {
            if at == stage {
                seen.fetch_add(1, Ordering::SeqCst);
                if fail {
                    return Err(std::io::Error::other("injected"));
                }
            }
            Ok(())
        }
    });
    (hook, seen)
}

/// A store at `path` holding `n` tasks; their ids.
pub(super) async fn seeded(path: &Path, n: u64) -> (TaskStore, Vec<String>) {
    let store = open(path).await;
    let mut ids = Vec::new();
    for identity in 1..=n {
        let task = task();
        store
            .create(PreparedTask::for_test(&task, OWNER, identity))
            .await
            .expect("a fixture task is created");
        ids.push(task.id().to_owned());
    }
    (store, ids)
}

/// Every task record file and its bytes.
pub(super) fn records(path: &Path) -> BTreeMap<String, Vec<u8>> {
    files(path)
        .into_iter()
        .filter(|(name, _)| name.starts_with("task-") && name.ends_with(".json"))
        .collect()
}

/// Pause and checkpoint through the adapter, as the coordinator does.
pub(super) async fn certify(row: &str, floor: &mut TaskFloor) -> Result<(), FloorFault> {
    let deadline = deadline();
    within(row, floor.pause(deadline)).await?;
    within(row, floor.checkpoint(deadline)).await
}

// S1: a good checkpoint re-saves every record once and changes no byte.
#[tokio::test]
async fn s1_a_good_checkpoint_resaves_every_record_byte_for_byte() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, ids) = seeded(&path, 2).await;
    let before = records(&path);
    let revisions: Vec<u64> = ids
        .iter()
        .map(|id| store.get(OWNER, id).unwrap().revision)
        .collect();
    let (hook, renames) = counting(StoreWriteStage::Rename, false);
    store.set_hook(Some(hook)).await;
    let mut floor = floor(&store);
    assert_eq!(certify("S1", &mut floor).await, Ok(()));
    assert_eq!(renames.load(Ordering::SeqCst), 2, "one re-save per record");
    assert_eq!(records(&path), before, "every record byte-identical");
    for (id, revision) in ids.iter().zip(revisions) {
        assert_eq!(store.get(OWNER, id).unwrap().revision, revision);
    }
    assert!(store.ready(), "the store stays ready");
    assert_eq!(
        store.gate_for_test().state(),
        GateState::Certified(1),
        "the checkpoint certifies its attempt"
    );
}

// S3: an empty store is synced, not skipped; a failed sync is SaveFailed and
// does not poison the store (nothing was renamed).
#[tokio::test]
async fn s3_an_empty_store_is_synced_and_a_failed_sync_does_not_poison() {
    for fail in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let store = open(&path).await;
        let (hook, syncs) = counting(StoreWriteStage::DirectorySync, fail);
        store.set_hook(Some(hook)).await;
        let mut floor = floor(&store);
        let outcome = certify("S3", &mut floor).await;
        assert_eq!(syncs.load(Ordering::SeqCst), 1, "fail={fail}: one sync");
        let want = if fail {
            Err(FloorFault::SaveFailed)
        } else {
            Ok(())
        };
        assert_eq!(outcome, want, "fail={fail}");
        assert!(store.ready(), "fail={fail}: not poisoned");
    }
}

// S2: a record in an older on-disk form is re-saved in the current form, with
// every other member (ids, status, admission, input, targets, cancel markers)
// unchanged: positive evidence the re-save ran.
#[tokio::test]
async fn s2_an_older_form_record_is_resaved_in_the_current_form() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, ids) = seeded(&path, 1).await;
    store.close().await.unwrap();
    let file = path.join(format!("{}.json", ids[0]));
    let mut old: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    old.as_object_mut()
        .unwrap()
        .remove("dispatched")
        .expect("the current form writes dispatched");
    std::fs::write(&file, serde_json::to_vec(&old).unwrap()).unwrap();
    let store = open(&path).await;
    let mut floor = floor(&store);
    assert_eq!(certify("S2", &mut floor).await, Ok(()));
    let mut now: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(
        now.as_object_mut().unwrap().remove("dispatched"),
        Some(serde_json::json!(false)),
        "re-saved in the current form"
    );
    assert_eq!(now, old, "every other member unchanged");
}

// S4: a fault before the rename fails the checkpoint cleanly: the old files
// stay, the store stays ready, and a retry certifies.
#[tokio::test]
async fn s4_a_fault_before_rename_fails_cleanly_and_a_retry_certifies() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, _) = seeded(&path, 2).await;
    let before = records(&path);
    let (hook, renames) = counting(StoreWriteStage::Rename, true);
    store.set_hook(Some(hook)).await;
    let mut floor = floor(&store);
    assert_eq!(certify("S4", &mut floor).await, Err(FloorFault::SaveFailed));
    assert_eq!(
        renames.load(Ordering::SeqCst),
        1,
        "the re-save reached a rename"
    );
    assert_eq!(records(&path), before, "the old files are intact");
    assert!(
        store.ready(),
        "a fault before rename leaves the store ready"
    );
    floor.resume();
    store.set_hook(None).await;
    assert_eq!(certify("S4 retry", &mut floor).await, Ok(()));
}

// S5 and S7: a fault after the rename poisons the store (no deadlock on the
// way: the row's own timeout); resume keeps the poison; a retry is Unavailable.
#[tokio::test]
async fn s5_a_fault_after_rename_poisons_and_a_retry_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, _) = seeded(&path, 1).await;
    let (hook, _) = counting(StoreWriteStage::DirectorySync, true);
    store.set_hook(Some(hook)).await;
    let mut floor = floor(&store);
    assert_eq!(
        certify("S5 (S7: no deadlock)", &mut floor).await,
        Err(FloorFault::SaveFailed)
    );
    assert!(!store.ready(), "durability uncertain: poisoned");
    floor.resume();
    assert!(!store.ready(), "resume keeps the poison");
    store.set_hook(None).await;
    assert_eq!(
        certify("S5 retry", &mut floor).await,
        Err(FloorFault::Unavailable)
    );
}

// S6: beside a live record, a reserved (unrestorable) row, a corrupt file, a
// temp file and the lease stay byte-identical, and close is never called.
// Sealed rows are disk-only like reserved ones: not in the loaded entries,
// so no re-save can reach them.
#[tokio::test]
async fn s6_skipped_files_and_the_lease_are_left_alone() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, ids) = seeded(&path, 2).await;
    store.close().await.unwrap();
    let reserved = path.join(format!("{}.json", ids[1]));
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&reserved).unwrap()).unwrap();
    value["model"]["task"]["lastUpdatedAt"] = serde_json::json!("2026-09-06T00:00:00Z");
    std::fs::write(&reserved, serde_json::to_vec(&value).unwrap()).unwrap();
    std::fs::write(
        path.join("task-00000000-0000-4000-8000-000000000001.json"),
        b"{not json",
    )
    .unwrap();
    std::fs::write(path.join(format!("{}.json.tmp.1.0", ids[0])), b"partial").unwrap();
    let store = open(&path).await;
    let live = format!("{}.json", ids[0]);
    let others = |path: &Path| {
        let mut all = files(path);
        all.remove(&live);
        all
    };
    let before = others(&path);
    let (hook, renames) = counting(StoreWriteStage::Rename, false);
    store.set_hook(Some(hook)).await;
    let mut floor = floor(&store);
    assert_eq!(certify("S6", &mut floor).await, Ok(()));
    assert_eq!(
        renames.load(Ordering::SeqCst),
        1,
        "the live record was re-saved"
    );
    assert_eq!(others(&path), before, "everything else untouched");
    assert_eq!(store.closes_for_test(), 0, "close is never called");
}

// O1: an admitted write that fails with Storage during the attempt fails the
// checkpoint (SaveFailed); the next pause clears it and a checkpoint certifies.
#[tokio::test]
#[expect(
    clippy::await_holding_lock,
    reason = "holding the ordering lock keeps the admitted write in flight across the pause"
)]
async fn o1_an_admitted_write_failing_in_the_attempt_is_save_failed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, ids) = seeded(&path, 1).await;
    let revision = store.get(OWNER, &ids[0]).unwrap().revision;
    let (hook, _) = counting(StoreWriteStage::Rename, true);
    store.set_hook(Some(hook)).await;
    let held = store.hold_order_for_test();
    let write = tokio::spawn({
        let (store, id) = (store.clone(), ids[0].clone());
        async move { store.mark_dispatched(OWNER, &id, revision).await }
    });
    within("O1 admitted", async {
        while store.gate_for_test().in_flight() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    let mut floor = floor(&store);
    let deadline = deadline();
    assert_eq!(within("O1 pause", floor.pause(deadline)).await, Ok(()));
    drop(held);
    assert_eq!(
        within("O1 checkpoint", floor.checkpoint(deadline)).await,
        Err(FloorFault::SaveFailed)
    );
    let written = within("O1 write", write).await.expect("the write task");
    assert_eq!(written, Err(StoreError::Storage));
    floor.resume();
    store.set_hook(None).await;
    assert_eq!(certify("O1 retry", &mut floor).await, Ok(()));
}

// O2: a re-save that panics is WorkerLost; after resume the store still
// serves a read and a write (its ordering lock recovers from the panic).
#[tokio::test]
async fn o2_a_panicking_resave_is_worker_lost_and_the_store_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, ids) = seeded(&path, 1).await;
    store
        .set_hook(Some(Arc::new(|stage| {
            assert_ne!(stage, StoreWriteStage::Rename, "the re-save panics here");
            Ok(())
        })))
        .await;
    let mut floor = floor(&store);
    assert_eq!(certify("O2", &mut floor).await, Err(FloorFault::WorkerLost));
    floor.resume();
    store.set_hook(None).await;
    let revision = store.get(OWNER, &ids[0]).expect("a read after").revision;
    store
        .mark_dispatched(OWNER, &ids[0], revision)
        .await
        .expect("a write after");
}

// O3: a store that is not ready answers Unavailable and nothing is written.
#[tokio::test]
async fn o3_a_store_not_ready_is_unavailable_and_nothing_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, _) = seeded(&path, 1).await;
    let before = records(&path);
    store.stop_serving();
    let (hook, renames) = counting(StoreWriteStage::Rename, false);
    store.set_hook(Some(hook)).await;
    let mut floor = floor(&store);
    assert_eq!(
        certify("O3", &mut floor).await,
        Err(FloorFault::Unavailable)
    );
    assert_eq!(renames.load(Ordering::SeqCst), 0, "nothing re-saved");
    assert_eq!(records(&path), before);
}

// O4: through the adapter, an External create and an Internal write both park
// while paused and land after resume; a sweep is skipped, never parked.
#[tokio::test]
async fn o4_writes_park_while_paused_and_land_after_resume() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, ids) = seeded(&path, 1).await;
    let revision = store.get(OWNER, &ids[0]).unwrap().revision;
    let mut floor = floor(&store);
    assert_eq!(within("O4 pause", floor.pause(deadline())).await, Ok(()));
    assert!(!store.sweeps_allowed(), "a sweep skips while paused");
    let created = tokio::spawn({
        let store = store.clone();
        async move {
            store
                .create(PreparedTask::for_test(&task(), OWNER, 9))
                .await
                .map(drop)
        }
    });
    let marked = tokio::spawn({
        let (store, id) = (store.clone(), ids[0].clone());
        async move { store.mark_dispatched(OWNER, &id, revision).await }
    });
    within("O4 parked", async {
        while store.gate_for_test().parked() < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    floor.resume();
    assert_eq!(within("O4 create", created).await.unwrap(), Ok(()));
    assert_eq!(within("O4 write", marked).await.unwrap(), Ok(()));
}

/// A config or health owner that always certifies and counts its resumes.
struct Fake(crate::gateway::restart_floor::FloorOwner, Arc<AtomicUsize>);

impl FloorAdapter for Fake {
    fn owner(&self) -> crate::gateway::restart_floor::FloorOwner {
        self.0
    }
    fn pause(&mut self, _: Instant) -> futures::future::BoxFuture<'_, Result<(), FloorFault>> {
        Box::pin(async { Ok(()) })
    }
    fn checkpoint(&mut self, _: Instant) -> futures::future::BoxFuture<'_, Result<(), FloorFault>> {
        Box::pin(async { Ok(()) })
    }
    fn resume(&mut self) {
        self.1.fetch_add(1, Ordering::SeqCst);
    }
    fn release_for_stop(&mut self) {}
    fn commit(&mut self) {}
    fn settled(&self) -> bool {
        true
    }
}

/// The real task adapter beside two fakes, as the coordinator holds them.
pub(super) fn three(store: &TaskStore, resumes: &Arc<AtomicUsize>) -> Vec<Box<dyn FloorAdapter>> {
    use crate::gateway::restart_floor::FloorOwner;
    vec![
        Box::new(floor(store)),
        Box::new(Fake(FloorOwner::Config, Arc::clone(resumes))),
        Box::new(Fake(FloorOwner::Health, Arc::clone(resumes))),
    ]
}

pub(super) fn task_save_cancel(
    reason: crate::gateway::restart_floor::CancelReason,
) -> crate::gateway::restart_floor::Cancelled {
    crate::gateway::restart_floor::Cancelled {
        owner: crate::gateway::restart_floor::FloorOwner::TaskStore,
        stage: crate::gateway::restart_floor::FloorStage::Checkpoint,
        reason,
    }
}

// T1: a task save fault before rename cancels the run at the task store's
// checkpoint, every owner resumes, the store still serves a read and a
// create, and a retry certifies.
#[tokio::test]
async fn t1_a_task_save_fault_cancels_the_run_and_a_retry_certifies() {
    use crate::gateway::restart_floor::{CancelReason, run_checkpoint};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, ids) = seeded(&path, 1).await;
    let (hook, _) = counting(StoreWriteStage::Rename, true);
    store.set_hook(Some(hook)).await;
    let resumes = Arc::new(AtomicUsize::new(0));
    let mut adapters = three(&store, &resumes);
    let outcome = within("T1", run_checkpoint(&mut adapters, deadline()))
        .await
        .map(drop);
    assert_eq!(outcome, Err(task_save_cancel(CancelReason::SaveFailed)));
    assert_eq!(resumes.load(Ordering::SeqCst), 2, "both fakes resumed");
    assert_eq!(
        store.gate_for_test().state(),
        GateState::Open,
        "the store resumed"
    );
    store.get(OWNER, &ids[0]).expect("a read is still served");
    store
        .create(PreparedTask::for_test(&task(), OWNER, 7))
        .await
        .expect("a create is still served");
    store.set_hook(None).await;
    let retry = within("T1 retry", run_checkpoint(&mut adapters, deadline())).await;
    assert!(retry.is_ok(), "the retry certifies");
}

// T2: a fault after rename cancels the same way, the poison outlives the
// resume, and the retry's checkpoint answers Unavailable.
#[tokio::test]
async fn t2_a_task_save_fault_after_rename_keeps_the_poison() {
    use crate::gateway::restart_floor::{CancelReason, run_checkpoint};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let (store, _) = seeded(&path, 1).await;
    let (hook, _) = counting(StoreWriteStage::DirectorySync, true);
    store.set_hook(Some(hook)).await;
    let resumes = Arc::new(AtomicUsize::new(0));
    let mut adapters = three(&store, &resumes);
    let outcome = within("T2", run_checkpoint(&mut adapters, deadline()))
        .await
        .map(drop);
    assert_eq!(outcome, Err(task_save_cancel(CancelReason::SaveFailed)));
    assert!(!store.ready(), "poisoned after the resume");
    store.set_hook(None).await;
    let retry = within("T2 retry", run_checkpoint(&mut adapters, deadline()))
        .await
        .map(drop);
    assert_eq!(retry, Err(task_save_cancel(CancelReason::Unavailable)));
}
