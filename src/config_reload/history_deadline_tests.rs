// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Design D-2 rows C3a-c and C10d: the whole-save deadline on the reload path.
//!
//! Each row runs on a current-thread runtime with a paused clock (see
//! `save_tests::paused`). The reload is spawned; the test waits until the save
//! job is where the row parks it (its timeout is armed by then), advances the
//! clock 1 ms short of the deadline (the reload must still be pending), then
//! past it (the reload must be done), and only then releases the job.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::SAVE_DEADLINE;
use super::record_tests::{ONE_BACKEND, TWO_BACKENDS, rig_in};
use super::save_tests::paused;
use super::seams::{self, ParkAt};
use crate::gateway::test_helpers::write_owner_only;

const MS: Duration = Duration::from_millis(1);

fn bytes_of(dir: &Path) -> Vec<u8> {
    std::fs::read(dir.join("config-history.json")).expect("the history file reads")
}

fn names_in(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .expect("the dir lists")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        // The history's own files: the reload keeps its config lock beside them.
        .filter(|name| name.contains("config-history"))
        .collect()
}

/// Whether `task` finishes within a bounded number of polls, with no time
/// passing: a parked blocking job holds the paused clock still.
async fn settles<T>(task: &tokio::task::JoinHandle<T>) -> bool {
    for _ in 0..1_000 {
        if task.is_finished() {
            return true;
        }
        tokio::task::yield_now().await;
    }
    task.is_finished()
}

/// The deadline's both sides: 1 ms short leaves the reload pending; past it,
/// the reload is done.
async fn cut_at_the_deadline<T>(reload: &tokio::task::JoinHandle<T>) {
    tokio::time::advance(SAVE_DEADLINE - MS).await;
    assert!(
        !settles(reload).await,
        "the reload ended before the deadline"
    );
    tokio::time::advance(2 * MS).await;
    assert!(
        settles(reload).await,
        "the reload did not end at the deadline"
    );
}

fn c3(at: ParkAt) {
    paused(move || async move {
        let dir = tempfile::tempdir().expect("tempdir");
        let installed = seams::install(dir.path());
        let rig = rig_in(dir, ONE_BACKEND);
        let before = bytes_of(rig.dir.path());
        let names = names_in(rig.dir.path());
        write_owner_only(&rig.path, TWO_BACKENDS).expect("add a backend");
        let gate = installed.seams.park(at);
        let ctx = Arc::clone(&rig.ctx);
        let reload = tokio::spawn(async move { ctx.reload_outcome().await });
        gate.arrival().await;
        cut_at_the_deadline(&reload).await;
        reload.await.expect("joined").expect("the reload applies");
        assert_eq!(
            bytes_of(rig.dir.path()),
            before,
            "{at:?}: byte-identical at the deadline"
        );
        let events = rig.store.events();
        // Parked before the read, the job never sent its state: this record
        // alone. Parked after it, the sent-back state: start and this reload.
        let held = if at == ParkAt::BeforeRead { 1 } else { 2 };
        assert_eq!(events.len(), held, "{at:?}: {events:?}");
        gate.release();
        gate.completion().await;
        match at {
            ParkAt::AfterCheck => {
                // Past its check, the job renames its own state and nothing else.
                let file: serde_json::Value =
                    serde_json::from_slice(&bytes_of(rig.dir.path())).expect("the file parses");
                let stored = file["events"].as_array().expect("events").len();
                assert_eq!(stored, 2, "{at:?}: the job's own state: {file}");
                // Exactly the job's versions, read back by a store of its own:
                // the start bytes, then the reload's under its published revision.
                let persisted =
                    super::ConfigHistory::open(rig.dir.path(), super::Bounds::default(), 1)
                        .snapshots();
                let gateway = rig.path.display().to_string();
                let bytes_at = |index: usize| {
                    persisted
                        .get(index)
                        .and_then(|snapshot| {
                            snapshot.files.iter().find(|file| file.path == gateway)
                        })
                        .map(|file| file.bytes.clone())
                };
                assert_eq!(persisted.len(), 2, "{at:?}: two versions: {persisted:?}");
                assert_eq!(bytes_at(0), Some(Some(ONE_BACKEND.as_bytes().to_vec())));
                assert_eq!(bytes_at(1), Some(Some(TWO_BACKENDS.as_bytes().to_vec())));
                let published = rig
                    .ctx
                    .live_config
                    .applied_now()
                    .map(|applied| applied.revision.clone());
                assert_eq!(
                    persisted.last().map(|snapshot| snapshot.revision.clone()),
                    published,
                    "{at:?}: under the revision the reload published"
                );
                let now = bytes_of(rig.dir.path());
                write_owner_only(&rig.path, ONE_BACKEND).expect("drop the backend");
                rig.ctx
                    .reload_outcome()
                    .await
                    .expect("the next reload applies");
                assert_eq!(
                    bytes_of(rig.dir.path()),
                    now,
                    "{at:?}: a later record writes nothing"
                );
            }
            _ => {
                assert_eq!(
                    bytes_of(rig.dir.path()),
                    before,
                    "{at:?}: still byte-identical"
                );
                assert_eq!(names_in(rig.dir.path()), names, "{at:?}: no temp file left");
            }
        }
        drop(installed);
    });
}

/// C3a: parked after the temp write, before the generation check.
#[test]
fn c3a_a_save_parked_before_its_check_is_cut_and_writes_nothing_later() {
    c3(ParkAt::BeforeCheck);
}

/// C3b: parked after a passed check: released, it renames only its own state.
#[test]
fn c3b_a_save_past_its_check_renames_only_its_own_state() {
    c3(ParkAt::AfterCheck);
}

/// C3c: parked before the read: the memory-only record is complete.
#[test]
fn c3c_a_save_parked_before_its_read_leaves_a_complete_memory_record() {
    c3(ParkAt::BeforeRead);
}

/// C10d: the sidecar held by another holder past the deadline: memory-only
/// with this record, the file byte-identical, before and after the sidecar frees.
#[test]
fn c10d_a_sidecar_held_past_the_deadline_keeps_the_record_in_memory() {
    paused(|| async {
        let dir = tempfile::tempdir().expect("tempdir");
        let installed = seams::install(dir.path());
        let rig = rig_in(dir, ONE_BACKEND);
        let before = bytes_of(rig.dir.path());
        // The late job, once the sidecar frees, parks at its generation check,
        // so the row watches it reach the check and fail it (code review r2).
        let gate = installed.seams.park(ParkAt::BeforeCheck);
        let lock = rig.dir.path().join("config-history.json.lock");
        let held = crate::fs_lock::ExclusiveFileLock::try_acquire(&lock).expect("hold the sidecar");
        let base = crate::fs_lock::lock_attempts(&lock);
        write_owner_only(&rig.path, TWO_BACKENDS).expect("add a backend");
        let ctx = Arc::clone(&rig.ctx);
        let reload = tokio::spawn(async move { ctx.reload_outcome().await });
        // The job is in its sidecar wait (so its timeout is armed) once it has
        // tried the lock; bounded in real time.
        let waited = std::time::Instant::now();
        while crate::fs_lock::lock_attempts(&lock) <= base {
            assert!(
                waited.elapsed() < Duration::from_secs(10),
                "the save never waited on the sidecar"
            );
            tokio::task::yield_now().await;
            std::thread::sleep(MS);
        }
        cut_at_the_deadline(&reload).await;
        reload.await.expect("joined").expect("the reload applies");
        assert_eq!(
            bytes_of(rig.dir.path()),
            before,
            "byte-identical at the deadline"
        );
        assert_eq!(rig.store.events().len(), 1, "memory-only with this record");
        drop(held);
        tokio::time::timeout(Duration::from_secs(30), gate.arrival())
            .await
            .expect("the late job took the sidecar and reached its check");
        gate.release();
        gate.completion().await;
        assert_eq!(
            bytes_of(rig.dir.path()),
            before,
            "the late job wrote nothing"
        );
        drop(installed);
    });
}
