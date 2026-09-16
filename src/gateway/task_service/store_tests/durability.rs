// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Repair-driven cases for the defects the runtime review found: shutdown racing
//! an in-flight writer, a cancelled caller losing its publish, duplicate records,
//! and startup accepting a directory that ignores every limit.
//!
//! Every wait here is a channel or an ordering-lock join. There are no sleeps: a
//! test that passes because a thread happened to be slow is not evidence.
use super::*;

/// Reach the final durability boundary and hold there until released.
fn paused_at_final_sync(
    store: &TaskStore,
) -> (
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::Sender<()>,
    CommitHook,
) {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let receiver = std::sync::Mutex::new(release_rx);
    let arrivals = AtomicUsize::new(0);
    let _ = store;
    // One shot. A later commit in the same test must pass straight through:
    // re-entering here would signal a dropped receiver and fail the write for a
    // reason the test is not about.
    let hook: CommitHook = Arc::new(move |stage| {
        if stage == CommitStage::DirectorySync && arrivals.fetch_add(1, Ordering::SeqCst) == 0 {
            entered_tx.send(()).unwrap();
            receiver
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .map_err(std::io::Error::other)?;
        }
        Ok(())
    });
    (entered_rx, release_tx, hook)
}

async fn wait_for(entered: std::sync::mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || entered.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .expect("writer reached the final durability boundary");
}

#[tokio::test]
async fn store_04_close_joins_the_writer_and_holds_custody_until_it_finishes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    let (entered, release, hook) = paused_at_final_sync(&store);
    store.set_hook(Some(hook)).await;

    let writer = store.clone();
    let prepared = PreparedTask::for_test(&task, OWNER, 1);
    let pending = tokio::spawn(async move { writer.create(prepared).await });
    wait_for(entered).await;

    let closer = store.clone();
    let (attempting_tx, attempting_rx) = std::sync::mpsc::channel();
    let closing = tokio::spawn(async move {
        // Sent from inside the shutdown task, with no await between this and the
        // call: observing it proves `close` was entered and polled, rather than
        // trusting the scheduler to have got round to it.
        attempting_tx.send(()).unwrap();
        closer.close().await
    });
    tokio::task::spawn_blocking(move || attempting_rx.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .expect("shutdown was actually attempted");
    assert!(
        !closing.is_finished(),
        "close must wait for the ordered writer"
    );
    assert!(
        store.ready(),
        "shutdown must not tear down the committed view while a write is in flight"
    );
    assert!(
        matches!(
            TaskStore::open(&path, StoreLimits::default()).await,
            Err(StoreError::AlreadyOwned)
        ),
        "shutdown must not release the lease while a write is in flight"
    );

    release.send(()).unwrap();
    pending.await.unwrap().unwrap();
    closing.await.unwrap().unwrap();
    // Custody really was released, so the directory is openable again.
    open(&path).await.close().await.unwrap();
}

#[tokio::test]
async fn store_01_a_cancelled_creation_still_publishes_its_committed_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    let (entered, release, hook) = paused_at_final_sync(&store);
    store.set_hook(Some(hook)).await;

    let writer = store.clone();
    let prepared = PreparedTask::for_test(&task, OWNER, 1);
    let pending = tokio::spawn(async move { writer.create(prepared).await });
    wait_for(entered).await;
    // The caller goes away while the writer is still inside the commit. Joining
    // the handle here proves the cancellation actually took effect BEFORE the
    // write was allowed to finish — an abort that had not landed yet would make
    // the rest of this case prove nothing.
    pending.abort();
    let cancelled = pending.await;
    assert!(
        cancelled
            .as_ref()
            .is_err_and(tokio::task::JoinError::is_cancelled),
        "the creating caller must be gone before the write completes: {cancelled:?}"
    );
    release.send(()).unwrap();

    // Taking the ordering lock is the join: this cannot begin until the
    // abandoned write has finished publishing or poisoning. No sleep involved.
    let settled = store
        .transition(
            OWNER,
            task.id(),
            1,
            TaskTransition::StatusMessage(Some("still ours".into())),
            at(2),
        )
        .await
        .expect("a cancelled creation must not leave the directory ahead of the committed view");
    assert_eq!(settled.revision, 2);
    assert!(path.join(format!("{}.json", task.id())).is_file());
    store.close().await.unwrap();

    let reopened = open(&path).await;
    assert_eq!(reopened.get(OWNER, task.id()).unwrap().revision, 2);
    reopened.close().await.unwrap();
}

#[tokio::test]
async fn store_04_duplicate_task_or_identity_is_refused_before_the_writer_runs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let first = task();
    store
        .create(PreparedTask::for_test(&first, OWNER, 1))
        .await
        .unwrap();
    let before = files(&path);

    // Any writer entry at all falsifies "refused before the write".
    let entered = Arc::new(AtomicUsize::new(0));
    let tripwire = entered.clone();
    store
        .set_hook(Some(Arc::new(move |_| {
            tripwire.fetch_add(1, Ordering::SeqCst);
            Err(std::io::Error::other("writer must not be entered"))
        })))
        .await;

    assert_eq!(
        store
            .create(PreparedTask::for_test(&first, OWNER, 2))
            .await
            .unwrap_err(),
        StoreError::Duplicate,
        "a live task id must not be rewritten"
    );
    assert_eq!(
        store
            .create(PreparedTask::for_test(&task(), OTHER, 1))
            .await
            .unwrap_err(),
        StoreError::Duplicate,
        "a live admission identity must not be reused under a new task"
    );
    assert_eq!(entered.load(Ordering::SeqCst), 0);
    assert_eq!(files(&path), before);

    store.set_hook(None).await;
    let second = task();
    store
        .create(PreparedTask::for_test(&second, OTHER, 3))
        .await
        .unwrap();
    store.close().await.unwrap();

    // The directory a duplicate would have produced is exactly the one the
    // loader refuses, so refusing at the writer keeps reopen possible.
    let reopened = open(&path).await;
    assert_eq!(reopened.get(OWNER, first.id()).unwrap().revision, 1);
    assert_eq!(reopened.get(OTHER, second.id()).unwrap().revision, 1);
    reopened.close().await.unwrap();
}

#[tokio::test]
async fn store_04_two_creations_of_one_task_race_and_exactly_one_record_survives() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();

    // Only the FIRST writer to reach the payload boundary is held. If a second
    // one gets there at all the store has already lost, and holding it too would
    // hide that behind a channel timeout instead of a failed assertion.
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let receiver = std::sync::Mutex::new(release_rx);
    let arrivals = Arc::new(AtomicUsize::new(0));
    let gate = arrivals.clone();
    store
        .set_hook(Some(Arc::new(move |stage| {
            if stage == CommitStage::Write && gate.fetch_add(1, Ordering::SeqCst) == 0 {
                entered_tx.send(()).unwrap();
                receiver
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(std::io::Error::other)?;
            }
            Ok(())
        })))
        .await;

    let (one, two) = (store.clone(), store.clone());
    let first = PreparedTask::for_test(&task, OWNER, 1);
    let second = PreparedTask::for_test(&task, OTHER, 2);
    let winner = tokio::spawn(async move { one.create(first).await });
    wait_for(entered_rx).await;
    // The overlap is real, not assumed: the second call is issued while the
    // first is provably inside the writer.
    let loser = tokio::spawn(async move { two.create(second).await });
    tokio::task::yield_now().await;
    assert!(
        !loser.is_finished(),
        "the second creation must still be in flight while the first holds the writer"
    );
    release_tx.send(()).unwrap();
    let (won, lost) = (winner.await.unwrap(), loser.await.unwrap());

    assert_eq!(
        [won.is_ok(), lost.is_ok()].iter().filter(|ok| **ok).count(),
        1,
        "exactly one creation may win: {won:?} then {lost:?}"
    );
    assert!(won.is_ok(), "the writer that held the lock is the winner");
    assert!(
        lost.is_err(),
        "the second creation must be refused, not written"
    );
    assert_eq!(
        arrivals.load(Ordering::SeqCst),
        1,
        "the refused creation must never reach the writer"
    );

    // Whole-record preservation: the survivor is the winner's record, byte for
    // byte in the field that tells them apart, not the loser's overwrite.
    let stored: Value =
        serde_json::from_slice(&fs::read(path.join(format!("{}.json", task.id()))).unwrap())
            .unwrap();
    assert_eq!(
        stored["admission"]["identityDigest"],
        json!(format!("{:064x}", 1)),
        "the winner's record must survive intact"
    );
    store.close().await.unwrap();

    let reopened = open(&path).await;
    assert_eq!(reopened.get(OWNER, task.id()).unwrap().revision, 1);
    assert_eq!(
        reopened.get(OTHER, task.id()).unwrap_err(),
        StoreError::NotFound,
        "the losing owner never acquired the task"
    );
    reopened.close().await.unwrap();
}

#[tokio::test]
async fn store_04_startup_enforces_every_limit_against_the_stored_directory() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let first = task();
    let second = task();
    store
        .create(PreparedTask::for_test(&first, OWNER, 1))
        .await
        .unwrap();
    store
        .create(PreparedTask::for_test(&second, OWNER, 2))
        .await
        .unwrap();
    store.close().await.unwrap();
    let before = files(&path);

    let generous = StoreLimits::default();
    for (label, limits) in [
        (
            "record bytes",
            StoreLimits {
                record_bytes: 16,
                ..generous
            },
        ),
        (
            "record count",
            StoreLimits {
                records: 1,
                ..generous
            },
        ),
        (
            "per principal",
            StoreLimits {
                per_principal: 1,
                ..generous
            },
        ),
        (
            "logical budget",
            StoreLimits {
                record_bytes: 4096,
                logical_bytes: 4096,
                ..generous
            },
        ),
    ] {
        assert!(
            matches!(
                TaskStore::open(&path, limits).await,
                Err(StoreError::Capacity)
            ),
            "{label} must refuse a stored directory that exceeds it"
        );
        assert_eq!(files(&path), before, "{label} must preserve every file");
    }

    // The positive control: the same directory still opens under limits it fits.
    let reopened = TaskStore::open(&path, generous).await.unwrap();
    assert_eq!(reopened.get(OWNER, first.id()).unwrap().revision, 1);
    reopened.close().await.unwrap();

    // And EXACTLY at the cap, not merely under it. `per_principal` is an
    // inclusive maximum — `admit` refuses new work once a principal already
    // holds the cap, so holding exactly the cap is the legal state — and a
    // store that refused it could not reopen a directory it wrote itself.
    // A generous control alone never sits on the boundary, which is how two
    // one-record-early comparisons survived here.
    let exact = TaskStore::open(
        &path,
        StoreLimits {
            per_principal: 2,
            ..generous
        },
    )
    .await
    .expect("two records for one principal are within an inclusive cap of two");
    // Both records, not just the one that happened to be read first: a load
    // that refused the second would fail the open above, and a load that
    // dropped it would pass a weaker assertion.
    assert_eq!(exact.get(OWNER, first.id()).unwrap().revision, 1);
    assert_eq!(exact.get(OWNER, second.id()).unwrap().revision, 1);
    exact.close().await.unwrap();
}

#[tokio::test]
async fn store_01_an_orphan_temp_is_stepped_over_and_never_consumed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    store.close().await.unwrap();

    // Exactly the name a reopened store picks first: the per-store counter
    // restarts at zero and the fixture shares this process id.
    let evidence = b"crash residue that must survive".to_vec();
    // Both shapes a crashed writer could have left: the name THIS build would
    // pick first, and the one an earlier build picked. Either must be stepped
    // over rather than reused, truncated or deleted.
    let orphans = [
        path.join(format!("{}.json.tmp.{}.0", task.id(), std::process::id())),
        path.join(format!("{}.json.tmp-0", task.id())),
    ];
    for orphan in &orphans {
        seed_private(orphan, &evidence);
    }

    let reopened = open(&path).await;
    let settled = reopened
        .transition(OWNER, task.id(), 1, TaskTransition::Cancel, at(1))
        .await
        .expect("a crash orphan must not fail the next settlement");
    assert_eq!(settled.revision, 2);
    for orphan in &orphans {
        assert_eq!(
            fs::read(orphan).unwrap(),
            evidence,
            "an orphan is stepped over, never truncated, reused or deleted"
        );
    }
    reopened.close().await.unwrap();
}

#[tokio::test]
async fn store_04_a_duplicate_creation_never_bricks_the_next_startup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let first = task();
    store
        .create(PreparedTask::for_test(&first, OWNER, 1))
        .await
        .unwrap();
    // A second record carrying the SAME admission identity. Whatever the store
    // answers, what it must never do is write a directory its own loader then
    // refuses — that turns one bad call into a store that cannot restart.
    let second = store
        .create(PreparedTask::for_test(&task(), OTHER, 1))
        .await;
    store.close().await.unwrap();

    let reopened = TaskStore::open(&path, StoreLimits::default()).await;
    assert!(
        reopened.is_ok(),
        "duplicate creation bricked the store; the second create returned {second:?}"
    );
    reopened.unwrap().close().await.unwrap();
}

#[tokio::test]
async fn store_03_an_oversized_settlement_is_refused_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = TaskStore::open(
        &path,
        StoreLimits {
            record_bytes: 4096,
            ..StoreLimits::default()
        },
    )
    .await
    .unwrap();
    let task = task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    let before = files(&path);

    assert_eq!(
        store
            .transition(
                OWNER,
                task.id(),
                1,
                TaskTransition::Complete(json!({"content":[{"text":"x".repeat(8192)}]})),
                at(1),
            )
            .await
            .unwrap_err(),
        StoreError::Capacity
    );
    assert_eq!(files(&path), before);
    let retained = store.get(OWNER, task.id()).unwrap();
    assert_eq!(retained.revision, 1);
    assert_eq!(retained.task.status(), TaskStatus::Working);
    store.close().await.unwrap();
}

#[tokio::test]
async fn store_03_a_poisoned_store_refuses_every_entry_point_not_only_reads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    store
        .set_hook(Some(Arc::new(|stage| {
            if stage == CommitStage::DirectorySync {
                Err(std::io::Error::other("injected settlement failure"))
            } else {
                Ok(())
            }
        })))
        .await;
    assert_eq!(
        store
            .transition(OWNER, task.id(), 1, TaskTransition::Cancel, at(1))
            .await
            .unwrap_err(),
        StoreError::Storage
    );
    assert!(!store.ready());

    // Readiness was poisoned because durability became uncertain. A store that
    // refuses reads while still accepting writes would be claiming to know
    // something it just admitted it does not, so all three entry points refuse.
    assert_eq!(
        store.get(OWNER, task.id()).unwrap_err(),
        StoreError::Unavailable
    );
    assert_eq!(
        store
            .create(PreparedTask::for_test(&self::task(), OTHER, 2))
            .await
            .unwrap_err(),
        StoreError::Unavailable
    );
    assert_eq!(
        store
            .transition(OWNER, task.id(), 1, TaskTransition::Cancel, at(2))
            .await
            .unwrap_err(),
        StoreError::Unavailable
    );
    store.close().await.unwrap();
}

#[tokio::test]
async fn store_01_exhausting_every_temporary_name_refuses_without_touching_an_orphan() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    store.close().await.unwrap();

    // Every candidate the bounded retry can reach, already occupied by crash
    // residue. The count is the store's own attempt bound: if that bound grows
    // this fixture stops being exhaustive and FAILS loudly rather than quietly
    // passing, which is the failure mode worth having.
    let evidence = b"residue at every candidate name".to_vec();
    let orphans: Vec<_> = (0..8)
        .map(|nonce| {
            path.join(format!(
                "{}.json.tmp.{}.{nonce}",
                task.id(),
                std::process::id()
            ))
        })
        .collect();
    for orphan in &orphans {
        seed_private(orphan, &evidence);
    }

    let reopened = open(&path).await;
    assert_eq!(
        reopened
            .transition(OWNER, task.id(), 1, TaskTransition::Cancel, at(1))
            .await
            .unwrap_err(),
        StoreError::Storage,
        "with no unused name left the write must refuse rather than loop or clobber"
    );
    for orphan in &orphans {
        assert_eq!(
            fs::read(orphan).unwrap(),
            evidence,
            "no orphan may be reused, truncated or deleted"
        );
    }
    assert_eq!(
        reopened.get(OWNER, task.id()).unwrap().revision,
        1,
        "a refused write leaves the committed view exactly as it was"
    );
    reopened.close().await.unwrap();
}

#[test]
fn store_04_the_record_reader_refuses_one_byte_past_its_cap() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payload");

    // Exactly at the cap is accepted, whole.
    fs::write(&path, vec![b'x'; 64]).unwrap();
    let mut file = fs::File::open(&path).unwrap();
    assert_eq!(read_bounded(&mut file, 64).unwrap(), vec![b'x'; 64]);

    // One byte past it is refused as over-budget — not parsed, not truncated
    // into something that looks like a smaller record.
    fs::write(&path, vec![b'x'; 65]).unwrap();
    let mut file = fs::File::open(&path).unwrap();
    assert_eq!(
        read_bounded(&mut file, 64).unwrap_err(),
        StoreError::Capacity
    );

    // A zero cap still refuses rather than accepting an empty read of a file
    // that has content.
    let mut file = fs::File::open(&path).unwrap();
    assert_eq!(
        read_bounded(&mut file, 0).unwrap_err(),
        StoreError::Capacity
    );
}

/// Serialize one creation and one settlement under a generous cap and report
/// the exact byte sizes the store writes for each.
///
/// Measured rather than computed on purpose: a padding calculation would agree
/// with today's serialization and drift silently the day the record gains a
/// field, which is the failure mode a boundary case exists to prevent.
async fn measured_record_sizes(root: &std::path::Path) -> (usize, usize) {
    let path = root.join("measure");
    let store = open(&path).await;
    let task = task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    let record = path.join(format!("{}.json", task.id()));
    let created = usize::try_from(fs::metadata(&record).unwrap().len()).unwrap();
    store
        .transition(OWNER, task.id(), 1, settlement(), at(1))
        .await
        .unwrap();
    let settled = usize::try_from(fs::metadata(&record).unwrap().len()).unwrap();
    store.close().await.unwrap();
    assert!(
        created + 1 < settled,
        "the settled record must be more than one byte larger, or the under-cap \
         half of this case would be testing the same number twice"
    );
    (created, settled)
}

fn settlement() -> TaskTransition {
    TaskTransition::Complete(json!({"content":[{"type":"text","text":"settled"}]}))
}

fn capped(bytes: usize) -> StoreLimits {
    StoreLimits {
        record_bytes: bytes,
        ..StoreLimits::default()
    }
}

#[tokio::test]
async fn store_04_a_record_of_exactly_the_cap_is_accepted_on_both_write_paths() {
    let dir = tempfile::tempdir().unwrap();
    let (created, settled) = measured_record_sizes(dir.path()).await;

    // `record_bytes` is an INCLUSIVE maximum: §13.3 calls it "512 KiB maximum
    // serialized record", and `read_bounded` already refuses only at cap+1. A
    // record landing exactly on the cap is legal on every write path, and both
    // of these sites were mutable to `>=` without any case noticing.

    // Creation, exactly at the cap — pins store.rs `admit`.
    let exact_create = dir.path().join("exact-create");
    let store = TaskStore::open(&exact_create, capped(created))
        .await
        .unwrap();
    let task = task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .expect("a creation of exactly the cap is within an inclusive maximum");
    store.close().await.unwrap();

    // Settlement, exactly at the cap — pins store.rs `transition_blocking`.
    // `self::task()` from here on: the binding above shadows the fixture
    // function, so a bare `task()` would try to call a `Task` value.
    let exact_settle = dir.path().join("exact-settle");
    let store = TaskStore::open(&exact_settle, capped(settled))
        .await
        .unwrap();
    let task = self::task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    let done = store
        .transition(OWNER, task.id(), 1, settlement(), at(1))
        .await
        .expect("a settlement of exactly the cap is within an inclusive maximum");
    assert_eq!(done.revision, 2);
    assert_eq!(done.task.status(), TaskStatus::Completed);
    store.close().await.unwrap();

    // One byte under each, refused. Without this half the case would pass
    // against a store with no cap at all — it would raise a ceiling rather than
    // pin a boundary, and an oracle that cannot fail is the thing being avoided.
    let under_create = dir.path().join("under-create");
    let store = TaskStore::open(&under_create, capped(created - 1))
        .await
        .unwrap();
    assert_eq!(
        store
            .create(PreparedTask::for_test(&self::task(), OWNER, 1))
            .await
            .unwrap_err(),
        StoreError::Capacity
    );
    store.close().await.unwrap();

    let under_settle = dir.path().join("under-settle");
    let store = TaskStore::open(&under_settle, capped(settled - 1))
        .await
        .unwrap();
    let task = self::task();
    store
        .create(PreparedTask::for_test(&task, OWNER, 1))
        .await
        .unwrap();
    assert_eq!(
        store
            .transition(OWNER, task.id(), 1, settlement(), at(1))
            .await
            .unwrap_err(),
        StoreError::Capacity
    );
    assert_eq!(store.get(OWNER, task.id()).unwrap().revision, 1);
    store.close().await.unwrap();
}
