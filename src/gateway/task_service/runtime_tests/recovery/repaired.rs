// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8121: a sealed row an operator repairs while the gateway runs is
//! readable after the next expiry sweep, without a restart. A live row goes
//! through the recovery a restart applies; a terminal row reads as stored.

use std::ops::ControlFlow::{Break, Continue};

use super::*;

/// `MIK-8121.READ.1` and `.READ.2`: repair a sealed in-flight row, a sealed
/// abandoned input round and a sealed settled row while the sweep runs. All
/// are then readable by their owner, the live ones settled exactly as startup
/// recovery would settle them and announced, and each key still answers as
/// its own row.
#[tokio::test]
async fn a_repaired_row_is_readable_without_a_restart() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    let (seeded, originals) = sealed_rows(&dir).await;

    let operation = operation();
    let representation = representation();
    let admission = fresh_admission();
    let heard = Arc::new(parking_lot::Mutex::new(Vec::<String>::new()));
    let (restored, executor) = timeout(
        BUDGET,
        crate::gateway::task_service::open_runtime_with_recovery(
            &dir,
            1,
            StoreLimits::default(),
            test_subscriptions(),
            Arc::clone(&admission),
            &[],
            |_, executor| {
                let heard = Arc::clone(&heard);
                executor.on_publication(Arc::new(move |id, _, _, _| {
                    heard.lock().push(id.to_owned());
                }));
            },
        ),
    )
    .await
    .expect("startup does not hang")
    .expect("sealed rows never stop startup");
    assert_eq!(restored.skipped_records().sealed, 3);

    let sweep = executor
        .start_expiry(Duration::from_millis(50))
        .expect("the sweep starts");
    for (record, original) in &originals {
        std::fs::write(record, original).unwrap();
    }
    // The seal lifts inside the sweep's blocking re-read; the announcement
    // follows when the sweep resumes on the runtime (execution.rs
    // `reread_sealed`). Wait for both, within BUDGET (5 s): a slow runner
    // (Windows' coarse timer) can see the seal gone before the announcement.
    let announced = |seeded: &[Seeded]| {
        let heard = heard.lock();
        seeded
            .iter()
            .filter(|row| row.expected.is_some())
            .all(|row| heard.contains(&row.id))
    };
    // Past the bound the report below names each row not re-read or announced.
    let _ = crate::test_wait::wait_until(BUDGET, || {
        let done = restored.skipped_records().sealed == 0 && announced(&seeded);
        std::future::ready(if done {
            Break(())
        } else {
            Continue(String::new())
        })
    })
    .await;
    assert_eq!(
        restored.skipped_records().sealed,
        0,
        "the expiry sweep never re-read the repaired rows"
    );

    let mut problems = Vec::new();
    for row in &seeded {
        match restored.get(OWNER, &row.id) {
            Ok(committed) => problems.extend(judge(row, &committed.task, committed.revision)),
            Err(error) => problems.push(format!(
                "{}: the repaired row is not readable without a restart: {error:?}",
                row.key
            )),
        }
        if !matches!(
            admission.admit(Request {
                mode: Mode::Sync,
                ..request(row.key, &operation, &representation)
            }),
            Err(Refusal::Mismatch)
        ) {
            problems.push(format!(
                "{}: the repaired key no longer answers as its own",
                row.key
            ));
        }
    }
    for row in seeded.iter().filter(|row| row.expected.is_some()) {
        if !heard.lock().contains(&row.id) {
            problems.push(format!(
                "{}: settled on repair but never announced",
                row.key
            ));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
    assert_eq!(
        restored.skipped_records().reserved,
        0,
        "a repaired row that restores is a readable row, not a reserved one"
    );

    timeout(BUDGET, sweep.shutdown())
        .await
        .expect("the sweep stops")
        .expect("the sweep ran clean");
    timeout(BUDGET, restored.shutdown())
        .await
        .expect("shutdown does not hang")
        .expect("custody is released");
    drop(executor);
}

/// Seed an in-flight row, an abandoned input round and a settled row, then
/// damage each so its key cannot be read. Returns the rows and, per row, its
/// record path and original bytes for the repair.
async fn sealed_rows(dir: &std::path::Path) -> (Vec<Seeded>, Vec<(std::path::PathBuf, Vec<u8>)>) {
    let seeded = timeout(
        BUDGET,
        seed_store(
            dir,
            rows()
                .into_iter()
                .filter(|(key, ..)| {
                    matches!(
                        *key,
                        "x6b-dispatched" | "x6d-input-required" | "x6e-terminal"
                    )
                })
                .collect(),
        ),
    )
    .await
    .expect("seeding completes");
    let originals = seeded
        .iter()
        .map(|row| {
            let record = dir.join(format!("{}.json", row.id));
            let original = std::fs::read(&record).unwrap();
            let text = String::from_utf8(original.clone()).unwrap();
            let damaged = text.replacen("\"dispatched\":", "\"dispatched\":@", 1);
            assert_ne!(
                damaged, text,
                "{}: the fixture must damage the row",
                row.key
            );
            std::fs::write(&record, damaged).unwrap();
            (record, original)
        })
        .collect();
    (seeded, originals)
}

/// A runtime over the three sealed rows of [`sealed_rows`], recording the
/// last-change time each announced transition carried.
async fn sealed_runtime(
    dir: &std::path::Path,
) -> (
    Vec<Seeded>,
    Vec<(std::path::PathBuf, Vec<u8>)>,
    Arc<TaskService>,
    Arc<crate::gateway::task_service::TaskExecutor>,
    Arc<parking_lot::Mutex<Vec<(String, chrono::DateTime<chrono::Utc>)>>>,
) {
    let (seeded, originals) = sealed_rows(dir).await;
    let heard = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let sink = Arc::clone(&heard);
    let (restored, executor) = crate::gateway::task_service::open_runtime_with_recovery(
        dir,
        1,
        StoreLimits::default(),
        test_subscriptions(),
        fresh_admission(),
        &[],
        |_, executor| {
            executor.on_publication(Arc::new(move |id, _, at, _| {
                sink.lock().push((id.to_owned(), at));
            }));
        },
    )
    .await
    .expect("sealed rows never stop startup");
    (seeded, originals, restored, executor, heard)
}

fn repair(originals: &[(std::path::PathBuf, Vec<u8>)]) {
    for (record, original) in originals {
        std::fs::write(record, original).unwrap();
    }
}

/// T14b (MIK-8202 RECORDER rule, P2 row 15): a repaired live row is settled
/// at the store clock's checked time, never a raw chrono read. The store
/// clock is frozen two hours ahead; the row's last-change time is exactly
/// that. Mutant: the raw read restored.
#[tokio::test]
async fn t14b_a_repaired_live_row_is_settled_at_the_frozen_store_time() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    let (seeded, originals, restored, executor, heard) = sealed_runtime(&dir).await;
    let frozen =
        crate::clock::utc_now().expect("host clock") + crate::duration_bound::delta!(hours, 2);
    restored.store.set_clock_for_test(Some(frozen));
    let sweep = executor
        .start_expiry(Duration::from_millis(50))
        .expect("sweep");
    repair(&originals);
    let dispatched = seeded
        .iter()
        .find(|r| r.key == "x6b-dispatched")
        .unwrap()
        .id
        .clone();
    let _ = crate::test_wait::wait_until(BUDGET, || {
        let seen = heard.lock().iter().any(|(id, _)| *id == dispatched);
        std::future::ready(if seen {
            Break(())
        } else {
            Continue(String::new())
        })
    })
    .await;
    let at = heard
        .lock()
        .iter()
        .find(|(id, _)| *id == dispatched)
        .map(|(_, at)| *at);
    sweep.shutdown().await.expect("sweep stops");
    restored.shutdown().await.expect("custody released");
    assert_eq!(at, Some(frozen), "settled at the store's time");
}

/// T14b (unreadable store clock): the repaired live rows are not settled; they
/// stays sealed until a pass can date it, then is served. Mutant: settle at
/// a raw 1969-or-now read anyway.
#[tokio::test]
async fn t14b_a_repaired_live_row_stays_sealed_while_the_store_clock_is_unreadable() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    let (_, originals, restored, executor, _heard) = sealed_runtime(&dir).await;
    restored
        .store
        .set_clock_for_test(Some(chrono::DateTime::from_timestamp(-1, 0).unwrap()));
    let sweep = executor
        .start_expiry(Duration::from_millis(50))
        .expect("sweep");
    let refused = restored.store.refused_reads_for_test();
    repair(&originals);
    // Two sweep passes past the repair, each refused a read of the clock:
    // an event, not a window. Either pass would have settled the rows.
    let _ = crate::test_wait::wait_until(BUDGET, || {
        let passes = restored.store.refused_reads_for_test() >= refused + 2;
        std::future::ready(if passes {
            Break(())
        } else {
            Continue(String::from("two refused sweep passes"))
        })
    })
    .await;
    let still_sealed = restored.skipped_records().sealed;
    restored.store.set_clock_for_test(None);
    let _ = crate::test_wait::wait_until(BUDGET, || {
        let done = restored.skipped_records().sealed == 0;
        std::future::ready(if done {
            Break(())
        } else {
            Continue(String::new())
        })
    })
    .await;
    let after = restored.skipped_records().sealed;
    sweep.shutdown().await.expect("sweep stops");
    restored.shutdown().await.expect("custody released");
    assert_eq!(
        still_sealed, 2,
        "the two live rows are not settled on an undatable clock"
    );
    assert_eq!(after, 0, "the next readable pass serves them");
}
