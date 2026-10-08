// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8121: a sealed row an operator repairs while the gateway runs is
//! readable after the next expiry sweep, without a restart. A live row goes
//! through the recovery a restart applies; a terminal row reads as stored.

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
    let deadline = std::time::Instant::now() + BUDGET;
    while restored.skipped_records().sealed != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the expiry sweep never re-read the repaired rows"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

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
