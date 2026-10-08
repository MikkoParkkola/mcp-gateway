// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8121: a sealed row an operator repairs while the gateway runs is
//! readable after the next expiry sweep, without a restart. A live row goes
//! through the recovery a restart applies; a terminal row reads as stored.

use super::*;

/// `MIK-8121.READ.1` and `.READ.2`: repair a sealed in-flight row and a sealed
/// settled row while the sweep runs. Both are then readable by their owner,
/// the in-flight one settled exactly as startup recovery would settle it, and
/// each key still answers as its own row.
#[tokio::test]
async fn a_repaired_row_is_readable_without_a_restart() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    let seeded = timeout(
        BUDGET,
        seed_store(
            &dir,
            rows()
                .into_iter()
                .filter(|(key, ..)| matches!(*key, "x6b-dispatched" | "x6e-terminal"))
                .collect(),
        ),
    )
    .await
    .expect("seeding completes");
    let originals: Vec<(std::path::PathBuf, Vec<u8>)> = seeded
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

    let operation = operation();
    let representation = representation();
    let admission = fresh_admission();
    let (restored, executor) = timeout(
        BUDGET,
        open_runtime_with_admission(
            &dir,
            1,
            StoreLimits::default(),
            test_subscriptions(),
            Arc::clone(&admission),
        ),
    )
    .await
    .expect("startup does not hang")
    .expect("sealed rows never stop startup");
    assert_eq!(restored.skipped_records().sealed, 2);

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
