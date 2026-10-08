// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

#[tokio::test]
async fn startup_settles_every_interrupted_row_by_what_its_record_can_prove() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    let seeded = timeout(BUDGET, seed_store(&dir, rows()))
        .await
        .expect("seeding completes");

    // The constructor the gateway itself calls, over an authority that has
    // never seen this store: nothing in memory can carry the answer across.
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
    .expect("startup imports and recovers the durable store");

    let mut problems = Vec::new();
    for row in &seeded {
        match restored.get(OWNER, &row.id) {
            Ok(committed) => problems.extend(judge(row, &committed.task, committed.revision)),
            Err(error) => problems.push(format!(
                "{}: a recovered task must still be readable by its owner: {error}",
                row.key
            )),
        }
    }
    // Custody first, verdict second: a failing assertion must not leave the
    // fixture directory leased.
    timeout(BUDGET, restored.shutdown())
        .await
        .expect("shutdown does not hang")
        .expect("custody is released");
    drop(executor);
    drop(restored);
    drop(admission);

    // Startup preserves the absent dispatch marker on the recovered record.
    // This fixture observes persisted state only; it has no backend witness
    // and therefore does not prove absence of invocation or publication.
    let undispatched = seeded
        .iter()
        .find(|row| matches!(row.seed, Seed::Undispatched))
        .expect("the fixture holds an undispatched row");
    let record: Value = serde_json::from_slice(
        &std::fs::read(dir.join(format!("{}.json", undispatched.id))).unwrap(),
    )
    .expect("the recovered record parses");
    if record.get("dispatched") != Some(&json!(false)) {
        problems.push(format!(
            "x6a-undispatched: recovery settles a record without ever claiming a \
             dispatch, but the marker on disk is {:?}",
            record.get("dispatched")
        ));
    }
    if record.pointer("/model/task/status") != Some(&json!("completed")) {
        problems.push(format!(
            "x6a-undispatched: the recovery rewrite goes through the durable commit \
             seam, but the record on disk is still {:?}",
            record.pointer("/model/task/status")
        ));
    }
    // MIK-7311: a recovered input round keeps no continuation on disk.
    for row in seeded
        .iter()
        .filter(|row| matches!(row.seed, Seed::InputRequired))
    {
        let record: Value =
            serde_json::from_slice(&std::fs::read(dir.join(format!("{}.json", row.id))).unwrap())
                .expect("the recovered record parses");
        if record.get("inputRound").is_some() {
            problems.push(format!("{}: the continuation survived recovery", row.key));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

#[tokio::test]
async fn a_second_startup_rewrites_nothing_the_first_one_recovered() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    let seeded = timeout(
        BUDGET,
        seed_store(
            &dir,
            rows()
                .into_iter()
                .filter(|(key, ..)| *key == "x6a-undispatched" || *key == "x6e-terminal")
                .collect(),
        ),
    )
    .await
    .expect("seeding completes");

    let mut after_first = Vec::new();
    {
        let admission = fresh_admission();
        let (restored, executor) = timeout(
            BUDGET,
            open_runtime_with_admission(
                &dir,
                1,
                StoreLimits::default(),
                test_subscriptions(),
                admission,
            ),
        )
        .await
        .expect("the first startup does not hang")
        .expect("the first startup recovers");
        for row in &seeded {
            let committed = restored
                .get(OWNER, &row.id)
                .expect("readable after startup");
            after_first.push((
                committed.revision,
                serde_json::to_value(committed.task.wire()).unwrap(),
            ));
        }
        timeout(BUDGET, restored.shutdown())
            .await
            .expect("shutdown does not hang")
            .expect("custody is released");
        drop(executor);
    }

    let admission = fresh_admission();
    let (again, executor) = timeout(
        BUDGET,
        open_runtime_with_admission(
            &dir,
            1,
            StoreLimits::default(),
            test_subscriptions(),
            admission,
        ),
    )
    .await
    .expect("the second startup does not hang")
    .expect("the second startup opens the recovered store");
    let mut problems = Vec::new();
    for (row, (revision, wire)) in seeded.iter().zip(&after_first) {
        let committed = again.get(OWNER, &row.id).expect("readable after restart");
        let now = serde_json::to_value(committed.task.wire()).unwrap();
        if committed.revision != *revision || now != *wire {
            problems.push(format!(
                "{}: recovery is not repeated on a store that is already recovered: \
                 revision {revision} and {wire} became revision {} and {now}",
                row.key, committed.revision
            ));
        }
    }
    timeout(BUDGET, again.shutdown())
        .await
        .expect("shutdown does not hang")
        .expect("custody is released");
    drop(executor);
    assert!(problems.is_empty(), "{problems:#?}");
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end recovery scenario read as a single sequence"
)]
async fn a_recovered_task_still_answers_the_owner_and_key_that_created_it() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    let seeded = timeout(
        BUDGET,
        seed_store(
            &dir,
            rows()
                .into_iter()
                .filter(|(key, ..)| *key == "x6a-undispatched")
                .collect(),
        ),
    )
    .await
    .expect("seeding completes");
    let row = &seeded[0];

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
    .expect("startup recovers the durable store");

    let owner_view = restored
        .get(OWNER, &row.id)
        .expect("the recovered owner can read its task");
    assert_eq!(owner_view.task.id(), row.id);
    assert!(
        matches!(
            restored.get("another-owner", &row.id),
            Err(crate::gateway::task_service::ServiceError::NotFound)
        ),
        "the same recovered handle remains hidden from another owner"
    );

    // A client that retries its original call gets the SAME durable task —
    // recovered, settled, and not a second one. Recovery settles a record; it
    // does not release the key that owns it.
    let workers = Arc::new(Semaphore::new(1));
    let slot = Arc::clone(&workers);
    let replay = timeout(
        BUDGET,
        restored.create(
            request(row.key, &operation, &representation),
            &Task::create("write"),
            "fixture",
            move || slot.try_acquire_owned().ok(),
        ),
    )
    .await
    .expect("the replay does not hang")
    .expect("the replay is answered");
    let mut problems = Vec::new();
    match replay {
        CreateOutcome::Existing(committed) => {
            if committed.task.id() != row.id {
                problems.push(format!(
                    "a replay must return the recovered task {}, not {}",
                    row.id,
                    committed.task.id()
                ));
            }
        }
        _ => problems.push("a same-owner, same-key replay must return the durable task".to_owned()),
    }
    // The refusal is about this owner and this key, not a saturated index.
    if !matches!(
        admission.admit(Request {
            key: "unclaimed-key",
            mode: Mode::Sync,
            ..request(row.key, &operation, &representation)
        }),
        Ok(Admission::Owned(_))
    ) {
        problems.push("a fresh key is still admitted after recovery".to_owned());
    }
    if !matches!(
        admission.admit(Request {
            principal: "another-owner",
            mode: Mode::Sync,
            ..request(row.key, &operation, &representation)
        }),
        Ok(Admission::Owned(_))
    ) {
        problems.push("another owner's identical call is still admitted".to_owned());
    }
    if !matches!(
        admission.admit(Request {
            mode: Mode::Sync,
            ..request(row.key, &operation, &representation)
        }),
        Err(Refusal::Mismatch)
    ) {
        problems.push("the recovered owner and key still refuse synchronous admission".to_owned());
    }
    timeout(BUDGET, restored.shutdown())
        .await
        .expect("shutdown does not hang")
        .expect("custody is released");
    drop(executor);
    assert!(problems.is_empty(), "{problems:#?}");
}

/// MIK-7840 HOOK.3: a listener installed before recovery hears the rows
/// recovery settles, so a task settled during startup is published.
#[tokio::test]
async fn a_task_settled_during_recovery_is_published() {
    use crate::gateway::task_service::open_runtime_with_recovery;
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    let seeded = timeout(BUDGET, seed_store(&dir, rows()))
        .await
        .expect("seeding completes");
    let undispatched = seeded
        .iter()
        .find(|row| matches!(row.seed, Seed::Undispatched))
        .expect("the fixture holds an undispatched row")
        .id
        .clone();

    let heard = Arc::new(parking_lot::Mutex::new(Vec::<String>::new()));
    let admission = fresh_admission();
    let (restored, executor) = timeout(
        BUDGET,
        open_runtime_with_recovery(
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
    .expect("startup recovers the durable store");
    timeout(BUDGET, restored.shutdown())
        .await
        .expect("shutdown does not hang")
        .expect("custody is released");
    drop(executor);
    drop(restored);
    drop(admission);

    assert!(
        heard.lock().contains(&undispatched),
        "recovery settled {undispatched}; the listener heard {:?}",
        heard.lock()
    );
}

/// `MIK-8052`: a sealed row (its key unreadable) changes nothing for recovery.
/// The interrupted row beside it is settled as before and its key still finds
/// it; only a NEW key is refused while the seal holds, and the running expiry
/// sweep lifts the seal once the file is gone.
#[tokio::test]
async fn recovery_beside_a_sealed_row_settles_and_keeps_keys() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    let seeded = timeout(
        BUDGET,
        seed_store(
            &dir,
            rows()
                .into_iter()
                .filter(|(key, ..)| matches!(*key, "x6a-undispatched" | "x6b-dispatched"))
                .collect(),
        ),
    )
    .await
    .expect("seeding completes");
    let (row, damaged) = (&seeded[0], &seeded[1]);
    let record = dir.join(format!("{}.json", damaged.id));
    let text = std::fs::read_to_string(&record).unwrap();
    std::fs::write(
        &record,
        text.replacen("\"dispatched\":", "\"dispatched\":@", 1),
    )
    .unwrap();

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
    .expect("a sealed row never stops startup");
    assert_eq!(restored.skipped_records().sealed, 1);
    assert!(
        restored.get(OWNER, &row.id).is_ok(),
        "the interrupted row was recovered"
    );
    assert!(
        matches!(
            admission.admit(Request {
                mode: Mode::Sync,
                ..request(row.key, &operation, &representation)
            }),
            Err(Refusal::Mismatch)
        ),
        "the recovered key still answers as its own"
    );
    assert!(
        matches!(
            admission.admit(Request {
                key: "unclaimed-key",
                mode: Mode::Sync,
                ..request(row.key, &operation, &representation)
            }),
            Ok(Admission::Sealed)
        ),
        "a new key is refused while the seal holds"
    );

    // The running expiry sweep is what lifts the seal: remove the file and
    // wait, bounded, for a sweep to notice, with no direct re-read here.
    let sweep = executor
        .start_expiry(std::time::Duration::from_millis(50))
        .expect("the sweep starts");
    std::fs::remove_file(&record).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while restored.skipped_records().sealed != 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the expiry sweep never re-read the sealed row"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        matches!(
            admission.admit(Request {
                key: "unclaimed-key",
                mode: Mode::Sync,
                ..request(row.key, &operation, &representation)
            }),
            Ok(Admission::Owned(_))
        ),
        "the seal lifted without a restart"
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
