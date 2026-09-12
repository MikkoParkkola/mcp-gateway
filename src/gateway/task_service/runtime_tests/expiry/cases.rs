// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
use super::*;

/// Every terminal shape, expired, is deleted with its retained key — and the
/// capacity the records held comes back with them.
///
/// The store is opened with room for exactly the three seeded rows, so a fourth
/// create is refused BEFORE the sweep and accepted after it. `Unavailable` is
/// the store's capacity refusal at this facade (`CreateOutcome::Capacity` is
/// reserved for worker-slot exhaustion), and the worker pool here is generous
/// enough that no refusal can come from it.
#[tokio::test]
async fn expiry_deletes_every_expired_terminal_row_with_its_key_and_capacity() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    let admission = fresh_admission();
    let limits = StoreLimits {
        records: 3,
        ..StoreLimits::default()
    };
    let (service, executor) = open_runtime_with_admission(
        &dir,
        8,
        limits,
        test_subscriptions(),
        Arc::clone(&admission),
    )
    .await
    .expect("the runtime opens");
    let workers = Arc::new(Semaphore::new(8));

    let rows = [
        ("x-completed", Settle::Completed),
        ("x-failed", Settle::Failed),
        ("x-cancelled", Settle::Cancelled),
    ];
    let mut seeded = Vec::new();
    for (key, settle) in rows {
        seeded.push((
            key,
            seed(
                &service,
                &workers,
                key,
                3_600_000,
                Some(SHORT_TTL_MS),
                settle,
            )
            .await,
        ));
    }

    // Full store, before any sweep: the control for the acceptance below.
    let (operation, representation) = (operation(), representation());
    let slot = Arc::clone(&workers);
    let refused = service
        .create(
            request("x-newcomer", &operation, &representation),
            &Task::create("write"),
            "fixture",
            move || slot.try_acquire_owned().ok(),
        )
        .await
        .unwrap();
    assert!(
        matches!(refused, CreateOutcome::Unavailable),
        "the fixture must start at full record capacity"
    );

    let guard = executor
        .start_expiry(TICK)
        .expect("the runtime owner starts the periodic sweep");

    for (key, row) in &seeded {
        assert!(
            swept(&service, &dir, &row.id).await,
            "the expired {key} row is still readable or still on disk"
        );
    }

    // The ORIGINAL key admits again, and to a genuinely new record: the dedupe
    // entry died with the record rather than outliving it. These rows carry the
    // release default TTL, so a tick landing mid-loop has nothing to select.
    for (key, row) in &seeded {
        let slot = Arc::clone(&workers);
        let created = service
            .create(
                request(key, &operation, &representation),
                &Task::create("write"),
                "fixture",
                move || slot.try_acquire_owned().ok(),
            )
            .await
            .unwrap();
        let CreateOutcome::Created { task, slot } = created else {
            panic!("the expired key {key} must admit a new task, not replay the deleted one");
        };
        assert_ne!(
            task.task.id(),
            row.id,
            "{key} must own a new record, not the deleted handle"
        );
        assert!(record_path(&dir, task.task.id()).exists());
        drop(slot);
    }

    guard
        .shutdown()
        .await
        .expect("the runtime owner stops the sweep before the store closes");
    service.shutdown().await.expect("custody is released");
    drop(executor);
}

/// Expiry is conditional, and its conditions are the record's own: an unexpired
/// TTL, a null TTL, and a live status each retain a row that a deadline-only
/// sweep would take. Retention is asserted while sentinels are actually being
/// swept, so a loop that never ran cannot pass this row.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end sweep scenario across four retention reasons and two passes; splitting it would hide that retention is observed across real sweeps, not asserted piecemeal"
)]
async fn expiry_retains_unexpired_null_ttl_and_live_rows_across_real_sweeps() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    let admission = fresh_admission();
    let (service, executor) = open_runtime_with_admission(
        &dir,
        8,
        StoreLimits::default(),
        test_subscriptions(),
        Arc::clone(&admission),
    )
    .await
    .expect("the runtime opens");
    let workers = Arc::new(Semaphore::new(8));

    // Retained for four different reasons. The two live rows are past their TTL
    // on purpose: only their status keeps them.
    let unexpired = seed(
        &service,
        &workers,
        "r-unexpired",
        0,
        Some(DAY_MS),
        Settle::Completed,
    )
    .await;
    let unlimited = seed(
        &service,
        &workers,
        "r-null-ttl",
        3_600_000,
        None,
        Settle::Completed,
    )
    .await;
    let working = seed(
        &service,
        &workers,
        "r-working",
        3_600_000,
        Some(SHORT_TTL_MS),
        Settle::Working,
    )
    .await;
    let asking = seed(
        &service,
        &workers,
        "r-input-required",
        3_600_000,
        Some(SHORT_TTL_MS),
        Settle::InputRequired,
    )
    .await;
    let first = seed(
        &service,
        &workers,
        "r-sentinel-1",
        3_600_000,
        Some(SHORT_TTL_MS),
        Settle::Cancelled,
    )
    .await;
    assert_eq!(
        service.get(OWNER, &working.id).unwrap().task.status(),
        TaskStatus::Working
    );
    assert_eq!(
        service.get(OWNER, &asking.id).unwrap().task.status(),
        TaskStatus::InputRequired
    );

    let guard = executor.start_expiry(TICK).expect("the sweep starts");

    // Each sentinel's deletion is a witnessed tick; the retained rows are
    // re-examined after each one, so retention is observed across two passes
    // rather than inferred from a loop that may have run once.
    assert!(
        swept(&service, &dir, &first.id).await,
        "the first expired sentinel was never swept, so retention proves nothing"
    );
    for (row, what) in [
        (&unexpired, "an unexpired record"),
        (&unlimited, "a null-TTL record"),
        (&working, "a Working record past its TTL"),
        (&asking, "an InputRequired record past its TTL"),
    ] {
        assert_retained(&service, &dir, row, what);
    }

    let second = seed(
        &service,
        &workers,
        "r-sentinel-2",
        3_600_000,
        Some(SHORT_TTL_MS),
        Settle::Completed,
    )
    .await;
    assert!(
        swept(&service, &dir, &second.id).await,
        "a second expired sentinel was never swept"
    );
    for (row, what) in [
        (&unexpired, "an unexpired record"),
        (&unlimited, "a null-TTL record"),
        (&working, "a Working record past its TTL"),
        (&asking, "an InputRequired record past its TTL"),
    ] {
        assert_retained(&service, &dir, row, what);
    }

    guard.shutdown().await.expect("the sweep stops");
    service.shutdown().await.expect("custody is released");
    drop(executor);
}

/// Shutdown JOINS the deletion that is already running.
///
/// The store's own commit seam parks the sweep inside its expiry transaction —
/// after the unlink, at the directory sync — and the guard's shutdown is polled
/// by hand there: it must not be ready while a record's fate is undecided. The
/// parked interval also lets a caller sample this deletion boundary and
/// requires the original terminal status there; it does not exhaust every
/// possible transient state between observations.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "a single scenario walking a parked commit through poll, release, join, restart and reopen; splitting it would separate assertions from the shared in-flight state they depend on"
)]
async fn guard_shutdown_joins_an_in_flight_sweep_before_the_store_closes() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    let admission = fresh_admission();
    let (service, executor) = open_runtime_with_admission(
        &dir,
        4,
        StoreLimits::default(),
        test_subscriptions(),
        Arc::clone(&admission),
    )
    .await
    .expect("the runtime opens");
    let workers = Arc::new(Semaphore::new(4));
    let row = seed(
        &service,
        &workers,
        "j-completed",
        3_600_000,
        Some(SHORT_TTL_MS),
        Settle::Completed,
    )
    .await;
    // Armed AFTER the seed, so the seam belongs to the deletion and not to a
    // creation's own directory sync.
    let (entered, release, hook) = paused_at(CommitStage::DirectorySync);
    service.store.set_hook(Some(hook)).await;

    let guard = executor.start_expiry(TICK).expect("the sweep starts");
    wait_for(entered, "CommitStage::DirectorySync").await;

    // Inside the transaction: the record is still the caller's committed one.
    let parked = service.get(OWNER, &row.id);
    let parked_status = parked.as_ref().ok().map(|held| held.task.status());

    let mut stopping = std::pin::pin!(guard.shutdown());
    let mut cx = Context::from_waker(Waker::noop());
    let first = std::future::Future::poll(stopping.as_mut(), &mut cx).is_pending();
    tokio::task::yield_now().await;
    let second = std::future::Future::poll(stopping.as_mut(), &mut cx).is_pending();

    // Release before asserting: a failure here must not strand the sweep.
    let _ = release.send(());
    let joined = timeout(BUDGET, stopping).await;

    assert_eq!(
        parked_status,
        Some(TaskStatus::Completed),
        "a task mid-expiry must read as the terminal state it was committed in"
    );
    assert!(
        first && second,
        "shutdown completed while a deletion was still in flight"
    );
    joined
        .expect("shutdown did not return once the in-flight deletion finished")
        .expect("the joined shutdown succeeds");
    assert!(
        matches!(service.get(OWNER, &row.id), Err(ServiceError::NotFound)),
        "the joined sweep must have finished its deletion"
    );

    // Observe a finite stopped interval, then prove the same expired row is
    // eligible by restarting the production owner. This does not claim an
    // unbounded absence of future work from a finite observation.
    let after_stop = seed(
        &service,
        &workers,
        "j-after-stop",
        3_600_000,
        Some(SHORT_TTL_MS),
        Settle::Completed,
    )
    .await;
    timeout(BUDGET, async {
        let until = tokio::time::Instant::now() + TICK * 5;
        while tokio::time::Instant::now() < until {
            assert_retained(&service, &dir, &after_stop, "a row after sweep shutdown");
            tokio::time::sleep(TICK).await;
        }
        assert_retained(&service, &dir, &after_stop, "a row after sweep shutdown");
    })
    .await
    .expect("the stopped observation is bounded");
    let restarted = executor
        .start_expiry(TICK)
        .expect("a stopped owner can be restarted");
    assert!(
        swept(&service, &dir, &after_stop.id).await,
        "the stopped row must be swept once the owner restarts"
    );
    timeout(BUDGET, restarted.shutdown())
        .await
        .expect("restarted shutdown is bounded")
        .expect("the restarted owner joins");

    // Custody is released only after the join, and the deletion is durable:
    // a fresh authority reopening the directory finds nothing to restore.
    service.shutdown().await.expect("custody is released");
    drop(executor);
    drop(service);
    let reopened_admission = fresh_admission();
    let (reopened, reopened_executor) = open_runtime_with_admission(
        &dir,
        4,
        StoreLimits::default(),
        test_subscriptions(),
        reopened_admission,
    )
    .await
    .expect("the released directory opens again");
    assert!(
        matches!(reopened.get(OWNER, &row.id), Err(ServiceError::NotFound)),
        "the expired record came back after a restart"
    );
    assert!(!record_path(&dir, &row.id).exists());
    reopened.shutdown().await.unwrap();
    drop(reopened_executor);
}

/// A zero interval is not a cadence. Starting the owner with one is refused
/// rather than accepted as a spin, and refusing it starts nothing.
#[tokio::test]
async fn a_zero_expiry_interval_is_refused() {
    let mut config = crate::config::Config::default();
    assert!(
        config.tasks.validate().is_ok(),
        "default task config is valid"
    );
    config.tasks.expiry_interval = Duration::ZERO;
    assert!(
        matches!(config.tasks.validate(),
        Err(crate::Error::ConfigValidation(message))
            if message == "tasks.expiry_interval must be nonzero"),
        "config validation must reject the zero expiry interval specifically"
    );
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("tasks");
    let (service, executor) = open_runtime_with_admission(
        &dir,
        1,
        StoreLimits::default(),
        test_subscriptions(),
        fresh_admission(),
    )
    .await
    .expect("the runtime opens");

    assert!(
        matches!(
            executor.start_expiry(Duration::ZERO),
            Err(ServiceError::Unavailable)
        ),
        "a zero sweep interval must be refused at startup"
    );

    service.shutdown().await.expect("custody is released");
    drop(executor);
}
