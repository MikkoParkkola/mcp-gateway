// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! An expiry pass that has upgraded the executor (as the stdio expiry sweep
//! does) keeps the store's folder through that handle: the row drops the
//! test's own share first, lets the pass delete, and expects the folder to go
//! only with the pass's last handle.
use super::*;

#[tokio::test]
async fn an_expiry_pass_holding_the_executor_keeps_the_folder() {
    let root = Arc::new(tempfile::tempdir().expect("store root"));
    let root_path = root.path().to_owned();
    let tasks = root_path.join("tasks");
    let (service, executor) = open_runtime_with_admission(
        &tasks,
        1,
        StoreLimits::default(),
        test_subscriptions(),
        fresh_admission(),
    )
    .await
    .expect("the runtime opens");
    service.keep_test_dir(Arc::clone(&root));
    // Committed through the create facade, so admission names the row and a
    // pass may delete it; created two days back, against a one-minute TTL.
    let workers = Arc::new(Semaphore::new(1));
    let age_ms = i64::try_from(2 * DAY_MS).expect("in range");
    let seeded = seed(
        &service,
        &workers,
        "x-expired",
        age_ms,
        Some(SHORT_TTL_MS),
        Settle::Completed,
    )
    .await;
    let record = tasks.join(format!("{}.json", seeded.id));
    assert!(record.is_file(), "premise: the row is stored");
    // The sweep upgrades its weak executor for each pass; this handle is that
    // upgrade. The test body ends: its own share and its service go first.
    let pass = Arc::clone(&executor);
    drop(root);
    drop(service);
    drop(executor);
    pass.expiry_pass_for_test()
        .await
        .expect("the pass deletes the expired row in the still-owned folder");
    assert!(!record.exists(), "the pass deleted the expired row");

    drop(pass);
    assert!(
        !root_path.exists(),
        "the folder outlived the pass's last handle"
    );
}
