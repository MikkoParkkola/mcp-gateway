// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Rows R8: a record's writers racing each other, or a cancel.
use super::*;

/// R8 (a): a worker settlement and an owner read of one task write exactly one
/// record. They share the record's query slot, so they never both settle it.
#[tokio::test]
async fn r8_a_worker_and_an_owner_read_write_one_record() {
    let path = Path::Worker;
    let fx = fixture(
        Setup::answering(Terminal::Completed(result_naming_cust9(""))),
        path,
    )
    .await;
    let id = fx.submit("min1-settlement-r8").await;
    fx.recovery.wait_for_queries(1).await;
    let reader = tokio::spawn({
        let (state, id) = (Arc::clone(&fx.state), id.clone());
        async move { get_task(&state, "key-a", &id).await }
    });
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
    fx.recovery.release_all();
    let fetched = reader.await.expect("the owner's read answers");
    join_workers(&fx.state).await;
    std::assert_eq!(status_of(&fetched), "completed", "{fetched}");
    let record = fx.only_settlement(path);
    std::assert_eq!(record["task_id"], json!(id), "{record}");
}

/// R8 (b): a cancel that wins the commit after the record was written leaves
/// that one record and a cancelled task.
#[tokio::test]
async fn r8_a_cancel_winning_after_the_record_leaves_one_record() {
    let path = Path::OwnerRead;
    let fx = fixture(
        Setup::answering(Terminal::Completed(result_naming_cust9(""))),
        path,
    )
    .await;
    let id = fx.submit("min1-settlement-r8-cancel").await;
    fx.recovery.wait_for_queries(1).await;
    join_workers(&fx.state).await;

    // The next append, the settlement record, is held until released.
    let stall = fx.log.stall_next_write_for_test(Duration::from_secs(30));
    fx.recovery.release_all();
    let reader = tokio::spawn({
        let (state, id) = (Arc::clone(&fx.state), id.clone());
        async move { get_task(&state, "key-a", &id).await }
    });
    let deadline = Instant::now() + ARRIVAL_BOUND;
    while !stall.0.is_entered() {
        std::assert!(
            Instant::now() < deadline,
            "no settlement record write began before the recovery's commit"
        );
        tokio::task::yield_now().await;
    }
    // The cancel's audit append queues on the permit the held write owns, so
    // release once it queued, not after it returns at the bound (MIK-7912).
    let waits = fx.log.permit_waits_for_test();
    let request = task_method(9_002, "tasks/cancel", json!({ "taskId": id }));
    let state = Arc::clone(&fx.state);
    let cancel = tokio::spawn(async move { post(&state, "key-a", request).await });
    let deadline = Instant::now() + ARRIVAL_BOUND;
    while fx.log.permit_waits_for_test() == waits {
        std::assert!(Instant::now() < deadline, "the cancel never queued");
        tokio::task::yield_now().await;
    }
    stall.0.release();
    let cancelled = cancel.await.expect("the cancel answers");
    std::assert!(cancelled.get("error").is_none(), "{cancelled}");
    let _ = reader.await.expect("the owner's read answers");

    let fetched = get_task(&fx.state, "key-a", &id).await;
    std::assert_eq!(
        status_of(&fetched),
        "cancelled",
        "the cancel's commit stands: {fetched}"
    );
    // The released write lands on the blocking pool; nothing above awaits it.
    let deadline = Instant::now() + ARRIVAL_BOUND;
    while fx.settlement_records().is_empty() && Instant::now() < deadline {
        tokio::task::yield_now().await;
    }
    std::assert_eq!(fx.settlement_records().len(), 1, "{:?}", fx.records());
}
