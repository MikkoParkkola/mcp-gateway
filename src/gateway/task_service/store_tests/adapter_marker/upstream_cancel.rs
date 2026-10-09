// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7642 PR.D: the one durable claim on a cancelled row's upstream cancel.

use super::*;
use crate::gateway::task_service::record::UpstreamRecord;
use crate::gateway::task_service::store::cancel::CancelClaim;

fn descriptor(binding: &TaskBinding, handle: &str) -> UpstreamRecord {
    UpstreamRecord {
        handle: handle.into(),
        backend: "orders".into(),
        tool: "create".into(),
        arguments: json!({"sku": "x"}),
        operation_digest: binding.operation().to_owned(),
    }
}

/// Mutants: the status check, the claimed check, the digest check, or the
/// durable-first precedence removed; or the claim not persisted.
#[tokio::test]
async fn one_sender_claims_a_cancelled_rows_upstream_cancel() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let admission = services();
    let (row, binding) = admitted(&store, &admission, "cancel-claim").await;
    let owner = binding.principal_digest().to_owned();
    let id = row.id().to_owned();

    // A working row is not ours to claim, whatever is offered.
    let offer = Some(descriptor(&binding, "job-a"));
    assert_eq!(
        store
            .claim_upstream_cancel(&owner, &id, offer.clone())
            .await
            .unwrap(),
        CancelClaim::NotOurs
    );
    store
        .transition(&owner, &id, 1, TaskTransition::Cancel, at(1))
        .await
        .unwrap();
    // A settled row has no cancel to make room for: the preflight measures the
    // descriptor alone.
    assert_eq!(
        store.admits_upstream_descriptor(&owner, &id, "orders", "create", &json!({"sku": "x"})),
        Ok(true)
    );
    let before = files(&path);
    // Cancelled, but no handle known: nothing claimed, so a later offer can win.
    assert_eq!(
        store
            .claim_upstream_cancel(&owner, &id, None)
            .await
            .unwrap(),
        CancelClaim::NotOurs
    );
    // An offer that names another operation is no handle for this row.
    let mut foreign = descriptor(&binding, "job-a");
    foreign.operation_digest = "f".repeat(64);
    assert_eq!(
        store
            .claim_upstream_cancel(&owner, &id, Some(foreign))
            .await
            .unwrap(),
        CancelClaim::NotOurs
    );
    assert_eq!(files(&path), before, "no claim writes nothing");

    assert_eq!(
        store
            .claim_upstream_cancel(&owner, &id, offer.clone())
            .await
            .unwrap(),
        CancelClaim::Claimed(descriptor(&binding, "job-a"))
    );
    let record = record_json(&path, &id);
    assert_eq!(record["upstreamCancelSent"], json!(true));
    assert!(
        record.get("upstream").is_none(),
        "the claim takes the descriptor off the row: {record}"
    );
    assert_eq!(record["version"], json!(7));
    assert_eq!(record["revision"], json!(2), "the claim moves no revision");
    // Every later sender, with or without a handle, is told it was taken.
    for again in [None, Some(descriptor(&binding, "job-b"))] {
        assert_eq!(
            store
                .claim_upstream_cancel(&owner, &id, again)
                .await
                .unwrap(),
            CancelClaim::AlreadyClaimed
        );
    }
    // The claim survives a restart.
    store.close().await.unwrap();
    let store = open(&path).await;
    assert_eq!(
        store
            .claim_upstream_cancel(&owner, &id, None)
            .await
            .unwrap(),
        CancelClaim::AlreadyClaimed
    );
    store.close().await.unwrap();
}

/// A descriptor already durable on the row wins over a different offer: the
/// first handle the row learned is the one cancelled.
#[tokio::test]
async fn the_durable_handle_wins_over_an_offered_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (row, binding) = admitted(&store, &services(), "cancel-durable").await;
    let owner = binding.principal_digest().to_owned();
    let id = row.id().to_owned();
    store
        .mark_upstream(&owner, &id, 1, descriptor(&binding, "job-durable"))
        .await
        .unwrap();
    store
        .transition(&owner, &id, 1, TaskTransition::Cancel, at(1))
        .await
        .unwrap();
    assert_eq!(
        store
            .claim_upstream_cancel(&owner, &id, Some(descriptor(&binding, "job-offered")))
            .await
            .unwrap(),
        CancelClaim::Claimed(descriptor(&binding, "job-durable"))
    );
    store.close().await.unwrap();
}

/// A claim whose descriptor would take the row over its byte budget is
/// refused with `Capacity` and writes nothing: no send is claimed for a row
/// that could not record it.
#[tokio::test]
async fn a_claim_over_the_record_budget_is_refused_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (row, binding) = admitted_with(&store, &services(), "cancel-cap", padding()).await;
    let owner = binding.principal_digest().to_owned();
    let id = row.id().to_owned();
    store
        .transition(&owner, &id, 1, TaskTransition::Cancel, at(1))
        .await
        .unwrap();
    store.close().await.unwrap();
    let size = fs::read(path.join(format!("{id}.json"))).unwrap().len();
    let store = TaskStore::open(
        &path,
        StoreLimits {
            record_bytes: size,
            ..StoreLimits::default()
        },
    )
    .await
    .expect("the loader accepts a record exactly at the byte cap");
    let before = files(&path);
    assert_eq!(
        store
            .claim_upstream_cancel(&owner, &id, Some(descriptor(&binding, "job-a")))
            .await
            .unwrap_err(),
        StoreError::Capacity
    );
    assert_eq!(files(&path), before, "a refused claim writes nothing");
    store.close().await.unwrap();
}

/// A row the dispatch preflight admits at the tightest budget, holding the
/// widest descriptor, can still be cancelled (which grows it) and still takes
/// the cancel claim. Mutant "the preflight measures only the working row"
/// admits a budget the cancel overflows: in production that cancel settles as
/// the bounded failure, the descriptor is discarded and nothing is sent.
#[tokio::test]
async fn a_row_admitted_at_the_tightest_budget_still_takes_the_cancel_claim() {
    use crate::gateway::task_service::record::widest_handle_reservation;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (row, binding) = admitted_with(&store, &services(), "cancel-room", padding()).await;
    let owner = binding.principal_digest().to_owned();
    let id = row.id().to_owned();
    store.close().await.unwrap();
    let at_cap = |record_bytes| {
        TaskStore::open(
            &path,
            StoreLimits {
                record_bytes,
                ..StoreLimits::default()
            },
        )
    };
    let admits = |store: &TaskStore| {
        store
            .admits_upstream_descriptor(&owner, &id, "orders", "create", &json!({"sku": "x"}))
            .unwrap()
    };
    // The tightest budget the preflight admits the descriptor at.
    let (mut low, mut high) = (
        fs::read(path.join(format!("{id}.json"))).unwrap().len(),
        64 * 1024,
    );
    while low < high {
        let mid = low.midpoint(high);
        let store = at_cap(mid)
            .await
            .expect("the row loads at any cap above its size");
        let fits = admits(&store);
        store.close().await.unwrap();
        if fits { high = mid } else { low = mid + 1 }
    }
    let store = at_cap(low).await.unwrap();
    assert!(admits(&store), "precondition: admitted at {low} bytes");
    let mut widest = descriptor(&binding, "x");
    widest.handle = widest_handle_reservation();
    store
        .mark_upstream(&owner, &id, 1, widest.clone())
        .await
        .unwrap();
    store
        .transition(&owner, &id, 1, TaskTransition::Cancel, at(1))
        .await
        .unwrap();
    assert_eq!(
        store
            .claim_upstream_cancel(&owner, &id, None)
            .await
            .unwrap(),
        CancelClaim::Claimed(widest)
    );
    store.close().await.unwrap();
}
