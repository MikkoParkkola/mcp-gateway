// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-7642 PR.D: the one durable claim on a cancelled row's upstream cancel.

use super::*;
use crate::gateway::task_service::record::UpstreamRecord;
use crate::gateway::task_service::store::targets::CancelClaim;

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
    let (row, binding) = admitted_with(
        &store,
        &admission,
        "cancel-claim",
        // As production admits a single call: its one target at creation.
        vec![Target {
            server: "orders".into(),
            tool: "create".into(),
        }],
    )
    .await;
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
    // Pending until a peer answers (MIK-8347): the handle stays, the call is
    // named through the target the claim kept, and nothing failed yet.
    let pending = &record["upstreamCancelPending"];
    assert_eq!(pending["handle"], json!("job-a"), "{record}");
    assert_eq!(pending["target"], json!(0), "{record}");
    assert_eq!(pending["attempts"], json!(0), "{record}");
    assert!(pending.get("backend").is_none(), "{record}");
    assert!(record.get("upstreamCancelSent").is_none(), "{record}");
    assert!(
        record.get("upstream").is_none(),
        "the claim takes the descriptor off the row: {record}"
    );
    assert_eq!(
        record["version"],
        json!(crate::gateway::task_service::record::BINDING_VERSION)
    );
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
        .mark_upstream(
            &owner,
            &id,
            1,
            (descriptor(&binding, "job-durable"), Vec::new()),
        )
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
        .mark_upstream(&owner, &id, 1, (widest.clone(), Vec::new()))
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
    // T8 (MIK-8347): the claim recorded a pending cancel, not a sent one.
    assert!(
        record_json(&path, &id)
            .get("upstreamCancelPending")
            .is_some(),
        "the cancel is pending until a peer answers"
    );
    store.close().await.unwrap();
}

/// T8b (MIK-8347). Red at base. A current row whose recorded calls do not
/// name the descriptor's backend (a composite plan) keeps a pending cancel by
/// copying the backend: admitted at the tightest budget the preflight allows
/// for the widest descriptor, that copy still fits.
/// Mutant: "the preflight does not reserve the copied-backend Pending".
#[tokio::test]
async fn a_row_without_a_naming_target_copies_the_backend_and_still_fits() {
    use crate::gateway::task_service::record::{Target, widest_handle_reservation};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (row, binding) = admitted_with(&store, &services(), "cancel-copy", padding()).await;
    let owner = binding.principal_digest().to_owned();
    let id = row.id().to_owned();
    store
        .add_targets(
            &owner,
            &id,
            1,
            (
                vec![Target {
                    server: "elsewhere".into(),
                    tool: "other".into(),
                }],
                Vec::new(),
            ),
        )
        .await
        .unwrap();
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
    let (mut low, mut high) = (
        fs::read(path.join(format!("{id}.json"))).unwrap().len(),
        64 * 1024,
    );
    while low < high {
        let mid = low.midpoint(high);
        let store = at_cap(mid).await.expect("the row loads above its size");
        let fits = admits(&store);
        store.close().await.unwrap();
        if fits { high = mid } else { low = mid + 1 }
    }
    let store = at_cap(low).await.unwrap();
    let mut widest = descriptor(&binding, "x");
    widest.handle = widest_handle_reservation();
    store
        .mark_upstream(&owner, &id, 1, (widest.clone(), Vec::new()))
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
    let record = record_json(&path, &id);
    let pending = &record["upstreamCancelPending"];
    assert_eq!(pending["backend"], json!("orders"), "{record}");
    assert!(pending.get("target").is_none(), "{record}");
    store.close().await.unwrap();
}

/// T8 (MIK-8347). Red at base. A legacy row written exactly at the byte cap,
/// before the pending state existed and so without its reservation, naming a
/// 128-byte backend, still takes the claim: the pending cancel names its
/// backend through the target the claim keeps, never a second copy.
/// Mutants: "Pending copies the backend", "Pending keeps the descriptor".
#[tokio::test]
async fn a_legacy_row_at_the_byte_cap_takes_a_pending_claim() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (row, binding) = admitted_legacy(&store, &services(), "cancel-legacy-cap").await;
    let owner = binding.principal_digest().to_owned();
    let id = row.id().to_owned();
    let mut wide = descriptor(&binding, "job-wide");
    wide.backend = "b".repeat(128);
    store
        .mark_upstream(&owner, &id, 1, (wide.clone(), Vec::new()))
        .await
        .unwrap();
    store
        .transition(&owner, &id, 1, TaskTransition::Cancel, at(1))
        .await
        .unwrap();
    assert_eq!(
        record_json(&path, &id)["version"],
        json!(3),
        "premise: legacy"
    );
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
    assert_eq!(
        store
            .claim_upstream_cancel(&owner, &id, None)
            .await
            .unwrap(),
        CancelClaim::Claimed(wide)
    );
    let record = record_json(&path, &id);
    let pending = &record["upstreamCancelPending"];
    assert_eq!(pending["handle"], json!("job-wide"), "{record}");
    assert!(pending.get("backend").is_none(), "{record}");
    assert_eq!(
        record["targets"][usize::try_from(pending["target"].as_u64().unwrap()).unwrap()]["server"],
        json!("b".repeat(128)),
        "{record}"
    );
    store.close().await.unwrap();
}

/// T6 (MIK-8347). Guard. A row a v7 gateway claimed (`upstreamCancelSent`,
/// no descriptor) reads as done: claimed already, nothing to send.
/// Mutant: "a legacy sent row read as pending".
#[tokio::test]
async fn a_legacy_sent_row_reads_as_done() {
    use crate::gateway::task_service::store::targets::UpstreamCancelState;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (row, binding) = admitted(&store, &services(), "cancel-legacy-sent").await;
    let owner = binding.principal_digest().to_owned();
    let id = row.id().to_owned();
    store
        .transition(&owner, &id, 1, TaskTransition::Cancel, at(1))
        .await
        .unwrap();
    assert!(matches!(
        store
            .claim_upstream_cancel(&owner, &id, Some(descriptor(&binding, "job-v7")))
            .await
            .unwrap(),
        CancelClaim::Claimed(_)
    ));
    store.close().await.unwrap();
    // Rewrite it as a v7 gateway left it.
    let file = path.join(format!("{id}.json"));
    let mut record = record_json(&path, &id);
    let fields = record.as_object_mut().unwrap();
    fields.remove("upstreamCancelPending");
    fields.insert("upstreamCancelSent".into(), json!(true));
    fields.insert("version".into(), json!(7));
    fs::write(&file, serde_json::to_vec(&record).unwrap()).unwrap();
    let store = open(&path).await;
    assert_eq!(
        store.upstream_cancel_state(&owner, &id),
        Some(UpstreamCancelState::Done)
    );
    assert_eq!(
        store
            .claim_upstream_cancel(&owner, &id, Some(descriptor(&binding, "job-v7")))
            .await
            .unwrap(),
        CancelClaim::AlreadyClaimed
    );
    store.close().await.unwrap();
}

/// A v3 row names its one call only through its descriptor. The claim raises
/// it past the version that reads targets and takes the descriptor off, so it
/// keeps that call as a target first: the cancelled row still says what ran.
/// Mutant "the claim drops the descriptor without keeping provenance" leaves
/// a dispatched row claiming it ran nothing.
#[tokio::test]
async fn a_claimed_legacy_row_keeps_its_call_as_a_target() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (row, binding) = admitted_legacy(&store, &services(), "cancel-legacy").await;
    let owner = binding.principal_digest().to_owned();
    let id = row.id().to_owned();
    store
        .mark_upstream(
            &owner,
            &id,
            1,
            (descriptor(&binding, "job-legacy"), Vec::new()),
        )
        .await
        .unwrap();
    assert_eq!(
        record_json(&path, &id)["version"],
        json!(3),
        "precondition: a v3 row"
    );
    store
        .transition(&owner, &id, 1, TaskTransition::Cancel, at(1))
        .await
        .unwrap();
    assert!(matches!(
        store
            .claim_upstream_cancel(&owner, &id, None)
            .await
            .unwrap(),
        CancelClaim::Claimed(_)
    ));
    let record = record_json(&path, &id);
    assert_eq!(record["version"], json!(8));
    assert!(record.get("upstream").is_none(), "{record}");
    assert_eq!(
        record["targets"],
        json!([{"server": "orders", "tool": "create"}]),
        "{record}"
    );
    store.close().await.unwrap();
    let store = open(&path).await;
    let read = store.get(&owner, &id).unwrap();
    assert!(
        read.targets_recorded && read.targets.len() == 1,
        "{:?}",
        read.targets
    );
    store.close().await.unwrap();
}

/// The same for a legacy row whose handle was never made durable: the offered
/// descriptor names the call that ran. Mutant "provenance read before the
/// winning descriptor is on the row" leaves the targets empty.
#[tokio::test]
async fn an_offered_claim_on_a_legacy_row_keeps_its_call_as_a_target() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (row, binding) = admitted_legacy(&store, &services(), "cancel-legacy-offer").await;
    let owner = binding.principal_digest().to_owned();
    let id = row.id().to_owned();
    store
        .transition(&owner, &id, 1, TaskTransition::Cancel, at(1))
        .await
        .unwrap();
    assert!(matches!(
        store
            .claim_upstream_cancel(&owner, &id, Some(descriptor(&binding, "job-offered")))
            .await
            .unwrap(),
        CancelClaim::Claimed(_)
    ));
    let record = record_json(&path, &id);
    assert_eq!(
        record["targets"],
        json!([{"server": "orders", "tool": "create"}]),
        "{record}"
    );
    assert!(record.get("upstream").is_none(), "{record}");
    store.close().await.unwrap();
}

/// MIK-8407 (final round-2 finding: the handle was durable before its
/// bindings): `mark_upstream` writes the handle and the bindings the dispatch
/// ran under in one write, and a reopened store reads both back. Mutant: the
/// bindings dropped from, or deferred past, that write.
#[tokio::test]
async fn a_durable_handle_carries_its_bindings_across_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (row, binding) = admitted(&store, &services(), "handle-bindings").await;
    let owner = binding.principal_digest().to_owned();
    let id = row.id().to_owned();
    let ran_under = vec![(
        "orders".to_owned(),
        "create".to_owned(),
        Some("work#f1".to_owned()),
    )];
    store
        .mark_upstream(
            &owner,
            &id,
            1,
            (descriptor(&binding, "job-bound"), ran_under.clone()),
        )
        .await
        .unwrap();
    store.close().await.unwrap();

    let reopened = open(&path).await;
    let read = reopened.get(&owner, &id).unwrap();
    assert!(read.bindings_recorded, "handle row not at BINDING_VERSION");
    assert_eq!(read.bindings, ran_under, "bindings lost with the handle");
    assert_eq!(
        reopened
            .upstream_for_test(&id)
            .map(|upstream| upstream.handle),
        Some("job-bound".to_owned()),
        "the handle is not on the reopened row"
    );
    reopened.close().await.unwrap();
}
