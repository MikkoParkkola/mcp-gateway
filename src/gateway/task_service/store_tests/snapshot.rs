// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The relay replay snapshot a completed row stores with its result: written
//! by the same compare-and-set, never at the cost of the result's room, never
//! on any other outcome, and read back as written.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use super::super::record::{
    BINDING_VERSION, ErrorAuthor, PreparedTask, Provenance, SNAPSHOT_UNTRACKABLE, SNAPSHOT_VERSION,
};
use super::super::store::{StoreError, StoreLimits, TaskStore};
use super::OWNER;
use super::support::*;
use crate::gateway::gateway_writes::WriteRecord;
use crate::protocol::JsonRpcError;
use crate::protocol::tasks::TaskTransition;

/// A snapshot as the firewall would hand it over: opaque to the store.
fn snapshot(fill: usize) -> Value {
    json!({"epoch": 7, "receipts": [{"segments": vec![1_u64; fill]}]})
}

fn result() -> Value {
    json!({"content": [{"type": "text", "text": "the plan's answer"}]})
}

fn carrying(snapshot: Option<Value>) -> Provenance {
    Provenance {
        replay_snapshot: snapshot.map(Box::new),
        ..Provenance::default()
    }
}

/// One task settled by `event` carrying `provenance` under `limits`, at the
/// revision it was created with plus `stale` (a lost compare-and-set when
/// non-zero); the store path, the task id and the settle's outcome.
async fn settle(
    root: &Path,
    limits: StoreLimits,
    event: TaskTransition,
    provenance: Provenance,
    stale: u64,
) -> (PathBuf, String, Result<(), StoreError>) {
    let path = root.join("tasks");
    let store = TaskStore::open(&path, limits)
        .await
        .expect("the store opens");
    let one = task();
    let created = store
        .create(PreparedTask::for_test(&one, OWNER, 1))
        .await
        .expect("the task is created");
    let settled = store
        .settle_bounded_as(
            crate::gateway::task_service::store::gate::Kind::Internal,
            OWNER,
            one.id(),
            created.revision + stale,
            (event, provenance, WriteRecord::default()),
            ErrorAuthor::Gateway,
            at(5),
        )
        .await
        .map(|_| ());
    store.close().await.unwrap();
    (path, one.id().to_owned(), settled)
}

/// The snapshot is stored with the completed result, at its own record
/// version, and read back as written across a reopen.
#[tokio::test]
async fn a_completed_row_stores_its_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let (path, id, settled) = settle(
        dir.path(),
        StoreLimits::default(),
        TaskTransition::Complete(result()),
        carrying(Some(snapshot(4))),
        0,
    )
    .await;
    settled.expect("the task settles");
    let row = record_file(&path, &id);
    assert_eq!(row["replaySnapshot"], snapshot(4), "{row}");
    assert_eq!(row["version"], SNAPSHOT_VERSION, "{row}");
    let store = TaskStore::open(&path, StoreLimits::default())
        .await
        .unwrap();
    let read = store.get(OWNER, &id).expect("the row reads");
    assert_eq!(read.replay_snapshot.as_deref(), Some(&snapshot(4)));
    store.close().await.unwrap();
}

/// K22: a row settled without a snapshot (as an older gateway wrote every
/// row) has no member, keeps its version and reads as no snapshot.
#[tokio::test]
async fn a_row_without_a_snapshot_reads_as_none() {
    let dir = tempfile::tempdir().unwrap();
    let (path, id, settled) = settle(
        dir.path(),
        StoreLimits::default(),
        TaskTransition::Complete(result()),
        carrying(None),
        0,
    )
    .await;
    settled.expect("the task settles");
    let row = record_file(&path, &id);
    assert!(row.get("replaySnapshot").is_none(), "{row}");
    assert!(
        row["version"].as_u64() < Some(u64::from(SNAPSHOT_VERSION)),
        "a row without a snapshot is not raised: {row}"
    );
    let store = TaskStore::open(&path, StoreLimits::default())
        .await
        .unwrap();
    assert_eq!(store.get(OWNER, &id).unwrap().replay_snapshot, None);
    store.close().await.unwrap();
}

/// K23: a row that carries a snapshot is written above the last version an
/// older gateway loads, so that gateway refuses it: downgrade past this
/// change is unsupported, on purpose (the upgrade note states it).
#[test]
fn a_snapshot_row_is_beyond_an_older_loader() {
    const { assert!(SNAPSHOT_VERSION > BINDING_VERSION) };
    assert_eq!(
        super::super::record::MAX_LOADABLE_VERSION,
        SNAPSHOT_VERSION,
        "the loader takes the newest field's version"
    );
}

/// The room row: a result that fits the default record budget on its own,
/// with a snapshot that does not, still completes and serves, the snapshot
/// replaced by the untrackable marker, never the result by the bounded
/// failure.
#[tokio::test]
async fn a_snapshot_with_no_room_leaves_the_marker_not_a_failure() {
    let budget = StoreLimits::default().record_bytes;
    // Two bytes per element ("1,"), so this snapshot alone is over budget.
    let over = snapshot(budget / 2 + 1);
    let dir = tempfile::tempdir().unwrap();
    let (path, id, settled) = settle(
        dir.path(),
        StoreLimits::default(),
        TaskTransition::Complete(result()),
        carrying(Some(over)),
        0,
    )
    .await;
    settled.expect("the task settles");
    let row = record_file(&path, &id);
    assert_eq!(row["model"]["task"]["status"], "completed", "{row}");
    assert!(
        row["model"]["task"]
            .to_string()
            .contains("the plan's answer"),
        "the result kept its place: {row}"
    );
    assert_eq!(row["replaySnapshot"], SNAPSHOT_UNTRACKABLE, "{row}");
    assert!(row.get("outputFree").is_none(), "{row}");
}

/// K28: an outcome that holds no backend result stores no snapshot: a
/// failure, and the bounded failure a row with no room at all settles as.
#[tokio::test]
async fn an_output_free_outcome_stores_no_snapshot() {
    let failed = TaskTransition::Fail(JsonRpcError {
        code: -32000,
        message: "the backend failed".to_owned(),
        data: None,
    });
    let dir = tempfile::tempdir().unwrap();
    let (path, id, settled) = settle(
        dir.path(),
        StoreLimits::default(),
        failed,
        carrying(Some(snapshot(4))),
        0,
    )
    .await;
    settled.expect("the task settles");
    let row = record_file(&path, &id);
    assert!(row.get("replaySnapshot").is_none(), "a failure: {row}");

    let bare = tempfile::tempdir().unwrap();
    let (bare_path, bare_id, _) = settle(
        bare.path(),
        StoreLimits::default(),
        TaskTransition::Fail(JsonRpcError {
            code: -32603,
            message: "the task's result exceeds the record size limit".to_owned(),
            data: None,
        }),
        carrying(None),
        0,
    )
    .await;
    let floor = encoded_len(&record_file(&bare_path, &bare_id));
    let big = json!({"content": [{"type": "text", "text": "x".repeat(4096)}]});
    let other = tempfile::tempdir().unwrap();
    let (path, id, settled) = settle(
        other.path(),
        StoreLimits {
            record_bytes: floor + 64,
            ..StoreLimits::default()
        },
        TaskTransition::Complete(big),
        carrying(Some(snapshot(4))),
        0,
    )
    .await;
    settled.expect("the task settles as the bounded failure");
    let row = record_file(&path, &id);
    assert_eq!(row["outputFree"], true, "premise: output-free: {row}");
    assert!(row.get("replaySnapshot").is_none(), "{row}");
}

/// K24: a settle that loses its compare-and-set stores nothing, snapshot
/// included.
#[tokio::test]
async fn a_lost_compare_and_set_stores_no_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let (path, id, settled) = settle(
        dir.path(),
        StoreLimits::default(),
        TaskTransition::Complete(result()),
        carrying(Some(snapshot(4))),
        1,
    )
    .await;
    assert!(
        matches!(settled, Err(StoreError::RevisionConflict)),
        "{settled:?}"
    );
    let row = record_file(&path, &id);
    assert!(row.get("replaySnapshot").is_none(), "{row}");
    assert_eq!(row["model"]["task"]["status"], "working", "{row}");
}

/// The boundary below the room row: a result sized so its completed row
/// is four bytes under the default budget fits on its own but not with even
/// the marker. Pinned as today's outcome: the cascade goes on to the
/// bounded failure (a register row names the window), never to a completed
/// row that holds no snapshot, which a read would serve untracked.
#[tokio::test]
async fn a_row_with_no_room_for_the_marker_settles_as_the_bounded_failure() {
    let budget = StoreLimits::default().record_bytes;
    let text = |n: usize| json!({"content": [{"type": "text", "text": "x".repeat(n)}]});
    let probe = tempfile::tempdir().unwrap();
    let (probe_path, probe_id, settled) = settle(
        probe.path(),
        StoreLimits::default(),
        TaskTransition::Complete(text(10)),
        carrying(None),
        0,
    )
    .await;
    settled.unwrap();
    let probe_bytes = encoded_len(&record_file(&probe_path, &probe_id));
    let sized = text(10 + budget - probe_bytes - 4);
    let bare = tempfile::tempdir().unwrap();
    let (bare_path, bare_id, settled) = settle(
        bare.path(),
        StoreLimits::default(),
        TaskTransition::Complete(sized.clone()),
        carrying(None),
        0,
    )
    .await;
    settled.unwrap();
    let bare_row = record_file(&bare_path, &bare_id);
    assert_eq!(
        bare_row["model"]["task"]["status"], "completed",
        "premise: fits alone"
    );
    assert_eq!(
        encoded_len(&bare_row),
        budget - 4,
        "premise: four bytes under"
    );
    let dir = tempfile::tempdir().unwrap();
    let (path, id, settled) = settle(
        dir.path(),
        StoreLimits::default(),
        TaskTransition::Complete(sized),
        carrying(Some(snapshot(4))),
        0,
    )
    .await;
    settled.expect("the task settles");
    let row = record_file(&path, &id);
    assert_eq!(row["outputFree"], true, "{row}");
    assert!(row.get("replaySnapshot").is_none(), "{row}");
}
