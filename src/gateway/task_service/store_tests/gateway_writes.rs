// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `MIK-7993`: a completed task row keeps the record of the members the
//! gateway wrote into its result. The record never costs the result its room,
//! never makes the row unreadable, and a row cut inside it keeps its key.

use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use super::super::record::{ErrorAuthor, PreparedTask};
use super::super::store::{StoreError, StoreLimits, TaskStore};
use super::OWNER;
use super::skipped::{rewrite, truncate_inside};
use super::support::*;
use crate::gateway::gateway_writes::WriteRecord;
use crate::protocol::tasks::TaskTransition;

/// `count` notes as a row stores them.
fn writes(count: usize) -> WriteRecord {
    let entry = json!({
        "layer": "value", "dest": ["_cost_warnings"], "kind": ["_cost_warnings"], "within": [],
        "digest": "636810988c0638ebda7b64c4fcac77cae55b300084dd6c553983f9c1aaf350db",
    });
    serde_json::from_value(Value::Array(vec![entry; count])).expect("a record decodes")
}

fn result() -> Value {
    json!({
        "content": [{"type": "text", "text": "the backend's answer"}],
        "_cost_warnings": ["the gateway's advice"],
        "_cost_suggestion": {"message": "a cheaper tool answers the same", "alternative": "beta:read"},
        "trace_id": "gw-trace-0000-0000-0000-000000000001",
    })
}

/// One task settled `Completed` with `notes` notes under `limits`; returns
/// the store path and the task id.
async fn settled(root: &Path, limits: StoreLimits, notes: usize) -> (std::path::PathBuf, String) {
    let path = root.join("tasks");
    let store = TaskStore::open(&path, limits)
        .await
        .expect("the store opens");
    let one = task();
    let created = store
        .create(PreparedTask::for_test(&one, OWNER, 1))
        .await
        .expect("the task is created");
    store
        .settle_bounded_by(
            OWNER,
            one.id(),
            created.revision,
            (TaskTransition::Complete(result()), None, writes(notes)),
            ErrorAuthor::Gateway,
            at(5),
        )
        .await
        .expect("the task settles");
    store.close().await.unwrap();
    (path, one.id().to_owned())
}

/// The record is stored with the result, read back as written, and kept
/// across a reopen.
#[tokio::test]
async fn a_completed_row_keeps_its_write_record() {
    let dir = tempfile::tempdir().unwrap();
    let (path, id) = settled(dir.path(), StoreLimits::default(), 1).await;
    let row = record_file(&path, &id);
    assert_eq!(
        row["gatewayWrites"],
        serde_json::to_value(writes(1)).unwrap(),
        "{row}"
    );
    let store = TaskStore::open(&path, StoreLimits::default())
        .await
        .unwrap();
    let read = store.get(OWNER, &id).expect("the row reads");
    assert_eq!(
        serde_json::to_value(&read.gateway_writes).unwrap(),
        serde_json::to_value(writes(1)).unwrap()
    );
    store.close().await.unwrap();
}

/// A row with no gateway writes serializes without the member, as before.
#[tokio::test]
async fn a_row_without_gateway_writes_has_no_member() {
    let dir = tempfile::tempdir().unwrap();
    let (path, id) = settled(dir.path(), StoreLimits::default(), 0).await;
    let row = record_file(&path, &id);
    assert!(row.get("gatewayWrites").is_none(), "{row}");
}

/// The record the gateway keeps for [`result`]: its three advice members,
/// noted as the dispatch notes them.
async fn real_writes() -> WriteRecord {
    use crate::gateway::gateway_writes::{Layer, note, recorded};
    crate::gateway::meta_mcp::invoke::relay::collecting(async {
        let value = result();
        note(Layer::Value, &["_cost_warnings"], &value);
        note(Layer::Value, &["_cost_suggestion"], &value);
        note(Layer::Value, &["trace_id"], &value);
        recorded()
    })
    .await
}

/// [`settled`] with a given record.
async fn settled_with(
    root: &Path,
    limits: StoreLimits,
    writes: WriteRecord,
) -> (std::path::PathBuf, String) {
    let path = root.join("tasks");
    let store = TaskStore::open(&path, limits)
        .await
        .expect("the store opens");
    let one = task();
    let created = store
        .create(PreparedTask::for_test(&one, OWNER, 1))
        .await
        .expect("the task is created");
    store
        .settle_bounded_by(
            OWNER,
            one.id(),
            created.revision,
            (TaskTransition::Complete(result()), None, writes),
            ErrorAuthor::Gateway,
            at(5),
        )
        .await
        .expect("the task settles");
    store.close().await.unwrap();
    (path, one.id().to_owned())
}

/// F1 (lead ruling c), row 2: a row with room for its record stores the
/// result unchanged, the gateway's members and their record both kept.
#[tokio::test]
async fn a_row_with_room_keeps_its_result_and_its_record() {
    let dir = tempfile::tempdir().unwrap();
    let writes = real_writes().await;
    assert_eq!(writes_len(&writes), 3, "premise: three notes");
    let (path, id) = settled_with(dir.path(), StoreLimits::default(), writes).await;
    let row = record_file(&path, &id);
    assert_eq!(
        row["gatewayWrites"].as_array().map(Vec::len),
        Some(3),
        "{row}"
    );
    let stored = row["model"]["task"].to_string();
    for member in ["_cost_warnings", "_cost_suggestion", "trace_id"] {
        assert!(stored.contains(member), "{member} was not stored: {row}");
    }
}

/// F1 (lead ruling c), row 1: a row with no room for its record stores the
/// result without the members the record would have exempted, so no
/// gateway text is stored unrecorded (and so never receipted as backend
/// text). The backend's text stays and the task completes.
#[tokio::test]
async fn a_row_with_no_room_for_its_record_stores_no_gateway_member() {
    let dir = tempfile::tempdir().unwrap();
    let (bare, bare_id) =
        settled_with(dir.path(), StoreLimits::default(), WriteRecord::default()).await;
    let room = encoded_len(&record_file(&bare, &bare_id));
    let tight = StoreLimits {
        record_bytes: room + 120,
        ..StoreLimits::default()
    };
    let other = tempfile::tempdir().unwrap();
    let (path, id) = settled_with(other.path(), tight, real_writes().await).await;
    let row = record_file(&path, &id);
    assert!(row.get("gatewayWrites").is_none(), "{row}");
    assert_eq!(row["model"]["task"]["status"], "completed", "{row}");
    let stored = row["model"]["task"].to_string();
    assert!(stored.contains("the backend's answer"), "{row}");
    for member in ["_cost_warnings", "_cost_suggestion", "trace_id"] {
        assert!(
            !stored.contains(member),
            "{member} stored unrecorded: {row}"
        );
    }
}

fn writes_len(writes: &WriteRecord) -> usize {
    serde_json::to_value(writes)
        .ok()
        .and_then(|v| v.as_array().map(Vec::len))
        .unwrap_or(0)
}

/// r5c: a write record of any shape never makes its row unreadable; the row
/// reads with an empty record, so its members stay receipted.
#[tokio::test]
async fn a_write_record_of_any_shape_never_stops_its_row() {
    for shape in [json!({"x": 1}), json!(7), json!(null), json!([{"bad": 1}])] {
        let dir = tempfile::tempdir().unwrap();
        let (path, id) = settled(dir.path(), StoreLimits::default(), 1).await;
        let record = path.join(format!("{id}.json"));
        rewrite(&record, |row| row["gatewayWrites"] = shape.clone());
        let store = TaskStore::open(&path, StoreLimits::default())
            .await
            .unwrap_or_else(|error| panic!("{shape}: the store opens: {error:?}"));
        let read = store
            .get(OWNER, &id)
            .unwrap_or_else(|error| panic!("{shape}: the row reads: {error:?}"));
        assert!(read.gateway_writes.is_empty(), "{shape}");
        store.close().await.unwrap();
    }
}

/// r5b: the record is declared after `admission`, so a row cut inside it is
/// damaged after its key: the key stays taken, never released.
#[tokio::test]
async fn a_row_cut_inside_its_write_record_keeps_its_key() {
    let dir = tempfile::tempdir().unwrap();
    let (path, id) = settled(dir.path(), StoreLimits::default(), 1).await;
    let record = path.join(format!("{id}.json"));
    let identity = record_file(&path, &id)["admission"]["identityDigest"]
        .as_str()
        .unwrap()
        .to_owned();
    let bytes = fs::read(&record).unwrap();
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        text.find("\"gatewayWrites\"") > text.find("\"admission\""),
        "premise: the record is written after the admission: {text}"
    );
    truncate_inside(&record, "gatewayWrites", 20);
    let store = TaskStore::open(&path, StoreLimits::default())
        .await
        .expect("one cut row does not stop the store");
    assert!(
        store
            .restored_bindings()
            .iter()
            .any(|(binding, bound)| binding.identity == identity && bound == &id),
        "the cut row's key stays taken"
    );
    assert!(matches!(store.get(OWNER, &id), Err(StoreError::NotFound)));
    store.close().await.unwrap();
}
