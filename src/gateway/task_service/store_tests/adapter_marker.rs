// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Adapter design §7 — the durable dispatch marker and the loader that ships
//! with it. Finding F2 of the P1 verdict, CLOSED, and therefore buildable.
//!
//! Every row here is I1 RECORD SEMANTICS. The marker is written by the worker
//! immediately before it calls the backend, so what a restart may conclude from
//! a record is decided here; the startup branch that CONCLUDES it is I3's and is
//! not simulated, asserted or named by any `executionOutcome` string below.
//! `marker_06` is the one row whose consumer is I3: it asserts only that a
//! legacy row and a never-dispatched current row stay DISTINGUISHABLE on the
//! record itself — the precondition I3's split needs and cannot recover later.
//!
//! Bindings are real: every record is committed through one actual
//! `ExecutionAdmission` lease, so no owner or fingerprint is fabricated. The raw
//! fixtures in `marker_05`/`marker_06` mutate an ACTUAL committed record's
//! `version` and marker fields and nothing else, with the untouched record as
//! the positive control that proves the seed was valid before the mutation.
use super::*;
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
mod boundary;
use crate::idempotency::admission::{
    ExecutionAdmission, Mode, Request, TaskAdmission, TaskBinding,
};

/// Owned fixture values: a `Request` borrows these, so an inline `json!` would
/// borrow a temporary that dies at the end of the statement (E0515).
static OPERATION: LazyLock<Value> =
    LazyLock::new(|| json!({"backend": "orders", "tool": "create"}));
static REPRESENTATION: LazyLock<Value> = LazyLock::new(|| json!({"full": false}));

const ALICE: &str = "oidc:acme:alice";

fn services() -> Arc<ExecutionAdmission> {
    ExecutionAdmission::new(Arc::new(|| 1_000))
}

fn task_request<'a>(principal: &'a str, key: &'a str) -> Request<'a> {
    Request {
        principal,
        key,
        operation: &OPERATION,
        representation: &REPRESENTATION,
        mode: Mode::Task,
    }
}

/// Commit one task through the real admission path and hand back the task and
/// the binding admission retained. The record's owner is the BINDING's principal
/// digest — the suite's `OWNER` constant does not apply to an admitted record.
async fn admitted(
    store: &TaskStore,
    admission: &Arc<ExecutionAdmission>,
    key: &str,
) -> (Task, TaskBinding) {
    let lease = match admission.admit_task(task_request(ALICE, key)) {
        Ok(TaskAdmission::Owned(lease)) => lease,
        other => panic!("the fixture needs a real admitted binding, got {other:?}"),
    };
    let binding = lease.binding().clone();
    let task = task();
    store
        .create(PreparedTask::admitted(
            &task,
            &binding,
            lease.into_publication(),
            "fixture",
        ))
        .await
        .expect("the fixture's own creation must commit before anything is asserted about it");
    (task, binding)
}

/// The durable record as it is on disk. Assertions read the FILE, not a private
/// field: the marker's whole purpose is what the next process finds there.
fn record_json(path: &Path, id: &str) -> Value {
    serde_json::from_slice(&fs::read(path.join(format!("{id}.json"))).unwrap())
        .expect("a committed record is parseable JSON")
}

/// Write a raw record back after mutating an actual committed one.
fn reseed(path: &Path, id: &str, record: &Value) {
    seed_private(
        &path.join(format!("{id}.json")),
        &serde_json::to_vec(record).unwrap(),
    );
}

/// A record as a binary that predates the marker wrote it: version 1, and no
/// marker field at all — that binary could not have recorded one.
fn as_legacy(record: &Value) -> Value {
    let mut legacy = record.clone();
    legacy["version"] = json!(1);
    legacy
        .as_object_mut()
        .expect("a record is a JSON object")
        .remove("dispatched");
    legacy
}

/// I1 — a record written by this binary is version 2 and claims no dispatch, and
/// the marker is on neither public projection.
#[tokio::test]
async fn marker_01_a_new_record_is_version_two_and_claims_no_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (task, binding) = admitted(&store, &services(), "k-1").await;

    let record = record_json(&path, task.id());
    assert_eq!(
        record["version"],
        json!(3),
        "the current format retains the dispatch marker introduced in version two"
    );
    assert_eq!(
        record["dispatched"],
        json!(false),
        "a committed record has not dispatched yet; the worker marks it later"
    );

    // Positive control: the mutated fixtures below start from a record the store
    // itself serves, at the revision it committed.
    let committed = store
        .get(binding.principal_digest(), task.id())
        .expect("the admitted record is readable by its own binding");
    assert_eq!(committed.revision, 1);
    assert_eq!(committed.task.status(), TaskStatus::Working);

    let wire = serde_json::to_value(committed.task.wire()).unwrap();
    assert!(
        wire.get("dispatched").is_none(),
        "the marker is gateway-internal and must not appear on the client contract"
    );
    let snapshot = serde_json::to_value(committed.task.snapshot()).unwrap();
    assert!(
        snapshot.get("dispatched").is_none(),
        "the marker is not part of TaskSnapshot, so no wire shape moves with it"
    );
    assert_eq!(
        record["model"], snapshot,
        "the marker sits beside the model, never inside it"
    );
    store.close().await.unwrap();
}

/// I1 — `mark_dispatched` is durable when it returns, and it moves nothing a
/// reader can see: no revision bump, so the settlement CAS is untouched.
#[tokio::test]
async fn marker_02_mark_dispatched_is_durable_and_moves_no_public_view() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (task, binding) = admitted(&store, &services(), "k-1").await;
    let owner = binding.principal_digest().to_owned();
    let before_record = record_json(&path, task.id());
    let before = store.get(&owner, task.id()).unwrap();
    let before_wire = serde_json::to_value(before.task.wire()).unwrap();
    let before_snapshot = serde_json::to_value(before.task.snapshot()).unwrap();

    store
        .mark_dispatched(&owner, task.id(), 1)
        .await
        .expect("a working record at its current revision accepts the marker");

    // Durable when the call returns — before the worker may reach the backend.
    let after_record = record_json(&path, task.id());
    let mut expected = before_record.clone();
    expected["dispatched"] = json!(true);
    assert_eq!(
        after_record, expected,
        "the marker write moves the marker and nothing else"
    );
    assert_eq!(
        after_record["revision"],
        json!(1),
        "no reader observes the marker, so it must not consume a revision"
    );

    let after = store.get(&owner, task.id()).unwrap();
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.task.status(), TaskStatus::Working);
    assert_eq!(
        serde_json::to_value(after.task.wire()).unwrap(),
        before_wire
    );
    assert_eq!(
        serde_json::to_value(after.task.snapshot()).unwrap(),
        before_snapshot
    );

    // The marker belongs to the record, not to this process.
    store.close().await.unwrap();
    let reopened = open(&path).await;
    assert_eq!(record_json(&path, task.id()), expected);
    let restored = reopened
        .get(&owner, task.id())
        .expect("a marked record still loads");
    assert_eq!(
        serde_json::to_value(restored.task.wire()).unwrap(),
        before_wire
    );
    reopened.close().await.unwrap();
}

/// I1 — a marker write that fails claims no dispatch. The proposed record is
/// captured whole at the rename boundary: the row asserts WHICH write was
/// refused, not merely that something was.
#[tokio::test]
async fn marker_03_a_refused_marker_write_claims_no_dispatch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let lease_name = PathBuf::from(created_sidecar(&path).file_name().unwrap());
    let (task, binding) = admitted(&store, &services(), "k-1").await;
    let owner = binding.principal_digest().to_owned();
    let before_record = record_json(&path, task.id());
    let final_name = PathBuf::from(format!("{}.json", task.id()));

    let captured: Arc<Mutex<Option<Manifest>>> = Arc::new(Mutex::new(None));
    let hook: CommitHook = {
        let captured = Arc::clone(&captured);
        let dir = path.clone();
        Arc::new(move |stage| {
            if stage == CommitStage::Rename {
                *captured.lock().unwrap() = Some(manifest(&dir));
                return Err(std::io::Error::other("the marker write is refused"));
            }
            Ok(())
        })
    };
    store.set_hook(Some(hook)).await;

    assert_eq!(
        store
            .mark_dispatched(&owner, task.id(), 1)
            .await
            .unwrap_err(),
        StoreError::Storage,
        "a refusal before the rename is a clean storage failure"
    );

    let image = captured
        .lock()
        .unwrap()
        .take()
        .expect("the marker write must reach its own rename boundary");
    let candidates: Vec<_> = image
        .iter()
        .filter(|(name, _)| !name.as_os_str().is_empty())
        .filter(|(name, _)| *name != &lease_name && *name != &final_name)
        .collect();
    assert_eq!(
        candidates.len(),
        1,
        "one proposed record beside the committed one at the writer boundary"
    );
    let proposed: Value = serde_json::from_slice(candidates[0].1.bytes.as_ref().unwrap())
        .expect("a complete proposed record at the rename boundary");
    let mut expected = before_record.clone();
    expected["dispatched"] = json!(true);
    assert_eq!(
        proposed, expected,
        "the refused write was the marker write, carrying the whole record"
    );

    // The committed record never claimed it — at the boundary, and after.
    let committed_at_boundary: Value = serde_json::from_slice(
        image
            .get(&final_name)
            .expect("the committed record stays in place")
            .bytes
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(committed_at_boundary, before_record);
    assert_eq!(
        record_json(&path, task.id()),
        before_record,
        "a failed marker write must not claim a dispatch"
    );
    assert!(
        store.ready(),
        "the refusal preceded the rename, so durability is not in doubt and the store keeps serving"
    );
    let after = store.get(&owner, task.id()).unwrap();
    assert_eq!(after.revision, 1);
    assert_eq!(after.task.status(), TaskStatus::Working);
    store.close().await.unwrap();
}

/// I1 — the marker refuses a moved revision and refuses a terminal record, and
/// writes nothing either time. The second half is the durable half of the cancel
/// interlock: a committed cancellation wins even at the matching revision.
#[tokio::test]
async fn marker_04_the_marker_refuses_a_moved_revision_and_a_terminal_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let admission = services();

    let (moved, moved_binding) = admitted(&store, &admission, "k-1").await;
    let moved_owner = moved_binding.principal_digest().to_owned();
    store
        .transition(
            &moved_owner,
            moved.id(),
            1,
            TaskTransition::StatusMessage(Some("working".into())),
            at(1),
        )
        .await
        .expect("a status message is a legal transition on a working task");
    assert_eq!(
        store
            .mark_dispatched(&moved_owner, moved.id(), 1)
            .await
            .unwrap_err(),
        StoreError::RevisionConflict,
        "the marker uses the same compare-and-set as a transition"
    );
    assert_eq!(
        record_json(&path, moved.id())["dispatched"],
        json!(false),
        "a refused marker claims nothing"
    );

    let (cancelled, cancelled_binding) = admitted(&store, &admission, "k-2").await;
    let cancelled_owner = cancelled_binding.principal_digest().to_owned();
    let terminal = store
        .transition(
            &cancelled_owner,
            cancelled.id(),
            1,
            TaskTransition::Cancel,
            at(2),
        )
        .await
        .expect("the owner cancels a running task");
    assert_eq!(terminal.task.status(), TaskStatus::Cancelled);
    assert_eq!(terminal.revision, 2);
    assert!(
        store
            .mark_dispatched(&cancelled_owner, cancelled.id(), 2)
            .await
            .is_err(),
        "a committed cancellation refuses the marker even at the matching revision"
    );
    let after = record_json(&path, cancelled.id());
    assert_eq!(
        after["dispatched"],
        json!(false),
        "a task the gateway must not dispatch never records that it did"
    );
    assert_eq!(after["revision"], json!(2));
    let view = store.get(&cancelled_owner, cancelled.id()).unwrap();
    assert_eq!(view.task.status(), TaskStatus::Cancelled);
    assert_eq!(view.revision, 2);
    store.close().await.unwrap();
}

/// I1 — the loader accepts every supported version and fails closed outside the
/// range, and an accepted record keeps the TTL and the binding it was created
/// with. The loader widening and the version bump must ship together, so both
/// halves are one row.
#[tokio::test]
async fn marker_05_the_loader_accepts_supported_versions_and_fails_closed_on_others() {
    for version in ["current", "marker_v2", "legacy", "below", "unsupported"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let store = open(&path).await;
        let admission = services();
        let (task, binding) = admitted(&store, &admission, "k-1").await;
        let committed = store.get(binding.principal_digest(), task.id()).unwrap();
        let wire = serde_json::to_value(committed.task.wire()).unwrap();
        // The positive control for every seed below: the record this fixture
        // mutates was committed, readable and lifetime-bearing first.
        assert!(wire["ttlMs"].as_u64().is_some_and(|ttl| ttl > 0));
        assert!(wire["pollIntervalMs"].as_u64().is_some_and(|poll| poll > 0));
        let record = record_json(&path, task.id());
        assert_eq!(record["version"], json!(3));
        store.close().await.unwrap();

        match version {
            "current" => {}
            "marker_v2" => {
                let mut seed = record.clone();
                seed["version"] = json!(2);
                seed.as_object_mut().unwrap().remove("upstream");
                reseed(&path, task.id(), &seed);
            }
            "legacy" => reseed(&path, task.id(), &as_legacy(&record)),
            "below" => {
                let mut seed = record.clone();
                seed["version"] = json!(0);
                reseed(&path, task.id(), &seed);
            }
            _ => {
                let mut seed = record.clone();
                seed["version"] = json!(4);
                reseed(&path, task.id(), &seed);
            }
        }
        let before = files(&path);

        let reopened = TaskStore::open(&path, StoreLimits::default()).await;
        if version == "below" || version == "unsupported" {
            assert!(
                matches!(reopened, Err(StoreError::CorruptRecord)),
                "{version} is outside the supported range and must fail closed"
            );
            assert_eq!(files(&path), before, "{version} must preserve every file");
            continue;
        }

        let reopened = reopened.expect("a supported version loads");
        let restored = reopened
            .get(binding.principal_digest(), task.id())
            .unwrap_or_else(|_| panic!("{version} must still be readable by its own binding"));
        assert_eq!(
            serde_json::to_value(restored.task.wire()).unwrap(),
            wire,
            "{version} keeps the TTL and poll interval it was created with"
        );
        assert_eq!(restored.revision, 1);
        let bindings = reopened.restored_bindings();
        assert_eq!(bindings.len(), 1, "{version} restores its one binding");
        let (persisted, id) = &bindings[0];
        assert_eq!(id, task.id());
        assert_eq!(persisted.identity, binding.identity());
        assert_eq!(persisted.principal_digest, binding.principal_digest());
        assert_eq!(persisted.operation, binding.operation());
        assert_eq!(persisted.representation, binding.representation());
        assert_eq!(persisted.metadata_bytes, binding.metadata_bytes());
        assert_eq!(
            files(&path),
            before,
            "{version} loads without rewriting anything"
        );
        reopened.close().await.unwrap();
    }
}

/// I1 record semantics for an I3 classification. A legacy row and a current row
/// that never dispatched must stay TELLABLE APART on the record itself: the
/// binary that wrote a v1 row could not record that it had not dispatched, so
/// only `version >= 2 && !dispatched` may ever become `not_executed`. This row
/// asserts the evidence; the branch that reads it is I3's and is not built here.
#[tokio::test]
async fn marker_06_a_legacy_working_row_is_not_evidence_of_a_missing_dispatch() {
    let admission = services();

    let legacy_dir = tempfile::tempdir().unwrap();
    let legacy_path = legacy_dir.path().join("tasks");
    let legacy_store = open(&legacy_path).await;
    let (legacy_task, legacy_binding) = admitted(&legacy_store, &admission, "k-legacy").await;
    let legacy_owner = legacy_binding.principal_digest().to_owned();
    let committed = record_json(&legacy_path, legacy_task.id());
    legacy_store.close().await.unwrap();
    reseed(&legacy_path, legacy_task.id(), &as_legacy(&committed));

    let restored = open(&legacy_path).await;
    let served = restored
        .get(&legacy_owner, legacy_task.id())
        .expect("a legacy row loads");
    assert_eq!(
        served.task.status(),
        TaskStatus::Working,
        "I1 opens and imports; it does not rewrite a restored row"
    );
    let legacy = record_json(&legacy_path, legacy_task.id());
    assert_eq!(
        legacy["version"],
        json!(1),
        "loading a legacy row must not silently upgrade it"
    );
    assert!(
        legacy.get("dispatched").is_none(),
        "a legacy row carries no marker, and the loader must not invent one"
    );

    let live_dir = tempfile::tempdir().unwrap();
    let live_path = live_dir.path().join("tasks");
    let live_store = open(&live_path).await;
    let (live_task, _) = admitted(&live_store, &admission, "k-live").await;
    let never_dispatched = record_json(&live_path, live_task.id());
    assert_eq!(never_dispatched["version"], json!(3));
    assert_eq!(never_dispatched["dispatched"], json!(false));

    // The distinction I3's split consumes: both rows are `working` with no
    // marker set, and only the current one carries the evidence that the
    // gateway had not dispatched.
    assert_ne!(
        legacy["version"], never_dispatched["version"],
        "a legacy row and a never-dispatched row must not be the same record state"
    );
    assert_ne!(
        legacy.get("dispatched"),
        never_dispatched.get("dispatched"),
        "an absent marker and a false marker are different facts about the same status"
    );
    restored.close().await.unwrap();
    live_store.close().await.unwrap();
}
