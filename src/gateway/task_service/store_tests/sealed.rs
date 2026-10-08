// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8052: a stored row whose idempotency key cannot be read seals new keyed
//! admissions, so a retry of that key never runs its backend twice. The seal
//! lifts on its own once the row is repaired or removed.

use std::path::Path;
use std::sync::Arc;

use serde_json::{Value, json};

use super::super::service::TaskService;
use super::super::store::StoreLimits;
use super::admission::{services, settled_task, task_request};
use super::support::*;
use crate::idempotency::admission::{ExecutionAdmission, TaskAdmission};

/// MIK-8052: the damage done to a settled row's bytes, each a way its
/// admission member stops reading unambiguously.
enum Damage {
    /// Syntax damage in `dispatched`, the member written before `admission`.
    BeforeAdmission,
    /// `admission` present but not an admission block.
    MistypedAdmission,
    /// A later, well-formed decoy copy of `identityDigest` inside `admission`.
    NestedDuplicate,
    /// A second, later `admission` member: either copy could be the writer's.
    RepeatedAdmission,
    /// A readable decoy copy, then the original copy with damage inside it.
    DecoyThenDamagedOriginal,
}

fn damage(record: &std::path::Path, how: &Damage) {
    let text = String::from_utf8(std::fs::read(record).unwrap()).unwrap();
    let damaged = match how {
        Damage::BeforeAdmission => text.replacen("\"dispatched\":", "\"dispatched\":@", 1),
        Damage::MistypedAdmission => {
            let mut value: Value = serde_json::from_str(&text).unwrap();
            value["admission"] = json!(null);
            serde_json::to_string(&value).unwrap()
        }
        Damage::NestedDuplicate => {
            // The block holds only scalars, so its first closing brace ends it.
            let start = text.find("\"admission\":{").expect("an admission block");
            let end = start + text[start..].find('}').unwrap();
            // A well-formed digest, so only the duplicate is wrong.
            let decoy = "0".repeat(64);
            format!(
                "{},\"identityDigest\":\"{decoy}\"{}",
                &text[..end],
                &text[end..]
            )
        }
        Damage::DecoyThenDamagedOriginal => {
            let start = text.find("\"admission\":{").expect("an admission block");
            let open = start + "\"admission\":".len();
            let end = open + text[open..].find('}').unwrap();
            let mut decoy: Value = serde_json::from_str(&text[open..=end]).unwrap();
            decoy["identityDigest"] = json!("0".repeat(64));
            format!(
                "{}\"admission\":{decoy},\"admission\":{{@{}",
                &text[..start],
                &text[open + 1..]
            )
        }
        Damage::RepeatedAdmission => {
            let end = text.rfind('}').expect("a record object");
            format!("{},\"admission\":null{}", &text[..end], &text[end..])
        }
    };
    assert_ne!(damaged, text, "the fixture must change the record");
    std::fs::write(record, damaged).unwrap();
}

/// `MIK-8052.AC1`: a row whose admission member cannot be read unambiguously
/// must not hand its key to a new task. The store still opens (`MIK-8023.LOAD.1`),
/// and a retry of the row's key is never admitted as a fresh owner, so its
/// backend never runs twice.
#[tokio::test]
async fn an_unreadable_admission_never_frees_its_key() {
    let mut freed = Vec::new();
    for (case, how) in [
        ("before_admission", Damage::BeforeAdmission),
        ("mistyped_admission", Damage::MistypedAdmission),
        ("nested_duplicate", Damage::NestedDuplicate),
        ("repeated_admission", Damage::RepeatedAdmission),
        (
            "decoy_then_damaged_original",
            Damage::DecoyThenDamagedOriginal,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let store = open(&path).await;
        let (id, _) = settled_task(&store, &services(), "k-8052").await;
        store.close().await.unwrap();
        damage(&path.join(format!("{id}.json")), &how);

        let admission = services();
        let service = match super::super::service::TaskService::open(
            &path,
            super::super::store::StoreLimits::default(),
            Arc::clone(&admission),
        )
        .await
        {
            Ok(service) => service,
            Err(error) => panic!("{case}: one damaged row stopped the store: {error:?}"),
        };
        let retry = admission.admit_task(task_request("oidc:acme:alice", "k-8052"));
        if matches!(retry, Ok(TaskAdmission::Owned(_))) {
            freed.push(case);
        }
        service.close().await.unwrap();
    }
    assert!(
        freed.is_empty(),
        "a retry of the damaged row's key was admitted as a new task: {freed:?}"
    );
}

/// A store holding one settled task per key, each row then damaged so its key
/// cannot be read; the service is open over it. Returns the store path, each
/// row's task id and its original bytes, the admission authority and the
/// service.
async fn sealed_service(
    root: &Path,
    keys: &[&str],
) -> (
    std::path::PathBuf,
    Vec<(String, Vec<u8>)>,
    Arc<ExecutionAdmission>,
    TaskService,
) {
    let path = root.join("tasks");
    let store = open(&path).await;
    let mut rows = Vec::new();
    let writer = services();
    for key in keys {
        let (id, _) = settled_task(&store, &writer, key).await;
        rows.push(id);
    }
    store.close().await.unwrap();
    let rows = rows
        .into_iter()
        .map(|id| {
            let record = path.join(format!("{id}.json"));
            let original = std::fs::read(&record).unwrap();
            damage(&record, &Damage::BeforeAdmission);
            (id, original)
        })
        .collect();
    let admission = services();
    let service = TaskService::open(&path, StoreLimits::default(), Arc::clone(&admission))
        .await
        .expect("sealed rows never stop the store");
    (path, rows, admission, service)
}

fn is_new_owner(admission: &Arc<ExecutionAdmission>, key: &str) -> bool {
    matches!(
        admission.admit_task(task_request("oidc:acme:alice", key)),
        Ok(TaskAdmission::Owned(_))
    )
}

/// A bad admission block must not end the walk before a later `version`: a
/// newer build's row still refuses the store, however its admission reads.
#[tokio::test]
async fn a_bad_admission_never_hides_a_newer_version() {
    for (case, admission) in [
        ("null", "null"),
        (
            "repeated_field",
            r#"{"identityDigest":"a","identityDigest":"b"}"#,
        ),
        ("list", "[1,2]"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let store = open(&path).await;
        let (id, _) = settled_task(&store, &services(), "k-version").await;
        store.close().await.unwrap();
        let record = path.join(format!("{id}.json"));
        let mut value: Value = serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
        value["admission"] = json!(null);
        let text = serde_json::to_string(&value).unwrap();
        let text = text.replacen(
            "\"admission\":null",
            &format!("\"admission\":{admission}"),
            1,
        );
        let end = text.rfind('}').unwrap();
        std::fs::write(
            &record,
            format!("{},\"version\":999{}", &text[..end], &text[end..]),
        )
        .unwrap();
        assert_eq!(
            super::super::store::TaskStore::open(&path, StoreLimits::default())
                .await
                .err(),
            Some(super::super::store::StoreError::CorruptRecord),
            "{case}: a newer build's row must refuse the store"
        );
    }
}

/// Removing the sealed file lifts the seal at the next re-read, with no
/// restart; until then every new key is refused.
#[tokio::test]
async fn removing_a_sealed_row_lifts_the_seal() {
    let dir = tempfile::tempdir().unwrap();
    let (path, rows, admission, service) = sealed_service(dir.path(), &["k-gone"]).await;
    assert_eq!(service.skipped_records().sealed, 1);
    assert!(!is_new_owner(&admission, "k-other"), "sealed: no new key");
    std::fs::remove_file(path.join(format!("{}.json", rows[0].0))).unwrap();
    service.reread_sealed().await;
    assert_eq!(service.skipped_records().sealed, 0);
    assert!(is_new_owner(&admission, "k-other"), "the seal lifted");
    service.close().await.unwrap();
}

/// A repaired row's key is imported BEFORE the seal lifts: its retry finds its
/// own task id, while a new key is admitted again.
#[tokio::test]
async fn repairing_a_sealed_row_keeps_its_key_and_lifts_the_seal() {
    let dir = tempfile::tempdir().unwrap();
    let (path, rows, admission, service) = sealed_service(dir.path(), &["k-fixed"]).await;
    let (id, original) = &rows[0];
    std::fs::write(path.join(format!("{id}.json")), original).unwrap();
    service.reread_sealed().await;
    assert_eq!(service.skipped_records().sealed, 0);
    assert_eq!(
        service.skipped_records().reserved,
        1,
        "the repaired row is kept"
    );
    match admission.admit_task(task_request("oidc:acme:alice", "k-fixed")) {
        Ok(TaskAdmission::Existing { task_id, .. }) => assert_eq!(&task_id, id),
        other => panic!("a retry of the repaired key must find its task, got {other:?}"),
    }
    assert!(is_new_owner(&admission, "k-new"), "the seal lifted");
    service.close().await.unwrap();
}

/// Two sealed rows: repairing one keeps the seal; repairing the second lifts
/// it. Each repaired key is kept.
#[tokio::test]
async fn the_seal_lifts_only_when_every_sealed_row_is_repaired() {
    let dir = tempfile::tempdir().unwrap();
    let (path, rows, admission, service) = sealed_service(dir.path(), &["k-a", "k-b"]).await;
    for (done, (id, original)) in rows.iter().enumerate() {
        std::fs::write(path.join(format!("{id}.json")), original).unwrap();
        service.reread_sealed().await;
        let left = rows.len() - done - 1;
        assert_eq!(service.skipped_records().sealed, left);
        assert_eq!(
            is_new_owner(&admission, &format!("k-new-{done}")),
            left == 0
        );
    }
    for key in ["k-a", "k-b"] {
        assert!(
            matches!(
                admission.admit_task(task_request("oidc:acme:alice", key)),
                Ok(TaskAdmission::Existing { .. })
            ),
            "{key}: a repaired key stays taken"
        );
    }
    service.close().await.unwrap();
}

/// A re-read never blocks and never takes the store down: a sealed row
/// replaced by a FIFO, or by a newer build's row, stays sealed.
#[cfg(unix)]
#[tokio::test]
async fn a_refused_reread_keeps_the_seal_and_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let (path, rows, admission, service) = sealed_service(dir.path(), &["k-fifo"]).await;
    let record = path.join(format!("{}.json", rows[0].0));
    std::fs::remove_file(&record).unwrap();
    crate::test_fifo::make_fifo(&record);
    {
        // Scoped so the pinned future's borrow of `service` ends before close.
        let reread = service.reread_sealed();
        tokio::pin!(reread);
        if tokio::time::timeout(std::time::Duration::from_secs(5), &mut reread)
            .await
            .is_err()
        {
            // Release the open blocked on the FIFO so teardown finishes, then fail.
            let _ = std::fs::OpenOptions::new().write(true).open(&record);
            reread.await;
            panic!("the re-read waited on a FIFO");
        }
    }
    assert_eq!(service.skipped_records().sealed, 1, "a FIFO stays sealed");
    std::fs::remove_file(&record).unwrap();
    let mut value: Value = serde_json::from_slice(&rows[0].1).unwrap();
    value["version"] = json!(999);
    std::fs::write(&record, serde_json::to_vec(&value).unwrap()).unwrap();
    // Private, so only the version decides.
    std::fs::set_permissions(
        &record,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
    )
    .unwrap();
    service.reread_sealed().await;
    assert_eq!(
        service.skipped_records().sealed,
        1,
        "a newer row stays sealed"
    );
    assert!(!is_new_owner(&admission, "k-other"));
    service.close().await.unwrap();
}

/// A repaired row moves from the sealed rows to the reserved ones: it counts
/// once against the record cap, before and after. With a cap of two, one
/// repaired row leaves room for exactly one new task.
#[tokio::test]
async fn a_repaired_row_counts_once_against_the_record_cap() {
    let dir = tempfile::tempdir().unwrap();
    let (path, rows, _admission, service) = sealed_service(dir.path(), &["k-cap"]).await;
    service.close().await.unwrap();
    let limits = StoreLimits {
        records: 2,
        ..StoreLimits::default()
    };
    let admission = services();
    let service = TaskService::open(&path, limits, Arc::clone(&admission))
        .await
        .unwrap();
    let (id, original) = &rows[0];
    std::fs::write(path.join(format!("{id}.json")), original).unwrap();
    service.reread_sealed().await;
    assert_eq!(service.skipped_records().reserved, 1);
    let writer = services();
    settled_task(&service.store, &writer, "k-second").await;
    let third = writer.admit_task(task_request("oidc:acme:alice", "k-third"));
    let Ok(TaskAdmission::Owned(lease)) = third else {
        panic!("admission itself is not capped here, got {third:?}");
    };
    let task = task();
    let binding = lease.binding().clone();
    let created = service
        .store
        .create(super::super::record::PreparedTask::admitted(
            &task,
            &binding,
            lease.into_publication(),
            "fixture",
        ))
        .await;
    assert_eq!(
        created.err(),
        Some(super::super::store::StoreError::Capacity),
        "the repaired row still holds its place"
    );
    service.close().await.unwrap();
}

/// No window frees a repaired key: inside the re-read, right after its import
/// and before the seal is lowered, a retry of that key already finds its task,
/// and a new key is still refused.
#[tokio::test]
async fn a_repaired_key_is_never_free_while_the_seal_lifts() {
    let dir = tempfile::tempdir().unwrap();
    let (path, rows, admission, service) = sealed_service(dir.path(), &["k-race"]).await;
    let (id, original) = &rows[0];
    std::fs::write(path.join(format!("{id}.json")), original).unwrap();
    let seen = std::sync::Mutex::new(Vec::new());
    let sealed = service
        .store
        .reread_sealed(|binding, task_id| {
            let imported = admission.import_tasks(&[(binding, task_id)]).is_ok();
            seen.lock().unwrap().push((
                admission.admit_task(task_request("oidc:acme:alice", "k-race")),
                is_new_owner(&admission, "k-meanwhile"),
            ));
            imported
        })
        .await;
    let seen = seen.into_inner().unwrap();
    assert_eq!(seen.len(), 1, "one repaired row");
    let (retry, new_owner) = &seen[0];
    assert!(
        matches!(retry, Ok(TaskAdmission::Existing { task_id, .. }) if task_id == id),
        "the repaired key is held from its import on, got {retry:?}"
    );
    assert!(!new_owner, "the seal holds until it is lowered");
    assert_eq!(sealed, 0);
    service.close().await.unwrap();
}

/// A repair that would take its owner over the per-principal cap keeps the
/// seal, as startup would refuse that directory, whether the owner's other row
/// loaded or was itself kept only as a reserved key.
#[tokio::test]
async fn a_repair_over_its_owners_cap_keeps_the_seal() {
    for held_as in ["loaded", "reserved"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks");
        let store = open(&path).await;
        let writer = services();
        let (held, _) = settled_task(&store, &writer, "k-held").await;
        let (damaged, _) = settled_task(&store, &writer, "k-damaged").await;
        store.close().await.unwrap();
        if held_as == "reserved" {
            // Its task no longer restores, but its key still reads.
            let record = path.join(format!("{held}.json"));
            let mut value: Value =
                serde_json::from_slice(&std::fs::read(&record).unwrap()).unwrap();
            value["model"]["task"]["lastUpdatedAt"] = json!("2026-09-06T00:00:00Z");
            std::fs::write(&record, serde_json::to_vec(&value).unwrap()).unwrap();
        }
        let record = path.join(format!("{damaged}.json"));
        let original = std::fs::read(&record).unwrap();
        damage(&record, &Damage::BeforeAdmission);
        let limits = StoreLimits {
            per_principal: 1,
            ..StoreLimits::default()
        };
        let service = TaskService::open(&path, limits, services()).await.unwrap();
        std::fs::write(&record, original).unwrap();
        service.reread_sealed().await;
        assert_eq!(
            service.skipped_records().sealed,
            1,
            "{held_as}: the owner already holds its one row"
        );
        service.close().await.unwrap();
    }
}

/// A startup whose import is refused leaves the caller's admission exactly as
/// it found it: the seal it set for the store's sealed rows is taken back, so
/// new keyed calls are not refused by a store that never opened.
#[tokio::test]
async fn a_refused_startup_import_leaves_the_seal_as_it_found_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let writer = services();
    settled_task(&store, &writer, "k-held").await;
    let (damaged, _) = settled_task(&store, &writer, "k-damaged").await;
    store.close().await.unwrap();
    damage(
        &path.join(format!("{damaged}.json")),
        &Damage::BeforeAdmission,
    );
    let admission = services();
    // The caller's admission already holds the stored key, so the import is
    // refused after the seal was set.
    let held = admission.admit_task(task_request("oidc:acme:alice", "k-held"));
    assert!(matches!(held, Ok(TaskAdmission::Owned(_))), "{held:?}");
    let opened = TaskService::open(&path, StoreLimits::default(), Arc::clone(&admission)).await;
    assert!(opened.is_err(), "a conflicting import refuses the startup");
    assert!(
        is_new_owner(&admission, "k-fresh"),
        "a refused startup left new keyed calls sealed"
    );
    assert!(
        !is_new_owner(&admission, "k-held"),
        "the caller's own lease survives the refused startup"
    );
    // A seal another holder already placed is left as it was, not cleared.
    admission.adjust_sealed(0, 7);
    let reopened = TaskService::open(&path, StoreLimits::default(), Arc::clone(&admission)).await;
    assert!(reopened.is_err(), "the import is still refused");
    assert_eq!(
        admission.sealed_for_test(),
        7,
        "the other holder's seal stands"
    );
    drop(held);
}

/// Sealed rows count while the load is still reading: a directory holding more
/// damaged rows than the record cap is refused at open, not loaded whole.
#[tokio::test]
async fn sealed_rows_count_against_the_record_cap_during_the_load() {
    let dir = tempfile::tempdir().unwrap();
    let (path, _rows, _admission, service) =
        sealed_service(dir.path(), &["k-one", "k-two", "k-three"]).await;
    service.close().await.unwrap();
    let limits = StoreLimits {
        records: 2,
        ..StoreLimits::default()
    };
    let opened = TaskService::open(&path, limits, services()).await;
    assert!(
        opened.is_err(),
        "three sealed rows loaded under a record cap of two"
    );
}

/// A service that gives its store back (a startup that failed after the
/// open, or any shutdown) hands back the seal it set, so the caller's
/// admission authority, which may keep serving without a task store, is
/// not left refusing every new keyed call.
#[tokio::test]
async fn a_shut_down_service_hands_back_its_seal() {
    let dir = tempfile::tempdir().unwrap();
    let (_path, _rows, admission, service) = sealed_service(dir.path(), &["k-sealed"]).await;
    assert!(
        !is_new_owner(&admission, "k-before"),
        "premise: the open service seals new keys"
    );
    service.shutdown().await.expect("the store closes");
    assert!(
        is_new_owner(&admission, "k-after"),
        "a shut-down service left the caller's admission sealed"
    );
}

/// The lead's interleaving: a service opens over a sealed row, another
/// holder seals after it, and the service's startup then fails and it shuts
/// down. Only the service's own share is released, and only once: the other
/// holder's seal stays in force through a second shutdown.
#[tokio::test]
async fn a_shutdown_releases_only_its_own_share_of_the_seal_once() {
    let dir = tempfile::tempdir().unwrap();
    let (_path, _rows, admission, service) = sealed_service(dir.path(), &["k-sealed"]).await;
    assert_eq!(
        admission.sealed_for_test(),
        1,
        "premise: the service's share"
    );
    admission.adjust_sealed(0, 1);
    service.shutdown().await.expect("the store closes");
    assert_eq!(
        admission.sealed_for_test(),
        1,
        "the other holder's seal stands"
    );
    assert!(
        !is_new_owner(&admission, "k-after"),
        "still sealed by the other holder"
    );
    service.shutdown().await.ok();
    assert_eq!(
        admission.sealed_for_test(),
        1,
        "a second shutdown released the other holder's seal"
    );
}

/// Seat-2 review: a sweep's re-read that finishes after shutdown cannot put
/// the service's share of the seal back.
#[tokio::test]
async fn a_reread_after_shutdown_puts_no_seal_back() {
    let dir = tempfile::tempdir().unwrap();
    let (_path, _rows, admission, service) = sealed_service(dir.path(), &["k-sealed"]).await;
    service.shutdown().await.expect("the store closes");
    assert_eq!(
        admission.sealed_for_test(),
        0,
        "premise: the share was released"
    );
    service.reread_sealed().await;
    assert_eq!(
        admission.sealed_for_test(),
        0,
        "a re-read after shutdown sealed the caller's admission again"
    );
}

/// The admin view names a sealed file by its full path even when the store
/// directory is configured relative, so the operator never resolves it
/// against the gateway's working directory.
#[tokio::test]
async fn sealed_files_are_absolute_under_a_relative_store_dir() {
    let dir = tempfile::tempdir_in(".").unwrap();
    // The store creates its own private directory inside the scratch one.
    let relative = Path::new(".")
        .join(dir.path().file_name().unwrap())
        .join("store");
    let store = open(&relative).await;
    store.seal_for_test("task-relative.json");

    let files = store.sealed_files();
    assert_eq!(files.len(), 1, "{files:?}");
    assert!(files[0].is_absolute(), "not a full path: {files:?}");
    assert!(files[0].ends_with("task-relative.json"), "{files:?}");
}

/// A store directory moved away (renamed, unmounted) is not a removed file:
/// every sealed row may still exist under the old directory, so the seal
/// stays, and so it does when a fresh directory takes the name.
#[cfg(unix)]
#[tokio::test]
async fn a_moved_store_directory_keeps_the_seal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    store.seal_for_test("task-00000000-0000-4000-8000-000000000001.json");
    std::fs::rename(&path, dir.path().join("moved")).unwrap();
    assert_eq!(
        store.reread_sealed(|_, _| true).await,
        1,
        "a missing store directory lifted the seal"
    );
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    assert_eq!(
        store.reread_sealed(|_, _| true).await,
        1,
        "another directory under the store's name lifted the seal"
    );
}

/// A repaired row read again after shutdown imports nothing: the closed
/// service has released custody, so its key must not be published on the
/// caller's authority.
#[tokio::test]
async fn a_repair_read_after_shutdown_imports_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (path, rows, admission, service) = sealed_service(dir.path(), &["k-late"]).await;
    service.shutdown().await.expect("the store closes");
    let (id, original) = &rows[0];
    std::fs::write(path.join(format!("{id}.json")), original).unwrap();
    service.reread_sealed().await;
    assert!(
        !matches!(
            admission.admit_task(task_request("oidc:acme:alice", "k-late")),
            Ok(TaskAdmission::Existing { .. })
        ),
        "a re-read after shutdown published the repaired key"
    );
}
