// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8175: the re-read of a sealed row refuses everything the load would
//! refuse, and each refusal keeps the seal. One test per fail-closed branch of
//! `reread_record`, plus the row whose admission and task id still read from
//! its envelope although the full record does not.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Mutex;

use super::admission::{services, settled_task};
use super::support::*;

/// `name` sealed, then read again: how many rows stay sealed, and the task
/// ids the re-read handed to import.
async fn reread_open(store: &super::super::store::TaskStore, name: &str) -> (usize, Vec<String>) {
    store.seal_for_test(name);
    let imported = Mutex::new(Vec::new());
    let sealed = store
        .reread_sealed(|_, task_id| {
            imported.lock().unwrap().push(task_id);
            true
        })
        .await;
    (sealed, imported.into_inner().unwrap())
}

fn private(path: &Path) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

const NAME: &str = "task-00000000-0000-4000-8000-000000000001.json";

/// A name whose parent is a regular file cannot even be looked at: an error
/// other than "not found" keeps the seal.
#[tokio::test]
async fn a_name_that_cannot_be_looked_at_stays_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    std::fs::write(path.join("blocker"), b"").unwrap();
    assert_eq!(
        reread_open(&store, &format!("blocker/{NAME}")).await,
        (1, vec![])
    );
}

/// A symlink at the row's name is never followed: the open refuses it and the
/// seal stays, although the link leads to the task's own valid record.
#[tokio::test]
async fn a_symlinked_row_stays_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (id, _) = settled_task(&store, &services(), "k-link").await;
    let row = path.join(format!("{id}.json"));
    let elsewhere = dir.path().join("elsewhere.json");
    std::fs::rename(&row, &elsewhere).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &row).unwrap();
    assert_eq!(
        reread_open(&store, &format!("{id}.json")).await,
        (1, vec![])
    );
}

/// A valid row padded one byte past the record cap is not read past the cap;
/// it stays sealed.
#[tokio::test]
async fn a_row_over_the_record_cap_stays_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (id, _) = settled_task(&store, &services(), "k-big").await;
    let row = path.join(format!("{id}.json"));
    let mut bytes = std::fs::read(&row).unwrap();
    let cap = super::super::store::StoreLimits::default().record_bytes;
    bytes.resize(cap + 1, b' ');
    std::fs::write(&row, bytes).unwrap();
    private(&row);
    assert_eq!(
        reread_open(&store, &format!("{id}.json")).await,
        (1, vec![])
    );
}

/// A valid row copied under another task's name names another task: the
/// re-read refuses it, as the load does.
#[tokio::test]
async fn a_row_that_names_another_task_stays_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (id, _) = settled_task(&store, &services(), "k-copy").await;
    let copy = path.join(NAME);
    assert_ne!(format!("{id}.json"), NAME);
    std::fs::copy(path.join(format!("{id}.json")), &copy).unwrap();
    private(&copy);
    assert_eq!(reread_open(&store, NAME).await, (1, vec![]));
}

/// A row damaged after its admission and model members no longer restores,
/// but its envelope still reads both: the re-read hands import the task id
/// the row names, and the seal lifts.
#[tokio::test]
async fn a_row_whose_envelope_still_reads_is_repaired_by_its_named_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (id, _) = settled_task(&store, &services(), "k-tail").await;
    let row = path.join(format!("{id}.json"));
    let text = std::fs::read_to_string(&row).unwrap();
    let end = text.rfind('}').expect("a record object");
    std::fs::write(&row, format!("{},\"tail\":@{}", &text[..end], &text[end..])).unwrap();
    private(&row);
    assert_eq!(
        reread_open(&store, &format!("{id}.json")).await,
        (0, vec![id])
    );
}

/// The same envelope-only row under another task's name: the id it names is
/// not the file's, so it stays sealed.
#[tokio::test]
async fn an_envelope_only_row_under_another_name_stays_sealed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let (id, _) = settled_task(&store, &services(), "k-moved").await;
    let text = std::fs::read_to_string(path.join(format!("{id}.json"))).unwrap();
    let end = text.rfind('}').expect("a record object");
    let copy = path.join(NAME);
    assert_ne!(format!("{id}.json"), NAME);
    std::fs::write(
        &copy,
        format!("{},\"tail\":@{}", &text[..end], &text[end..]),
    )
    .unwrap();
    private(&copy);
    assert_eq!(reread_open(&store, NAME).await, (1, vec![]));
}
