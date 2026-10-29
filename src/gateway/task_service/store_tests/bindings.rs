// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8407 REC.1: a task row records the binding each call ran under, and
//! it survives a reopen of the store. No full restart-through-gateway row
//! exists: custody (the account store) does not survive a rebuild of the
//! router fixture, so the restart path is pinned here (the binding read back
//! from the REOPENED store) and by the router's backend-swap rows.
#![cfg_attr(
    test,
    allow(
        clippy::disallowed_methods,
        reason = "test code reads the host clock (MIK-8202 AC.14)"
    )
)]
use super::super::record::{BINDING_VERSION, Provenance};
use super::*;
use chrono::Utc;

fn bound() -> Vec<(String, String, Option<String>)> {
    vec![
        (
            "work-mail".to_owned(),
            "read".to_owned(),
            Some("work#f1".to_owned()),
        ),
        ("plain".to_owned(), "read".to_owned(), None),
    ]
}

fn complete() -> TaskTransition {
    TaskTransition::Complete(json!({"content": [{"type": "text", "text": "settled"}]}))
}

/// RB-restart (REC.1; mutant M-rec-store): a settled row's bindings are
/// written at `BINDING_VERSION`, and a reopened store reads them back from
/// disk, not from memory.
#[tokio::test]
async fn rb_restart_bindings_survive_a_reopen_of_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    // Admitted by this gateway: a row recording its bindings from creation.
    let mut prepared = PreparedTask::for_test(&task, OWNER, 1);
    prepared.record.version = BINDING_VERSION;
    store.create(prepared).await.unwrap();
    store
        .settle_bounded_by(
            OWNER,
            task.id(),
            1,
            (
                complete(),
                Provenance {
                    targets: None,
                    bindings: bound(),
                    ..Provenance::default()
                },
                crate::gateway::gateway_writes::WriteRecord::default(),
            ),
            crate::gateway::task_service::ErrorAuthor::Gateway,
            Utc::now(),
        )
        .await
        .unwrap();
    store.close().await.unwrap();

    let file = path.join(format!("{}.json", task.id()));
    let on_disk: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    assert_eq!(on_disk["version"], json!(BINDING_VERSION), "{on_disk}");
    let reopened = open(&path).await;
    let read = reopened.get(OWNER, task.id()).unwrap();
    assert!(read.bindings_recorded, "RB-restart: not recorded");
    assert_eq!(read.bindings, bound(), "RB-restart: bindings lost");
    reopened.close().await.unwrap();
}

/// RB-legacy-held (lead condition; gpt and grok final F2): a row written
/// before bindings were recorded reads as unrecorded, stays so after this
/// gateway settles it, and the store still reads it: nothing is deleted.
#[tokio::test]
async fn rb_legacy_a_pre_binding_row_reads_unrecorded_and_stays_held() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tasks");
    let store = open(&path).await;
    let task = task();
    // The row as a 4.0 beta admitted it: the version before bindings.
    let mut prepared = PreparedTask::for_test(&task, OWNER, 1);
    prepared.record.version = BINDING_VERSION - 1;
    store.create(prepared).await.unwrap();
    // Settled by this gateway, with bindings: it must not become recorded.
    store
        .settle_bounded_by(
            OWNER,
            task.id(),
            1,
            (
                complete(),
                Provenance {
                    targets: None,
                    bindings: bound(),
                    ..Provenance::default()
                },
                crate::gateway::gateway_writes::WriteRecord::default(),
            ),
            crate::gateway::task_service::ErrorAuthor::Gateway,
            Utc::now(),
        )
        .await
        .unwrap();
    store.close().await.unwrap();

    let reopened = open(&path).await;
    for read in 0..2 {
        let row = reopened
            .get(OWNER, task.id())
            .unwrap_or_else(|_| panic!("read {read}: the legacy row is gone"));
        assert!(!row.bindings_recorded, "a beta row reads as recorded");
        assert!(row.serves_backend_output(), "premise: it holds output");
    }
    reopened.close().await.unwrap();
}
