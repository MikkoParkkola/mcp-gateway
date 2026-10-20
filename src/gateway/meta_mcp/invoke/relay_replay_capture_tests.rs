// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! MIK-8408 capture-policy rows (the sync replay key's identity, and
//! which note a capture is filed under), split from
//! `relay_replay_tests` for the file-size ceiling.

use std::time::Duration;

use serde_json::json;

use super::super::super::collecting;
use super::super::{
    CaptureKey, note_sync_capture, note_task_capture, sync_replay_key, take_capture,
};

/// The sync replay key's identity is the identity admission itself
/// computes for the same principal and key (`admission_identity`, the
/// one definition both sides call), and its operation is the
/// canonical-JSON hash `Request::prepare` stores.
/// Mutant killed: recompute the identity in `sync_replay_key` under a
/// second spelling of the domain (every sync replay would silently
/// miss its entry once the two spellings drift).
#[test]
fn sync_replay_keys_identity_is_admissions_identity() {
    let operation = json!({"name": "gateway_execute", "arguments": {"chain": []}});
    let (identity, op) = sync_replay_key("principal-a", "key-1", &operation);
    assert_eq!(
        identity,
        crate::idempotency::admission::admission_identity("principal-a", "key-1"),
        "the replay key must recompute admission's own identity"
    );
    assert_eq!(
        op,
        crate::hashing::canonical_json_sha256(&operation),
        "the replay key's operation is prepare's operation hash"
    );
}

/// Capture policy, stated and pinned: a sync capture keeps the FIRST
/// note in a delivery (an inner keyed call never takes the outer
/// delivery's key); a task capture keeps the LAST (one delivery
/// settles once in today's wiring, so last-wins is the settled row's
/// own note). A TTL-less task's capture retention is the 24 h
/// fallback; a task TTL is carried through as given.
/// Mutants killed: last-wins sync capture (filed under identity-2);
/// first-wins task capture (filed under task-1 at revision 1); a
/// fallback other than 24 h.
#[tokio::test]
async fn sync_capture_keeps_the_first_note_and_task_capture_the_last() {
    let sync = collecting(async {
        note_sync_capture(
            "identity-1".to_owned(),
            "round-1".to_owned(),
            "op-1".to_owned(),
        );
        note_sync_capture(
            "identity-2".to_owned(),
            "round-2".to_owned(),
            "op-2".to_owned(),
        );
        take_capture().0
    })
    .await;
    let Some(sync) = sync else {
        panic!("premise: a sync capture was noted");
    };
    assert!(
        matches!(
            &sync.key,
            CaptureKey::Sync { identity, round, operation }
                if identity.as_str() == "identity-1"
                    && round.as_str() == "round-1"
                    && operation.as_str() == "op-1"
        ),
        "the sync capture was not filed under the first note in the delivery"
    );
    let task = collecting(async {
        note_task_capture("task-1".to_owned(), 1, None);
        note_task_capture("task-2".to_owned(), 2, Some(5_000));
        take_capture().0
    })
    .await;
    let Some(task) = task else {
        panic!("premise: a task capture was noted");
    };
    assert!(
        matches!(
            &task.key,
            CaptureKey::Task { id, revision: 2 } if id.as_str() == "task-2"
        ),
        "the task capture was not filed under the last note in the delivery"
    );
    assert_eq!(
        task.retention,
        Duration::from_secs(5),
        "the task's own TTL is the capture retention"
    );
    let ttl_less = collecting(async {
        note_task_capture("task-3".to_owned(), 1, None);
        take_capture().0
    })
    .await;
    let Some(ttl_less) = ttl_less else {
        panic!("premise: a task capture was noted");
    };
    assert_eq!(
        ttl_less.retention,
        Duration::from_secs(24 * 60 * 60),
        "a TTL-less task's capture falls back to 24 h"
    );
}
