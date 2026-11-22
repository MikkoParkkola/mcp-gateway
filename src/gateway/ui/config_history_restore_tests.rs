// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Restore rows: the stored bytes come back exactly,
//! the replaced file stays beside them, the write is a Restore on the shared
//! audited writer, and every refusal leaves gateway.yaml as it was.

use std::time::{Duration, Instant};

use axum::http::StatusCode;
use serde_json::json;

use super::support_tests::{Audit, Caller, Rig, config_text};
use crate::config_reload::history::{Bounds, Event, Outcome, Snapshot, Source, StoredFile};

/// The answer every refused write of this route gives for a write it did not do.
const NOT_WRITTEN: &str = "the restore was not written";
/// The writer's busy answer.
const BUSY: &str =
    "the gateway is applying another config change; nothing was written, retry shortly";
/// The guard's refusal of a caller the route bars.
const FORBIDDEN: &str = "Authentication required";

/// An older version whose bytes any re-serialisation would change: a
/// comment above the keys, odd spacing and a trailing comment.
fn older() -> String {
    format!(
        "# a note the operator wrote\n{}",
        config_text("environment:   \"older\"    # spaced on purpose\n\n")
    )
}

fn current() -> String {
    config_text("environment: \"current\"\n")
}

/// A gateway started on `older`, then reloaded to `current`: both kept.
async fn two_versions(audit: Audit) -> (Rig, String) {
    let rig = Rig::start(&older(), audit).await;
    rig.reload_to(&current()).await;
    let old = rig.version_of(older().as_bytes());
    (rig, old)
}

#[tokio::test]
async fn r1_a_restore_writes_the_stored_bytes_back_and_keeps_the_replaced_file() {
    let (rig, old) = two_versions(Audit::Logged).await;
    let (status, body) = rig.restore(&old, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(rig.bytes(), older().into_bytes());
    let beside = rig.rejected();
    assert_eq!(beside.len(), 1, "{beside:?}");
    assert_eq!(
        std::fs::read(&beside[0]).expect("the kept copy"),
        current().into_bytes()
    );
    let name = beside[0]
        .file_name()
        .and_then(|n| n.to_str())
        .expect("a name");
    assert_eq!(body["kept_beside"], json!(name));
    assert_eq!(body["changed"], json!(true));
    assert_eq!(body["version"], json!(old));
    let last = rig.store.events().pop().expect("an event");
    assert_eq!(last.outcome, Outcome::Applied);
    assert_eq!(last.source, Source::Ui { who: "root".into() });
}

#[tokio::test]
async fn r1b_an_edit_the_history_never_saw_is_what_stays_beside_the_file() {
    let (rig, old) = two_versions(Audit::Logged).await;
    let unseen = config_text("environment: \"edited by hand, never reloaded\"\n");
    rig.write(&unseen);
    let (status, body) = rig.restore(&old, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let beside = rig.rejected();
    assert_eq!(beside.len(), 1, "{beside:?}");
    assert_eq!(
        std::fs::read(&beside[0]).expect("the kept copy"),
        unseen.into_bytes()
    );
}

#[tokio::test]
async fn r3_an_unknown_version_is_404_and_an_evicted_one_is_410() {
    let (rig, _) = two_versions(Audit::Logged).await;
    let before = rig.bytes();
    let (status, body) = rig.restore("rv-nobody-recorded", Caller::Root).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::NOT_FOUND, json!("unknown_version"))
    );
    assert_eq!(
        body["message"],
        json!("no kept or recorded config version has that id")
    );
    assert_eq!(rig.bytes(), before);

    // One kept version: the reload evicts the start one, whose event stays.
    let one = Bounds {
        snapshots: 1,
        ..Bounds::default()
    };
    let rig = Rig::start_bounded(&older(), Audit::Logged, one).await;
    let gone = rig.version_of(older().as_bytes());
    rig.reload_to(&current()).await;
    let before = rig.bytes();
    let (status, body) = rig.restore(&gone, Caller::Root).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::GONE, json!("no_longer_kept"))
    );
    assert_eq!(
        body["message"],
        json!("that config version is no longer kept, so it cannot be restored")
    );
    assert_eq!(rig.bytes(), before);
}

#[tokio::test]
async fn r5_an_audited_restore_appends_a_restore_intent_before_it_commits() {
    let (rig, old) = two_versions(Audit::Logged).await;
    rig.steps();
    let (status, body) = rig.restore(&old, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let lines = rig.audit_lines();
    let count = |kind: &str| lines.iter().filter(|line| line.contains(kind)).count();
    assert_eq!(count("config_restore_intent"), 1, "{lines:?}");
    assert_eq!(count("config_save_intent"), 0, "{lines:?}");
    let steps = rig.steps();
    let at = |step: &str| steps.iter().position(|s| *s == step);
    assert!(
        matches!((at("intent"), at("commit")), (Some(i), Some(c)) if i < c),
        "{steps:?}"
    );
}

#[tokio::test]
async fn r6_a_refused_intent_append_refuses_the_restore_with_the_file_untouched() {
    let (rig, old) = two_versions(Audit::Logged).await;
    let before = rig.bytes();
    let events = rig.store.events().len();
    rig.steps();
    rig.state
        .transparency_log
        .as_ref()
        .expect("an audit log")
        .fail_next_append_for_test();
    let (status, body) = rig.restore(&old, Caller::Root).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::INTERNAL_SERVER_ERROR, json!(NOT_WRITTEN))
    );
    let steps = rig.steps();
    assert!(steps.is_empty(), "the writer went on: {steps:?}");
    assert_eq!(rig.bytes(), before);
    assert!(rig.rejected().is_empty());
    assert_eq!(rig.store.events().len(), events);
}

#[tokio::test]
async fn r7_auth_on_without_an_audit_log_refuses_the_restore() {
    let (rig, old) = two_versions(Audit::Unlogged).await;
    let before = rig.bytes();
    let (status, body) = rig.restore(&old, Caller::Root).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["error"], json!("audit_log_required"));
    assert_eq!(body["message"], json!(crate::config_reload::NO_AUDIT_LOG));
    assert_eq!(rig.bytes(), before);
    assert!(rig.rejected().is_empty());
}

#[tokio::test]
async fn r8_a_held_config_lock_makes_the_restore_busy_until_it_is_released() {
    let (rig, old) = two_versions(Audit::Logged).await;
    let before = rig.bytes();
    let held = crate::config_persistence::lock::lock_config(
        &rig.path(),
        Instant::now() + Duration::from_secs(30),
    )
    .await
    .expect("the row holds the config lock");
    let (status, body) = rig.restore(&old, Caller::Root).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::SERVICE_UNAVAILABLE, json!(BUSY))
    );
    assert_eq!(rig.bytes(), before);
    drop(held);
    let (status, body) = rig.restore(&old, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn r8b_a_held_reload_lock_makes_the_restore_busy_until_it_is_released() {
    let (rig, old) = two_versions(Audit::Logged).await;
    let before = rig.bytes();
    let held = rig.state.backends.lock_reload().await;
    let (status, body) = rig.restore(&old, Caller::Root).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::SERVICE_UNAVAILABLE, json!(BUSY))
    );
    assert_eq!(rig.bytes(), before);
    drop(held);
    let (status, body) = rig.restore(&old, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn r9_a_kept_version_the_loader_now_refuses_leaves_the_file_as_it_was() {
    let (rig, _) = two_versions(Audit::Logged).await;
    let served = rig.version_of(current().as_bytes());
    // The one defect: a kept version whose gateway.yaml is not a config.
    let broken = "rv-no-longer-loads";
    let file = StoredFile {
        path: rig.path().display().to_string(),
        bytes: Some(b"backends: [this is not a map\n".to_vec()),
    };
    let kept = Snapshot {
        files: vec![file],
        source: Source::File,
        pending_restart: vec![],
        at: 7,
        revision: broken.into(),
    };
    let named = Event {
        revision: Some(broken.into()),
        outcome: Outcome::Applied,
        source: Source::File,
        at: 7,
        attempted_diff: None,
        location: None,
        still_running: None,
        unchanged: false,
    };
    rig.store.record(named, Some(kept), &served, 7);
    let before = rig.bytes();
    let (status, body) = rig.restore(broken, Caller::Root).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::INTERNAL_SERVER_ERROR, json!(NOT_WRITTEN))
    );
    assert_eq!(rig.bytes(), before);
    assert!(rig.rejected().is_empty(), "{:?}", rig.rejected());
}

#[tokio::test]
async fn r10_a_restart_only_difference_is_listed_as_restart_required() {
    let rig = Rig::start(&current(), Audit::Logged).await;
    let ported = config_text("environment: \"current\"\nserver:\n  port: 39421\n");
    rig.reload_to(&ported).await;
    let with_port = rig.version_of(ported.as_bytes());
    rig.reload_to(&current()).await;
    let (status, body) = rig.restore(&with_port, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["restart_required"], json!(["server"]));
}

/// What a refused CLI caller must leave behind: the file, no kept copy, no
/// writer step, no new history event.
fn untouched(rig: &Rig, before: &[u8], events: usize) {
    assert_eq!(rig.bytes(), before);
    assert!(rig.rejected().is_empty(), "{:?}", rig.rejected());
    assert!(rig.steps().is_empty());
    assert_eq!(rig.store.events().len(), events);
}

#[tokio::test]
async fn r12_a_cli_key_or_its_session_cannot_restore() {
    let (rig, old) = two_versions(Audit::Logged).await;
    let session = rig.cli_session().await;
    let before = rig.bytes();
    let events = rig.store.events().len();
    rig.steps();
    for caller in [Caller::Cli, Caller::Session(&session)] {
        let (status, body) = rig.restore(&old, caller).await;
        assert_eq!(
            (status, body),
            (StatusCode::FORBIDDEN, json!({ "error": FORBIDDEN }))
        );
        untouched(&rig, &before, events);
    }
    // Control: the same version restores for root, so the rows reach the rule.
    let (status, body) = rig.restore(&old, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[cfg(unix)]
#[tokio::test]
async fn r12_the_cli_refusal_comes_before_the_read_and_the_locks() {
    let (rig, old) = two_versions(Audit::Logged).await;
    let session = rig.cli_session().await;
    let before = rig.bytes();
    let events = rig.store.events().len();
    rig.steps();
    // (a) Any read of the history now fails; a CLI caller still gets 403.
    let file = rig.store.file();
    let moved = rig.dir.path().join("history-moved.json");
    std::fs::rename(&file, &moved).expect("move the history aside");
    std::os::unix::fs::symlink(&moved, &file).expect("link it back");
    for caller in [Caller::Cli, Caller::Session(&session)] {
        let (status, body) = rig.restore(&old, caller).await;
        assert_eq!(
            (status, body),
            (StatusCode::FORBIDDEN, json!({ "error": FORBIDDEN }))
        );
    }
    std::fs::remove_file(&file).expect("drop the link");
    std::fs::rename(&moved, &file).expect("put the history back");
    // (b) Both locks of the pair held: a CLI caller still gets 403, not busy.
    let reload = rig.state.backends.lock_reload().await;
    let config = crate::config_persistence::lock::lock_config(
        &rig.path(),
        Instant::now() + Duration::from_secs(30),
    )
    .await
    .expect("the row holds the config lock");
    for caller in [Caller::Cli, Caller::Session(&session)] {
        let (status, body) = rig.restore(&old, caller).await;
        assert_eq!(
            (status, body),
            (StatusCode::FORBIDDEN, json!({ "error": FORBIDDEN }))
        );
    }
    drop((config, reload));
    untouched(&rig, &before, events);
}

#[cfg(unix)]
#[tokio::test]
async fn g4b_a_history_that_cannot_be_read_refuses_a_restore_with_the_read_answer() {
    let (rig, old) = two_versions(Audit::Logged).await;
    let before = rig.bytes();
    let file = rig.store.file();
    let moved = rig.dir.path().join("history-moved.json");
    std::fs::rename(&file, &moved).expect("move the history aside");
    std::os::unix::fs::symlink(&moved, &file).expect("link it back");
    let (status, body) = rig.restore(&old, Caller::Root).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::SERVICE_UNAVAILABLE, json!("history_unreadable"))
    );
    assert_eq!(
        body["message"],
        json!("the config history could not be read; nothing was changed")
    );
    assert_eq!(rig.bytes(), before);
    assert!(rig.rejected().is_empty());

    // The same answer for a history file cut short.
    std::fs::remove_file(&file).expect("drop the link");
    crate::gateway::test_helpers::write_owner_only(&file, b"{\"snapshots\": [{\"rev")
        .expect("cut the history short");
    let (status, body) = rig.restore(&old, Caller::Root).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::SERVICE_UNAVAILABLE, json!("history_unreadable"))
    );
    assert_eq!(
        body["message"],
        json!("the config history could not be read; nothing was changed")
    );
    assert_eq!(rig.bytes(), before);
    assert!(rig.rejected().is_empty());
}
