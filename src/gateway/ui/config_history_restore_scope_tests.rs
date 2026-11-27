// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a restore covers: restoring the served version is a no-op unless
//! the file moved on without a reload, env files and grants are never
//! written, and `not_restored` names each one that differs from the served
//! version, by the paths the store recorded.

use axum::http::StatusCode;
use serde_json::json;

use super::support_tests::{Audit, Caller, History, Rig, config_text, env_files, put};
use crate::config_reload::history::{Bounds, Event, Outcome, Source, StoredFile};

#[tokio::test]
async fn r2_restoring_the_served_version_writes_nothing_but_still_appends_its_intent() {
    let rig = Rig::start(&config_text("environment: \"a\"\n"), Audit::Logged).await;
    rig.reload_to(&config_text("environment: \"b\"\n")).await;
    let served = rig.served();
    let before = rig.bytes();
    rig.steps();
    let (status, body) = rig.restore(&served, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["changed"], json!(false));
    assert!(
        body.get("revision").is_none() && body.get("kept_beside").is_none(),
        "{body}"
    );
    assert!(rig.rejected().is_empty());
    assert_eq!(rig.bytes(), before);
    let steps = rig.steps();
    assert!(
        steps.contains(&"intent") && !steps.contains(&"commit"),
        "{steps:?}"
    );
}

#[tokio::test]
async fn r2b_restoring_the_served_version_over_an_unrecorded_edit_writes_it_back() {
    let second = config_text("environment: \"b\"\n");
    let rig = Rig::start(&config_text("environment: \"a\"\n"), Audit::Logged).await;
    rig.reload_to(&second).await;
    let served = rig.served();
    let unseen = config_text("environment: \"c, never reloaded\"\n");
    rig.write(&unseen);
    let (status, body) = rig.restore(&served, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["changed"], json!(true));
    assert_eq!(rig.bytes(), second.into_bytes());
    let beside = rig.rejected();
    assert_eq!(beside.len(), 1, "{beside:?}");
    assert_eq!(
        std::fs::read(&beside[0]).expect("the kept copy"),
        unseen.into_bytes()
    );
    let name = beside[0]
        .file_name()
        .and_then(|n| n.to_str())
        .expect("a name");
    assert_eq!(body["kept_beside"], json!(name));
}

#[tokio::test]
async fn r4_an_env_file_that_differs_is_listed_and_neither_env_file_is_written() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let changed = put(&dir, "changed.env", b"X=1\n");
    let same = put(&dir, "same.env", b"Y=kept\n");
    let both = env_files(&[&changed, &same]);
    let first = config_text(&format!("environment: \"a\"\n{both}"));
    let rig = Rig::start_in(dir, &first, Audit::Logged, Bounds::default(), History::Kept).await;
    let a = rig.version_of(first.as_bytes());
    put(&rig.dir, "changed.env", b"X=2\n");
    rig.reload_to(&config_text(&format!("environment: \"b\"\n{both}")))
        .await;
    let recorded = rig.env_paths(&a);
    let (status, body) = rig.restore(&a, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(std::fs::read(&changed).expect("X"), b"X=2\n");
    assert_eq!(std::fs::read(&same).expect("Y"), b"Y=kept\n");
    assert_eq!(
        body["not_restored"],
        json!([{"path": recorded[0], "kind": "env_file"}, {"kind": "grants"}])
    );
}

#[tokio::test]
async fn r4b_with_every_env_file_equal_only_the_grants_entry_is_listed() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let env = put(&dir, "app.env", b"K=same\n");
    let first = config_text(&format!("environment: \"a\"\n{}", env_files(&[&env])));
    let rig = Rig::start_in(dir, &first, Audit::Logged, Bounds::default(), History::Kept).await;
    let a = rig.version_of(first.as_bytes());
    rig.reload_to(&config_text(&format!(
        "environment: \"b\"\n{}",
        env_files(&[&env])
    )))
    .await;
    let (status, body) = rig.restore(&a, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["not_restored"], json!([{"kind": "grants"}]));
}

#[tokio::test]
async fn r4c_env_files_on_one_side_only_are_both_listed() {
    // A change to env_files waits for a restart, so a reload keeps the
    // running set: a version listing other env files comes from another
    // run. That version is recorded straight into the store here, beside a
    // gateway serving with env file Q.
    let dir = crate::test_dir_keep::kept_tempdir();
    let only_old = put(&dir, "old-only.env", b"P=1\n");
    let only_new = put(&dir, "new-only.env", b"Q=1\n");
    let serving = config_text(&format!("environment: \"b\"\n{}", env_files(&[&only_new])));
    let rig = Rig::start_in(
        dir,
        &serving,
        Audit::Logged,
        Bounds::default(),
        History::Kept,
    )
    .await;
    let served = rig.served();
    let q = rig.env_paths(&served);
    let other_run = config_text(&format!("environment: \"a\"\n{}", env_files(&[&only_old])));
    let p = only_old.display().to_string();
    let mut earlier = rig.kept(&served);
    earlier.revision = "rv-another-run".into();
    earlier.files = vec![
        StoredFile {
            path: rig.path().display().to_string(),
            bytes: Some(other_run.into_bytes()),
        },
        StoredFile {
            path: p.clone(),
            bytes: Some(b"P=1\n".to_vec()),
        },
    ];
    let named = Event {
        revision: Some(earlier.revision.clone()),
        source: Source::File,
        outcome: Outcome::Applied,
        at: earlier.at,
        unchanged: false,
        location: None,
        still_running: None,
        attempted_diff: None,
    };
    rig.store
        .record(named, Some(earlier.clone()), &served, earlier.at);
    assert_eq!(
        q.len(),
        1,
        "the premise: the served version lists Q alone: {q:?}"
    );
    let (status, body) = rig.restore(&earlier.revision, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["not_restored"],
        json!([
            {"path": p, "kind": "env_file"},
            {"path": q[0], "kind": "env_file"},
            {"kind": "grants"}
        ])
    );
}
