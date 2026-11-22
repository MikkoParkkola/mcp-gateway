// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! History rows: the GET answers a projection of the kept versions and the
//! events, newest first, marks the version the gateway serves, never serves
//! a stored byte, and answers a history it cannot read with one fixed 503.

use std::collections::BTreeSet;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::support_tests::{Audit, Caller, History, Rig, config_text, env_files, put};
use crate::config_reload::history::{Bounds, Event, Outcome, Source};

/// The fixed text of the answer to a history that cannot be read.
#[cfg(unix)]
const UNREADABLE: &str = "the config history could not be read; nothing was changed";

/// The revision of each entry of `list`, in order.
fn revisions(list: &Value) -> Vec<String> {
    list.as_array()
        .expect("a list")
        .iter()
        .map(|entry| entry["revision"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// The `running` flag of each version entry, in order.
fn flags(body: &Value) -> Vec<bool> {
    body["versions"]
        .as_array()
        .expect("versions")
        .iter()
        .map(|entry| entry["running"].as_bool().expect("a running flag"))
        .collect()
}

/// An applied event naming `revision`, as a UI save by `who` records it.
fn applied_by(who: &str, revision: &str, at: u64) -> Event {
    Event {
        revision: Some(revision.into()),
        source: Source::Ui { who: who.into() },
        outcome: Outcome::Applied,
        at,
        unchanged: false,
        location: None,
        still_running: None,
        attempted_diff: None,
    }
}

/// A gateway started on version A, reloaded to B (served), then a third
/// version C recorded straight into the store: C is newest, B is served.
async fn served_in_the_middle() -> (Rig, [String; 3]) {
    let first = config_text("environment: \"a\"\n");
    let second = config_text("environment: \"b\"\n");
    let rig = Rig::start(&first, Audit::Logged).await;
    rig.reload_to(&second).await;
    let (a, b) = (rig.version_of(first.as_bytes()), rig.served());
    let mut third = rig.kept(&b);
    third.revision = "rv-third-by-hand".into();
    third.at += 10;
    third.source = Source::Ui {
        who: "someone".into(),
    };
    rig.store.record(
        applied_by("someone", &third.revision, third.at),
        Some(third.clone()),
        &b,
        third.at,
    );
    (rig, [a, b, third.revision])
}

#[tokio::test]
async fn g1_versions_and_events_come_newest_first_and_the_served_one_is_marked() {
    let (rig, [a, b, c]) = served_in_the_middle().await;
    let (status, body) = rig.history(Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        revisions(&body["versions"]),
        [c.clone(), b.clone(), a.clone()]
    );
    assert_eq!(flags(&body), [false, true, false]);
    assert_eq!(body["running"], json!(b));
    let keys: BTreeSet<&str> = body["versions"][0]
        .as_object()
        .expect("an entry")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "at",
            "files",
            "pending_restart",
            "revision",
            "running",
            "source"
        ])
    );
    assert_eq!(
        body["versions"][0]["source"],
        json!({"kind": "ui", "who": "someone"})
    );
    assert_eq!(body["versions"][2]["source"], json!({"kind": "start"}));
    assert_eq!(revisions(&body["events"]), [c, b, a]);
    let outcomes: Vec<&Value> = body["events"]
        .as_array()
        .expect("events")
        .iter()
        .map(|event| &event["outcome"])
        .collect();
    assert_eq!(
        outcomes,
        [&json!("applied"), &json!("applied"), &json!("applied")]
    );
}

#[tokio::test]
async fn g1b_only_the_newest_copy_of_the_served_revision_is_marked() {
    let (rig, [_, b, _]) = served_in_the_middle().await;
    let mut again = rig.kept(&b);
    again.at += 20;
    rig.store.record(
        applied_by("someone", &b, again.at),
        Some(again.clone()),
        &b,
        again.at,
    );
    let (status, body) = rig.history(Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(revisions(&body["versions"])[0], b);
    assert_eq!(flags(&body), [true, false, false, false]);
}

#[tokio::test]
async fn g1c_after_a_hot_reload_the_served_version_is_marked_and_restores_as_a_no_op() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let env = put(&dir, "app.env", b"K=one\n");
    // F is equal in A and B: listing it would mean the wrong baseline.
    let steady = put(&dir, "steady.env", b"S=same\n");
    let first = config_text(&format!(
        "environment: \"a\"\n{}",
        env_files(&[&env, &steady])
    ));
    let second = config_text(&format!(
        "environment: \"b\"\n{}",
        env_files(&[&env, &steady])
    ));
    let rig = Rig::start_in(dir, &first, Audit::Logged, Bounds::default(), History::Kept).await;
    let a = rig.version_of(first.as_bytes());
    let started = rig.state.live_config.running_revision();
    put(&rig.dir, "app.env", b"K=two\n");
    rig.reload_to(&second).await;
    let b = rig.served();
    // The premise: the reload moved the served revision off the startup one.
    assert_eq!(rig.state.live_config.running_revision(), started);
    assert_ne!(started.as_deref(), Some(b.as_str()));
    assert_ne!(a, b);

    let (status, body) = rig.history(Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["running"], json!(b));
    assert_eq!(revisions(&body["versions"]), [b.clone(), a.clone()]);
    assert_eq!(flags(&body), [true, false]);

    // The version marked running restores as a no-op.
    let before = rig.bytes();
    let (status, body) = rig.restore(&b, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["changed"], json!(false));
    assert!(body.get("kept_beside").is_none(), "{body}");
    assert!(rig.rejected().is_empty());
    assert_eq!(rig.bytes(), before);

    // Then A: its env file differs from the served B's, so it is listed.
    let path = rig
        .env_paths(&a)
        .into_iter()
        .next()
        .expect("A recorded its env files, E first");
    let (status, body) = rig.restore(&a, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["not_restored"],
        json!([{"path": path, "kind": "env_file"}, {"kind": "grants"}])
    );
}

/// Every object key anywhere in `value`.
fn all_keys(value: &Value, into: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                into.insert(key.clone());
                all_keys(inner, into);
            }
        }
        Value::Array(items) => items.iter().for_each(|inner| all_keys(inner, into)),
        _ => {}
    }
}

#[tokio::test]
async fn g2_no_stored_byte_reaches_the_history_answer() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let env = put(&dir, "app.env", b"TOKEN=sentinel-env-9902\n");
    let text = format!(
        "# sentinel-yaml-4471\n{}",
        config_text(&format!("environment: \"a\"\n{}", env_files(&[&env])))
    );
    let rig = Rig::start_in(dir, &text, Audit::Logged, Bounds::default(), History::Kept).await;
    let a = rig.version_of(text.as_bytes());
    let (status, body) = rig.history(Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let served = body.to_string();
    assert!(!served.contains("sentinel-env-9902"), "{served}");
    assert!(!served.contains("sentinel-yaml-4471"), "{served}");
    let mut keys = BTreeSet::new();
    all_keys(&body, &mut keys);
    assert!(
        !keys.contains("bytes") && !keys.contains("attempted_diff"),
        "{keys:?}"
    );
    let mut stored: Vec<Value> =
        vec![json!({"path": rig.path().display().to_string(), "present": true})];
    stored.extend(
        rig.env_paths(&a)
            .into_iter()
            .map(|path| json!({"path": path, "present": true})),
    );
    assert_eq!(body["versions"][0]["files"], json!(stored));
}

#[tokio::test]
async fn g3_both_routes_are_for_admins_only() {
    let first = config_text("environment: \"a\"\n");
    let rig = Rig::start(&first, Audit::Logged).await;
    rig.reload_to(&config_text("environment: \"b\"\n")).await;
    let a = rig.version_of(first.as_bytes());
    assert_eq!(
        rig.history(Caller::Nobody).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(rig.history(Caller::Viewer).await.0, StatusCode::FORBIDDEN);
    assert_eq!(rig.history(Caller::Root).await.0, StatusCode::OK);
    assert_eq!(
        rig.restore(&a, Caller::Nobody).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        rig.restore(&a, Caller::Viewer).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(rig.restore(&a, Caller::Root).await.0, StatusCode::OK);
}

#[cfg(unix)]
#[tokio::test]
async fn g4_a_history_that_cannot_be_read_is_one_fixed_503() {
    let rig = Rig::start(&config_text("environment: \"a\"\n"), Audit::Logged).await;
    let file = rig.store.file();
    let moved = rig.dir.path().join("history-moved.json");
    std::fs::rename(&file, &moved).expect("move the history aside");
    std::os::unix::fs::symlink(&moved, &file).expect("link it back");
    let (status, body) = rig.history(Caller::Root).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::SERVICE_UNAVAILABLE, json!("history_unreadable"))
    );
    assert_eq!(body["message"], json!(UNREADABLE));
    let text = body.to_string();
    assert!(!text.contains(&*file.to_string_lossy()), "{text}");
    assert!(!text.contains("symbolic"), "{text}");

    std::fs::remove_file(&file).expect("drop the link");
    crate::gateway::test_helpers::write_owner_only(&file, b"{\"events\": [{\"at\"")
        .expect("cut the history short");
    let (status, body) = rig.history(Caller::Root).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::SERVICE_UNAVAILABLE, json!("history_unreadable"))
    );
    assert_eq!(body["message"], json!(UNREADABLE));
    let text = body.to_string();
    assert!(!text.contains("EOF") && !text.contains("line "), "{text}");
}

#[tokio::test]
async fn g5_a_gateway_with_no_history_answers_the_no_config_file_answer() {
    let dir = crate::test_dir_keep::kept_tempdir();
    let rig = Rig::start_in(
        dir,
        &config_text("environment: \"a\"\n"),
        Audit::Logged,
        Bounds::default(),
        History::Absent,
    )
    .await;
    let (status, body) = rig.history(Caller::Root).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::CONFLICT, json!("no_config_file"))
    );
    let (status, body) = rig.restore("rv-any", Caller::Root).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::CONFLICT, json!("no_config_file"))
    );
}
