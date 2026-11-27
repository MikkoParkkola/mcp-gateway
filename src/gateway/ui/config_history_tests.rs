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

/// The gateway G1d to G1f share, and its versions.
struct GrantsAfterB {
    rig: Rig,
    version_a: String,
    version_b: String,
    text_b: String,
}

/// The publish that moves the published revision with no version stored.
#[derive(Clone, Copy)]
enum PartOnly {
    Grants,
    Capabilities,
}

/// Started on A with env files E (edited before B) and F (equal in both),
/// reloaded to B, then a grants publish, so the published revision names no
/// kept version. `bounds` are the store's; `part` picks the part-only
/// publish (a grants save unless the row says otherwise).
async fn grants_after_b(bounds: Bounds, part: PartOnly) -> GrantsAfterB {
    let home = crate::test_dir_keep::kept_tempdir();
    let edited = put(&home, "edited.env", b"E=before\n");
    // Equal in A and B: it shows up only when no baseline was found.
    let same = put(&home, "same.env", b"F=kept\n");
    let listed = env_files(&[&edited, &same]);
    let text_a = config_text(&format!("environment: \"a\"\n{listed}"));
    let text_b = config_text(&format!("environment: \"b\"\n{listed}"));
    let rig = Rig::start_in(home, &text_a, Audit::Logged, bounds, History::Kept).await;
    let version_a = rig.version_of(text_a.as_bytes());
    put(&rig.dir, "edited.env", b"E=after\n");
    rig.reload_to(&text_b).await;
    let version_b = rig.served();
    // A part-only publish: a new revision over the same files, and no
    // record handed to the history.
    match part {
        PartOnly::Grants => rig
            .state
            .live_config
            .set_grants(Some(b"grants changed by a save\n")),
        PartOnly::Capabilities => rig.state.live_config.set_capabilities(
            1,
            crate::config_reload::revision::CapabilityPart::Loaded(vec![(
                "caps/scanned.yaml".to_owned(),
                [0x5c; 32],
            )]),
        ),
    }
    let published = rig.served();
    assert_ne!(
        published, version_b,
        "premise: the published revision moved"
    );
    assert!(
        rig.store
            .snapshots()
            .iter()
            .all(|kept| kept.revision != published),
        "premise: no kept version carries the published revision"
    );
    GrantsAfterB {
        rig,
        version_a,
        version_b,
        text_b,
    }
}

#[tokio::test]
async fn g1d_a_grants_publish_leaves_the_served_version_marked() {
    let GrantsAfterB {
        rig,
        version_a,
        version_b,
        ..
    } = grants_after_b(Bounds::default(), PartOnly::Grants).await;
    let (status, listing) = rig.history(Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    assert_eq!(listing["running"], json!(version_b));
    assert_eq!(
        revisions(&listing["versions"]),
        [version_b.clone(), version_a.clone()]
    );
    assert_eq!(flags(&listing), [true, false]);
    let edited_path = rig
        .env_paths(&version_a)
        .into_iter()
        .next()
        .expect("A's first env file is the edited one");
    let (status, answer) = rig.restore(&version_a, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        answer["not_restored"],
        json!([{"path": edited_path, "kind": "env_file"}, {"kind": "grants"}])
    );
}

#[tokio::test]
async fn g1d_plus_an_unchanged_reload_after_the_grants_publish_keeps_b_marked() {
    let GrantsAfterB {
        rig,
        version_a,
        version_b,
        text_b,
    } = grants_after_b(Bounds::default(), PartOnly::Grants).await;
    // The one change: a reload that finds every file as it was.
    rig.reload_to(&text_b).await;
    let (status, listing) = rig.history(Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{listing}");
    // An event only, no new version (C11), and B is still the one marked.
    assert_eq!(
        (
            &listing["events"][0]["outcome"],
            &listing["events"][0]["unchanged"]
        ),
        (&json!("applied"), &json!(true))
    );
    assert_eq!(
        revisions(&listing["versions"]),
        [version_b.clone(), version_a.clone()]
    );
    assert_eq!(listing["running"], json!(version_b));
    assert_eq!(flags(&listing), [true, false]);
    let edited = rig
        .env_paths(&version_a)
        .into_iter()
        .next()
        .expect("A lists the edited env file first");
    let (status, answer) = rig.restore(&version_a, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(
        answer["not_restored"],
        json!([{"path": edited, "kind": "env_file"}, {"kind": "grants"}])
    );
}

#[tokio::test]
async fn g1d_cap_a_capability_publish_then_an_unchanged_reload_keeps_b_marked() {
    let setup = grants_after_b(Bounds::default(), PartOnly::Capabilities).await;
    setup.rig.reload_to(&setup.text_b).await;
    let (status, page) = setup.rig.history(Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{page}");
    let expected = [setup.version_b.clone(), setup.version_a.clone()];
    assert_eq!(revisions(&page["versions"]), expected, "no version stored");
    assert_eq!(page["running"], json!(setup.version_b));
    assert_eq!(flags(&page), [true, false]);
    let first_env = setup.rig.env_paths(&setup.version_a)[0].clone();
    let (status, reply) = setup.rig.restore(&setup.version_a, Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        reply["not_restored"],
        json!([{"path": first_env, "kind": "env_file"}, {"kind": "grants"}])
    );
}

/// The revisions the store keeps, oldest first.
fn kept_revisions(rig: &Rig) -> Vec<String> {
    rig.store
        .snapshots()
        .into_iter()
        .map(|kept| kept.revision)
        .collect()
}

#[tokio::test]
async fn g1e_a_refusal_after_the_grants_publish_keeps_b_pinned() {
    let bounds = Bounds {
        max_age_secs: 100,
        ..Bounds::default()
    };
    let GrantsAfterB { rig, version_b, .. } = grants_after_b(bounds, PartOnly::Grants).await;
    let hook = rig
        .state
        .live_config
        .history_hook()
        .expect("a history hook");
    let refusal = rig
        .state
        .live_config
        .refused_record(Source::File, Some(3))
        .expect("a refusal record");
    // Saved well past both versions' age limit.
    let late = crate::clock::unix_secs().expect("the clock reads") + 1_000;
    hook.run(refusal, late);
    // A ages out (the age rule ran); B stays, pinned by the refusal.
    assert_eq!(kept_revisions(&rig), std::slice::from_ref(&version_b));
    let still = rig
        .store
        .events()
        .pop()
        .and_then(|event| event.still_running)
        .expect("the refusal names the version still served");
    assert_eq!(still.revision, version_b);
    assert_eq!(still.since, rig.kept(&version_b).at);
}

#[tokio::test]
async fn g1f_an_unchanged_record_after_the_grants_publish_keeps_b_pinned() {
    let bounds = Bounds {
        max_age_secs: 0,
        ..Bounds::default()
    };
    let GrantsAfterB {
        rig,
        version_b,
        text_b,
        ..
    } = grants_after_b(bounds, PartOnly::Grants).await;
    // Records carry whole seconds. Wait (bounded) until the clock's second
    // passes B's stamp, so A and B are both past a 0 s age when the next
    // record is saved. Nothing else waits on this.
    let stamped = rig.kept(&version_b).at;
    let give_up = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while crate::clock::unix_secs().expect("the clock reads") <= stamped {
        assert!(
            std::time::Instant::now() < give_up,
            "the clock did not pass B's stamp"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    rig.reload_to(&text_b).await;
    // A ages out; B stays, pinned by the unchanged reload's record.
    assert_eq!(kept_revisions(&rig), [version_b]);
}

#[tokio::test]
async fn g1g_a_restart_on_the_served_files_then_an_aged_refusal_keeps_them() {
    let bounds = Bounds {
        max_age_secs: 100,
        ..Bounds::default()
    };
    let GrantsAfterB {
        rig,
        version_b,
        text_b,
        ..
    } = grants_after_b(bounds, PartOnly::Grants).await;
    let before = kept_revisions(&rig);
    // A new process starts on B's files over the same history directory.
    // No audit log: the first gateway still holds its lease (Windows refuses
    // a second holder), and nothing here writes through the audited writer.
    let restarted = Rig::start_in(
        std::sync::Arc::clone(&rig.dir),
        &text_b,
        Audit::Unlogged,
        bounds,
        History::Kept,
    )
    .await;
    assert_eq!(
        kept_revisions(&restarted),
        before,
        "premise: the restart's start record stores no second copy of B"
    );
    let refusal = restarted
        .state
        .live_config
        .refused_record(Source::File, Some(3))
        .expect("a refusal record");
    let late = crate::clock::unix_secs().expect("the clock reads") + 1_000;
    restarted
        .state
        .live_config
        .history_hook()
        .expect("a history hook")
        .run(refusal, late);
    // A ages out; B, what the restarted process serves, stays pinned.
    assert_eq!(kept_revisions(&restarted), std::slice::from_ref(&version_b));
    // And the refusal dates B from its first stored copy, not the restart.
    let named = restarted
        .store
        .events()
        .pop()
        .and_then(|event| event.still_running)
        .expect("the refusal names what still runs");
    assert_eq!(
        (named.revision, named.since),
        (version_b.clone(), restarted.kept(&version_b).at)
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
    // An event holding a diff with a secret in it, as a store may hold one.
    let at = crate::clock::unix_secs().expect("the clock reads");
    rig.store.record(
        Event {
            at,
            source: Source::File,
            outcome: Outcome::Refused,
            revision: None,
            unchanged: false,
            still_running: None,
            location: Some(7),
            attempted_diff: Some("+TOKEN=sentinel-diff-6618\n".into()),
        },
        None,
        &a,
        at,
    );
    let (status, body) = rig.history(Caller::Root).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // The premise: the answer lists that event.
    assert_eq!(body["events"][0]["location"], json!(7), "{body}");
    let served = body.to_string();
    assert!(!served.contains("sentinel-env-9902"), "{served}");
    assert!(!served.contains("sentinel-yaml-4471"), "{served}");
    assert!(!served.contains("sentinel-diff-6618"), "{served}");
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
