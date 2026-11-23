// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Diff route rows: a kept version against the one kept before it, every
//! file masked, change judged on stored bytes, errors as the history route
//! answers them. Versions are recorded straight into the rig's store, so
//! each row chooses its own bytes and times.

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::support_tests::{Audit, Caller, Rig, config_text};
use super::{NOTE_UNSHOWN, WITHHELD_LARGE, WITHHELD_UNSAFE};
use crate::config_reload::history::{Event, Outcome, Snapshot, Source, StoredFile};

fn sentinel(n: usize) -> String {
    format!("QZ7XJ9WK{n}V")
}

/// No 3-byte window of `secret` appears anywhere in `shown`.
fn assert_no_part(shown: &str, secret: &str) {
    for part in secret.as_bytes().windows(3) {
        assert!(
            !shown.as_bytes().windows(3).any(|w| w == part),
            "{:?} of a secret shows in {shown:?}",
            String::from_utf8_lossy(part)
        );
    }
}

fn applied(revision: &str, at: u64) -> Event {
    Event {
        revision: Some(revision.into()),
        source: Source::File,
        outcome: Outcome::Applied,
        at,
        unchanged: false,
        location: None,
        still_running: None,
        attempted_diff: None,
    }
}

fn env_path(rig: &Rig, name: &str) -> String {
    rig.dir.path().join(name).display().to_string()
}

/// A time after the rig's start version.
fn after_start(rig: &Rig, step: u64) -> u64 {
    rig.kept(&rig.served()).at + 100 + step
}

/// Record a kept version holding `yaml` as gateway.yaml and each named env
/// file's text.
fn keep(rig: &Rig, revision: &str, at: u64, yaml: &str, env: &[(&str, &str)]) {
    let mut files = vec![StoredFile {
        path: rig.path().display().to_string(),
        bytes: Some(yaml.as_bytes().to_vec()),
    }];
    files.extend(env.iter().map(|(name, text)| StoredFile {
        path: env_path(rig, name),
        bytes: Some(text.as_bytes().to_vec()),
    }));
    let snapshot = Snapshot {
        revision: revision.into(),
        at,
        source: Source::File,
        files,
        pending_restart: Vec::new(),
    };
    rig.store
        .record(applied(revision, at), Some(snapshot), revision, at);
}

async fn diff_of(rig: &Rig, revision: &str, caller: Caller<'_>) -> (StatusCode, Value) {
    rig.send(
        "GET",
        &format!("/ui/api/config/history/{revision}/diff"),
        None,
        caller,
    )
    .await
}

/// The entry for `path` in an answer's files.
fn file<'a>(body: &'a Value, path: &str) -> &'a Value {
    body["files"]
        .as_array()
        .expect("files")
        .iter()
        .find(|entry| entry["path"] == json!(path))
        .unwrap_or_else(|| panic!("no entry for {path} in {body}"))
}

/// The answer's gateway.yaml entry.
fn yaml_entry<'a>(rig: &Rig, body: &'a Value) -> &'a Value {
    file(body, &rig.path().display().to_string())
}

const TEN: &str = "server:\n  port: 1\na: 1\nb: 2\nc: 3\nd: 4\ne: 5\nf: 6\ng: 7\nh: 8\ni: 9\n";

#[tokio::test]
async fn d1_the_diff_of_a_version_is_against_the_one_before() {
    let rig = Rig::start(&config_text("environment: \"a\"\n"), Audit::Unlogged).await;
    let start = rig.served();
    let second = TEN
        .replace("a: 1\n", "a: 10\n")
        .replace("i: 9\n", "i: 90\n");
    let third = second.replace("port: 1\n", "port: 2\n");
    keep(&rig, "rv-one", after_start(&rig, 1), TEN, &[]);
    keep(&rig, "rv-two", after_start(&rig, 2), &second, &[]);
    keep(&rig, "rv-three", after_start(&rig, 3), &third, &[]);

    let (status, body) = diff_of(&rig, "rv-one", Caller::Root).await;
    assert_eq!((status, &body["against"]), (StatusCode::OK, &json!(start)));

    let (_, body) = diff_of(&rig, "rv-two", Caller::Root).await;
    assert_eq!(body["revision"], json!("rv-two"));
    assert_eq!(body["against"], json!("rv-one"));
    let entry = yaml_entry(&rig, &body);
    assert_eq!(
        (&entry["kind"], &entry["change"]),
        (&json!("gateway_yaml"), &json!("changed"))
    );
    // Two changes eight lines apart: two hunks, three lines of context each.
    assert_eq!(
        entry["diff"],
        json!(concat!(
            "@@ -1,5 +1,5 @@\n",
            " server.port: 1\n",
            "+a: 10\n",
            "-a: 1\n",
            " b: 2\n",
            " c: 3\n",
            " d: 4\n",
            "@@ -7,4 +7,4 @@\n",
            " f: 6\n",
            " g: 7\n",
            " h: 8\n",
            "+i: 90\n",
            "-i: 9\n",
        ))
    );
    assert_eq!(
        (&entry["withheld"], &entry["note"]),
        (&Value::Null, &Value::Null)
    );

    let (_, body) = diff_of(&rig, "rv-three", Caller::Root).await;
    assert_eq!(body["against"], json!("rv-two"));
    assert_eq!(
        yaml_entry(&rig, &body)["diff"],
        json!("@@ -1,4 +1,4 @@\n+server.port: 2\n-server.port: 1\n a: 10\n b: 2\n c: 3\n")
    );

    // One id kept twice, and equal times: the newest copy is compared with
    // the entry kept just before it in store order, never with its own
    // earlier copy.
    let at = after_start(&rig, 10);
    keep(&rig, "rv-w", at, "k: w\n", &[]);
    keep(&rig, "rv-x", at, "k: x\n", &[]);
    keep(&rig, "rv-w", at, "k: w\n", &[]);
    let (_, body) = diff_of(&rig, "rv-w", Caller::Root).await;
    assert_eq!(body["against"], json!("rv-x"));
    assert_eq!(
        yaml_entry(&rig, &body)["diff"],
        json!("@@ -1,1 +1,1 @@\n+k: w\n-k: x\n")
    );
    let (_, body) = diff_of(&rig, "rv-x", Caller::Root).await;
    assert_eq!(body["against"], json!("rv-w"));
}

#[tokio::test]
async fn d2_the_oldest_version_reads_added() {
    let rig = Rig::start(&config_text("environment: \"a\"\n"), Audit::Unlogged).await;
    let (status, body) = diff_of(&rig, &rig.served(), Caller::Root).await;
    assert_eq!((status, &body["against"]), (StatusCode::OK, &Value::Null));
    let entry = yaml_entry(&rig, &body);
    assert_eq!(entry["change"], json!("added"));
    let diff = entry["diff"].as_str().expect("a diff");
    let mut lines = diff.lines();
    let header = lines.next().expect("a hunk header");
    assert!(header.starts_with("@@ -0,0 +1,"), "{header}");
    assert!(lines.all(|line| line.starts_with('+')), "{diff}");
    assert!(diff.contains("+environment: a\n"), "{diff}");
}

#[tokio::test]
async fn d3_env_file_added_removed_changed() {
    let rig = Rig::start(&config_text("environment: \"a\"\n"), Audit::Unlogged).await;
    keep(
        &rig,
        "rv-env-1",
        after_start(&rig, 1),
        "a: 1\n",
        &[("a.env", "A=@1\n"), ("b.env", "B=x\n")],
    );
    keep(
        &rig,
        "rv-env-2",
        after_start(&rig, 2),
        "a: 1\n",
        &[("a.env", "A=@2\n"), ("c.env", "C=y\n")],
    );
    let (status, body) = diff_of(&rig, "rv-env-2", Caller::Root).await;
    assert_eq!(status, StatusCode::OK);
    let paths: Vec<&str> = body["files"]
        .as_array()
        .expect("files")
        .iter()
        .map(|entry| entry["path"].as_str().expect("a path"))
        .collect();
    let (a, b, c) = (
        env_path(&rig, "a.env"),
        env_path(&rig, "b.env"),
        env_path(&rig, "c.env"),
    );
    let config = rig.path().display().to_string();
    assert_eq!(paths, [config.as_str(), a.as_str(), c.as_str(), b.as_str()]);
    let expect = [
        (config.as_str(), "gateway_yaml", "same", ""),
        (
            a.as_str(),
            "env_file",
            "changed",
            "@@ -1,1 +1,1 @@\n+A=<set> (changed)\n-A=<set>\n",
        ),
        (
            c.as_str(),
            "env_file",
            "added",
            "@@ -0,0 +1,1 @@\n+C=<set>\n",
        ),
        (
            b.as_str(),
            "env_file",
            "removed",
            "@@ -1,1 +0,0 @@\n-B=<set>\n",
        ),
    ];
    for (path, kind, change, diff) in expect {
        let entry = file(&body, path);
        assert_eq!(
            (&entry["kind"], &entry["change"], &entry["diff"]),
            (&json!(kind), &json!(change), &json!(diff)),
            "{path}"
        );
    }
}

#[tokio::test]
async fn d4_unknown_evicted_and_unreadable_answer_as_the_history_route_does() {
    let rig = Rig::start(&config_text("environment: \"a\"\n"), Audit::Unlogged).await;
    let (status, body) = diff_of(&rig, "rv-never-seen", Caller::Root).await;
    assert_eq!(
        (status, &body["error"]),
        (StatusCode::NOT_FOUND, &json!("unknown_version"))
    );

    let at = after_start(&rig, 1);
    rig.store
        .record(applied("rv-gone", at), None, &rig.served(), at);
    let (status, body) = diff_of(&rig, "rv-gone", Caller::Root).await;
    assert_eq!(
        (status, &body["error"]),
        (StatusCode::GONE, &json!("no_longer_kept"))
    );

    crate::gateway::test_helpers::write_owner_only(rig.store.file(), b"{\"events\": [{\"at\"")
        .expect("cut the history short");
    let (status, body) = diff_of(&rig, &rig.served(), Caller::Root).await;
    assert_eq!(
        (status, &body["error"]),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            &json!("history_unreadable")
        )
    );
}

#[tokio::test]
async fn d5_a_file_the_masker_withholds_is_served_as_the_fixed_sentence() {
    let rig = Rig::start(&config_text("environment: \"a\"\n"), Audit::Unlogged).await;
    keep(&rig, "rv-plain", after_start(&rig, 1), "a: 1\n", &[]);
    let aliased = format!(
        "plain: &v {}\nbackends:\n  x:\n    env:\n      A: *v\n",
        sentinel(1)
    );
    keep(&rig, "rv-aliased", after_start(&rig, 2), &aliased, &[]);
    keep(
        &rig,
        "rv-broken",
        after_start(&rig, 3),
        &format!("a: [{}\n", sentinel(2)),
        &[],
    );
    for revision in ["rv-aliased", "rv-broken"] {
        let (status, body) = diff_of(&rig, revision, Caller::Root).await;
        assert_eq!(status, StatusCode::OK, "{revision}");
        let entry = yaml_entry(&rig, &body);
        assert_eq!(
            (&entry["diff"], &entry["withheld"]),
            (&Value::Null, &json!(WITHHELD_UNSAFE)),
            "{revision}"
        );
        assert_eq!(entry["change"], json!("changed"), "{revision}");
        for n in 1..=2 {
            assert_no_part(&body.to_string(), &sentinel(n));
        }
    }
}

#[tokio::test]
async fn d6_a_change_past_the_cap_is_not_served() {
    let rig = Rig::start(&config_text("environment: \"a\"\n"), Audit::Unlogged).await;
    keep(&rig, "rv-small", after_start(&rig, 1), "a: 1\n", &[]);
    let big: String = (0..12_000)
        .map(|n| format!("k{n:05}: vvvvvvvvvvvvvvvvvvvvvvvv\n"))
        .collect();
    keep(&rig, "rv-big", after_start(&rig, 2), &big, &[]);
    let (status, body) = diff_of(&rig, "rv-big", Caller::Root).await;
    assert_eq!(status, StatusCode::OK);
    let entry = yaml_entry(&rig, &body);
    assert_eq!(
        (&entry["diff"], &entry["withheld"]),
        (&Value::Null, &json!(WITHHELD_LARGE))
    );
}

#[tokio::test]
async fn d7_admin_only() {
    let rig = Rig::start(&config_text("environment: \"a\"\n"), Audit::Unlogged).await;
    let served = rig.served();
    assert_eq!(
        diff_of(&rig, &served, Caller::Nobody).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        diff_of(&rig, &served, Caller::Viewer).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(diff_of(&rig, &served, Caller::Root).await.0, StatusCode::OK);
}

#[tokio::test]
async fn d8_the_answer_holds_no_stored_byte() {
    let rig = Rig::start(&config_text("environment: \"a\"\n"), Audit::Unlogged).await;
    let slots = |first: usize| {
        format!(
            "auth:\n  bearer_token: {}\nkey_server:\n  admin_token: {}\nbackends:\n  gh:\n    env:\n      REGION: {}\n",
            sentinel(first),
            sentinel(first + 1),
            sentinel(first + 2)
        )
    };
    let env = |n: usize| format!("TOKEN={}\n", sentinel(n));
    keep(
        &rig,
        "rv-slots-1",
        after_start(&rig, 1),
        &slots(0),
        &[("s.env", &env(6))],
    );
    keep(
        &rig,
        "rv-slots-2",
        after_start(&rig, 2),
        &slots(3),
        &[("s.env", &env(7))],
    );
    let (status, body) = diff_of(&rig, "rv-slots-2", Caller::Root).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        yaml_entry(&rig, &body)["diff"],
        json!(concat!(
            "@@ -1,3 +1,3 @@\n",
            "+auth.bearer_token: <set> (changed)\n",
            "+key_server.admin_token: <set> (changed)\n",
            "+backends.gh.env.REGION: <set> (changed)\n",
            "-auth.bearer_token: <set>\n",
            "-key_server.admin_token: <set>\n",
            "-backends.gh.env.REGION: <set>\n",
        ))
    );
    assert_eq!(
        file(&body, &env_path(&rig, "s.env"))["diff"],
        json!("@@ -1,1 +1,1 @@\n+TOKEN=<set> (changed)\n-TOKEN=<set>\n")
    );
    let whole = body.to_string();
    for n in 0..=7 {
        assert_no_part(&whole, &sentinel(n));
    }
}

#[tokio::test]
async fn d9_a_stored_edit_never_reads_as_no_change() {
    let rig = Rig::start(&config_text("environment: \"a\"\n"), Audit::Unlogged).await;
    let env = [("v.env", "TOKEN=$A_UNSET_9617\n")];
    let one = "s:\n  b: 1 # one\n";
    let two = "s:\n  b: 1 # two\n";
    let indented = "s:\n    b: 1 # two\n";
    keep(&rig, "rv-c1", after_start(&rig, 1), one, &env);
    // A comment edited.
    keep(&rig, "rv-c2", after_start(&rig, 2), two, &env);
    // The same pair re-indented.
    keep(&rig, "rv-c3", after_start(&rig, 3), indented, &env);
    // A variable reference in the env file changed, neither set.
    keep(
        &rig,
        "rv-c4",
        after_start(&rig, 4),
        "s:\n    b: 1 # two\n",
        &[("v.env", "TOKEN=$B_UNSET_9617\n")],
    );
    let env_file = env_path(&rig, "v.env");
    let config = rig.path().display().to_string();
    let unshown = |change: &str| {
        let note = if change == "same" {
            Value::Null
        } else {
            json!(NOTE_UNSHOWN)
        };
        json!({ "change": change, "diff": "", "note": note })
    };
    for (revision, yaml, env) in [
        ("rv-c2", "changed", "same"),
        ("rv-c3", "changed", "same"),
        ("rv-c4", "same", "changed"),
    ] {
        let (status, body) = diff_of(&rig, revision, Caller::Root).await;
        assert_eq!(status, StatusCode::OK, "{revision}");
        for (path, change) in [(&config, yaml), (&env_file, env)] {
            let entry = file(&body, path);
            let seen = json!({
                "change": entry["change"],
                "diff": entry["diff"],
                "note": entry["note"],
            });
            assert_eq!(seen, unshown(change), "{revision} {path}");
        }
    }
}
