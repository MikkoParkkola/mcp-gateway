// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Overview rows O5, split from the overview tests: the newest admin actions,
//! read from the transparency log. A child of the overview tests, so it
//! shares their fixture, request and log helpers.

use super::*;

fn admin_action(log: &TransparencyLogger, route: &str) {
    let mut fields = Map::new();
    fields.insert("route".into(), route.into());
    fields.insert("method".into(), "POST".into());
    let envelope = AuditEnvelope::ok(AuditWho::from_actor_id("operator"));
    log.append_admin_action("admin_ui", fields, &envelope)
        .expect("admin action appended");
}

/// O5c: the log rotates between two windows of one read. Every window comes
/// from the handle opened first, so the older window still holds the
/// actions, never another file's bytes at the same offsets.
#[tokio::test]
async fn o5c_a_rotation_between_windows_reads_the_opened_segment() {
    use crate::security::transparency_log::segments::sealed_path;
    let (mut state, _dir) = fixture(1, false).await;
    let logs = tempfile::tempdir().expect("log dir");
    let log = with_log(&mut state, &logs);
    for i in 0..3 {
        admin_action(&log, &format!("/ui/api/route-{i}"));
    }
    // More than one window of newer records, so the actions are in the
    // second window read.
    for _ in 0..400 {
        let mut fields = Map::new();
        fields.insert("event".into(), "invocation_note".into());
        fields.insert("pad".into(), "x".repeat(1024).into());
        let envelope = AuditEnvelope::ok(AuditWho::from_actor_id("caller"));
        log.append_event(fields, &envelope)
            .expect("invocation appended");
    }
    let path = logs.path().join("overview-audit.jsonl");
    let sealed = sealed_path(&path, 0);
    // What rotation does: the live file takes its sealed name, and a new,
    // shorter one starts under the live name.
    crate::security::transparency_log::pager::seam::after_window(move || {
        std::fs::rename(&path, sealed_path(&path, 0)).expect("seal");
        let opened = json!({"event": "audit_segment_opened", "segment_seq": 1});
        std::fs::write(&path, format!("{opened}\n")).expect("new live file");
    });

    let body = overview(&state).await;

    assert!(sealed.exists(), "the rotation ran between the windows");
    assert!(body.get("degraded").is_none(), "{body}");
    let routes: Vec<&str> = body["last_actions"]["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .filter_map(|r| r["route"].as_str())
        .collect();
    assert_eq!(
        routes,
        ["/ui/api/route-2", "/ui/api/route-1", "/ui/api/route-0"],
        "{body}"
    );
}

/// O5: no log configured, `last_actions` is absent and not degraded. With a
/// log, seven admin actions and invocation records after them: the five
/// newest actions, newest first. A log that cannot be read: absent, and
/// `degraded` names it.
#[tokio::test]
async fn o5_last_actions_are_the_newest_admin_actions() {
    let (mut state, _dir) = fixture(1, false).await;
    let body = overview(&state).await;
    assert!(body.get("last_actions").is_none(), "no log: {body}");

    let logs = tempfile::tempdir().expect("log dir");
    let log = with_log(&mut state, &logs);
    for i in 0..7 {
        admin_action(&log, &format!("/ui/api/route-{i}"));
    }
    for _ in 0..50 {
        let mut fields = Map::new();
        fields.insert("event".into(), "invocation_note".into());
        let envelope = AuditEnvelope::ok(AuditWho::from_actor_id("caller"));
        log.append_event(fields, &envelope)
            .expect("invocation appended");
    }
    let body = overview(&state).await;
    let routes: Vec<&str> = body["last_actions"]["rows"]
        .as_array()
        .expect("action rows")
        .iter()
        .map(|row| row["route"].as_str().expect("a route"))
        .collect();
    assert_eq!(
        routes,
        [
            "/ui/api/route-6",
            "/ui/api/route-5",
            "/ui/api/route-4",
            "/ui/api/route-3",
            "/ui/api/route-2"
        ],
        "{body}"
    );
    assert_eq!(body["last_actions"]["complete"], true, "{body}");
    assert!(body.get("degraded").is_none(), "{body}");

    let path = log.path();
    std::fs::remove_file(&path).expect("remove the log file");
    std::fs::create_dir(&path).expect("a directory where the log was");
    let body = overview(&state).await;
    assert!(body.get("last_actions").is_none(), "unreadable log: {body}");
    assert_eq!(body["degraded"], json!(["last_actions"]), "{body}");
}

/// O5b: a line too long to read, newer than the five actions found, may
/// itself have been an action, so the list says it is not complete.
#[tokio::test]
async fn o5b_a_skipped_newer_line_makes_the_list_incomplete() {
    use std::io::Write as _;
    let (mut state, _dir) = fixture(1, false).await;
    let logs = tempfile::tempdir().expect("log dir");
    let log = with_log(&mut state, &logs);
    for i in 0..ACTION_ROWS {
        admin_action(&log, &format!("/ui/api/route-{i}"));
    }
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(log.path())
        .expect("open the log for a raw append");
    writeln!(file, "{}", "x".repeat(300 << 10)).expect("a 300 KiB line");
    drop(file);
    let body = overview(&state).await;
    assert_eq!(
        body["last_actions"]["rows"].as_array().map(Vec::len),
        Some(ACTION_ROWS),
        "the five older actions are still found: {body}"
    );
    assert_eq!(body["last_actions"]["complete"], false, "{body}");
}

/// O5c: a newer record that does not parse may have been an action too, so
/// the list is not complete even with five rows found.
#[tokio::test]
async fn o5c_an_unreadable_newer_record_makes_the_list_incomplete() {
    use std::io::Write as _;
    let (mut state, _dir) = fixture(1, false).await;
    let logs = tempfile::tempdir().expect("log dir");
    let log = with_log(&mut state, &logs);
    for i in 0..ACTION_ROWS {
        admin_action(&log, &format!("/ui/api/route-{i}"));
    }
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(log.path())
        .expect("open the log for a raw append");
    writeln!(file, "{{\"event\": \"admin_action\", broken").expect("a broken record");
    drop(file);
    let body = overview(&state).await;
    assert_eq!(
        body["last_actions"]["rows"].as_array().map(Vec::len),
        Some(ACTION_ROWS),
        "{body}"
    );
    assert_eq!(body["last_actions"]["complete"], false, "{body}");
}
