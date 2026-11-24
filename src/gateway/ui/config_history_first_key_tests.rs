// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The history restore on a one-operator gateway whose gateway.yaml holds API
//! keys that come into use at the next start. A restore that leaves such a
//! key in place answers the shared `restart_pending` 409; one that would add
//! keys the file never waited on is turned down with no 409 of that kind; one
//! that drops the waiting keys goes through and the wait is over.

use super::support_tests::{Audit, Caller, History, Rig};
use axum::http::StatusCode as Code;

/// gateway.yaml for one operator holding the root admin key, plus the list
/// items in `more`, then the top-level lines in `after`.
fn one_operator(more: &[String], after: &str) -> String {
    let mut text = String::from("secrets:\n  store: files\nbackends: {}\nauth:\n");
    text.push_str("  enabled: true\n  single_user: true\n  api_keys:\n");
    text.push_str(&super::super::keys_create_fixture_tests::root_item());
    for line in more {
        text.push_str(line);
    }
    text.push_str(after);
    text
}

/// An `auth.api_keys` item called `name`, under a secret only this file uses.
fn entry(name: &str) -> String {
    let secret = format!("restore-rows-{name}");
    super::super::keys_create_fixture_tests::item(name, &secret, "")
}

/// The history of an earlier run that served `earlier` (the root key plus a
/// second one: several credentials) and a rig started afterwards, in the same
/// folder, on `later`. Gives the rig and the version id of `earlier`.
async fn rig_after_multi_user(earlier: &str, later: &str) -> (Rig, String) {
    let first_run = Rig::start(earlier, Audit::Logged).await;
    let kept = first_run.version_of(earlier.as_bytes());
    let folder = std::sync::Arc::clone(&first_run.dir);
    drop(first_run);
    let bounds = crate::config_reload::history::Bounds::default();
    let second_run = Rig::start_in(folder, later, Audit::Logged, bounds, History::Kept).await;
    (second_run, kept)
}

/// Asks the key route for "first"; it is written and held for the next start.
async fn hold_first(rig: &Rig) {
    let seen = crate::config_reload::FileRevision::of(&rig.bytes());
    let request =
        serde_json::json!({"revision": seen.as_str(), "name": "first", "backends": ["*"]});
    let (code, body) = rig
        .send("POST", "/ui/api/keys", Some(&request), Caller::Root)
        .await;
    assert_eq!(code, Code::CREATED, "{body}");
    assert_eq!(body["pending_restart"], true, "{body}");
}

/// The names the gateway's record of the last reload says are waiting.
fn waits(rig: &Rig) -> Option<Vec<String>> {
    rig.state.live_config.waiting_keys()
}

/// R1 for the restore route: the version to restore still lists "first",
/// which waits in the file now, so the answer is the shared 409 for it and
/// the file does not change.
#[tokio::test]
async fn r1_a_restore_keeping_the_waiting_key_is_restart_pending() {
    let earlier = one_operator(&[entry("first")], "environment: \"older\"\n");
    let (rig, kept) = rig_after_multi_user(&earlier, &one_operator(&[], "")).await;
    hold_first(&rig).await;
    let untouched = rig.bytes();
    let (code, body) = rig.restore(&kept, Caller::Root).await;
    assert_eq!(code, Code::CONFLICT, "{body}");
    assert_eq!(body["error"], "restart_pending", "{body}");
    assert_eq!(body["waiting_keys"], serde_json::json!(["first"]), "{body}");
    assert_eq!(rig.bytes(), untouched, "the restore wrote gateway.yaml");
}

/// R4: nothing waits in the file, and the version would add "first", a key
/// only the create may bring in. The restore is turned down, writes nothing,
/// and says nothing of a restart or of waiting keys.
#[tokio::test]
async fn r4_a_restore_bringing_in_a_first_key_is_refused_without_a_wait() {
    let later = one_operator(&[], "");
    let (rig, kept) = rig_after_multi_user(&one_operator(&[entry("first")], ""), &later).await;
    let (code, body) = rig.restore(&kept, Caller::Root).await;
    assert_ne!(body["error"], "restart_pending", "{code} {body}");
    // R10 for the restore: a 422 whose message is the question's sentence
    // for a key only the create may bring in.
    assert_eq!(code, Code::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body["error"], "invalid", "{body}");
    let said = body["message"].as_str().unwrap_or_default();
    assert!(
        said.contains("API key") && said.contains("multi-user"),
        "{said}"
    );
    assert!(body.get("waiting_keys").is_none(), "{body}");
    let shown = body.to_string().to_lowercase();
    assert!(!shown.contains("restart"), "{body}");
    assert_eq!(
        rig.bytes(),
        later.as_bytes(),
        "the restore wrote gateway.yaml"
    );
    assert_eq!(waits(&rig), None);
}

/// R4: "first" waits; going back to the version from before the create
/// takes it out, so the restore goes through and nothing waits any more.
#[tokio::test]
async fn r4_a_restore_without_the_waiting_key_ends_the_wait() {
    let base = one_operator(&[], "");
    let rig = Rig::start(&base, Audit::Logged).await;
    let before_create = rig.version_of(base.as_bytes());
    hold_first(&rig).await;
    assert_eq!(waits(&rig), Some(vec!["first".to_owned()]), "premise");
    let (code, body) = rig.restore(&before_create, Caller::Root).await;
    assert_eq!(code, Code::OK, "{body}");
    assert_eq!(rig.bytes(), base.as_bytes());
    assert_eq!(waits(&rig), None);
}

/// R4: two keys added by hand both wait (revoking just one is refused, L7);
/// a restore to the version that has neither goes through and ends the wait.
#[tokio::test]
async fn r4_a_restore_without_two_waiting_keys_ends_the_wait() {
    let base = one_operator(&[], "");
    let rig = Rig::start(&base, Audit::Logged).await;
    let before_edit = rig.version_of(base.as_bytes());
    rig.write(&one_operator(&[entry("first"), entry("second")], ""));
    assert!(
        rig.ctx.reload_outcome().await.is_err(),
        "premise: the reload refuses and records both keys as waiting"
    );
    let both = Some(vec!["first".to_owned(), "second".to_owned()]);
    assert_eq!(waits(&rig), both, "premise");
    let (code, body) = rig.restore(&before_edit, Caller::Root).await;
    assert_eq!(code, Code::OK, "{body}");
    assert_eq!(rig.bytes(), base.as_bytes());
    assert_eq!(waits(&rig), None);
}
