// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! WRITE.1 and WRITE.2 through the router: every settings save leaves one
//! `admin_action` whose `save_outcome` says what happened, carrying the
//! intent's id exactly when an intent was appended, and the intent names the
//! caller. Rows run on the cancel rows' admin-keyed gateway and its log.
//!
//! The panic legs run in the test profile only: a release build aborts on a
//! panic, so there the process exits and the intent has no admin action.

use std::path::Path;
use std::sync::Arc;

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::ui_audit_cancel_tests::{Fixture, GUARD, KEY, START, fixture, reload_context, request};
use crate::config::Config;
use crate::config_persistence::journal::fault::{self, Fault};
use crate::config_reload::{FileRevision, LiveConfig, ReloadContext, write_order};
use crate::gateway::test_helpers::write_owner_only;
use crate::identity_grants::journal::resolved;
use crate::security::audit::AuditFailurePolicy;

const SETTINGS: &str = "/ui/api/settings";

/// How the row's reload context answers a reload.
#[derive(Clone, Copy)]
enum Reloads {
    Accept,
    Refuse,
}

/// A reload context over `path` as a serving gateway has one, with a config
/// history and a revision key, answering `reloads`.
fn context(path: &Path, reloads: Reloads) -> Arc<ReloadContext> {
    let evaluated = Config::load_evaluated(Some(path)).expect("the config loads");
    let dir = path.parent().expect("a config dir");
    let key = crate::gateway::record_principal::test_record_key();
    let live = LiveConfig::new(evaluated.config)
        .with_history(crate::config_reload::history::hook_for(dir, path))
        .with_startup_revision(&key, Some(evaluated.inputs));
    let ctx = reload_context(path, live);
    Arc::new(match reloads {
        Reloads::Accept => ctx,
        Reloads::Refuse => ctx.refusing_reloads_for_test(),
    })
}

/// The cancel rows' gateway (auth on, an admin key, an audit log), its
/// config file now holding `text` and its reload context rebuilt over it.
async fn gateway(text: &str, reloads: Reloads) -> Fixture {
    let mut fx = fixture(AuditFailurePolicy::FailClosed).await;
    write_owner_only(&fx.path, text).expect("write the config");
    fx.ctx = context(&fx.path, reloads);
    fx.state.meta_mcp.set_reload_context(Arc::clone(&fx.ctx));
    fx
}

fn file(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("read the config")
}

/// A save of `environment = value` over the revision `base` names.
fn body(base: &[u8], value: &str) -> Value {
    json!({
        "base_revision": FileRevision::of(base).as_str(),
        "fields": [{"field": "environment", "value": {"set": value}}],
    })
}

/// The save of `environment = value` over the file as it is now.
async fn save(fx: &Fixture, value: &str) -> (StatusCode, Value) {
    let body = body(&file(&fx.path), value);
    fx.send_json(request("POST", SETTINGS, &body)).await
}

/// Entries in the config history: a save that wrote nothing adds none.
fn history(fx: &Fixture) -> usize {
    fx.ctx
        .live_config
        .history_hook()
        .map_or(0, |hook| hook.store.events().len())
}

/// The files secret store beside the config: its index and its entries,
/// each name with its bytes, sorted; empty while there is no store.
fn store(fx: &Fixture) -> Vec<(String, Vec<u8>)> {
    let dir = fx.path.parent().expect("a config dir");
    let mut seen = Vec::new();
    if let Ok(bytes) = std::fs::read(dir.join("secrets-index.jsonl")) {
        seen.push(("secrets-index.jsonl".to_owned(), bytes));
    }
    if let Ok(entries) = std::fs::read_dir(dir.join("secrets")) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            seen.push((name, std::fs::read(entry.path()).unwrap_or_default()));
        }
    }
    seen.sort();
    seen
}

/// What a refused save must leave as it was.
#[derive(Debug, PartialEq)]
struct Kept {
    file: Vec<u8>,
    history: usize,
    store: Vec<(String, Vec<u8>)>,
}

fn kept(fx: &Fixture) -> Kept {
    Kept {
        file: file(&fx.path),
        history: history(fx),
        store: store(fx),
    }
}

/// The one `config_save_intent` line in the log; exactly one (A4).
fn intent(fx: &Fixture, row: &str) -> Value {
    let text = std::fs::read_to_string(fx.log.path()).unwrap_or_default();
    let intents: Vec<Value> = text
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["event"] == "config_save_intent")
        .collect();
    assert_eq!(intents.len(), 1, "{row}: one save intent:\n{text}");
    intents.into_iter().next().expect("one intent")
}

/// What a row expects of its record's `intent_id`.
enum Id {
    /// No intent was appended: the key is not there at all.
    Absent,
    /// The hash of the one save intent in the log.
    OfTheIntent,
}

/// The one `admin_action` in the log, for the settings route, with
/// `outcome` and the intent id `id` asks for.
fn assert_record(fx: &Fixture, row: &str, outcome: &str, id: &Id) {
    let records = fx.admin_actions();
    assert_eq!(records.len(), 1, "{row}: one admin_action: {records:#?}");
    let record = &records[0];
    assert_eq!(record["route"], SETTINGS, "{row}: {record}");
    assert_eq!(record["save_outcome"], outcome, "{row}: {record}");
    match id {
        Id::Absent => assert!(record.get("intent_id").is_none(), "{row}: {record}"),
        Id::OfTheIntent => {
            let hash = &intent(fx, row)["entry_hash"];
            assert_eq!(&record["intent_id"], hash, "{row}: {record}");
        }
    }
}

/// W1: a refused save leaves the file, the config history and the secret
/// store as they were, and one record saying `outcome`.
fn assert_refused(fx: &Fixture, row: &str, before: &Kept, outcome: &str, id: &Id) {
    assert_eq!(
        &kept(fx),
        before,
        "{row}: file, history and store unchanged"
    );
    assert_record(fx, row, outcome, id);
}

/// W1 leg 1: an edit the file cannot take in place (an anchored value).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w1_an_unprovable_save_is_refused() {
    let fx = gateway(START, Reloads::Accept).await;
    write_owner_only(&fx.path, format!("{START}environment: &env \"dev\"\n")).expect("hand edit");
    let before = kept(&fx);
    let (status, answer) = save(&fx, "prod").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_refused(&fx, "W1.1", &before, "refused", &Id::Absent);
}

/// W1 leg 2: a base revision the file no longer has.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w1_a_stale_save_says_stale() {
    let fx = gateway(START, Reloads::Accept).await;
    let before = kept(&fx);
    let stale = body(b"bytes the file never held", "prod");
    fx.send_json(request("POST", SETTINGS, &stale)).await;
    assert_refused(&fx, "W1.2", &before, "stale", &Id::Absent);
}

/// W1 leg 3: the config lock is held for the whole request; the answer is
/// today's busy answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w1_a_busy_save_is_refused() {
    let fx = gateway(START, Reloads::Accept).await;
    let lock = crate::config_persistence::lock::lock_path(&resolved(&fx.path));
    let _held =
        crate::fs_lock::ExclusiveFileLock::try_acquire(&lock).expect("the row holds the lock");
    let before = kept(&fx);
    let (status, answer) = save(&fx, "prod").await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["error"], "the config is being written; retry");
    assert_refused(&fx, "W1.3", &before, "refused", &Id::Absent);
}

/// W1 leg 4: the config gate admits no write while a restart is prepared;
/// the answer is today's restart-busy answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w1_a_gated_save_is_refused() {
    use crate::gateway::restart_floor::FloorAdapter as _;
    let fx = gateway(START, Reloads::Accept).await;
    let mut floor =
        crate::gateway::restart_config_floor::support::booted_floor(&fx.ctx.registry, &fx.path);
    floor
        .pause(tokio::time::Instant::now() + GUARD)
        .await
        .expect("pause");
    let before = kept(&fx);
    let (status, answer) = save(&fx, "prod").await;
    assert_eq!(status, StatusCode::CONFLICT, "{answer}");
    assert_eq!(answer["error"], "a restart is being prepared; retry");
    assert_refused(&fx, "W1.4", &before, "refused", &Id::Absent);
    drop(floor);
}

/// W1 leg 5: a field the handler refuses before the writer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w1_an_unknown_field_is_refused() {
    let fx = gateway(START, Reloads::Accept).await;
    let before = kept(&fx);
    let unknown = json!({
        "base_revision": FileRevision::of(&before.file).as_str(),
        "fields": [{"field": "no.such.field", "value": {"set": "x"}}],
    });
    fx.send_json(request("POST", SETTINGS, &unknown)).await;
    assert_refused(&fx, "W1.5", &before, "refused", &Id::Absent);
}

/// W1 leg 6: the template check refuses the new bytes before any intent (a
/// hand-edited port the loader cannot read).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w1_a_save_the_template_check_refuses_is_refused() {
    let fx = gateway(START, Reloads::Accept).await;
    let edited = format!("{START}server:\n  port: \"not-a-port\"\n");
    write_owner_only(&fx.path, edited).expect("hand edit");
    let before = kept(&fx);
    let (status, answer) = save(&fx, "prod").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_refused(&fx, "W1.6", &before, "refused", &Id::Absent);
}

/// W1 leg 8: the writer fails before its append (a directory where the
/// config lock goes).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w1_a_writer_failure_before_the_intent_is_refused() {
    let fx = gateway(START, Reloads::Accept).await;
    let lock = crate::config_persistence::lock::lock_path(&resolved(&fx.path));
    std::fs::create_dir(&lock).expect("a directory where the lock goes");
    let before = kept(&fx);
    save(&fx, "prod").await;
    assert_refused(&fx, "W1.8", &before, "refused", &Id::Absent);
}

/// W1 leg 9: staging fails after the append (a directory at the journal's
/// scratch path): refused, not rolled back, and the id is the intent's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w1_a_staging_failure_after_the_intent_is_refused_with_its_id() {
    let fx = gateway(START, Reloads::Accept).await;
    let target = resolved(&fx.path);
    let scratch = target.with_file_name(".gateway.yaml.replace-journal.new");
    write_order::on(
        &target,
        "intent",
        Arc::new(move || {
            let _ = std::fs::create_dir(&scratch);
        }),
    );
    let before = kept(&fx);
    save(&fx, "prod").await;
    write_order::take(&target);
    assert_refused(&fx, "W1.9", &before, "refused", &Id::OfTheIntent);
}

/// W2 a: an applied save. The history entry it adds also proves the
/// fixture's history counts (the other side of W1's "no entry").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w2_an_applied_save_carries_its_outcome_and_id() {
    let fx = gateway(START, Reloads::Accept).await;
    let entries = history(&fx);
    let (status, answer) = save(&fx, "prod").await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_record(&fx, "W2.a", "applied", &Id::OfTheIntent);
    let notices = answer
        .get("notices")
        .map(Value::to_string)
        .unwrap_or_default();
    assert!(
        !notices.contains("OUTSIDE_CHANGE_APPLIED") && !notices.contains("NOT_AUDITED"),
        "W2.a: {answer}"
    );
    let deadline = tokio::time::Instant::now() + GUARD;
    while history(&fx) <= entries {
        assert!(
            tokio::time::Instant::now() < deadline,
            "W2.a: no history entry"
        );
        tokio::task::yield_now().await;
    }
}

/// W2 b: the reload refuses the written bytes; they are put back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w2_a_save_the_reload_refuses_is_rolled_back() {
    let fx = gateway(START, Reloads::Refuse).await;
    save(&fx, "prod").await;
    assert_eq!(
        file(&fx.path),
        START.as_bytes(),
        "W2.b: the original is back"
    );
    assert_record(&fx, "W2.b", "rolled_back", &Id::OfTheIntent);
}

/// W2 c: the write itself fails; the original stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w2_a_failed_write_is_rolled_back() {
    let fx = gateway(START, Reloads::Accept).await;
    let _armed = fault::set(&fx.path, Fault::FailWrite);
    save(&fx, "prod").await;
    assert!(fault::fired(&fx.path) > 0, "W2.c: the write fault fired");
    assert_eq!(file(&fx.path), START.as_bytes(), "W2.c: the original stays");
    assert_record(&fx, "W2.c", "rolled_back", &Id::OfTheIntent);
}

/// W2 d: the config link is re-pointed after the write; the write is undone
/// on the file it went to.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w2_a_save_whose_link_moved_is_rolled_back() {
    let mut fx = fixture(AuditFailurePolicy::FailClosed).await;
    let dir = fx.path.parent().expect("a config dir").to_path_buf();
    let (real, other) = (dir.join("real.yaml"), dir.join("other.yaml"));
    write_owner_only(&real, START).expect("the real file");
    write_owner_only(&other, START).expect("the other file");
    std::fs::remove_file(&fx.path).expect("drop the plain file");
    std::os::unix::fs::symlink(&real, &fx.path).expect("link to the real file");
    fx.ctx = context(&fx.path, Reloads::Accept);
    fx.state.meta_mcp.set_reload_context(Arc::clone(&fx.ctx));
    let (target, link) = (resolved(&fx.path), fx.path.clone());
    write_order::on(
        &target,
        "commit",
        Arc::new(move || {
            let _ = std::fs::remove_file(&link);
            let _ = std::os::unix::fs::symlink(&other, &link);
        }),
    );
    save(&fx, "prod").await;
    write_order::take(&target);
    assert_eq!(file(&real), START.as_bytes(), "W2.d: the original is back");
    assert_record(&fx, "W2.d", "rolled_back", &Id::OfTheIntent);
}

/// W2 e: the rollback cannot finish (its journal stays): indeterminate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w2_a_rollback_that_fails_is_indeterminate() {
    let fx = gateway(START, Reloads::Refuse).await;
    let _armed = fault::set(&fx.path, Fault::FailJournalRemove);
    save(&fx, "prod").await;
    assert_record(&fx, "W2.e", "indeterminate", &Id::OfTheIntent);
}

/// W2 f: the reload took the bytes but the journal cannot be marked:
/// indeterminate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w2_an_unconfirmed_save_is_indeterminate() {
    let fx = gateway(START, Reloads::Accept).await;
    let _armed = fault::set(&fx.path, Fault::FailJournalMark);
    save(&fx, "prod").await;
    assert!(fault::fired(&fx.path) > 0, "W2.f: the mark fault fired");
    assert_record(&fx, "W2.f", "indeterminate", &Id::OfTheIntent);
}

/// W2 g and W2b b (test profile): the write task dies right after its
/// append. The record says indeterminate with the intent's id, and the
/// intent still names the caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w2_a_write_that_dies_after_its_intent_is_indeterminate() {
    let fx = gateway(START, Reloads::Accept).await;
    let target = resolved(&fx.path);
    write_order::on(
        &target,
        "intent",
        Arc::new(|| panic!("W2.g stops the write after its intent")),
    );
    save(&fx, "prod").await;
    write_order::take(&target);
    assert_record(&fx, "W2.g", "indeterminate", &Id::OfTheIntent);
    assert_eq!(intent(&fx, "W2b.b")["who"]["account"], KEY);
}

/// W2 h: the bytes are already the file's and the reload refuses: refused,
/// and the unchanged save still appended its intent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w2_an_unchanged_save_the_reload_refuses_is_refused() {
    let fx = gateway(&format!("{START}environment: \"prod\"\n"), Reloads::Refuse).await;
    let before = kept(&fx);
    save(&fx, "prod").await;
    assert_refused(&fx, "W2.h", &before, "refused", &Id::OfTheIntent);
}

/// W2 i: auth on and the log refuses the intent: nothing is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w2_a_save_whose_intent_is_refused_writes_nothing() {
    let fx = gateway(START, Reloads::Accept).await;
    fx.log
        .fail_next_append_of_kind_for_test("config_save_intent");
    let before = kept(&fx);
    save(&fx, "prod").await;
    assert_refused(&fx, "W2.i", &before, "refused", &Id::Absent);
}

/// W2b a: an applied save's intent names its caller, the named admin key,
/// and carries no key subject.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w2b_the_intent_names_the_caller() {
    let fx = gateway(START, Reloads::Accept).await;
    let (status, answer) = save(&fx, "prod").await;
    assert_eq!(status, StatusCode::OK, "{answer}");
    let intent = intent(&fx, "W2b.a");
    assert_eq!(intent["who"]["account"], KEY, "W2b.a: {intent}");
    assert!(intent.get("subject").is_none(), "W2b.a: {intent}");
}
