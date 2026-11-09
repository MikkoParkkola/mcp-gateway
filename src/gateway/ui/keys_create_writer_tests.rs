// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/api/keys` answering each way the writer can end: one row per
//! `ReplaceError` variant (the writer's answer injected), the live-table
//! check after a write, and the order of the intent and the commit.

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use serde_json::Value;

use super::keys_create::InjectWriter;
use super::keys_create_fixture_tests::{Call, Fixture, KNOWN, Sent, Setup};
use crate::config_reload::{FileRevision, ReplaceError, ReplaceOutcome};

/// A valid create whose writer answers `answer` instead of running.
fn injected(fx: &Fixture, answer: fn() -> Result<ReplaceOutcome, ReplaceError>) -> Sent {
    let mut call = Call::new(&fx.body("injected"));
    call.inject = Some(InjectWriter(Arc::new(answer)));
    let before = fx.bytes();
    let sent = fx.post(call);
    assert_eq!(fx.bytes(), before, "the file changed");
    sent
}

fn error_of(sent: &Sent) -> Value {
    sent.json()["error"].clone()
}

fn path() -> std::path::PathBuf {
    std::path::PathBuf::from("journal")
}

/// P9: a busy lock is a retryable 503.
#[test]
fn p9_busy_is_a_503() {
    let fx = Fixture::new(Setup::default());
    let sent = injected(&fx, || Err(ReplaceError::Busy));
    assert_eq!(
        sent.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        sent.body
    );
    assert_ne!(error_of(&sent), "audit_unavailable");
}

/// P9: a writer-raised stale answers 409 `stale` with the current revision.
#[test]
fn p9_a_writer_stale_is_a_409_naming_the_current_revision() {
    let fx = Fixture::new(Setup::default());
    let sent = injected(&fx, || {
        Err(ReplaceError::Stale {
            current: FileRevision::of(b"newer"),
        })
    });
    assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
    assert_eq!(error_of(&sent), "stale");
    assert_eq!(sent.json()["current"], FileRevision::of(b"newer").as_str());
}

/// P9: a stage, a write and an unsupported target are 500s with fixed text.
#[test]
fn p9_definite_failures_are_500s() {
    let fx = Fixture::new(Setup::default());
    let answers: [fn() -> Result<ReplaceOutcome, ReplaceError>; 3] = [
        || Err(ReplaceError::Stage("zq-detail".into())),
        || Err(ReplaceError::Write("zq-detail".into())),
        || Err(ReplaceError::Unsupported("zq-detail".into())),
    ];
    for answer in answers {
        let sent = injected(&fx, answer);
        assert_eq!(
            sent.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{}",
            sent.body
        );
        assert!(!sent.body.contains("zq-detail"), "{}", sent.body);
    }
}

/// The writer's own read check finding gateway.yaml gone, or refusing it
/// (its type, mode, owner or encoding), wrote nothing: a definite refusal,
/// answered as the preconditions answer the same states, never
/// `state_uncertain`, and never with the guard's text.
#[test]
fn p9_a_config_the_writer_cannot_read_is_a_definite_refusal() {
    let fx = Fixture::new(Setup::default());
    let gone = injected(&fx, || Err(ReplaceError::NoConfigFile));
    assert_eq!(gone.status, StatusCode::CONFLICT, "{}", gone.body);
    assert_eq!(gone.json()["error"], "no_config_file", "{}", gone.body);
    let refused = injected(&fx, || Err(ReplaceError::ConfigRefused("zq-guard".into())));
    assert_eq!(
        refused.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        refused.body
    );
    assert!(!refused.body.contains("zq-guard"), "{}", refused.body);
    assert!(
        !refused.body.contains("state_uncertain"),
        "{}",
        refused.body
    );
}

/// A `Refused` the audit log did not raise (a loader or slot refusal) is a
/// 500 and never `audit_unavailable`.
#[test]
fn a_candidate_refusal_is_a_500_and_not_an_audit_refusal() {
    let fx = Fixture::new(Setup::default());
    let sent = injected(&fx, || Err(ReplaceError::Refused("zq-loader".into())));
    assert_eq!(
        sent.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        sent.body
    );
    assert_ne!(error_of(&sent), "audit_unavailable");
    assert!(!sent.body.contains("zq-loader"), "{}", sent.body);
}

/// P9: a reload refusal is 409 `reload_refused`, and the variant is logged.
#[test]
fn p9_a_reload_refusal_is_a_409_and_logs_its_variant() {
    let fx = Fixture::new(Setup::default());
    let sent = injected(&fx, || Err(ReplaceError::ReloadRefused("zq-detail".into())));
    assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
    assert_eq!(error_of(&sent), "reload_refused");
    assert!(sent.logs.contains("reload_refused"), "{}", sent.logs);
    assert!(!sent.body.contains("zq-detail"), "{}", sent.body);
}

/// P9b: a reload refusal whose text reads like the flip is still answered by
/// the compute's outcome cell alone, which is empty: `reload_refused`.
#[test]
fn p9b_writer_text_that_reads_like_the_flip_is_not_parsed() {
    let fx = Fixture::new(Setup::default());
    let sent = injected(&fx, || {
        Err(ReplaceError::ReloadRefused(
            "the key list would change whether the gateway is multi-user".into(),
        ))
    });
    assert_eq!(sent.status, StatusCode::CONFLICT, "{}", sent.body);
    assert_eq!(error_of(&sent), "reload_refused");
}

/// P9: a failed rollback, an unconfirmed write, any other failure and a dead
/// writer task leave the file's state unproven: 500 `state_uncertain`.
#[test]
fn p9_uncertain_endings_are_state_uncertain() {
    let fx = Fixture::new(Setup::default());
    let answers: [fn() -> Result<ReplaceOutcome, ReplaceError>; 4] = [
        || {
            Err(ReplaceError::RollbackFailed {
                journal: path(),
                error: "zq-detail".into(),
            })
        },
        || {
            Err(ReplaceError::Unconfirmed {
                journal: path(),
                error: "zq-detail".into(),
            })
        },
        || Err(ReplaceError::Failed("zq-detail".into())),
        || {
            Err(ReplaceError::Failed(
                "the config write task failed: zq-detail".into(),
            ))
        },
    ];
    for answer in answers {
        let sent = injected(&fx, answer);
        assert_eq!(
            sent.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{}",
            sent.body
        );
        assert_eq!(error_of(&sent), "state_uncertain");
        assert!(!sent.body.contains("zq-detail"), "{}", sent.body);
        // The operator's way out: re-read the list before creating again.
        let recovery = sent.json()["recovery"].as_str().map(str::to_owned);
        assert!(
            recovery.is_some_and(|text| text.contains("GET /ui/api/keys")),
            "{}",
            sent.body
        );
    }
}

/// The root key alone: a live table the write never reaches.
fn root_only() -> crate::config::AuthConfig {
    Setup::default().running
}

/// P10: the writer reports success but the live generation lacks the key: no
/// 201, no secret, `state_uncertain`; GET's recovery read shows the entry
/// not live, under the new revision.
#[test]
fn p10_a_write_the_live_generation_never_saw_is_not_a_success() {
    let fx = Fixture::new(Setup {
        split_live: Some(root_only()),
        ..Setup::default()
    });
    let sent = fx.post(Call::new(&fx.body("late")));
    assert_eq!(
        sent.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        sent.body
    );
    assert_eq!(error_of(&sent), "state_uncertain");
    assert!(fx.text().contains("late"), "the write itself landed");
    let listed = fx.get();
    assert_eq!(listed["revision"], fx.revision());
    let entry = listed["keys"]
        .as_array()
        .and_then(|k| k.iter().find(|e| e["name"] == "late"));
    assert_eq!(entry.map(|e| e["live"].clone()), Some(Value::Bool(false)));
    assert!(!sent.body.contains(KNOWN), "{}", sent.body);
}

/// P10 twin: a live key of the requested name under another digest is not
/// taken as success either.
#[test]
fn p10_a_live_key_of_that_name_under_another_digest_is_not_success() {
    let mut live = root_only();
    live.api_keys.push(crate::config::ApiKeyConfig {
        name: "twin".into(),
        key_sha256: Some(super::keys_create_fixture_tests::spec("another-secret")),
        backends: vec!["*".into()],
        ..Default::default()
    });
    let fx = Fixture::new(Setup {
        split_live: Some(live),
        ..Setup::default()
    });
    let sent = fx.post(Call::new(&fx.body("twin")));
    assert_eq!(
        sent.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        sent.body
    );
    assert_eq!(error_of(&sent), "state_uncertain");
    assert!(!sent.body.contains(KNOWN), "{}", sent.body);
}

/// A4 order: the intent is appended (fsynced) before the writer commits, and
/// the writer records "intent" only once the append has returned: at that
/// step the audit log already holds the intent line.
#[test]
fn a4_the_intent_is_durable_before_the_writer_commits() {
    use crate::config_reload::write_order;
    let fx = Fixture::new(Setup::default());
    let target = crate::identity_grants::journal::resolved(&fx.path());
    write_order::take(&target);
    let audit = fx.dir.path().join("audit.jsonl");
    let held = Arc::new(Mutex::new(None));
    let cell = Arc::clone(&held);
    write_order::on(
        &target,
        "intent",
        Arc::new(move || {
            // The create's own intent: its event and its key, read from the
            // record, so another key's intent cannot stand in for it.
            let log = std::fs::read_to_string(&audit).unwrap_or_default();
            let own = log
                .lines()
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                .any(|record| {
                    record["event"] == "config_key_create_intent" && record["subject"] == "ordered"
                });
            *cell.lock().expect("cell") = Some(own);
        }),
    );
    assert_eq!(
        fx.post(Call::new(&fx.body("ordered"))).status,
        StatusCode::CREATED
    );
    let steps = write_order::take(&target);
    assert_eq!(steps, ["intent", "commit"]);
    let on_disk = *held.lock().expect("cell");
    assert_eq!(
        on_disk,
        Some(true),
        "\"intent\" came before the append of the ordered key's intent"
    );
}

/// P9r: a reload that refuses after the rename, and a journal that then
/// cannot be removed, leave the file unproven (the real writer, two real
/// faults): 500 `state_uncertain`, the logged variant `rollback_failed`.
/// The recovery restored the original bytes (`recover` writes them back
/// before it tries to remove the journal), so gateway.yaml and GET show the
/// original and no new entry, while a `staged` journal and the staged
/// original stay. The leak check (secret, digest) runs inside `post`. The
/// refusal is armed from the writer's own "commit" step: after the
/// pre-write check, before the rename and reload, on the thread that
/// reloads.
#[test]
fn p9r_a_failed_rollback_is_state_uncertain_and_keeps_the_original() {
    use crate::config_persistence::journal::{self, fault};
    use crate::config_reload::{refuse_hook, write_order};
    let fx = Fixture::new(Setup::default());
    let target = crate::identity_grants::journal::resolved(&fx.path());
    let (original, revision) = (fx.bytes(), fx.revision());
    let armed = fault::set(&target, fault::Fault::FailJournalRemove);
    let reached = Arc::new(Mutex::new(None));
    let cell = Arc::clone(&reached);
    write_order::on(
        &target,
        "commit",
        Arc::new(move || {
            *cell.lock().expect("cell") = Some(refuse_hook::arm("zq-reload-refusal"));
        }),
    );
    let sent = fx.post(Call::new(&fx.body("stuck")));
    let hook = reached.lock().expect("cell").take();
    let removals = fault::fired(&target);
    let journal_bytes = std::fs::read(journal::journal_path(&target)).expect("journal is readable");
    let staged = std::fs::read(journal::original_path(&target)).expect("staged original");
    drop(armed);
    write_order::take(&target);
    let hook = hook.expect("the writer never reached its commit step");
    assert!(
        hook.load(std::sync::atomic::Ordering::SeqCst),
        "the reload never took the refusal: no rollback was exercised"
    );
    assert!(removals >= 1, "the journal-remove fault never fired");
    assert_eq!(
        sent.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        sent.body
    );
    assert_eq!(error_of(&sent), "state_uncertain");
    let logged = r#""variant":"rollback_failed""#;
    assert!(
        sent.logs.contains(logged),
        "no rollback_failed: {}",
        sent.logs
    );
    let journal: Value = serde_json::from_slice(&journal_bytes).expect("journal is JSON");
    assert_eq!(journal["state"], "staged", "{journal}");
    assert_eq!(staged, original, "the staged original is the old file");
    assert_eq!(fx.bytes(), original, "the rollback restored the original");
    let listed = fx.get();
    assert_eq!(listed["revision"], revision);
    let names: Vec<_> = listed["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|e| e["name"].clone())
        .collect();
    assert_eq!(names, ["root"], "{listed}");
}
