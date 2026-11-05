// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `POST /ui/api/keys` answering each way the writer can end: one row per
//! `ReplaceError` variant (the writer's answer injected), the live-table
//! check after a write, and the order of the intent and the commit.

use std::sync::Arc;

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
    fx.assert_leak_free(&sent, KNOWN);
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
    assert_eq!(sent.status, StatusCode::SERVICE_UNAVAILABLE, "{}", sent.body);
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
        assert_eq!(sent.status, StatusCode::INTERNAL_SERVER_ERROR, "{}", sent.body);
        assert!(!sent.body.contains("zq-detail"), "{}", sent.body);
    }
}

/// A `Refused` the audit log did not raise (a loader or slot refusal) is a
/// 500 and never `audit_unavailable`.
#[test]
fn a_candidate_refusal_is_a_500_and_not_an_audit_refusal() {
    let fx = Fixture::new(Setup::default());
    let sent = injected(&fx, || Err(ReplaceError::Refused("zq-loader".into())));
    assert_eq!(sent.status, StatusCode::INTERNAL_SERVER_ERROR, "{}", sent.body);
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
        || Err(ReplaceError::RollbackFailed { journal: path(), error: "zq-detail".into() }),
        || Err(ReplaceError::Unconfirmed { journal: path(), error: "zq-detail".into() }),
        || Err(ReplaceError::Failed("zq-detail".into())),
        || Err(ReplaceError::Failed("the config write task failed: zq-detail".into())),
    ];
    for answer in answers {
        let sent = injected(&fx, answer);
        assert_eq!(sent.status, StatusCode::INTERNAL_SERVER_ERROR, "{}", sent.body);
        assert_eq!(error_of(&sent), "state_uncertain");
        assert!(!sent.body.contains("zq-detail"), "{}", sent.body);
    }
}
