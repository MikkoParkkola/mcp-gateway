// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The save's write trace and outcome word: the intent id leaving
//! the writer, the one traced writer behind the old entry, the envelope
//! choice, and one outcome per writer answer. On the save rows' fixtures.

use super::*;

/// An open log for a writer row, kept with its directory, and its path.
fn audit_log() -> (Arc<crate::security::TransparencyLogger>, std::path::PathBuf) {
    use crate::security::transparency_log::TransparencyLogConfig;
    let dir = crate::test_dir_keep::kept_tempdir();
    let log = dir.path().join("w0.jsonl");
    let config = TransparencyLogConfig {
        key_id: "w0".to_owned(),
        path: log.to_string_lossy().into_owned(),
        enabled: true,
        ..TransparencyLogConfig::default()
    };
    let logger = crate::security::TransparencyLogger::open(Arc::new(config)).expect("open the log");
    logger.keep_test_dir(Arc::clone(&dir));
    (Arc::new(logger), log)
}

/// The one save intent in `log` (exactly one), as its JSON entry.
fn save_intent(log: &std::path::Path) -> serde_json::Value {
    let text = std::fs::read_to_string(log).expect("read the log");
    let intents: Vec<serde_json::Value> = text
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|entry| entry["event"] == "config_save_intent")
        .collect();
    assert_eq!(intents.len(), 1, "want exactly one save intent:\n{text}");
    intents.into_iter().next().expect("one intent")
}

/// The save intent's entry hash, read from the log file itself.
fn intent_hash(log: &std::path::Path) -> crate::config_reload::reload_context::replace::IntentId {
    let entry = save_intent(log);
    let hash = entry["entry_hash"].as_str().expect("an entry hash");
    crate::config_reload::reload_context::replace::IntentId(hash.to_owned())
}

/// `BASE` with environment prod, for the writer's fixed-bytes compute.
fn prod_bytes() -> &'static str {
    Box::leak(BASE.replace("\"dev\"", "\"prod\"").into_boxed_str())
}

/// W0 (WRITE.2): the intent id leaves the writer: on the outcome when the
/// save stands, on the trace when it does not, a panicked task included.
#[tokio::test]
async fn the_intent_id_leaves_the_writer() {
    use crate::config_reload::history::Source;
    use crate::config_reload::reload_context::replace::{
        Expected, IntentKind, ReplaceError, Replaced, order, replace_traced,
    };
    use crate::config_reload::replace_test_support::to;

    let kind = || IntentKind::Save {
        fields: vec!["environment".to_owned()],
    };
    let ui = || Source::Ui { who: String::new() };

    // (a) A save that stands carries the log's own hash; the intent comes
    // before the commit, over the revision the file had.
    let (logger, log) = audit_log();
    let gw = gw(BASE);
    let audit = AuditPosture::of(Some(Arc::clone(&logger)), GatewayAuth::Off)
        .audit(kind())
        .expect("an audit");
    let replace = to(
        Expected::Revision(gw.base()),
        prod_bytes(),
        Replaced::Discard,
    );
    let outcome = replace_traced(Arc::clone(&gw.ctx), replace, audit, ui(), WAIT)
        .await
        .expect("the save stands");
    assert_eq!(outcome.intent_id, Some(intent_hash(&log)));
    assert_eq!(
        save_intent(&log)["base_revision"],
        FileRevision::of(BASE.as_bytes()).as_str()
    );
    let events = order::take(&crate::identity_grants::journal::resolved(&gw.path));
    let at = |event| events.iter().position(|seen| *seen == event);
    assert!(
        at("intent").is_some() && at("intent") < at("commit"),
        "{events:?}"
    );

    // (b) No log: no intent, so no id.
    let gw = gw_with(BASE, false, false);
    let audit = AuditPosture::of(None, GatewayAuth::Off)
        .audit(kind())
        .expect("an audit");
    let replace = to(
        Expected::Revision(gw.base()),
        prod_bytes(),
        Replaced::Discard,
    );
    let outcome = replace_traced(Arc::clone(&gw.ctx), replace, audit, ui(), WAIT)
        .await
        .expect("the save stands");
    assert_eq!(outcome.intent_id, None);

    // (c) A write the reload refuses: put back, and the trace says so.
    let (logger, log) = audit_log();
    let gw = gw_with(BASE, true, false);
    let audit = AuditPosture::of(Some(Arc::clone(&logger)), GatewayAuth::Off)
        .audit(kind())
        .expect("an audit");
    let replace = to(
        Expected::Revision(gw.base()),
        prod_bytes(),
        Replaced::Discard,
    );
    let Err((error, trace)) = replace_traced(Arc::clone(&gw.ctx), replace, audit, ui(), WAIT).await
    else {
        panic!("the reload refuses the write");
    };
    assert!(
        matches!(error, ReplaceError::ReloadRefused { .. }),
        "{error:?}"
    );
    assert_eq!(trace.intent_id, Some(intent_hash(&log)));
    assert!(trace.written && trace.restored, "{trace:?}");

    // (d) Test profile only (release aborts on panic): a task that dies
    // right after its append still yields the id.
    let (logger, log) = audit_log();
    let gw = gw_with(BASE, false, false);
    order::on(
        &crate::identity_grants::journal::resolved(&gw.path),
        "intent",
        Arc::new(|| panic!("W0 stops the write after its intent")),
    );
    let audit = AuditPosture::of(Some(Arc::clone(&logger)), GatewayAuth::Off)
        .audit(kind())
        .expect("an audit");
    let replace = to(
        Expected::Revision(gw.base()),
        prod_bytes(),
        Replaced::Discard,
    );
    let Err((error, trace)) = replace_traced(Arc::clone(&gw.ctx), replace, audit, ui(), WAIT).await
    else {
        panic!("the task died");
    };
    assert!(matches!(error, ReplaceError::Failed(_)), "{error:?}");
    assert_eq!(trace.intent_id, Some(intent_hash(&log)));
}

/// W7 (D3): the old writer entry runs the traced one and drops its trace.
#[tokio::test]
async fn the_old_writer_entry_delegates_to_the_traced_one() {
    use crate::config_reload::history::Source;
    use crate::config_reload::reload_context::replace::{
        Audit, Expected, ReplaceError, Replaced, order, replace_detached, replace_traced,
    };
    use crate::config_reload::replace_test_support::to;

    let gw = gw_with(BASE, true, false);
    let replace = to(
        Expected::Revision(gw.base()),
        prod_bytes(),
        Replaced::Discard,
    );
    let refused = replace_detached(Arc::clone(&gw.ctx), replace, WAIT).await;
    assert!(
        matches!(refused, Err(ReplaceError::ReloadRefused { .. })),
        "{refused:?}"
    );
    let events = order::take(&crate::identity_grants::journal::resolved(&gw.path));
    assert_eq!(events.first(), Some(&"traced"), "{events:?}");
    assert!(
        events.contains(&"commit") && events.contains(&"rollback"),
        "{events:?}"
    );

    // The same save through the traced entry keeps what the write got to.
    let gw = gw_with(BASE, true, false);
    let replace = to(
        Expected::Revision(gw.base()),
        prod_bytes(),
        Replaced::Discard,
    );
    let ui = Source::Ui { who: String::new() };
    let Err((_, trace)) = replace_traced(Arc::clone(&gw.ctx), replace, Audit::Off, ui, WAIT).await
    else {
        panic!("the reload refuses the write");
    };
    assert!(trace.written && trace.restored, "{trace:?}");
}

/// W2b (c): both sides of the intent's envelope choice. A key write's
/// intent keeps its key as `subject` beside its caller; an intent with no
/// writer, a recovery's, names the gateway.
#[test]
fn a_key_write_keeps_its_subject_and_a_recovery_names_the_gateway() {
    use crate::config_reload::reload_context::replace::{Audit, Intent, IntentKind};
    use crate::security::audit::AuditWho;
    let (logger, log) = audit_log();
    let posture = AuditPosture::of(Some(Arc::clone(&logger)), GatewayAuth::Off);
    let caller = AuditWho::from_actor_id("w2b-caller");
    let Ok(Audit::Required {
        mut sink,
        kind,
        writer,
    }) = posture.key_write(IntentKind::KeyCreate, caller, "w2b-key")
    else {
        panic!("a log makes the key write audited");
    };
    let base = FileRevision::of(BASE.as_bytes());
    let key_intent = Intent {
        kind,
        base: base.clone(),
        outside_change: false,
        recovery_intent_id: None,
        writer,
    };
    sink.append(&key_intent).expect("the key write's intent");
    let recovery = Intent {
        kind: IntentKind::Recovery,
        base,
        outside_change: false,
        recovery_intent_id: None,
        writer: None,
    };
    sink.append(&recovery).expect("the recovery intent");

    let text = std::fs::read_to_string(&log).expect("read the log");
    let entry = |event: &str| -> serde_json::Value {
        text.lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|entry| entry["event"] == event)
            .unwrap_or_else(|| panic!("no {event}:\n{text}"))
    };
    let key = entry("config_key_create_intent");
    assert_eq!(key["subject"], "w2b-key", "{key}");
    assert_eq!(key["who"]["account"], "w2b-caller", "{key}");
    let recovered = entry("config_recovery_intent");
    let gateway = AuditWho::gateway().account;
    assert_eq!(recovered["who"]["account"], gateway.as_str(), "{recovered}");
    assert!(recovered.get("subject").is_none(), "{recovered}");
}

/// W2c: one outcome word for every writer answer and trace, all seventeen
/// errors named.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one table naming all seventeen writer errors, so a missing one shows in one place"
)]
fn every_writer_answer_has_one_save_outcome() {
    use super::super::{SaveOutcome, save_outcome};
    use crate::config_reload::reload_context::replace::{IntentId, ReplaceError, Trace};
    use crate::gateway::restart_config_floor::Refusal;
    use crate::secret_store::SaveError;

    let trace = |id: bool, written: bool, restored: bool| Trace {
        intent_id: id.then(|| IntentId("sha256:w2c".to_owned())),
        written,
        restored,
    };
    let journal = || std::path::PathBuf::from("j");
    let stale = || ReplaceError::Stale {
        current: FileRevision::of(b"x"),
    };
    let reload = || ReplaceError::ReloadRefused {
        class: RefusalClass::Internal,
        reason: "r".to_owned(),
    };
    let ok = [
        ((true, false), trace(true, true, false), "applied"),
        ((false, true), trace(true, false, false), "applied"),
        ((false, false), trace(true, false, false), "unchanged"),
        ((true, true), trace(true, true, false), "applied"),
    ];
    for (answer, trace, word) in ok {
        assert_eq!(
            save_outcome(Ok(answer), &trace).as_str(),
            word,
            "{answer:?}"
        );
    }
    let refused = [
        (ReplaceError::Busy, trace(false, false, false), "refused"),
        (
            ReplaceError::Gated(Refusal::Busy),
            trace(false, false, false),
            "refused",
        ),
        (stale(), trace(false, false, false), "stale"),
        (stale(), trace(true, false, false), "stale"),
        (
            ReplaceError::Refused("r".to_owned()),
            trace(false, false, false),
            "refused",
        ),
        (
            ReplaceError::NoAuditLog,
            trace(false, false, false),
            "refused",
        ),
        (
            ReplaceError::AuditRefused("r".to_owned()),
            trace(false, false, false),
            "refused",
        ),
        (
            ReplaceError::Unsupported("u".to_owned()),
            trace(false, false, false),
            "refused",
        ),
        (
            ReplaceError::Unsupported("u".to_owned()),
            trace(true, true, true),
            "rolled_back",
        ),
        (
            ReplaceError::Stage("s".to_owned()),
            trace(true, false, false),
            "refused",
        ),
        (
            ReplaceError::Write("w".to_owned()),
            trace(true, true, true),
            "rolled_back",
        ),
        (
            ReplaceError::Write("w".to_owned()),
            trace(true, true, false),
            "indeterminate",
        ),
        (
            ReplaceError::WriterRefused {
                code: "c",
                text: "t".to_owned(),
            },
            trace(true, true, true),
            "rolled_back",
        ),
        (reload(), trace(false, false, false), "refused"),
        (reload(), trace(true, false, false), "refused"),
        (reload(), trace(true, true, true), "rolled_back"),
        (
            ReplaceError::RollbackFailed {
                journal: journal(),
                error: "e".to_owned(),
            },
            trace(true, true, false),
            "indeterminate",
        ),
        (
            ReplaceError::RollbackFailed {
                journal: journal(),
                error: "e".to_owned(),
            },
            trace(true, true, true),
            "indeterminate",
        ),
        (
            ReplaceError::Unconfirmed {
                journal: journal(),
                error: "e".to_owned(),
            },
            trace(true, true, false),
            "indeterminate",
        ),
        (
            ReplaceError::Failed("f".to_owned()),
            trace(false, false, false),
            "refused",
        ),
        (
            ReplaceError::Failed("f".to_owned()),
            trace(true, false, false),
            "indeterminate",
        ),
        (
            ReplaceError::Secrets(SaveError::Store(StoreError::TimedOut)),
            trace(true, false, false),
            "refused",
        ),
        (
            ReplaceError::NoConfigFile,
            trace(false, false, false),
            "refused",
        ),
        (
            ReplaceError::ConfigRefused("c".to_owned()),
            trace(false, false, false),
            "refused",
        ),
    ];
    for (error, trace, word) in &refused {
        assert_eq!(
            save_outcome(Err(error), trace).as_str(),
            *word,
            "{error:?} with {trace:?}"
        );
    }
    // Each word is the literal the audit reader reads.
    let words = [
        (SaveOutcome::Applied, "applied"),
        (SaveOutcome::Unchanged, "unchanged"),
        (SaveOutcome::Refused, "refused"),
        (SaveOutcome::Stale, "stale"),
        (SaveOutcome::RolledBack, "rolled_back"),
        (SaveOutcome::Indeterminate, "indeterminate"),
    ];
    for (outcome, word) in words {
        assert_eq!(outcome.as_str(), word);
    }
}

/// W3 (e): the writer's applied flag comes from the reload's own patch. A
/// no-op write whose reload took up an outside edit sets it; the same no-op
/// write over an unedited file leaves it unset.
#[tokio::test]
async fn the_reload_says_whether_it_applied_a_change() {
    use crate::config_reload::history::Source;
    use crate::config_reload::reload_context::replace::{
        Audit, Expected, Replaced, replace_traced,
    };
    use crate::config_reload::replace_test_support::to;
    let staging: &'static str = Box::leak(BASE.replace("\"dev\"", "\"staging\"").into_boxed_str());
    for (edited, bytes) in [(true, staging), (false, BASE)] {
        let gw = gw_with(BASE, false, false);
        if edited {
            write_owner_only(&gw.path, staging).expect("hand edit");
        }
        let replace = to(Expected::Revision(gw.base()), bytes, Replaced::Discard);
        let ui = Source::Ui { who: String::new() };
        let written = replace_traced(Arc::clone(&gw.ctx), replace, Audit::Off, ui, WAIT).await;
        let outcome = written.expect("the no-op write stands");
        assert!(outcome.revision.is_none(), "edited {edited}: a no-op write");
        assert_eq!(outcome.reload_applied, edited, "edited {edited}");
    }
}
