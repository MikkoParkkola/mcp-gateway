// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Startup-gate rows whose producer is the journal drain or the abandoned-file drain.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

use super::super::abandoned::{decode_frames, marked};
use super::super::fixtures::{self as journal_fixtures, NEW, OLD};
use super::super::{Fact, IntentId, JournalV2, ParkReason, Phase};
use super::DrainSession;
use super::fault::{self, At, Fault, Pause};
use super::fixtures::{
    Live, SAVE, accepted, attempt, decided, payload, replace_bytes, staged, state,
};
use super::handover::{self, hand_over};
use crate::config_persistence::commit::FileRevision;
use crate::config_persistence::lock::{self, NotLocked};
use crate::config_reload::startup_settle::{
    StartError, StartupSession, finish_start, prepare_start, prepare_start_within,
};
use crate::security::transparency_log::TransparencyLogger;
use crate::security::transparency_log::settle::{IntentKind, Role};

const JOURNAL: &str = ".gateway.yaml.replace-journal";
const ORIGINAL: &str = ".gateway.yaml.replace-original";
const ABANDONED: &str = "gateway.yaml.abandoned";
const OTHER_JOURNAL: &str = ".other.yaml.replace-journal";
const SENTENCE: &str = concat!(
    "A config write's journal beside the config still owes audit records to ",
    "the log it was bound to. Start with that audit log configured and reachable."
);

/// Copied from `src/backend/descriptor_withholding_tests.rs` (`capture`).
fn capture() -> (tracing::subscriber::DefaultGuard, Arc<Mutex<Vec<u8>>>) {
    struct W(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for W {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    crate::test_log_capture::keep_interest_open();
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buffer);
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || W(Arc::clone(&writer)))
        .finish();
    (tracing::subscriber::set_default(subscriber), buffer)
}

/// Copied from `config_persistence_journal_v2_drain_file_tests.rs` (`unfrozen`).
fn unfrozen(donor: &mut JournalV2) {
    let writer = donor.writer.as_mut().expect("fixture writer");
    writer.intent_counter = None;
    writer.records.clear();
}

/// Copied from `config_persistence_journal_v2_drain_file_refusal_tests.rs` (`plant`).
/// `std::fs::write` leaves 0644; on Unix the drain would then refuse the handle, not the tail.
fn plant_abandoned(dir: &Path, bytes: &[u8]) {
    let path = dir.join(ABANDONED);
    std::fs::write(&path, bytes).expect("planted gateway.yaml.abandoned");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    }
}
fn artifact(dir: &Path, name: &str, row: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap_or_else(|error| panic!("{row}: read {name}: {error}"))
}
fn journal_at(live: &Live, row: &str) -> JournalV2 {
    JournalV2::decode(&artifact(&live.resolved, JOURNAL, row))
        .unwrap_or_else(|_| panic!("{row}: {JOURNAL} decodes"))
}
fn gone(dir: &Path, name: &str, row: &str) {
    match std::fs::symlink_metadata(dir.join(name)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        other => panic!("{row}: {name} is gone, metadata {other:?}"),
    }
}
fn same(dir: &Path, name: &str, before: &[u8], row: &str) {
    assert_eq!(
        artifact(dir, name, row),
        before,
        "{row}: {name} byte-identical"
    );
}
fn held(path: &Path, row: &str) {
    match lock::lock_config_blocking_deferred(path, Instant::now(), |_| {}) {
        Err(NotLocked::Busy) => {}
        Err(error) => panic!("{row}: zero-bound acquire while held is Busy, got {error:?}"),
        Ok(_guard) => panic!("{row}: zero-bound acquire succeeded; the session does not hold it"),
    }
}
fn free(path: &Path, row: &str) {
    match lock::lock_config_blocking_deferred(path, Instant::now(), |_| {}) {
        Ok(_guard) => {}
        Err(error) => panic!("{row}: zero-bound acquire (lock free) got {error:?}"),
    }
}
fn prepared(path: &Path, row: &str) -> StartupSession {
    match super::fixtures::runtime(prepare_start(path)) {
        Ok(session) => session,
        Err(error) => panic!("{row}: prepare_start returned {error:?}"),
    }
}
fn finished(session: StartupSession, log: Option<Arc<TransparencyLogger>>, row: &str) {
    if let Err(error) = super::fixtures::runtime(finish_start(session, log)) {
        panic!("{row}: finish_start returned {error:?}");
    }
}
fn plant_staged(live: &Live, row: &str) {
    let mut journal = state(&live.resolved);
    staged(&mut journal);
    replace_bytes(&live.path, NEW);
    drop(live.seed(journal, row));
}
fn plant_accepted(live: &Live, row: &str) {
    let mut journal = state(&live.resolved);
    accepted(&mut journal);
    replace_bytes(&live.path, NEW);
    drop(live.seed(journal, row));
}
fn plant_unbound(live: &Live) {
    let mut journal = state(&live.resolved);
    journal.writer = None;
    journal.attempts.clear();
    journal.binding = None;
    staged(&mut journal);
    replace_bytes(&live.path, NEW);
    replace_bytes(&live.resolved.join(ORIGINAL), OLD);
    journal_fixtures::seed(&live.path, &journal);
}
/// `decided` then `unfrozen`, retokened, so the file owes its own intent and a refused outcome.
fn file_donor(live: &Live) -> JournalV2 {
    let mut donor = state(&live.resolved);
    decided(&mut donor);
    staged(&mut donor);
    donor.phase = Phase::Accepted;
    unfrozen(&mut donor);
    let writer = donor.writer.as_mut().expect("file donor");
    writer.intent_id = IntentId("file-1".to_owned());
    writer.intent = journal_fixtures::frozen(
        "file-1",
        Role::Intent(IntentKind::Save),
        &serde_json::json!({"kind": "settle.save"}),
    );
    donor
}
fn handed(session: &mut DrainSession, row: &str) {
    let Err(error) = hand_over(session) else {
        return;
    };
    let kind = match error {
        handover::HandoverError::Journal => "journal",
        handover::HandoverError::Write => "write",
        handover::HandoverError::Sync => "sync",
        handover::HandoverError::Finish => "finish",
        handover::HandoverError::Foreign => "foreign",
    };
    panic!("{row}: handover failed ({kind})");
}
fn abandon(live: &Live, row: &str, edit: impl FnOnce(&mut JournalV2)) -> StartupSession {
    let mut donor = state(&live.resolved);
    accepted(&mut donor);
    edit(&mut donor);
    let mut session = live.seed(donor, row);
    handed(&mut session, row);
    drop(session);
    prepared(&live.path, row)
}
fn arrived(records: &[Value]) -> String {
    records
        .iter()
        .map(|r| {
            format!(
                "{} {} {} {}",
                r["token"], r["event"], r["result"], r["reason"]
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}
fn owe(rec: &[Value], token: &str, event: &str, pair: Option<(&str, &str)>, n: usize, row: &str) {
    let got = rec
        .iter()
        .filter(|record| {
            record["token"] == token
                && record["event"] == event
                && pair.is_none_or(|(res, why)| record["result"] == res && record["reason"] == why)
        })
        .count();
    let shape = pair
        .map(|(result, reason)| format!(" {result}/{reason}"))
        .unwrap_or_default();
    assert_eq!(
        got,
        n,
        "{row}: {token} {event}{shape}={got} want {n}; arrived {}",
        arrived(rec)
    );
}

/// The writer's intent arrived at least once and at most twice (the seeded surviving copy plus
/// one resend), and every copy carries its frozen bytes. A fixture whose intent has a counter
/// seeds it as appended before a crash with its flag unsynced, and the drain resends such an
/// intent: the drain's own `late_journal_retry` row allows these equal repeats and counts
/// terminals, not intent copies.
fn intent_arrived(rec: &[Value], token: &str, row: &str) {
    let copies: Vec<&Value> = rec
        .iter()
        .filter(|record| record["token"] == token && record["event"] == "config_save_intent")
        .collect();
    assert!(
        !copies.is_empty(),
        "{row}: {token} intent arrived; arrived {}",
        arrived(rec)
    );
    assert!(
        copies.len() <= 2,
        "{row}: {token} intent at most twice (the seeded surviving copy plus one resend); arrived {}",
        arrived(rec)
    );
    for copy in copies {
        for (key, value) in payload(SAVE) {
            assert_eq!(copy[&key], value, "{row}: {token} intent copy keeps {key}");
        }
    }
}

/// The recovery attempt's token, read from the journal after `prepare_start`.
fn recovery_attempt_token(live: &Live, row: &str) -> String {
    let journal = journal_at(live, row);
    let tokens: Vec<String> = journal
        .attempts
        .iter()
        .filter(|attempt| attempt.intent.role == Role::RecoveryIntent)
        .map(|attempt| attempt.intent_id.0.clone())
        .collect();
    assert_eq!(
        tokens.len(),
        1,
        "{row}: one recovery attempt after prepare, got {tokens:?}"
    );
    tokens.into_iter().next().expect(row)
}

/// How many captured lines each carry both `path` and `cause`.
fn lines_naming(text: &str, path: &str, cause: &str) -> usize {
    text.lines()
        .filter(|line| line.contains(path) && line.contains(cause))
        .count()
}

/// Writer save, writer rolled-back outcome, one recovery intent for `token`, and that
/// attempt's outcome.
pub(super) fn expect_staged_owed(records: &[Value], token: &str, row: &str) {
    owe(records, "writer-1", "config_save_intent", None, 1, row);
    owe(
        records,
        "writer-1",
        "config_write_outcome",
        Some(("not_written", "rolled_back")),
        1,
        row,
    );
    let recoveries: Vec<_> = records
        .iter()
        .filter(|record| record["event"] == "config_recovery_intent")
        .collect();
    assert_eq!(
        recoveries.len(),
        1,
        "{row}: one config_recovery_intent; arrived {}",
        arrived(records)
    );
    assert_eq!(
        recoveries[0]["token"].as_str().unwrap_or(""),
        token,
        "{row}: recovery intent carries the attempt token {token}"
    );
    assert_ne!(token, "writer-1", "{row}: recovery token is not writer-1");
    assert_ne!(token, "", "{row}: recovery token is not empty");
    owe(
        records,
        token,
        "config_write_outcome",
        Some(("written", "rolled_back")),
        1,
        row,
    );
}
async fn until_parked(pause: &Pause, row: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !pause.parked() {
        assert!(
            Instant::now() < deadline,
            "{row}: worker parked within 30s on this thread"
        );
        tokio::task::yield_now().await;
    }
}
async fn must_prepare(path: &Path, row: &str) -> StartupSession {
    prepare_start(path)
        .await
        .unwrap_or_else(|error| panic!("{row}: prepare_start returned {error:?}"))
}

/// GATE.4: S1 restores the staged original before any logger exists.
#[test]
fn prepare_repairs_before_load() {
    const ROW: &str = "prepare_repairs_before_load";
    let live = Live::new();
    plant_staged(&live, ROW);
    let records = live.records();
    let session = prepared(&live.path, ROW);
    assert_eq!(
        std::fs::read(&live.path).expect(ROW),
        OLD,
        "{ROW}: config is the original bytes"
    );
    assert_eq!(
        journal_at(&live, ROW).fact,
        Some(Fact::RolledBack(FileRevision::of(OLD))),
        "{ROW}: journal records the restore fact"
    );
    assert_eq!(
        live.records(),
        records,
        "{ROW}: audit log grew before a logger; arrived {}",
        arrived(&live.records())
    );
    assert_eq!(
        session.target(),
        live.path.as_path(),
        "{ROW}: target is the config"
    );
    held(&live.path, ROW);
}

/// GATE.4: a staged restore whose original is gone is `RepairPending`. One undecided recovery
/// attempt is appended; the writer, phase, original revision, binding and config stay.
#[test]
fn prepare_refuses_unrepairable() {
    const ROW: &str = "prepare_refuses_unrepairable";
    let live = Live::new();
    plant_staged(&live, ROW);
    std::fs::remove_file(live.resolved.join(ORIGINAL)).expect(ROW);
    let config = std::fs::read(&live.path).expect(ROW);
    // Repair persists the attempt before it finds the original gone, so the journal is not
    // byte-identical. The writer and the config are never touched.
    let before = journal_at(&live, ROW);
    let error = super::fixtures::runtime(prepare_start(&live.path)).map(drop);
    assert_eq!(
        error,
        Err(StartError::RepairPending),
        "{ROW}: RepairPending"
    );
    // Every field but the one appended attempt equals the journal before: the writer (its flags,
    // counter and records), the fact, the phase, the binding and every earlier attempt.
    let mut after = journal_at(&live, ROW);
    let Some(added) = after.attempts.pop() else {
        panic!("{ROW}: repair appended its recovery attempt");
    };
    assert_eq!(
        after, before,
        "{ROW}: the journal is unchanged but for one appended attempt"
    );
    // The appended attempt, against the design's recovery attempt: an undecided, unsent recovery
    // intent at start that settles the writer.
    assert_eq!(
        added.intent.role,
        Role::RecoveryIntent,
        "{ROW}: a recovery intent"
    );
    assert_eq!(added.decision, None, "{ROW}: undecided");
    assert_eq!(added.intent_counter, None, "{ROW}: never sent");
    assert!(!added.intent.delivered, "{ROW}: not flagged delivered");
    assert!(added.records.is_empty(), "{ROW}: no records");
    assert!(!added.handed_over, "{ROW}: not handed over");
    let payload: Value = serde_json::from_slice(&added.intent.payload_json).expect(ROW);
    assert_eq!(
        payload["kind"], "settle.recovery",
        "{ROW}: recovery payload kind"
    );
    assert_eq!(payload["at_start"], true, "{ROW}: at start");
    assert_eq!(payload["settles"], "writer-1", "{ROW}: settles the writer");
    assert_eq!(
        std::fs::read(&live.path).expect(ROW),
        config,
        "{ROW}: config unchanged"
    );
    free(&live.path, ROW);
}

/// GATE.4: one handed-over token and one not is `JournalPending` before any caller load, and
/// the config bytes stay.
#[test]
fn prepare_refuses_partial_handover() {
    const ROW: &str = "prepare_refuses_partial_handover";
    let live = Live::new();
    let mut journal = state(&live.resolved);
    let mut extra = attempt();
    extra.handed_over = true;
    journal.attempts.push(extra);
    drop(live.seed(journal, ROW));
    let before = artifact(&live.resolved, JOURNAL, ROW);
    let config = std::fs::read(&live.path).expect(ROW);
    let error = super::fixtures::runtime(prepare_start(&live.path)).map(drop);
    assert_eq!(
        error,
        Err(StartError::JournalPending),
        "{ROW}: partial handover"
    );
    same(&live.resolved, JOURNAL, &before, ROW);
    assert_eq!(
        std::fs::read(&live.path).expect(ROW),
        config,
        "{ROW}: config byte-identical"
    );
    free(&live.path, ROW);
}

/// GATE.4: an unaudited v2 journal (no tokens, binding None) is restored, then removed with logging off.
#[test]
fn prepare_repairs_an_unaudited_v2_journal() {
    const ROW: &str = "prepare_repairs_an_unaudited_v2_journal";
    let live = Live::new();
    plant_unbound(&live);
    let records = live.records();
    let session = prepared(&live.path, ROW);
    assert_eq!(
        std::fs::read(&live.path).expect(ROW),
        OLD,
        "{ROW}: original bytes"
    );
    assert_eq!(
        live.records(),
        records,
        "{ROW}: log unchanged; arrived {}",
        arrived(&records)
    );
    held(&live.path, ROW);
    finished(session, None, ROW);
    gone(&live.resolved, JOURNAL, ROW);
    free(&live.path, ROW);
}

/// GATE.4: an all-handed-over journal is left for the file drain, which delivers and removes both.
#[test]
fn prepare_leaves_handover_to_the_file_drain() {
    const ROW: &str = "prepare_leaves_handover_to_the_file_drain";
    let live = Live::new();
    let mut donor = state(&live.resolved);
    accepted(&mut donor);
    replace_bytes(&live.path, NEW);
    let mut session = live.seed(donor, ROW);
    let cloned = session.journal().expect(ROW).clone();
    handed(&mut session, ROW);
    journal_fixtures::seed(&live.path, &marked(&cloned));
    drop(session);
    let journal = artifact(&live.resolved, JOURNAL, ROW);
    let file = artifact(&live.resolved, ABANDONED, ROW);
    let session = prepared(&live.path, ROW);
    same(&live.resolved, JOURNAL, &journal, ROW);
    same(&live.resolved, ABANDONED, &file, ROW);
    held(&live.path, ROW);
    finished(session, Some(Arc::clone(&live.log)), ROW);
    let records = live.records();
    intent_arrived(&records, "writer-1", ROW);
    owe(
        &records,
        "writer-1",
        "config_write_outcome",
        Some(("written", "committed")),
        1,
        ROW,
    );
    gone(&live.resolved, JOURNAL, ROW);
    gone(&live.resolved, ABANDONED, ROW);
    free(&live.path, ROW);
}

/// GATE.4: a repair that fails at `RepairPaused` is `JournalPending` and does not restore.
#[test]
fn prepare_refuses_a_failed_repair() {
    const ROW: &str = "prepare_refuses_a_failed_repair";
    let live = Live::new();
    plant_staged(&live, ROW);
    let config = std::fs::read(&live.path).expect(ROW);
    assert_eq!(config, NEW, "{ROW}: fixture config is the staged new bytes");
    let _armed = fault::arm(&live.path, Fault::Fail(At::RepairPaused));
    let error = super::fixtures::runtime(prepare_start(&live.path)).map(drop);
    assert_eq!(
        error,
        Err(StartError::JournalPending),
        "{ROW}: JournalPending, never Locked"
    );
    assert_eq!(
        std::fs::read(&live.path).expect(ROW),
        config,
        "{ROW}: config unchanged"
    );
    free(&live.path, ROW);
}

/// GATE.7: S1 repair parks off this current-thread runtime, so the test task can see it.
#[tokio::test(flavor = "current_thread")]
async fn prepare_runs_off_the_async_workers() {
    const ROW: &str = "prepare_runs_off_the_async_workers";
    let live = Live::new();
    plant_staged(&live, ROW);
    let pause = Arc::new(Pause::default());
    let _armed = fault::arm(&live.path, Fault::Pause(Arc::clone(&pause)));
    let path = live.path.clone();
    let task = tokio::spawn(async move { prepare_start(&path).await });
    until_parked(&pause, ROW).await;
    assert!(pause.parked(), "{ROW}: still parked on this thread");
    pause.release();
    let session = task
        .await
        .unwrap_or_else(|error| panic!("{ROW}: prepare task ended {error}"))
        .unwrap_or_else(|error| panic!("{ROW}: prepare_start returned {error:?}"));
    held(&live.path, ROW);
    drop(session);
}

#[path = "config_persistence_journal_v2_drain_startup_policy_tests.rs"]
mod policy;

// `StartupSession: Clone` makes this probe ambiguous, so the build fails.
trait AmbiguousIfClone<A> {
    fn probe() {}
}
impl<T> AmbiguousIfClone<()> for T {}
impl<T: Clone> AmbiguousIfClone<u8> for T {}

/// GATE.5: dropping the session releases the lock, keeps the journal and the config bytes, and
/// appends nothing.
#[test]
fn startup_session_drop_releases() {
    const ROW: &str = "startup_session_drop_releases";
    let _ = <StartupSession as AmbiguousIfClone<_>>::probe;
    let live = Live::new();
    drop(live.seed(state(&live.resolved), ROW));
    let config = std::fs::read(&live.path).expect(ROW);
    let session = prepared(&live.path, ROW);
    let journal = artifact(&live.resolved, JOURNAL, ROW);
    let records = live.records();
    drop(session);
    free(&live.path, ROW);
    same(&live.resolved, JOURNAL, &journal, ROW);
    assert_eq!(
        live.records(),
        records,
        "{ROW}: log unchanged; arrived {}",
        arrived(&records)
    );
    assert_eq!(
        std::fs::read(&live.path).expect(ROW),
        config,
        "{ROW}: config byte-identical"
    );
}

/// GATE.1: the locked target stays A after the symlink is re-pointed, and finish drains only A.
#[test]
fn locked_target_survives_a_repoint() {
    const ROW: &str = "locked_target_survives_a_repoint";
    let live = Live::new();
    drop(live.seed(state(&live.resolved), ROW));
    let link = live.resolved.join("configured.yaml");
    crate::test_symlink::symlink(&live.path, &link).unwrap_or_else(|e| panic!("{ROW}: {e}"));
    let session = prepared(&link, ROW);
    assert_eq!(session.target(), live.path.as_path(), "{ROW}: target is A");
    assert_ne!(
        session.target(),
        link.as_path(),
        "{ROW}: target is not the symlink"
    );
    let other = live.resolved.join("other.yaml");
    replace_bytes(&other, OLD);
    journal_fixtures::seed(&other, &state(&live.resolved));
    std::fs::remove_file(&link).expect(ROW);
    crate::test_symlink::symlink(&other, &link).unwrap_or_else(|error| panic!("{ROW}: {error}"));
    assert_eq!(
        session.target(),
        live.path.as_path(),
        "{ROW}: target still A"
    );
    let bee = artifact(&live.resolved, OTHER_JOURNAL, ROW);
    finished(session, Some(Arc::clone(&live.log)), ROW);
    gone(&live.resolved, JOURNAL, ROW);
    same(&live.resolved, OTHER_JOURNAL, &bee, ROW);
    free(&live.path, ROW);
}

/// GATE.7: finish's repair parks off this current-thread runtime, so the test task can release it.
#[tokio::test(flavor = "current_thread")]
async fn finish_runs_off_the_async_workers() {
    const ROW: &str = "finish_runs_off_the_async_workers";
    let live = Live::new();
    plant_staged(&live, ROW);
    let session = must_prepare(&live.path, ROW).await;
    let pause = Arc::new(Pause::default());
    let _armed = fault::arm(&live.path, Fault::Pause(Arc::clone(&pause)));
    let log = Arc::clone(&live.log);
    let task = tokio::spawn(async move { finish_start(session, Some(log)).await });
    until_parked(&pause, ROW).await;
    assert!(pause.parked(), "{ROW}: still parked on this thread");
    pause.release();
    assert_eq!(
        task.await
            .unwrap_or_else(|error| panic!("{ROW}: finish task ended {error}")),
        Ok(()),
        "{ROW}: finish_start after release"
    );
}

/// GATE.5: aborting finish while its worker is parked frees the lock, and a retry owes each record once.
#[tokio::test(flavor = "current_thread")]
async fn finish_cancelled_releases_the_lock() {
    const ROW: &str = "finish_cancelled_releases_the_lock";
    let live = Live::new();
    plant_staged(&live, ROW);
    let session = must_prepare(&live.path, ROW).await;
    // Read now: the cancelled worker still drains, and finishing removes the journal.
    let token = recovery_attempt_token(&live, ROW);
    let pause = Arc::new(Pause::default());
    let _armed = fault::arm(&live.path, Fault::Pause(Arc::clone(&pause)));
    let log = Arc::clone(&live.log);
    let task = tokio::spawn(async move { finish_start(session, Some(log)).await });
    until_parked(&pause, ROW).await;
    assert!(pause.parked(), "{ROW}: parked before abort");
    task.abort();
    tokio::task::yield_now().await;
    assert!(
        pause.parked(),
        "{ROW}: still parked after the finish task was aborted"
    );
    pause.release();
    // Off this thread: the aborted worker may still need this runtime to drive its drains.
    let path = live.path.clone();
    let acquired = tokio::task::spawn_blocking(move || {
        lock::lock_config_blocking_deferred(&path, Instant::now() + Duration::from_secs(30), |_| {})
            .map(drop)
    })
    .await
    .expect(ROW);
    if let Err(error) = acquired {
        panic!("{ROW}: 30s acquire after cancel got {error:?}");
    }
    let again = must_prepare(&live.path, ROW).await;
    let finished = finish_start(again, Some(Arc::clone(&live.log))).await;
    assert_eq!(finished, Ok(()), "{ROW}: a fresh start finishes");
    expect_staged_owed(&live.records(), &token, ROW);
    free(&live.path, ROW);
}

/// GATE.4: a P2 refusal logs the journal path and `OtherLog`; `Display` stays the fixed sentence.
#[tokio::test(flavor = "current_thread")]
async fn refusal_logs_path_and_cause() {
    const ROW: &str = "refusal_logs_path_and_cause";
    let live = Live::new();
    let other = Live::new();
    drop(live.seed(state(&live.resolved), ROW));
    let session = must_prepare(&live.path, ROW).await;
    let journal = live.resolved.join(JOURNAL);
    let (guard, buffer) = capture();
    let error = finish_start(session, Some(Arc::clone(&other.log)))
        .await
        .expect_err(ROW);
    let text = String::from_utf8_lossy(&buffer.lock().expect(ROW)).into_owned();
    drop(guard);
    let journal_text = journal.display().to_string();
    assert_eq!(
        lines_naming(&text, &journal_text, "OtherLog"),
        1,
        "{ROW}: one captured line names {journal_text} and OtherLog; captured {text:?}"
    );
    assert_eq!(error, StartError::JournalPending, "{ROW}: JournalPending");
    assert_eq!(
        error.to_string(),
        SENTENCE,
        "{ROW}: Display is the fixed sentence, with no path"
    );
    // A held lock is logged too: the configured path, and Busy as the cause.
    let held_lock = match lock::lock_config_blocking_deferred(&live.path, Instant::now(), |_| {}) {
        Ok(held_lock) => held_lock,
        Err(error) => panic!("{ROW}: the test takes the free lock, got {error:?}"),
    };
    let (guard, buffer) = capture();
    let busy = prepare_start_within(&live.path, Duration::ZERO)
        .await
        .map(drop);
    let text = String::from_utf8_lossy(&buffer.lock().expect(ROW)).into_owned();
    drop(guard);
    drop(held_lock);
    assert_eq!(busy, Err(StartError::Busy), "{ROW}: Busy while held");
    let config_text = live.path.display().to_string();
    assert_eq!(
        lines_naming(&text, &config_text, "Busy"),
        1,
        "{ROW}: one captured line names {config_text} and Busy; captured {text:?}"
    );
}
