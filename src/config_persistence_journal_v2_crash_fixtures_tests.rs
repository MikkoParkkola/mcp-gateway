// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Crash runners preserve page-cache evidence and recover in a new process.

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::super::fixtures::{NEW, OLD, collect_case, decision};
use super::super::observe;
use super::super::{Fact, IntentId, Pending, Phase, ResultClass};
use super::JournalDrain;
use super::fault::{self, At, Fault};
use super::fixtures::{
    ATTEMPT, Live, WRITER, acquire, attempt, decided, payload, record, records_at, reopen,
    replace_bytes, runtime, staged, state, state_of, terminal_count,
};
use crate::config_persistence::commit::{Action, FileRevision, SyncKey};
use crate::config_persistence::crash_fs::{self, Mode};
use crate::config_persistence::journal::{self, fault as a_fault};
use crate::config_persistence::lock;
use crate::security::transparency_log::settle::{Reason, Role};
use crate::security::transparency_log::{
    TransparencyLogConfig, TransparencyLogger, VerifyMode, verify_audit_log,
};

pub(super) const ATTEMPT_OUTCOME: &[u8] =
    br#"{"intent_counter":4,"kind":"settle.recovery","reason":"rolled_back","result":"written"}"#;
pub(super) const WRITER_OUTCOME: &[u8] = concat!(
    r#"{"intent_counter":3,"kind":"settle.save","reason":"rolled_back","result":"not_written","#,
    r#""settled_by":{"intent_counter":4,"token":"attempt-1"}}"#,
)
.as_bytes();

pub(super) fn setup(live: &Live, row: &str) -> super::DrainSession {
    let mut initial = state(live.dir.path());
    staged(&mut initial);
    replace_bytes(&live.path, NEW);
    if matches!(
        row,
        "crash_d2" | "crash_d3" | "crash_d4" | "crash_d5" | "crash_d8"
    ) {
        initial.attempts.push(attempt());
    }
    if row == "crash_d4" {
        initial.fact = Some(Fact::RolledBack(FileRevision::of(OLD)));
        replace_bytes(&live.path, OLD);
        let writer = initial.writer.as_mut().expect(row);
        writer.intent_counter = Some(3);
        writer.intent.delivered = true;
        let mut choice = decision(ResultClass::NotWritten, Reason::RolledBack);
        choice.settled_by = Some(IntentId(ATTEMPT.into()));
        writer.decision = Some(choice);
        writer.records = vec![record(Role::Outcome, WRITER_OUTCOME, WRITER_OUTCOME_DIGEST)];
        let attempt = &mut initial.attempts[0];
        attempt.intent_counter = Some(4);
        attempt.intent.delivered = true;
        attempt.decision = Some(decision(ResultClass::Written, Reason::RolledBack));
        attempt.records = vec![record(
            Role::Outcome,
            ATTEMPT_OUTCOME,
            ATTEMPT_OUTCOME_DIGEST,
        )];
    }
    if row != "crash_d7" {
        let writer = initial.writer.as_mut().expect(row);
        writer.intent_counter = Some(3);
        writer.intent.delivered = true;
    }
    if row == "crash_d5" {
        initial.fact = None;
        initial.pending = Some(Pending {
            action: Action::Restore,
            expected: FileRevision::of(OLD),
            pre_action: FileRevision::of(NEW),
            tried: true,
        });
    }
    if row == "crash_d7" {
        initial.phase = Phase::Intended;
        initial.fact = Some(Fact::Untouched);
        decided(&mut initial);
        replace_bytes(&live.path, OLD);
    }
    live.seed(initial, row)
}

pub(super) fn projections(failures: &mut Vec<String>, row: &str, at: At) {
    for mode in [
        Mode::DropAll,
        Mode::KeepAll,
        Mode::KeepRenameDropData { seed: 7 },
    ] {
        let expected = "one real seam; durable owner; convergent retry";
        collect_case(
            failures,
            row,
            &format!("projection_{mode:?}"),
            expected,
            || {
                let live = Live::new();
                let mut owner = setup(&live, row);
                let watch = observe::watch(&live.path);
                let overlay = crash_fs::arm_config(&live.path);
                let armed = fault::arm(&live.path, Fault::Cut(at, mode));
                let a_failure = restore_sync_fault(&live.path, row);
                if at == At::AttemptPersisted {
                    let _ = JournalDrain::recovery_intent(&mut owner, true, false);
                } else {
                    let _ = JournalDrain::repair(&mut owner, false);
                    let _ = runtime(JournalDrain::deliver(&mut owner, &live.log));
                }
                let fired = fault::fired(&live.path);
                let events = observe::events(&live.path);
                drop(a_failure);
                drop(armed);
                drop(overlay);
                assert_eq!(fired, 1, "{row}: cut boundary reached exactly once");
                assert_eq!(
                    events.iter().filter(|e| **e == fault::event(at)).count(),
                    1,
                    "{row}: observe confirms real boundary"
                );
                assert!(
                    journal::journal_path(&live.path).exists(),
                    "{row}: durable journal owns every token"
                );
                drop(owner);
                let owner = reopen(acquire(&live.path));
                let result = runtime(JournalDrain::run(owner, Some(Arc::clone(&live.log))));
                assert!(result.is_ok(), "{row}: recovery after projection succeeds");
                assert_eq!(
                    std::fs::read(&live.path).expect(row),
                    OLD,
                    "{row}: repaired original in every mode"
                );
                assert!(
                    !journal::journal_path(&live.path).exists(),
                    "{row}: all flags permit finish"
                );
                assert_eq!(
                    terminal_count(&live.records(), WRITER),
                    1,
                    "{row}: writer has one logical terminal"
                );
                accounted(&live.records(), row);
                live.verify(row);
                drop(watch);
                Ok(())
            },
        );
    }
}

pub(super) fn restore_sync_fault(path: &Path, row: &str) -> Option<a_fault::Armed> {
    (row == "crash_d5").then(|| {
        a_fault::set(
            path,
            a_fault::Fault::FailDirSync(SyncKey::Commit(Action::Restore)),
        )
    })
}

#[cfg(unix)]
pub(super) fn child(row: &str, at: At) -> bool {
    let Some(directory) = std::env::var_os("S6A2_CHILD_DIR") else {
        return false;
    };
    let directory = std::path::PathBuf::from(directory);
    let path = directory.join("gateway.yaml");
    let owner = reopen(acquire(&path));
    let config = Arc::new(TransparencyLogConfig {
        enabled: true,
        path: directory.join("audit.jsonl").to_string_lossy().into_owned(),
        key_id: "s6a2-fixture".into(),
        ..Default::default()
    });
    // This directory belongs to the parent process, which outlives this child.
    let log = Arc::new(TransparencyLogger::open(config).expect(row));
    let recover = std::env::var_os("S6A2_RECOVER").is_some();
    let overlay = crash_fs::arm_config(&path);
    let watch = observe::watch(&path);
    let armed = (!recover).then(|| fault::arm(&path, Fault::Kill(at)));
    let a_failure = (!recover).then(|| restore_sync_fault(&path, row));
    let result = runtime(JournalDrain::run(owner, Some(log)));
    if recover {
        assert!(result.is_ok(), "{row}: child recovery completes");
    }
    drop((a_failure, armed, overlay, watch));
    true
}

#[cfg(unix)]
pub(super) fn killed(failures: &mut Vec<String>, row: &str, at: At) {
    let expected = "SIGABRT at exact seam; new-process recovery";
    collect_case(failures, row, "subprocess_kill", expected, || {
        use std::os::unix::process::ExitStatusExt as _;
        let live = Live::new();
        let owner = setup(&live, row);
        drop(owner);
        let path = live.path.clone();
        let config = Arc::clone(&live.config);
        let log_path = live.log_path.clone();
        let dir = Arc::clone(&live.dir);
        drop(live);
        let status = subprocess(row, dir.path(), false);
        assert_eq!(
            status.signal(),
            Some(6),
            "{row}: child aborted at requested boundary {at:?}"
        );
        assert_eq!(
            std::fs::read(path.with_extension("s6a2-seam"))
                .ok()
                .as_deref(),
            Some(b"1".as_slice()),
            "{row}: kill seam fired exactly once"
        );
        let recovered_attempts = inspect_crash(&path, &log_path, &config, row);
        assert!(
            subprocess(row, dir.path(), true).success(),
            "{row}: recovery succeeds in new process"
        );
        assert_eq!(
            std::fs::read(&path).expect(row),
            OLD,
            "{row}: original bytes after recovery"
        );
        assert!(
            !journal::journal_path(&path).exists() && !journal::original_path(&path).exists(),
            "{row}: owner artifacts removed only after all flags"
        );
        let records = records_at(&log_path);
        accounted(&records, row);
        assert_eq!(
            terminal_count(&records, WRITER),
            1,
            "{row}: writer terminal once after equal collapse"
        );
        for token in recovered_attempts {
            assert_eq!(
                terminal_count(&records, &token.0),
                1,
                "{row}: same attempt token reaches one terminal"
            );
        }
        if row == "crash_d4" {
            let writer = records
                .iter()
                .find(|r| r["token"] == WRITER && r["event"] == "config_write_outcome")
                .expect(row);
            assert_eq!(
                writer["settled_by"],
                payload(WRITER_OUTCOME)["settled_by"],
                "{row}: writer references attempt intent counter"
            );
        }
        assert!(
            verify_audit_log(&log_path, &config, VerifyMode::Live, None).is_ok_and(|v| v.ok),
            "{row}: final chain and pairing pass"
        );
        Ok(())
    });
}

#[cfg(unix)]
fn subprocess(row: &str, dir: &Path, recover: bool) -> std::process::ExitStatus {
    let mut command = std::process::Command::new(std::env::current_exe().expect(row));
    command
        .arg("--exact")
        .arg(format!(
            "config_persistence::journal::v2::drain::crash_tests::{row}"
        ))
        .arg("--nocapture")
        .env("S6A2_CHILD_DIR", dir);
    if recover {
        command.env("S6A2_RECOVER", "1");
    } else {
        command.env_remove("S6A2_RECOVER");
    }
    let mut child = command.spawn().expect(row);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect(row) {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().expect(row);
            let status = child.wait().expect(row);
            panic!("{row}: subprocess deadline: {status}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

const WRITER_OUTCOME_DIGEST: &str =
    "15645b8ce6c321bec6f6dcc542244a1efe55d25aade1ce4f944f05f290d4afa1";

const ATTEMPT_OUTCOME_DIGEST: &str =
    "7c64b592accea35171745ce5dd061cafa03be59c2b7d8c7111706da491ef86a2";

#[cfg(unix)]
fn inspect_crash(
    path: &Path,
    log_path: &Path,
    config: &TransparencyLogConfig,
    row: &str,
) -> Vec<IntentId> {
    let locked = acquire(&path);
    let before = reopen(locked);
    let recovered_attempts: Vec<_> = state_of(&before)
        .attempts
        .iter()
        .map(|a| a.intent_id.clone())
        .collect();
    assert!(
        !recovered_attempts.is_empty() || row == "crash_d7",
        "{row}: persisted attempt owns repair"
    );
    assert!(
        journal::journal_path(&path).exists(),
        "{row}: donor journal survives kill"
    );
    let verdict = verify_audit_log(&log_path, &config, VerifyMode::Live, None);
    if row == "crash_d7" {
        let raw = std::fs::read(&log_path).expect(row);
        assert!(
            raw.ends_with(b"{\"event\":"),
            "{row}: real invalid partial bytes observed before reopen"
        );
        assert!(
            !verdict.as_ref().is_ok_and(|v| v.ok),
            "{row}: torn tail is visible to reader"
        );
    } else {
        assert!(
            verdict.is_ok_and(|v| v.ok),
            "{row}: reader verdict before recovery"
        );
    }
    if row == "crash_d5" {
        assert!(
            lock::refuse_pending_v2(&before.locked).is_err(),
            "{row}: unresolved Restore refuses next writer"
        );
        assert!(
            state_of(&before).pending.is_some(),
            "{row}: no terminal guessed from Sync"
        );
    }
    if matches!(row, "crash_d3" | "crash_d4") {
        let mut expected = decision(ResultClass::NotWritten, Reason::RolledBack);
        expected.settled_by = Some(IntentId(ATTEMPT.into()));
        assert_eq!(
            state_of(&before).writer.as_ref().expect(row).decision,
            Some(expected),
            "{row}: writer decision retained without recomputation"
        );
        assert_eq!(
            state_of(&before).attempts[0].decision,
            Some(decision(ResultClass::Written, Reason::RolledBack)),
            "{row}: attempt decision retained without recomputation"
        );
    }
    if row == "crash_d2" {
        assert_eq!(
            state_of(&before).attempts[0].intent.payload_json,
            super::fixtures::RECOVERY,
            "{row}: attempt caller bytes frozen across append uncertainty"
        );
    }
    drop(before);
    recovered_attempts
}

pub(super) fn accounted(records: &[Value], row: &str) {
    let mut seen = std::collections::BTreeMap::new();
    for record in records.iter().filter(|r| r["token"].is_string()) {
        let token = record["token"].as_str().expect(row);
        let event = record["event"].as_str().expect(row);
        let content: Vec<_> = [
            "kind",
            "intent_counter",
            "result",
            "reason",
            "settled_by",
            "settles",
            "root",
            "at_start",
            "who",
        ]
        .into_iter()
        .map(|key| record[key].clone())
        .collect();
        if let Some(previous) = seen.insert((token, event), content.clone()) {
            assert_eq!(
                previous, content,
                "{row}: physical retries have identical caller/actor content"
            );
        }
        assert_eq!(
            terminal_count(records, token),
            1,
            "{row}: every live token has one terminal"
        );
    }
    if row == "crash_d1" {
        let attempts = seen
            .keys()
            .filter(|(_, event)| *event == "config_recovery_intent")
            .count();
        assert_eq!(
            attempts, 1,
            "{row}: recovery reuses the sole persisted attempt"
        );
    }
    if matches!(row, "crash_d3" | "crash_d4") {
        for (token, literal) in [(WRITER, WRITER_OUTCOME), (ATTEMPT, ATTEMPT_OUTCOME)] {
            let terminal = records
                .iter()
                .find(|r| r["token"] == token && r["event"] == "config_write_outcome");
            assert!(
                terminal.is_some(),
                "{row}: both immutable decisions delivered"
            );
            for (key, expected) in payload(literal) {
                assert_eq!(
                    terminal.expect(row)[&key],
                    expected,
                    "{row}: immutable terminal field {key}"
                );
            }
        }
    }
}
