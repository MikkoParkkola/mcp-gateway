// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Delivery rows collect every case before reporting the row's failures.

use std::sync::Arc;

use super::super::fixtures::{bytes, collect_case, decision};
use super::super::observe::{self, Event};
use super::super::{IntentId, JournalError, ParkReason, ResultClass};
use super::fault::{self, At, Fault};
use super::fixtures::{
    Live, OUTCOME, SAVE, WRITER, actor, attributed, decided, payload, reread, retry, runtime,
    staged, state, state_of, terminal_count,
};
use crate::config_persistence::crash_fs::{self, Mode};
use crate::config_persistence::journal;
use crate::config_persistence::journal::drain::{DrainError, JournalDrain};
use crate::config_persistence::lock;
use crate::security::transparency_log::rotation::WriteFault;
#[cfg(unix)]
use crate::security::transparency_log::rotation::syncs_of;
use crate::security::transparency_log::settle::Reason;

#[test]
fn journal_first_intent() {
    const ROW: &str = "journal_first_intent";
    let mut failures = Vec::new();
    let expected = "verified frozen actor; append before flag";
    collect_case(&mut failures, ROW, "actor_and_ack", expected, || {
        let live = Live::new();
        let mut initial = state(&live.resolved);
        attributed(&mut initial);
        let mut owner = live.seed(initial, ROW);
        let durable = bytes(&live.path);
        let watching = observe::watch(&live.path);
        let armed = crash_fs::arm_config(&live.path);
        let delivered = runtime(JournalDrain::deliver(&mut owner, &live.log));
        assert_eq!(delivered, Ok(()), "{ROW}: seeded intent must be delivered");
        let trace = observe::events(&live.path);
        assert_eq!(
            trace,
            vec![Event::BStarted, Event::IntentAppended, Event::FlagSynced],
            "{ROW}: acknowledgement precedes durable flag"
        );
        assert!(!durable.is_empty(), "{ROW}: seeded owner predates B");
        crash_fs::cut(&live.resolved, Mode::DropAll);
        drop(armed);
        reread(&mut owner);
        let writer = state_of(&owner).writer.as_ref().expect(ROW);
        assert!(
            writer.intent.delivered && writer.intent_counter.is_some(),
            "{ROW}: acknowledgement and flag survive immediate power loss"
        );
        let records = live.records();
        let intent = records.iter().find(|record| record["token"] == WRITER);
        assert!(
            intent.is_some(),
            "{ROW}: verified log contains writer intent"
        );
        let intent = intent.expect(ROW);
        assert_eq!(
            intent["who"],
            serde_json::to_value(actor()).expect(ROW),
            "{ROW}: complete frozen non-empty actor, never gateway actor"
        );
        assert_eq!(
            intent["who"]["principal"], "0123ab45cd67",
            "{ROW}: principal retained"
        );
        assert!(
            intent.get("subject").is_none(),
            "{ROW}: no envelope subject"
        );
        live.verify(ROW);
        drop(watching);
        Ok(())
    });
    collect_case(
        &mut failures,
        ROW,
        "sink_contract",
        "actor-only typed sink appends",
        || {
            super::delivery_cases::sink_contract(ROW);
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn audit_sync_failure_not_acknowledged() {
    const ROW: &str = "audit_sync_failure_not_acknowledged";
    let mut failures = Vec::new();
    collect_case(
        &mut failures,
        ROW,
        "sync_error_keeps_flag_unset",
        "append sync failure: no delivered flag, retry lands once",
        || {
            let live = Live::new();
            let mut initial = state(&live.resolved);
            attributed(&mut initial);
            let mut owner = live.seed(initial, ROW);
            live.log.arm_write_fault(Some(WriteFault::SyncError));
            let failed = runtime(JournalDrain::deliver(&mut owner, &live.log));
            assert!(failed.is_err(), "{ROW}: failed sync is not acknowledged");
            reread(&mut owner);
            let writer = state_of(&owner).writer.as_ref().expect(ROW);
            assert!(
                !writer.intent.delivered,
                "{ROW}: no delivered flag without a synced append"
            );
            live.log.arm_write_fault(None);
            #[cfg(unix)]
            let synced = syncs_of(&live.log_path);
            retry(&mut owner, &live, ROW);
            #[cfg(unix)]
            assert!(
                syncs_of(&live.log_path) > synced,
                "{ROW}: the acknowledged append really synced the file"
            );
            let writer = state_of(&owner).writer.as_ref().expect(ROW);
            assert!(writer.intent.delivered, "{ROW}: retry delivers");
            let intents = live
                .records()
                .iter()
                .filter(|record| record["token"] == WRITER)
                .count();
            assert_eq!(intents, 1, "{ROW}: one logical intent after retry");
            live.verify(ROW);
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

/// A disk-full rebuild can adopt a replaced log after the binding was
/// checked; the receipt then names another log and must not be accepted.
#[cfg(unix)]
#[test]
fn foreign_receipt_is_not_acknowledged() {
    const ROW: &str = "foreign_receipt_is_not_acknowledged";
    let mut failures = Vec::new();
    collect_case(
        &mut failures,
        ROW,
        "log_replaced_during_disk_full_rebuild",
        "OtherLog, no delivered flag, original binding retained",
        || {
            let live = Live::new();
            let foreign = Live::new();
            let mut initial = state(&live.resolved);
            attributed(&mut initial);
            let mut owner = live.seed(initial, ROW);
            let swap = live.log_path.with_extension("swap");
            let (source, target) = (foreign.log_path.clone(), live.log_path.clone());
            live.log
                .arm_write_fault(Some(WriteFault::FullUntilReserveFreed));
            live.log.arm_after_partial_write(Some(Box::new(move || {
                std::fs::copy(&source, &swap).expect("copy the other log");
                std::fs::rename(&swap, &target).expect("replace the active log");
            })));
            let got = runtime(JournalDrain::deliver(&mut owner, &live.log));
            assert_eq!(
                got,
                Err(DrainError::OtherLog),
                "{ROW}: a receipt for another log is refused"
            );
            assert!(
                live.records()
                    .iter()
                    .all(|record| record["token"] != WRITER),
                "{ROW}: nothing was written to the log that took its place"
            );
            assert_eq!(
                live.records().len(),
                foreign.records().len(),
                "{ROW}: the replacing log gained no record"
            );
            reread(&mut owner);
            let writer = state_of(&owner).writer.as_ref().expect(ROW);
            assert!(
                !writer.intent.delivered,
                "{ROW}: no delivered flag for a foreign acknowledgement"
            );
            assert_eq!(
                state_of(&owner).binding,
                Some(live.log.log_id()),
                "{ROW}: original binding retained"
            );
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn journal_persist_uncertainty() {
    const ROW: &str = "journal_persist_uncertainty";
    let mut failures = Vec::new();
    let expected = "Persist, frozen decision survives";
    collect_case(
        &mut failures,
        ROW,
        "rename_without_directory_sync",
        expected,
        || {
            let live = Live::new();
            let mut owner = live.seed(state(&live.resolved), ROW);
            let armed = fault::arm(&live.path, Fault::Fail(At::BeforeDecisionSync));
            let choice = decision(ResultClass::NotWritten, Reason::Refused);
            let got = owner
                .journal
                .as_mut()
                .expect(ROW)
                .decide(&IntentId(WRITER.into()), choice.clone());
            assert_eq!(
                got,
                Err(JournalError::Persist),
                "{ROW}: failed directory sync is not acknowledged"
            );
            assert_eq!(
                fault::fired(&live.path),
                1,
                "{ROW}: decision-sync fault reached once"
            );
            let candidate = bytes(&live.path);
            drop(armed);
            reread(&mut owner);
            assert_eq!(
                bytes(&live.path),
                candidate,
                "{ROW}: reopened candidate bytes retained"
            );
            assert_eq!(
                state_of(&owner).writer.as_ref().expect(ROW).decision,
                Some(choice.clone()),
                "{ROW}: possibly landed decision retained after reopen"
            );
            for _ in 0..2 {
                super::delivery_cases::retained_retry(&mut owner, &live, &choice, ROW);
            }
            assert_eq!(
                terminal_count(&live.records(), WRITER),
                1,
                "{ROW}: no second terminal content"
            );
            assert!(!candidate.is_empty(), "{ROW}: retained candidate bytes");
            live.verify(ROW);
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn overwrite_decision_reopen() {
    const ROW: &str = "overwrite_decision_reopen";
    let mut failures = Vec::new();
    for reason in [Reason::Moved, Reason::NothingPending, Reason::WriterDied] {
        let expected = "ChangedDecision; original delivered";
        collect_case(&mut failures, ROW, &format!("{reason:?}"), expected, || {
            let live = Live::new();
            let mut initial = state(&live.resolved);
            decided(&mut initial);
            let mut owner = live.seed(initial, ROW);
            reread(&mut owner);
            let before = bytes(&live.path);
            let got = owner.journal.as_mut().expect(ROW).decide(
                &IntentId(WRITER.into()),
                decision(ResultClass::NotWritten, reason),
            );
            assert_eq!(
                got,
                Err(JournalError::ChangedDecision),
                "{ROW}: reopened decision is immutable"
            );
            assert_eq!(
                bytes(&live.path),
                before,
                "{ROW}: persisted bytes unchanged"
            );
            retry(&mut owner, &live, ROW);
            let records = live.records();
            let terminal = records
                .iter()
                .find(|r| r["event"] == "config_write_outcome");
            assert!(
                terminal.is_some(),
                "{ROW}: original terminal delivered on drain"
            );
            assert_eq!(
                terminal.expect(ROW)["reason"],
                "refused",
                "{ROW}: original reason retained"
            );
            live.verify(ROW);
            Ok(())
        });
    }
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn invalid_record_is_parked() {
    const ROW: &str = "invalid_record_is_parked";
    let mut failures = Vec::new();
    for invalid in [
        br#"{"kind":17}"#.as_slice(),
        br#"{"kind":"plain.save"}"#.as_slice(),
    ] {
        let case = String::from_utf8_lossy(invalid);
        let expected = "one Invalid, durable park, lock refused";
        collect_case(&mut failures, ROW, &case, expected, || {
            let live = Live::new();
            let mut initial = state(&live.resolved);
            initial.writer.as_mut().expect(ROW).intent.payload_json = invalid.to_vec();
            let mut owner = live.seed(initial, ROW);
            let watching = observe::watch(&live.path);
            let first = runtime(JournalDrain::deliver(&mut owner, &live.log));
            assert_eq!(
                first,
                Err(DrainError::Parked),
                "{ROW}: B Invalid parks record"
            );
            reread(&mut owner);
            let second = runtime(JournalDrain::deliver(&mut owner, &live.log));
            assert_eq!(
                second,
                Err(DrainError::Parked),
                "{ROW}: reopened parked record never resent"
            );
            let writer = state_of(&owner).writer.as_ref().expect(ROW);
            assert_eq!(
                writer.intent.parked,
                Some(ParkReason::InvalidPayload),
                "{ROW}: park persisted"
            );
            assert_eq!(
                writer.intent.payload_json, invalid,
                "{ROW}: rejected bytes immutable"
            );
            assert!(
                !writer.intent.delivered
                    && writer.intent_counter.is_none()
                    && writer.decision.is_none(),
                "{ROW}: zero flags, counters or terminal claims"
            );
            assert_eq!(
                observe::events(&live.path)
                    .iter()
                    .filter(|e| **e == Event::BInvalid)
                    .count(),
                1,
                "{ROW}: exactly one B Invalid call"
            );
            assert!(
                lock::refuse_pending_v2(&owner.locked).is_err(),
                "{ROW}: pending invalid owner refuses lock"
            );
            assert!(
                live.records().iter().all(|r| r["token"] != WRITER),
                "{ROW}: nothing appended"
            );
            drop(watching);
            Ok(())
        });
    }
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn wrong_log_is_not_rebound() {
    const ROW: &str = "wrong_log_is_not_rebound";
    let mut failures = Vec::new();
    collect_case(
        &mut failures,
        ROW,
        "foreign_logger",
        "OtherLog and immutable owner",
        || {
            let live = Live::new();
            let foreign = Live::new();
            let owner = live.seed(state(&live.resolved), ROW);
            let before = bytes(&live.path);
            let log_before = std::fs::read(&foreign.log_path).unwrap_or_default();
            let result = runtime(JournalDrain::run(owner, Some(Arc::clone(&foreign.log))));
            assert!(
                matches!(&result, Err(failure) if failure.error == DrainError::OtherLog),
                "{ROW}: drain refuses the other log"
            );
            let failure = result.err().expect(ROW);
            assert_eq!(
                state_of(&failure.session).binding,
                Some(live.log.log_id()),
                "{ROW}: original binding retained"
            );
            assert_eq!(bytes(&live.path), before, "{ROW}: journal bytes unchanged");
            assert_eq!(
                std::fs::read(&foreign.log_path).unwrap_or_default(),
                log_before,
                "{ROW}: no M records"
            );
            assert!(
                journal::journal_path(&live.path).exists(),
                "{ROW}: owner retained"
            );
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "foreign_logger_before_repair",
        "OtherLog refuses before any repair work",
        || {
            let live = Live::new();
            let foreign = Live::new();
            let mut initial = state(&live.resolved);
            staged(&mut initial);
            let owner = live.seed(initial, ROW);
            let before = bytes(&live.path);
            let journal_before = std::fs::read(journal::journal_path(&live.path)).expect(ROW);
            let result = runtime(JournalDrain::run(owner, Some(Arc::clone(&foreign.log))));
            assert!(
                matches!(&result, Err(failure) if failure.error == DrainError::OtherLog),
                "{ROW}: a repairable owner still refuses the other log first"
            );
            assert_eq!(bytes(&live.path), before, "{ROW}: config bytes unchanged");
            assert_eq!(
                std::fs::read(journal::journal_path(&live.path)).expect(ROW),
                journal_before,
                "{ROW}: no recovery attempt written before the refusal"
            );
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "missing_logger",
        "NoLogger retains the owner",
        || {
            let live = Live::new();
            let owner = live.seed(state(&live.resolved), ROW);
            let before = bytes(&live.path);
            let result = runtime(JournalDrain::run(owner, None));
            assert!(
                matches!(&result, Err(failure) if failure.error == DrainError::NoLogger),
                "{ROW}: a bound owner cannot drain without its logger"
            );
            assert_eq!(
                bytes(&live.path),
                before,
                "{ROW}: missing logger preserves journal"
            );
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn late_journal_retry() {
    const ROW: &str = "late_journal_retry";
    let mut failures = Vec::new();
    collect_case(
        &mut failures,
        ROW,
        "old_owner",
        "same role keys and bytes without TTL",
        || {
            let live = Live::new();
            let mut initial = state(&live.resolved);
            decided(&mut initial);
            let mut owner = live.seed(initial, ROW);
            let path = journal::journal_path(&live.path);
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .expect(ROW);
            let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(946_684_800);
            file.set_times(std::fs::FileTimes::new().set_modified(old))
                .expect(ROW);
            reread(&mut owner);
            retry(&mut owner, &live, ROW);
            reread(&mut owner);
            retry(&mut owner, &live, ROW);
            let records = live.records();
            assert!(
                records
                    .iter()
                    .any(|r| r["token"] == WRITER && r["event"] == "config_save_intent"),
                "{ROW}: intent role retained despite age"
            );
            assert_eq!(
                terminal_count(&records, WRITER),
                1,
                "{ROW}: one logical terminal after equal repeats"
            );
            for record in records.iter().filter(|r| r["token"] == WRITER) {
                let expected = if record["event"] == "config_save_intent" {
                    SAVE
                } else {
                    OUTCOME
                };
                for (key, value) in payload(expected) {
                    assert_eq!(
                        record[&key], value,
                        "{ROW}: immutable caller bytes for {key}"
                    );
                }
            }
            let writer = state_of(&owner).writer.as_ref().expect(ROW);
            assert_eq!(
                writer.intent.payload_json, SAVE,
                "{ROW}: frozen intent bytes retained"
            );
            assert_eq!(
                writer.records[0].payload_json, OUTCOME,
                "{ROW}: frozen outcome bytes retained"
            );
            live.verify(ROW);
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "finish_only",
        "Finish failure never repeats A or B",
        || {
            super::delivery_cases::finish_only(ROW);
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}
