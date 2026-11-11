// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! D1 through D8 keep their design names and report independent cases.

use std::sync::Arc;
use std::time::{Duration, Instant};

use super::super::fixtures::{NEW, OLD, collect_case};
use super::super::observe::{self, Event};
use super::crash_fixtures::{self, setup};
use super::fault::{self, At, Fault, Pause};
use super::fixtures::{
    Live, OUTCOME, WRITER, accepted, decided, replace_bytes, reread, retry, runtime, state,
    state_of, terminal_count,
};
use super::{DrainError, JournalDrain};
use crate::config_persistence::crash_fs::{self, Mode};
use crate::config_persistence::journal;
use crate::config_persistence::lock::{self, NotLocked};
use crate::security::transparency_log::settle::FailSettle;

#[cfg(unix)]
#[test]
fn crash_d1() {
    const ROW: &str = "crash_d1";
    if crash_fixtures::child(ROW, At::AttemptPersisted) {
        return;
    }
    let mut failures = Vec::new();
    crash_fixtures::killed(&mut failures, ROW, At::AttemptPersisted);
    crash_fixtures::projections(&mut failures, ROW, At::AttemptPersisted);
    let expected = "persist/reuse exactly one attempt before repair";
    collect_case(&mut failures, ROW, "reuse_attempt", expected, || {
        let live = Live::new();
        let mut owner = setup(&live, ROW);
        let first = JournalDrain::recovery_intent(&mut owner, true, false);
        assert!(
            matches!(&first, Ok(Some(_))),
            "{ROW}: owed repair persists an attempt"
        );
        reread(&mut owner);
        let second = JournalDrain::recovery_intent(&mut owner, true, false);
        assert_eq!(
            first, second,
            "{ROW}: same persisted token reused after reopen"
        );
        assert_eq!(
            state_of(&owner).attempts.len(),
            1,
            "{ROW}: exactly one attempt"
        );
        Ok(())
    });
    collect_case(
        &mut failures,
        ROW,
        "accepted_delivery_only",
        "zero attempts without repair",
        || {
            let live = Live::new();
            let mut initial = state(live.dir.path());
            accepted(&mut initial);
            replace_bytes(&live.path, NEW);
            let mut owner = live.seed(initial, ROW);
            assert_eq!(
                JournalDrain::recovery_intent(&mut owner, false, false),
                Ok(None),
                "{ROW}: accepted delivery-only creates no attempt"
            );
            let result = runtime(JournalDrain::run(owner, Some(Arc::clone(&live.log))));
            assert!(
                result.is_ok(),
                "{ROW}: accepted delivery-only drain succeeds"
            );
            assert!(
                live.records()
                    .iter()
                    .all(|r| r["event"] != "config_recovery_intent"),
                "{ROW}: zero attempt intents for delivery-only owner"
            );
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[cfg(unix)]
#[test]
fn crash_d2() {
    const ROW: &str = "crash_d2";
    if crash_fixtures::child(ROW, At::IntentAppended) {
        return;
    }
    let mut failures = Vec::new();
    crash_fixtures::killed(&mut failures, ROW, At::IntentAppended);
    crash_fixtures::projections(&mut failures, ROW, At::IntentAppended);
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[cfg(unix)]
#[test]
fn crash_d3() {
    const ROW: &str = "crash_d3";
    if crash_fixtures::child(ROW, At::DecisionPersisted) {
        return;
    }
    let mut failures = Vec::new();
    crash_fixtures::killed(&mut failures, ROW, At::DecisionPersisted);
    crash_fixtures::projections(&mut failures, ROW, At::DecisionPersisted);
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[cfg(unix)]
#[test]
fn crash_d4() {
    const ROW: &str = "crash_d4";
    if crash_fixtures::child(ROW, At::OutcomeAppended) {
        return;
    }
    let mut failures = Vec::new();
    crash_fixtures::killed(&mut failures, ROW, At::OutcomeAppended);
    crash_fixtures::projections(&mut failures, ROW, At::OutcomeAppended);
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[cfg(unix)]
#[test]
fn crash_d5() {
    const ROW: &str = "crash_d5";
    if crash_fixtures::child(ROW, At::DeferredFlagged) {
        return;
    }
    let mut failures = Vec::new();
    crash_fixtures::killed(&mut failures, ROW, At::DeferredFlagged);
    crash_fixtures::projections(&mut failures, ROW, At::DeferredFlagged);
    collect_case(
        &mut failures,
        ROW,
        "restore_sync",
        "Sync leaves pending, no guessed proof",
        || {
            let live = Live::new();
            let mut owner = setup(&live, ROW);
            let armed = crash_fixtures::restore_sync_fault(&live.path, ROW);
            let result = JournalDrain::repair(&mut owner, false);
            assert!(
                matches!(result, Err(DrainError::RepairPending)),
                "{ROW}: Restore Sync leaves repair pending"
            );
            assert_eq!(
                journal::fault::fired(&live.path),
                1,
                "{ROW}: A sync seam fired"
            );
            assert!(
                state_of(&owner).pending.is_some() && state_of(&owner).fact.is_none(),
                "{ROW}: no fact without CommitToken"
            );
            assert!(
                state_of(&owner)
                    .writer
                    .as_ref()
                    .expect(ROW)
                    .decision
                    .is_none(),
                "{ROW}: no writer terminal guessed"
            );
            assert!(
                lock::refuse_pending_v2(&owner.locked).is_err(),
                "{ROW}: next writer refused"
            );
            drop(armed);
            let repaired = runtime(JournalDrain::run(owner, Some(Arc::clone(&live.log))));
            assert!(repaired.is_ok(), "{ROW}: later repair produces terminals");
            assert_eq!(
                std::fs::read(&live.path).expect(ROW),
                OLD,
                "{ROW}: restored original"
            );
            live.verify(ROW);
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn crash_d6() {
    const ROW: &str = "crash_d6";
    let mut failures = Vec::new();
    let expected = "Refused leaves frozen unflagged bytes; retry succeeds";
    collect_case(&mut failures, ROW, "before_append", expected, || {
        let live = Live::new();
        let mut initial = state(live.dir.path());
        decided(&mut initial);
        let mut owner = live.seed(initial, ROW);
        let before = std::fs::read(&live.log_path).expect(ROW);
        let watching = observe::watch(&live.path);
        let overlay = crash_fs::arm_config(&live.path);
        live.log.arm_settle_fault(FailSettle::BeforeAppend);
        let result = runtime(JournalDrain::deliver(&mut owner, &live.log));
        assert_eq!(
            result,
            Err(DrainError::Refused),
            "{ROW}: B BeforeAppend is Refused"
        );
        assert_eq!(
            observe::events(&live.path)
                .iter()
                .filter(|e| **e == Event::BStarted)
                .count(),
            1,
            "{ROW}: exactly one real B call reached the refusal seam"
        );
        assert_eq!(
            std::fs::read(&live.log_path).expect(ROW),
            before,
            "{ROW}: no first-call bytes"
        );
        assert!(
            state_of(&owner)
                .writer
                .as_ref()
                .expect(ROW)
                .records
                .iter()
                .all(|r| !r.delivered),
            "{ROW}: no flag before append"
        );
        crash_fs::cut(live.dir.path(), Mode::DropAll);
        drop(overlay);
        reread(&mut owner);
        retry(&mut owner, &live, ROW);
        assert_eq!(
            state_of(&owner).writer.as_ref().expect(ROW).records[0].payload_json,
            OUTCOME,
            "{ROW}: retry uses exact same payload"
        );
        assert_eq!(
            terminal_count(&live.records(), WRITER),
            1,
            "{ROW}: one logical terminal"
        );
        live.verify(ROW);
        drop(watching);
        Ok(())
    });
    collect_case(
        &mut failures,
        ROW,
        "after_append",
        "Unconfirmed preserves immutable retry",
        || {
            let live = Live::new();
            let mut initial = state(live.dir.path());
            decided(&mut initial);
            let mut owner = live.seed(initial, ROW);
            let before = std::fs::read(&live.log_path).expect(ROW);
            live.log.arm_settle_fault(FailSettle::AfterAppend);
            let result = runtime(JournalDrain::deliver(&mut owner, &live.log));
            assert_eq!(
                result,
                Err(DrainError::Unconfirmed),
                "{ROW}: AfterAppend is not Refused"
            );
            assert_ne!(
                std::fs::read(&live.log_path).expect(ROW),
                before,
                "{ROW}: append may already have landed"
            );
            assert!(
                !state_of(&owner)
                    .writer
                    .as_ref()
                    .expect(ROW)
                    .intent
                    .delivered,
                "{ROW}: unconfirmed intent has no acknowledged flag"
            );
            reread(&mut owner);
            retry(&mut owner, &live, ROW);
            crash_fixtures::accounted(&live.records(), ROW);
            live.verify(ROW);
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[cfg(unix)]
#[test]
fn crash_d7() {
    const ROW: &str = "crash_d7";
    if crash_fixtures::child(ROW, At::AfterTornWrite) {
        return;
    }
    let mut failures = Vec::new();
    crash_fixtures::killed(&mut failures, ROW, At::AfterTornWrite);
    super::torn_cases::cases(&mut failures, ROW);
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn crash_d8() {
    const ROW: &str = "crash_d8";
    let mut failures = Vec::new();
    let expected = "detached task owns lock until completion";
    collect_case(
        &mut failures,
        ROW,
        "cancel_while_repair_paused",
        expected,
        || {
            let live = Live::new();
            let owner = setup(&live, ROW);
            let pause = Arc::new(Pause::default());
            let armed = fault::arm(&live.path, Fault::Pause(Arc::clone(&pause)));
            let watching = observe::watch(&live.path);
            let overlay = crash_fs::arm_config(&live.path);
            runtime(async {
                let task = tokio::spawn(JournalDrain::run(owner, Some(Arc::clone(&live.log))));
                let entered = pause.entered();
                task.abort();
                let _ = task.await;
                if !entered {
                    pause.release();
                }
                assert!(entered, "{ROW}: detached repair reached Pause");
                let competing = lock::lock_config_blocking_deferred(
                    &live.path,
                    Instant::now() + Duration::from_millis(30),
                    |_| {},
                );
                pause.release();
                assert!(
                    matches!(competing, Err(NotLocked::Busy)),
                    "{ROW}: dropping caller cannot unlock running repair"
                );
                let held = lock::lock_config_blocking_deferred(
                    &live.path,
                    Instant::now() + Duration::from_secs(2),
                    |_| {},
                );
                assert!(held.is_ok(), "{ROW}: task eventually releases the lock");
                drop(held);
            });
            assert_eq!(
                fault::fired(&live.path),
                1,
                "{ROW}: pause fired exactly once"
            );
            crash_fs::cut(live.dir.path(), Mode::DropAll);
            drop(overlay);
            assert_eq!(
                std::fs::read(&live.path).expect(ROW),
                OLD,
                "{ROW}: repair fact durable"
            );
            assert!(
                !journal::journal_path(&live.path).exists(),
                "{ROW}: flags durable before finish"
            );
            assert_eq!(
                terminal_count(&live.records(), WRITER),
                1,
                "{ROW}: writer delivered after caller leaves"
            );
            assert_eq!(
                terminal_count(&live.records(), super::fixtures::ATTEMPT),
                1,
                "{ROW}: attempt delivered after caller leaves"
            );
            live.verify(ROW);
            drop((armed, watching));
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}
