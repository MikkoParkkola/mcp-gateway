// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Repair precedence and acquisition dispatch, with independent disk bytes.

use std::sync::Arc;

use super::super::fixtures::{NEW, OLD, bytes, collect_case};
use super::super::observe::{self, Event};
use super::super::{Fact, JournalError, OpenJournal, Pending, Phase};
use super::fixtures::{
    FOREIGN, Live, accepted, replace_bytes, reseed, runtime, staged, state, state_of,
};
use super::{DrainError, JournalDrain};
use crate::config_persistence::commit::{Action, FileRevision};
use crate::config_persistence::journal::{self, Recovered};
use crate::config_persistence::lock;

#[test]
fn phase_fact_precedence() {
    const ROW: &str = "phase_fact_precedence";
    let mut failures = Vec::new();
    for case in [
        "staged_committed",
        "staged_rolled_back",
        "restore_pending",
        "accepted",
    ] {
        collect_case(
            &mut failures,
            ROW,
            case,
            "phase-specific proof and original/new bytes",
            || {
                phase_case(case, ROW);
                Ok(())
            },
        );
    }
    for case in ["v2", "v1", "unknown", "unresolved"] {
        collect_case(
            &mut failures,
            ROW,
            case,
            "version dispatch and unresolved-owner refusal",
            || {
                dispatch_case(case, ROW);
                Ok(())
            },
        );
    }
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

fn phase_case(case: &str, row: &str) {
    let live = Live::new();
    let mut initial = state(live.dir.path());
    staged(&mut initial);
    let expected = if case == "accepted" { NEW } else { OLD };
    match case {
        "staged_rolled_back" => initial.fact = Some(Fact::RolledBack(FileRevision::of(OLD))),
        "restore_pending" => {
            initial.fact = None;
            initial.pending = Some(Pending {
                action: Action::Restore,
                expected: FileRevision::of(OLD),
                pre_action: FileRevision::of(NEW),
                tried: true,
            });
        }
        "accepted" => initial.phase = Phase::Accepted,
        _ => {}
    }
    replace_bytes(
        &live.path,
        if case == "staged_committed" {
            NEW
        } else {
            expected
        },
    );
    let mut owner = live.seed(initial, row);
    let watching = observe::watch(&live.path);
    let before = journal::fault::synced(&live.path);
    let report = JournalDrain::repair(&mut owner, false);
    assert!(report.is_ok(), "{row}: repair returns proven phase result");
    let report = report.ok().expect(row);
    assert_eq!(
        std::fs::read(&live.path).expect(row),
        expected,
        "{row}: phase chooses correct disk bytes"
    );
    match case {
        "staged_committed" | "restore_pending" => {
            assert_eq!(
                report.recovered,
                Recovered::RolledBack,
                "{row}: restore proved original"
            );
            assert!(report.reload_owed, "{row}: runtime repair owes reload");
            assert_eq!(
                state_of(&owner).fact,
                Some(Fact::RolledBack(FileRevision::of(OLD))),
                "{row}: fact requires Restore proof for original, never new"
            );
            assert!(
                observe::events(&live.path).contains(&Event::RestoreVerified),
                "{row}: A verified original revision"
            );
        }
        "staged_rolled_back" => {
            assert_eq!(
                journal::fault::synced(&live.path),
                before,
                "{row}: rolled-back fact does no A"
            );
            assert!(
                !observe::events(&live.path).contains(&Event::RestoreVerified),
                "{row}: no redundant restore"
            );
        }
        "accepted" => {
            assert_eq!(
                report.recovered,
                Recovered::KeptNew,
                "{row}: accepted recorded digest verified"
            );
            assert!(
                observe::events(&live.path).contains(&Event::ForwardVerified),
                "{row}: accepted runs A verify"
            );
        }
        _ => unreachable!("fixture case"),
    }
    drop(watching);
}

fn dispatch_case(case: &str, row: &str) {
    let live = Live::new();
    let owner = live.seed(state(live.dir.path()), row);
    let path = journal::journal_path(&live.path);
    if case == "unknown" {
        replace_bytes(&path, br#"{"version":93}"#);
    } else if case == "v1" {
        journal::stage_original(&live.path, super::super::fixtures::OLD).expect(row);
    }
    let before = std::fs::read(&path).expect(row);
    if case == "unresolved" {
        assert!(
            lock::refuse_pending_v2(&owner.locked).is_err(),
            "{row}: v2 owner cannot reach writer"
        );
    } else {
        let got = lock::dispatch_journal(&owner.locked);
        match case {
            "v2" => assert!(
                matches!(got, Ok(Some(OpenJournal::Current(_)))),
                "{row}: v2 dispatch"
            ),
            "v1" => assert!(
                matches!(got, Ok(Some(OpenJournal::Legacy(_)))),
                "{row}: v1 dispatch preserved"
            ),
            "unknown" => assert!(
                matches!(got, Err(JournalError::UnsupportedVersion)),
                "{row}: unknown version refused"
            ),
            _ => unreachable!("fixture case"),
        }
    }
    assert_eq!(
        std::fs::read(path).expect(row),
        before,
        "{row}: dispatch/refusal never removes evidence"
    );
}

#[test]
fn accepted_foreign_bytes() {
    const ROW: &str = "accepted_foreign_bytes";
    let mut failures = Vec::new();
    let expected = "repair refusal, no append or cleanup";
    collect_case(
        &mut failures,
        ROW,
        "foreign_after_acceptance",
        expected,
        || {
            let live = Live::new();
            let mut initial = state(live.dir.path());
            accepted(&mut initial);
            let owner = live.seed(initial, ROW);
            reseed(&owner);
            let before = bytes(&live.path);
            let audit = std::fs::read(&live.log_path).unwrap_or_default();
            replace_bytes(&live.path, FOREIGN);
            let result = runtime(JournalDrain::run(owner, Some(Arc::clone(&live.log))));
            assert!(
                matches!(&result, Err(f) if f.error == DrainError::RepairPending),
                "{ROW}: accepted foreign bytes refuse repair"
            );
            let failure = result.err().expect(ROW);
            assert_eq!(
                failure.session.configured, live.path,
                "{ROW}: held configured target retained"
            );
            assert_eq!(bytes(&live.path), before, "{ROW}: decision bytes unchanged");
            assert_eq!(
                std::fs::read(&live.log_path).unwrap_or_default(),
                audit,
                "{ROW}: no append"
            );
            assert_eq!(
                std::fs::read(&live.path).expect(ROW),
                FOREIGN,
                "{ROW}: foreign bytes preserved"
            );
            assert!(
                journal::original_path(&live.path).exists(),
                "{ROW}: no finish"
            );
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}
