// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! File-drain crash rows: a cut at each drain and handover boundary, then a fresh session and a
//! reopened log, must converge to one terminal per token with no evidence lost.

use super::super::super::JournalV2;
use super::super::fault::{self, At, Fault};
use super::super::fixtures::{Live, acquire, decided, reopen, runtime, staged, state};
use super::super::handover::hand_over;
use super::super::{DrainError, DrainSession, JournalDrain};
use super::tests::{DrainRig, file_at, terminal_contents, unfrozen};
use crate::config_persistence::crash_fs::{self, Mode};
use crate::config_persistence::journal;

const MODES: [Mode; 4] = [
    Mode::DropAll,
    Mode::KeepAll,
    Mode::KeepRenameDropData { seed: 3 },
    Mode::KeepRenameDropData { seed: 11 },
];

/// Run `step` with a cut armed at `at` in `mode`; the cut must fire exactly once and stop it.
/// Then the "restart": a fresh session from what survived and a reopened log.
fn cut(rig: DrainRig, at: At, mode: Mode, step: impl FnOnce(&mut DrainRig)) -> DrainRig {
    let path = rig.live.path.clone();
    let overlay = crash_fs::arm_config(&path);
    let armed = fault::arm(&path, Fault::Cut(at, mode));
    let mut rig = rig;
    let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| step(&mut rig)));
    let fired = fault::fired(&path);
    drop((armed, overlay));
    assert_eq!(fired, 1, "the cut boundary {at:?} is reached exactly once");
    match stopped {
        Err(panic) => {
            if let Err(other) = panic.downcast::<fault::Captured>() {
                std::panic::resume_unwind(other);
            }
        }
        Ok(()) => panic!("the cut at {at:?} must stop the step"),
    }
    restart(rig)
}

/// A new process: the old session and logger are gone; reacquire the lock and reopen the log.
fn restart(rig: DrainRig) -> DrainRig {
    let DrainRig {
        live,
        session,
        donor,
    } = rig;
    let path = live.path.clone();
    drop(session);
    let live = live.reopen_log();
    DrainRig {
        session: reopen(acquire(&path)),
        live,
        donor,
    }
}

/// A seeded donor bound to a live log, NOT yet handed over.
fn seeded(row: &str, edit: impl FnOnce(&mut JournalV2)) -> DrainRig {
    seeded_on(Live::new(), row, edit)
}

fn seeded_on(live: Live, row: &str, edit: impl FnOnce(&mut JournalV2)) -> DrainRig {
    let mut donor = state(&live.resolved);
    decided(&mut donor);
    staged(&mut donor);
    donor.phase = super::super::super::Phase::Accepted;
    donor.binding = Some(live.log.log_id());
    edit(&mut donor);
    let session: DrainSession = live.seed(donor.clone(), row);
    DrainRig {
        live,
        session,
        donor,
    }
}

fn handover_step(rig: &mut DrainRig) {
    let _ = hand_over(&mut rig.session);
}

fn drain_step(rig: &mut DrainRig) {
    let _ = rig.drain();
}

fn writer_token(rig: &DrainRig) -> String {
    rig.donor
        .writer
        .as_ref()
        .expect("fixture writer")
        .intent_id
        .0
        .clone()
}

/// The converged end state every crash row reaches: file and journal gone, one terminal content
/// for the writer, and a log the reader verifies (chain and pairing).
fn converged(rig: &DrainRig, row: &str) {
    assert_eq!(
        file_at(&rig.live.path),
        None,
        "{row}: the drained file is gone"
    );
    assert_eq!(
        std::fs::read(journal::journal_path(&rig.live.path)).ok(),
        None,
        "{row}: no journal survives or is recreated"
    );
    let token = writer_token(rig);
    assert_eq!(
        terminal_contents(&rig.live, &token).len(),
        1,
        "{row}: exactly one terminal content for the writer: {:?}",
        terminal_contents(&rig.live, &token)
    );
    rig.live.verify(row);
}

fn journal_of(rig: &DrainRig) -> Option<Vec<u8>> {
    std::fs::read(journal::journal_path(&rig.live.path)).ok()
}

/// The journal drain never finishes a flagged donor whose file is missing or unsynced: it
/// refuses, the donor stays byte-identical, and the file drain then resumes the handover.
#[test]
fn run_refuses_flagged_donor() {
    const ROW: &str = "run_refuses_flagged_donor";
    for (at, mode) in [
        (At::HandoverFlagged, Mode::KeepAll),
        (At::AbandonFileAppended, Mode::DropAll),
    ] {
        let rig = cut(seeded(ROW, unfrozen), at, mode, handover_step);
        let before = journal_of(&rig).expect("the flagged donor survives the cut");
        let DrainRig {
            live,
            session,
            donor,
        } = rig;
        let result = runtime(JournalDrain::run(
            session,
            Some(std::sync::Arc::clone(&live.log)),
        ));
        let session = match result {
            Ok(_) => panic!("{ROW} {at:?}: run finished a flagged donor"),
            Err(failure) => {
                assert_eq!(failure.error, DrainError::Journal, "{ROW} {at:?}: refused");
                *failure.session
            }
        };
        let mut rig = DrainRig {
            live,
            session,
            donor,
        };
        assert_eq!(
            journal_of(&rig).as_deref(),
            Some(before.as_slice()),
            "{ROW} {at:?}: donor kept"
        );
        assert_eq!(
            rig.drain(),
            Ok(()),
            "{ROW} {at:?}: the file drain resumes and drains"
        );
        converged(&rig, ROW);
    }
}

/// X4: file and directory synced, donor still present: one drain completes both.
#[test]
fn crash_x4() {
    const ROW: &str = "crash_x4";
    let mut rig = cut(
        seeded(ROW, unfrozen),
        At::AbandonFileSynced,
        Mode::KeepAll,
        handover_step,
    );
    assert!(journal_of(&rig).is_some(), "{ROW}: the donor survives");
    assert!(
        file_at(&rig.live.path).is_some(),
        "{ROW}: the file survives"
    );
    assert_eq!(rig.drain(), Ok(()), "{ROW}");
    converged(&rig, ROW);
}

/// X5: the journal is gone, the file alone drains; the config bytes are untouched.
#[test]
fn crash_x5() {
    const ROW: &str = "crash_x5";
    let mut rig = cut(
        seeded(ROW, unfrozen),
        At::HandoverFinished,
        Mode::KeepAll,
        handover_step,
    );
    assert_eq!(journal_of(&rig), None, "{ROW}: the journal is gone");
    let config = std::fs::read(&rig.live.path).expect("fixture config");
    assert_eq!(rig.drain(), Ok(()), "{ROW}");
    converged(&rig, ROW);
    assert_eq!(
        std::fs::read(&rig.live.path).expect("config"),
        config,
        "{ROW}: writer bytes unchanged"
    );
}

/// X5b (planted, design D3): a flagged donor restored beside a file a drain already advanced.
/// Neither drain freezes or delivers from the donor; donor, file and log stay byte-identical.
#[test]
fn crash_x5b() {
    const ROW: &str = "crash_x5b";
    let rig = super::tests::drain_rig(ROW, unfrozen);
    // Advance the file: the intent is delivered and its counter persisted, the terminal frozen.
    let rig = cut(rig, At::OutcomeAppended, Mode::KeepAll, drain_step);
    let advanced = file_at(&rig.live.path).expect("the advanced file survives");
    super::super::super::fixtures::seed(
        &rig.live.path,
        &super::super::super::abandoned::marked(&rig.donor),
    );
    let mut rig = restart(rig);
    let donor = journal_of(&rig).expect("the planted donor");
    let records = rig.live.records().len();
    let DrainRig {
        live,
        session,
        donor: seeded_donor,
    } = rig;
    let result = runtime(JournalDrain::run(
        session,
        Some(std::sync::Arc::clone(&live.log)),
    ));
    let session = match result {
        Ok(_) => panic!("{ROW}: run finished the planted donor"),
        Err(failure) => {
            assert_eq!(failure.error, DrainError::Journal, "{ROW}: run refuses");
            *failure.session
        }
    };
    rig = DrainRig {
        live,
        session,
        donor: seeded_donor,
    };
    assert_eq!(
        rig.drain(),
        Err(DrainError::Journal),
        "{ROW}: the drain refuses"
    );
    assert_eq!(
        journal_of(&rig).as_deref(),
        Some(donor.as_slice()),
        "{ROW}: donor kept"
    );
    assert_eq!(
        file_at(&rig.live.path).as_deref(),
        Some(advanced.as_slice()),
        "{ROW}: file kept"
    );
    assert_eq!(rig.live.records().len(), records, "{ROW}: nothing appended");
}

/// How many times the log holds the writer's intent.
fn intents(rig: &DrainRig) -> usize {
    let token = writer_token(rig);
    rig.live
        .records()
        .iter()
        .filter(|r| r["token"] == token.as_str() && r["event"] == "config_save_intent")
        .count()
}

/// F1: killed after the intent's append, before its flag: the resend collapses.
#[test]
fn crash_f1() {
    const ROW: &str = "crash_f1";
    let rig = super::tests::drain_rig(ROW, unfrozen);
    let mut rig = cut(rig, At::IntentAppended, Mode::KeepAll, drain_step);
    assert!(
        file_at(&rig.live.path).is_some(),
        "{ROW}: the file survives"
    );
    assert_eq!(rig.drain(), Ok(()), "{ROW}");
    assert_eq!(intents(&rig), 2, "{ROW}: the intent was resent once");
    converged(&rig, ROW);
}

/// F1, terminal side: killed after the terminal's append, before its flag: an equal resend.
#[test]
fn crash_f1_terminal() {
    const ROW: &str = "crash_f1_terminal";
    let rig = super::tests::drain_rig(ROW, unfrozen);
    let mut rig = cut(rig, At::OutcomeAppended, Mode::KeepAll, drain_step);
    assert_eq!(rig.drain(), Ok(()), "{ROW}");
    assert_eq!(intents(&rig), 1, "{ROW}: the flagged intent is not resent");
    converged(&rig, ROW);
}

/// F2: a drain that stops after a persist leaves its progress as evidence; the next completes it
/// without repeating what was flagged.
#[test]
fn crash_f2() {
    const ROW: &str = "crash_f2";
    let mut rig = super::tests::drain_rig(ROW, unfrozen);
    let original = file_at(&rig.live.path).expect("the handed-over file");
    let armed = fault::arm(&rig.live.path, Fault::Fail(At::FileRewritten));
    assert_eq!(
        rig.drain(),
        Err(DrainError::Journal),
        "{ROW}: stopped after a persist"
    );
    drop(armed);
    let partial = file_at(&rig.live.path).expect("the partial file survives");
    assert_ne!(
        partial, original,
        "{ROW}: the persisted progress is in the file"
    );
    let mut rig = restart(rig);
    assert_eq!(rig.drain(), Ok(()), "{ROW}");
    assert_eq!(
        intents(&rig),
        1,
        "{ROW}: delivered records are not repeated"
    );
    converged(&rig, ROW);
}

/// F2-PL: a cut between a rewrite's rename and its directory sync, every mode, converges.
#[test]
fn crash_f2_pl() {
    const ROW: &str = "crash_f2_pl";
    for mode in MODES {
        let rig = super::tests::drain_rig(ROW, unfrozen);
        let mut rig = cut(rig, At::FileRewritten, mode, drain_step);
        assert!(
            file_at(&rig.live.path).is_some(),
            "{ROW} {mode:?}: a file survives"
        );
        assert_eq!(rig.drain(), Ok(()), "{ROW} {mode:?}");
        converged(&rig, ROW);
    }
}

/// F2-PL after the freeze (design M3): power lost after the frozen terminal was appended. Every
/// earlier persist must already be durable, or the next drain refreezes with another counter.
#[test]
fn crash_f2_pl_after_freeze() {
    const ROW: &str = "crash_f2_pl_after_freeze";
    let rig = super::tests::drain_rig(ROW, unfrozen);
    let mut rig = cut(rig, At::OutcomeAppended, Mode::DropAll, drain_step);
    assert_eq!(rig.drain(), Ok(()), "{ROW}");
    converged(&rig, ROW);
}

/// F3: killed after the drained file's unlink, before its directory sync.
#[test]
fn crash_f3() {
    const ROW: &str = "crash_f3";
    let rig = super::tests::drain_rig(ROW, unfrozen);
    let mut rig = cut(rig, At::FileUnlinked, Mode::KeepAll, drain_step);
    let records = rig.live.records().len();
    assert_eq!(rig.drain(), Ok(()), "{ROW}");
    assert_eq!(
        rig.live.records().len(),
        records,
        "{ROW}: nothing appended again"
    );
    converged(&rig, ROW);
}

/// F3-PL: the unlink is lost and the fully flagged file returns; the next drain appends nothing
/// and removes it. A drain that returned has removed the file durably.
#[test]
fn crash_f3_pl() {
    const ROW: &str = "crash_f3_pl";
    let rig = super::tests::drain_rig(ROW, unfrozen);
    let mut rig = cut(rig, At::FileUnlinked, Mode::DropAll, drain_step);
    assert!(
        file_at(&rig.live.path).is_some(),
        "{ROW}: the file reappears"
    );
    let records = rig.live.records().len();
    assert_eq!(rig.drain(), Ok(()), "{ROW}");
    assert_eq!(
        rig.live.records().len(),
        records,
        "{ROW}: nothing appended again"
    );
    converged(&rig, ROW);

    let mut rig = super::tests::drain_rig(ROW, unfrozen);
    let overlay = crash_fs::arm_config(&rig.live.path);
    assert_eq!(rig.drain(), Ok(()), "{ROW}: an uncut drain");
    crash_fs::cut(
        rig.live.path.parent().expect("config directory"),
        Mode::DropAll,
    );
    drop(overlay);
    assert_eq!(
        file_at(&rig.live.path),
        None,
        "{ROW}: the removal was durable when the drain returned"
    );
}

/// Every file in the audit directory with its length: a drain that appends anywhere, in any
/// segment, changes this.
fn audit_files(rig: &DrainRig) -> Vec<(String, u64)> {
    let dir = rig.live.log_path.parent().expect("audit directory");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("audit directory listing")
        .map(|entry| {
            let entry = entry.expect("audit entry");
            let len = entry.metadata().expect("audit entry metadata").len();
            (entry.file_name().to_string_lossy().into_owned(), len)
        })
        .collect();
    files.sort();
    files
}

/// A fully flagged file that comes back after its drain, across a restart and segment rotation,
/// is applied once: the second drain appends nothing anywhere and removes it.
#[test]
fn late_abandoned_retry() {
    const ROW: &str = "late_abandoned_retry";
    let small = crate::security::audit_rotation_config::RotationConfig {
        max_segment_bytes: 1024,
        ..crate::security::audit_rotation_config::RotationConfig::default()
    };
    let mut rig = seeded_on(Live::with_rotation(small), ROW, unfrozen);
    assert_eq!(
        hand_over(&mut rig.session),
        Ok(()),
        "{ROW}: fixture handover"
    );
    let mut rig = cut(rig, At::FileUnlinked, Mode::DropAll, drain_step);
    let late = file_at(&rig.live.path).expect("the flagged file returns");
    assert_eq!(rig.drain(), Ok(()), "{ROW}: first drain removes it");
    let mut rig = restart(rig);
    std::fs::write(
        super::super::handover::abandoned_path(&rig.live.path),
        &late,
    )
    .expect(ROW);
    std::fs::set_permissions(
        super::super::handover::abandoned_path(&rig.live.path),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .expect(ROW);
    let before = audit_files(&rig);
    assert_eq!(rig.drain(), Ok(()), "{ROW}: the late copy drains");
    assert_eq!(audit_files(&rig), before, "{ROW}: no append in any segment");
    // Segments rotated, so the active one need not hold the terminal: judge the whole log.
    assert_eq!(
        file_at(&rig.live.path),
        None,
        "{ROW}: the late copy is gone"
    );
    rig.live.verify(ROW);
}

/// A rolled-back write: the writer's terminal cites the recovery attempt's counter through
/// `settled_by`, and both intents are undelivered at handover.
fn rolled_back(donor: &mut JournalV2) {
    use super::super::super::fixtures::decision;
    use super::super::super::{Fact, IntentId, Phase, ResultClass};
    use crate::security::transparency_log::settle::Reason;
    unfrozen(donor);
    donor.phase = Phase::Staged;
    donor.fact = donor.original_revision.clone().map(Fact::RolledBack);
    let mut attempt = super::super::fixtures::attempt();
    attempt.decision = Some(decision(ResultClass::Written, Reason::RolledBack));
    let writer = donor.writer.as_mut().expect("fixture writer");
    let mut cited = decision(ResultClass::NotWritten, Reason::RolledBack);
    cited.settled_by = Some(IntentId(attempt.intent_id.0.clone()));
    writer.decision = Some(cited);
    donor.attempts.push(attempt);
}

/// Every token has one terminal content, and the writer's cites the attempt's logged counter.
fn two_tokens_converged(rig: &DrainRig, row: &str) {
    assert_eq!(
        file_at(&rig.live.path),
        None,
        "{row}: the drained file is gone"
    );
    let records = rig.live.records();
    let attempt = &rig.donor.attempts[0].intent_id.0;
    let counters: Vec<_> = records
        .iter()
        .filter(|r| r["token"] == attempt.as_str() && r["event"] == "config_recovery_intent")
        .map(|r| r["counter"].clone())
        .collect();
    for token in [writer_token(rig), attempt.clone()] {
        assert_eq!(
            terminal_contents(&rig.live, &token).len(),
            1,
            "{row}: one terminal content for {token}"
        );
    }
    let writer = writer_token(rig);
    let cited = records
        .iter()
        .find(|r| r["token"] == writer.as_str() && r["event"] == "config_write_outcome")
        .map(|r| r["settled_by"]["intent_counter"].clone())
        .expect("the writer's terminal");
    assert!(
        counters.contains(&cited),
        "{row}: settled_by cites a logged attempt counter: {cited} in {counters:?}"
    );
    rig.live.verify(row);
}

/// F2 with two tokens (closed design): a drain stopped after a persist, and one cut by power
/// loss after a terminal's append, both converge with the cross-token citation intact.
#[test]
fn crash_f2_two_tokens() {
    const ROW: &str = "crash_f2_two_tokens";
    let mut rig = super::tests::drain_rig(ROW, rolled_back);
    let armed = fault::arm(&rig.live.path, Fault::Fail(At::FileRewritten));
    assert_eq!(
        rig.drain(),
        Err(DrainError::Journal),
        "{ROW}: stopped after a persist"
    );
    drop(armed);
    let mut rig = restart(rig);
    assert_eq!(rig.drain(), Ok(()), "{ROW}: resumed");
    two_tokens_converged(&rig, ROW);

    let rig = super::tests::drain_rig(ROW, rolled_back);
    let mut rig = cut(rig, At::OutcomeAppended, Mode::DropAll, drain_step);
    assert_eq!(rig.drain(), Ok(()), "{ROW}: after power loss");
    two_tokens_converged(&rig, ROW);
}
