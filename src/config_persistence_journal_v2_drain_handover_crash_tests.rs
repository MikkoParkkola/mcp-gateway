// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Handover power-loss rows: cut the directory at a seam, reopen from what survived, and finish.

use super::super::super::abandoned::{Placement, against_donor, marked};
use super::super::super::fixtures::collect_case;
use super::super::fault::{self, At, Fault};
use super::super::fixtures::{acquire, reopen, state_of};
use super::tests::{Rig, file_bytes, good_file, journal_bytes, rig};
use super::{abandoned_path, hand_over};
use crate::config_persistence::crash_fs::{self, Mode};

const MODES: [Mode; 4] = [
    Mode::DropAll,
    Mode::KeepAll,
    Mode::KeepRenameDropData { seed: 3 },
    Mode::KeepRenameDropData { seed: 11 },
];

/// Run a handover on a fresh rig, cut the directory at `at` in `mode`, and return what is left:
/// the rig's donor and path, with a new session reopened from the surviving journal (if any).
fn cut_at(at: At, mode: Mode) -> (Rig, bool) {
    let rig = rig(|_| {});
    let path = rig.path.clone();
    let overlay = crash_fs::arm_config(&path);
    let armed = fault::arm(&path, Fault::Cut(at, mode));
    let mut session = rig.session;
    let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = hand_over(&mut session);
    }));
    let fired = fault::fired(&path);
    drop((armed, overlay, session));
    assert_eq!(fired, 1, "the cut boundary {at:?} is reached exactly once");
    match stopped {
        Err(panic) => {
            if let Err(other) = panic.downcast::<fault::Captured>() {
                std::panic::resume_unwind(other);
            }
        }
        Ok(()) => panic!("the cut at {at:?} must stop the handover"),
    }
    let survived = journal_bytes(&path).is_some();
    let session = reopen(acquire(&path));
    (
        Rig {
            session,
            donor: rig.donor,
            path,
            dir: rig.dir,
        },
        survived,
    )
}

/// Every token of the reopened journal carries the handed-over flag.
fn flagged(rig: &Rig) -> bool {
    let state = state_of(&rig.session);
    state
        .writer
        .iter()
        .chain(&state.attempts)
        .all(|t| t.handed_over)
}

/// Resume on what survived a cut: the handover completes to exactly the reference file.
fn resumes(rig: &mut Rig, good: &[u8]) {
    assert_eq!(hand_over(&mut rig.session), Ok(()), "resume");
    assert_eq!(journal_bytes(&rig.path), None, "the journal is gone");
    assert_eq!(
        file_bytes(&rig.path).as_deref(),
        Some(good),
        "exactly the reference frames, none twice"
    );
    assert_eq!(
        against_donor(good, &marked(&rig.donor)),
        Placement::Whole,
        "and the donor proves them all"
    );
}

#[test]
fn crash_x3_pl() {
    const ROW: &str = "crash_x3_pl";
    let good = good_file();
    let mut failures = Vec::new();
    for mode in MODES {
        collect_case(
            &mut failures,
            ROW,
            &format!("{mode:?}"),
            "flag durable before any frame; resume completes the exact frames",
            || {
                let (mut rig, survived) = cut_at(At::AbandonFileAppended, mode);
                assert!(survived, "the journal outlives a cut before the file sync");
                assert!(
                    flagged(&rig),
                    "the flag was durable before the first append"
                );
                if matches!(mode, Mode::KeepAll) {
                    assert_eq!(
                        file_bytes(&rig.path).as_deref(),
                        Some(good.as_slice()),
                        "complete unsynced frames survive KeepAll"
                    );
                }
                resumes(&mut rig, &good);
                Ok(())
            },
        );
    }
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn crash_before_first_append() {
    const ROW: &str = "crash_before_first_append";
    let good = good_file();
    let mut failures = Vec::new();
    for mode in MODES {
        collect_case(
            &mut failures,
            ROW,
            &format!("{mode:?}"),
            "flag durable, no file yet; resume writes it",
            || {
                let (mut rig, survived) = cut_at(At::HandoverFlagged, mode);
                assert!(survived && flagged(&rig), "flagged donor survives");
                assert_eq!(file_bytes(&rig.path), None, "nothing appended yet");
                resumes(&mut rig, &good);
                Ok(())
            },
        );
    }
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn crash_x5b_prime() {
    const ROW: &str = "crash_x5b_prime";
    let good = good_file();
    let (mut rig, survived) = cut_at(At::AbandonFileAppended, Mode::DropAll);
    assert!(
        survived && flagged(&rig),
        "{ROW}: the flag is durable at the append seam"
    );
    let state = state_of(&rig.session);
    assert_eq!(
        state.writer.as_ref().map(|t| &t.records),
        rig.donor.writer.as_ref().map(|t| &t.records),
        "{ROW}: the donor froze nothing new"
    );
    resumes(&mut rig, &good);
}

#[test]
fn crash_after_file_sync() {
    const ROW: &str = "crash_after_file_sync";
    let good = good_file();
    let mut failures = Vec::new();
    for mode in MODES {
        collect_case(
            &mut failures,
            ROW,
            &format!("{mode:?}"),
            "file and directory durable before the journal goes",
            || {
                let (mut rig, survived) = cut_at(At::AbandonFileSynced, mode);
                assert!(survived, "the journal still exists");
                assert_eq!(
                    file_bytes(&rig.path).as_deref(),
                    Some(good.as_slice()),
                    "the file is whole and durable in every mode"
                );
                resumes(&mut rig, &good);
                Ok(())
            },
        );
    }
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[test]
fn handover_cleanup_drop_all() {
    const ROW: &str = "handover_cleanup_drop_all";
    let good = good_file();
    let (rig, survived) = cut_at(At::HandoverFinished, Mode::DropAll);
    assert!(!survived, "{ROW}: the journal removal is durable");
    assert_eq!(
        file_bytes(&rig.path).as_deref(),
        Some(good.as_slice()),
        "{ROW}: every frame survives, none missing, none twice"
    );
    assert!(
        abandoned_path(&rig.path).exists(),
        "{ROW}: at the same path"
    );
}

#[test]
fn crash_between_file_and_dir_sync() {
    const ROW: &str = "crash_between_file_and_dir_sync";
    let good = good_file();
    let mut failures = Vec::new();
    for mode in MODES {
        collect_case(
            &mut failures,
            ROW,
            &format!("{mode:?}"),
            "data durable, directory entry not yet: DropAll loses the name, the others keep the file; resume finishes",
            || {
                let (mut rig, survived) = cut_at(At::AbandonFileDataSynced, mode);
                assert!(survived && flagged(&rig), "the flagged journal survives");
                let expected = match mode {
                    Mode::DropAll => None,
                    _ => Some(good.clone()),
                };
                assert_eq!(
                    file_bytes(&rig.path),
                    expected,
                    "the name is durable only if the directory was synced"
                );
                resumes(&mut rig, &good);
                Ok(())
            },
        );
    }
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}
