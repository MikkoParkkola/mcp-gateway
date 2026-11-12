// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Handover rows: each reports its cases one by one instead of stopping at the first.

use std::path::PathBuf;

use super::super::super::abandoned::{
    Placement, against_donor, canonical_frames, decode_frames, marked,
};
use super::super::super::fixtures::{collect_case, config};
use super::super::super::{JournalV2, Phase};
use super::super::DrainSession;
use super::super::fixtures::{decided, reopen, staged, state};
use super::{HandoverError, abandoned_path, hand_over};
use crate::config_persistence::journal;

/// A journal ready to hand over: one decided writer whose outcome is not yet delivered, the
/// change accepted, and the journal on disk. Returns the live donor beside the session.
pub(super) struct Rig {
    pub(super) _dir: tempfile::TempDir,
    pub(super) path: PathBuf,
    pub(super) donor: JournalV2,
    pub(super) session: DrainSession,
}

pub(super) fn rig(edit: impl FnOnce(&mut JournalV2)) -> Rig {
    let (dir, path, locked) = config();
    let mut donor = state(dir.path());
    decided(&mut donor);
    staged(&mut donor);
    donor.phase = Phase::Accepted;
    edit(&mut donor);
    super::super::super::fixtures::seed(&path, &donor);
    let session = reopen(locked);
    Rig {
        _dir: dir,
        path,
        donor,
        session,
    }
}

pub(super) fn journal_bytes(path: &std::path::Path) -> Option<Vec<u8>> {
    std::fs::read(journal::journal_path(path)).ok()
}

pub(super) fn file_bytes(path: &std::path::Path) -> Option<Vec<u8>> {
    std::fs::read(abandoned_path(path)).ok()
}

#[test]
fn handover_undelivered_token_succeeds() {
    const ROW: &str = "handover_undelivered_token_succeeds";
    let mut rig = rig(|_| {});
    assert_eq!(hand_over(&mut rig.session), Ok(()), "{ROW}");
    assert_eq!(journal_bytes(&rig.path), None, "{ROW}: the journal is gone");
    let bytes = file_bytes(&rig.path).expect("the abandoned file exists");
    assert_eq!(
        against_donor(&bytes, &marked(&rig.donor)),
        Placement::Whole,
        "{ROW}: the file is exactly the donor's frames, flagged"
    );
    let read = decode_frames(&bytes).expect(ROW);
    assert_eq!(
        read.frames.len(),
        canonical_frames(&marked(&rig.donor)).len(),
        "{ROW}: one frame per record and intent"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(abandoned_path(&rig.path))
            .expect(ROW)
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "{ROW}: private to the owner");
    }
}

#[test]
fn handover_binding_is_the_journals() {
    const ROW: &str = "handover_binding_is_the_journals";
    let mut rig = rig(|_| {});
    let binding = rig.donor.binding.clone().expect("the donor is bound");
    assert_eq!(hand_over(&mut rig.session), Ok(()), "{ROW}");
    let bytes = file_bytes(&rig.path).expect("the abandoned file exists");
    let read = decode_frames(&bytes).expect(ROW);
    assert!(!read.frames.is_empty(), "{ROW}: frames were written");
    assert!(
        read.frames.iter().all(|frame| frame.log_id == binding),
        "{ROW}: every frame carries the journal's binding, never another log's"
    );
}

/// The bytes a successful handover of the standard rig writes: the reference good file.
pub(super) fn good_file() -> Vec<u8> {
    let mut rig = rig(|_| {});
    assert_eq!(hand_over(&mut rig.session), Ok(()), "reference handover");
    file_bytes(&rig.path).expect("reference file")
}

/// Hand over a rig whose abandoned path already holds `existing`, expecting a refusal that
/// leaves the journal and the file byte-identical.
fn refused(what: &str, existing: &[u8], mode: u32, expected: HandoverError) {
    let mut rig = rig(|_| {});
    let path = abandoned_path(&rig.path);
    std::fs::write(&path, existing).expect("pre-existing file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("mode");
    }
    let _ = mode;
    let (journal_before, file_before) = (journal_bytes(&rig.path), file_bytes(&rig.path));
    assert_eq!(hand_over(&mut rig.session), Err(expected), "{what}");
    assert_eq!(
        journal_bytes(&rig.path),
        journal_before,
        "{what}: journal untouched"
    );
    assert_eq!(file_bytes(&rig.path), file_before, "{what}: file untouched");
}

#[test]
fn handover_refusals_leave_bytes() {
    const ROW: &str = "handover_refusals_leave_bytes";
    let good = good_file();
    let lines: Vec<&[u8]> = good.split_inclusive(|b| *b == b'\n').collect();
    assert!(
        lines.len() >= 2,
        "{ROW}: the reference file has several frames"
    );
    let mut bad_sum = good.clone();
    let tab = bad_sum
        .iter()
        .position(|b| *b == b'\t')
        .expect("a header tab");
    bad_sum[tab + 1] = if bad_sum[tab + 1] == b'0' { b'1' } else { b'0' };
    let reordered = [lines[1], lines[0]].concat();
    let duplicated = [lines[0], lines[0]].concat();
    let extra = [good.as_slice(), lines[0]].concat();
    let torn_after = [good.as_slice(), &lines[0][..10]].concat();
    let cases: Vec<(&str, Vec<u8>, u32)> = vec![
        ("a bad checksum", bad_sum, 0o600),
        ("a reorder", reordered, 0o600),
        ("a duplicate frame", duplicated, 0o600),
        ("a frame past the whole sequence", extra, 0o600),
        ("a torn tail after the whole sequence", torn_after, 0o600),
        ("not frames at all", b"hello\n".to_vec(), 0o600),
        ("the whole file with group write", good.clone(), 0o660),
    ];
    let mut failures = Vec::new();
    for (what, bytes, mode) in cases {
        collect_case(
            &mut failures,
            ROW,
            what,
            "refused with the journal and file unchanged",
            || {
                refused(what, &bytes, mode, HandoverError::Foreign);
                Ok(())
            },
        );
    }
    collect_case(
        &mut failures,
        ROW,
        "a parked record",
        "a journal that finish would refuse is refused before anything is written",
        || {
            let mut rig = rig(|donor| {
                donor.writer.as_mut().expect("a writer").intent.parked =
                    Some(super::super::super::ParkReason::InvalidPayload);
            });
            let before = journal_bytes(&rig.path);
            assert_eq!(
                hand_over(&mut rig.session),
                Err(HandoverError::Journal),
                "parked"
            );
            assert_eq!(journal_bytes(&rig.path), before, "journal untouched");
            assert_eq!(file_bytes(&rig.path), None, "no file created");
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

/// Hand over a rig whose abandoned path already holds `existing` (mode 0600), flagged or not.
fn resume_from(existing: &[u8], flagged: bool) -> Rig {
    let mut rig = rig(|donor| {
        if flagged {
            for token in donor.writer.iter_mut().chain(donor.attempts.iter_mut()) {
                token.handed_over = true;
            }
        }
    });
    let path = abandoned_path(&rig.path);
    std::fs::write(&path, existing).expect("pre-existing file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    }
    assert_eq!(
        hand_over(&mut rig.session),
        Ok(()),
        "resume from {} bytes",
        existing.len()
    );
    rig
}

#[test]
fn crash_x3b_resume_from_every_cut() {
    const ROW: &str = "crash_x3b_resume_from_every_cut";
    let good = good_file();
    for n in 0..=good.len() {
        let rig = resume_from(&good[..n], n % 2 == 0);
        assert_eq!(
            file_bytes(&rig.path).as_deref(),
            Some(good.as_slice()),
            "{ROW}: cut at {n}"
        );
        assert_eq!(
            journal_bytes(&rig.path),
            None,
            "{ROW}: cut at {n}: journal gone"
        );
    }
}

#[test]
fn crash_x5_pl_whole_file_and_reappeared_journal() {
    const ROW: &str = "crash_x5_pl_whole_file_and_reappeared_journal";
    let good = good_file();
    let rig = resume_from(&good, true);
    assert_eq!(
        file_bytes(&rig.path).as_deref(),
        Some(good.as_slice()),
        "{ROW}: a flagged journal beside a whole file only completes the handover"
    );
    assert_eq!(journal_bytes(&rig.path), None, "{ROW}: and goes away");
}

#[test]
fn handover_file_alone_reconstructs() {
    const ROW: &str = "handover_file_alone_reconstructs";
    let mut rig = rig(|_| {});
    assert_eq!(hand_over(&mut rig.session), Ok(()), "{ROW}");
    let bytes = file_bytes(&rig.path).expect("the abandoned file exists");
    let read = decode_frames(&bytes).expect(ROW);
    let donor = marked(&rig.donor);
    let canonical = canonical_frames(&donor);
    assert_eq!(read.frames.len(), canonical.len(), "{ROW}: every frame");
    let writer = donor.writer.as_ref().expect("a writer");
    let intent = &read.frames[0];
    assert_eq!(intent.record, writer.intent, "{ROW}: the intent record");
    let owner = intent
        .owner
        .as_ref()
        .expect("owner facts on the intent frame");
    assert!(owner.handed_over, "{ROW}: handed over, in the file itself");
    assert_eq!(owner.decision, writer.decision, "{ROW}: the decision");
    assert_eq!(
        owner.intent_counter, writer.intent_counter,
        "{ROW}: the counter"
    );
    assert!(!owner.root, "{ROW}: not a root token while a writer exists");
    for (index, record) in writer.records.iter().enumerate() {
        assert_eq!(
            &read.frames[index + 1].record,
            record,
            "{ROW}: record {index}, flags included"
        );
    }
}

fn frames_of_file(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes
        .split_inclusive(|b| *b == b'\n')
        .map(<[u8]>::to_vec)
        .collect()
}

#[test]
fn handover_seal_checks() {
    use super::{open_guarded, seal};
    const ROW: &str = "handover_seal_checks";
    let good = good_file();
    let frames = frames_of_file(&good);
    let dir = tempfile::tempdir().expect("scratch directory");
    let path = dir.path().join("sealed.abandoned");
    let mut failures = Vec::new();
    let open_with = |bytes: &[u8]| {
        std::fs::write(&path, bytes).expect("file");
        open_guarded(&path, false).expect("open")
    };
    collect_case(
        &mut failures,
        ROW,
        "exact",
        "the file is exactly the frames: sealed",
        || {
            let mut file = open_with(&good);
            assert_eq!(seal(&mut file, &path, &frames), Ok(()));
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "one byte off",
        "a changed byte is refused",
        || {
            let mut altered = good.clone();
            altered[0] = altered[0].wrapping_add(1);
            let mut file = open_with(&altered);
            assert_eq!(seal(&mut file, &path, &frames), Err(HandoverError::Write));
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "short",
        "a short file is refused",
        || {
            let mut file = open_with(&good[..good.len() - 1]);
            assert_eq!(seal(&mut file, &path, &frames), Err(HandoverError::Write));
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "path replaced",
        "another file at the path is refused",
        || {
            let mut file = open_with(&good);
            let other = dir.path().join("other");
            std::fs::write(&other, &good).expect("replacement");
            std::fs::rename(&other, &path).expect("rename over the path");
            assert_eq!(seal(&mut file, &path, &frames), Err(HandoverError::Write));
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "path removed",
        "a missing path is refused",
        || {
            let mut file = open_with(&good);
            std::fs::remove_file(&path).expect("remove");
            assert_eq!(seal(&mut file, &path, &frames), Err(HandoverError::Write));
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}

#[cfg(unix)]
#[test]
fn handover_fifo_and_symlink_refused() {
    const ROW: &str = "handover_fifo_and_symlink_refused";
    let mut failures = Vec::new();
    collect_case(
        &mut failures,
        ROW,
        "fifo",
        "a FIFO at the path is refused without blocking the open",
        || {
            let dir = tempfile::tempdir().expect("scratch directory");
            let fifo = dir.path().join("fifo.abandoned");
            let made = std::process::Command::new("mkfifo").arg(&fifo).status();
            assert!(made.expect("mkfifo runs").success(), "mkfifo");
            let (tx, rx) = std::sync::mpsc::channel();
            let at = fifo.clone();
            std::thread::spawn(move || {
                let _ = tx.send(super::open_existing(&at, 4096).map(|opened| opened.is_some()));
            });
            let got = rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("the open of a FIFO must not block");
            assert_eq!(got, Err(HandoverError::Foreign));
            Ok(())
        },
    );
    collect_case(
        &mut failures,
        ROW,
        "symlink",
        "a symlink at the path is refused and nothing it names is touched",
        || {
            let mut rig = rig(|_| {});
            let target = rig.path.with_file_name("elsewhere");
            std::fs::write(&target, good_file()).expect("symlink target");
            let link = abandoned_path(&rig.path);
            std::os::unix::fs::symlink(&target, &link).expect("symlink");
            let (journal_before, target_before) =
                (journal_bytes(&rig.path), std::fs::read(&target).ok());
            assert_eq!(
                hand_over(&mut rig.session),
                Err(HandoverError::Foreign),
                "symlink"
            );
            assert_eq!(
                journal_bytes(&rig.path),
                journal_before,
                "journal untouched"
            );
            assert_eq!(
                std::fs::read(&target).ok(),
                target_before,
                "target untouched"
            );
            assert!(
                std::fs::symlink_metadata(&link)
                    .expect("link")
                    .file_type()
                    .is_symlink()
            );
            Ok(())
        },
    );
    assert!(failures.is_empty(), "{ROW}:\n{}", failures.join("\n"));
}
