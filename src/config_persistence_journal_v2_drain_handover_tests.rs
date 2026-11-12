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
struct Rig {
    _dir: tempfile::TempDir,
    path: PathBuf,
    donor: JournalV2,
    session: DrainSession,
}

fn rig(edit: impl FnOnce(&mut JournalV2)) -> Rig {
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

fn journal_bytes(path: &std::path::Path) -> Option<Vec<u8>> {
    std::fs::read(journal::journal_path(path)).ok()
}

fn file_bytes(path: &std::path::Path) -> Option<Vec<u8>> {
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
fn good_file() -> Vec<u8> {
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
