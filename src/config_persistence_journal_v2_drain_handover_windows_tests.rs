// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Off Unix the handover fails closed: no owner check exists there yet, so it refuses before it
//! writes anything. The success-path rows run on Unix only.

use super::super::super::Phase;
use super::super::super::fixtures::{config, seed};
use super::super::fixtures::{decided, reopen, staged, state};
use super::{HandoverError, abandoned_path, hand_over};
use crate::config_persistence::journal;

#[test]
fn handover_refuses_off_unix_without_writing() {
    const ROW: &str = "handover_refuses_off_unix_without_writing";
    let (dir, path, locked) = config();
    let mut donor = state(dir.path());
    decided(&mut donor);
    staged(&mut donor);
    donor.phase = Phase::Accepted;
    seed(&path, &donor);
    let mut session = reopen(locked);
    let journal_path = journal::journal_path(&path);
    let before = std::fs::read(&journal_path).expect("journal");
    assert_eq!(
        hand_over(&mut session),
        Err(HandoverError::Foreign),
        "{ROW}: refused with no file present"
    );
    assert!(!abandoned_path(&path).exists(), "{ROW}: nothing created");
    std::fs::write(abandoned_path(&path), b"").expect("an empty pre-existing file");
    assert_eq!(
        hand_over(&mut session),
        Err(HandoverError::Foreign),
        "{ROW}: an empty pre-existing file is refused too"
    );
    assert_eq!(
        std::fs::read(&journal_path).expect("journal"),
        before,
        "{ROW}: the journal is untouched"
    );
    assert_eq!(
        std::fs::read(abandoned_path(&path)).expect("file"),
        Vec::<u8>::new(),
        "{ROW}: and so is the file"
    );
}
