// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! File-drain rows: the abandoned file drains into its own log, refuses what it cannot prove,
//! and keeps a refused file exactly as found.

use std::path::Path;
use std::sync::Arc;

use super::super::super::abandoned::{encode_frame, frames_of, marked};
use super::super::super::{JournalV2, Phase};
use super::super::DrainSession;
use super::super::fixtures::{Live, decided, runtime, staged, state};
use super::super::handover::{abandoned_path, hand_over};
use super::drain_abandoned;
use crate::config_persistence::journal;

/// A donor bound to a live log, handed over: the abandoned file exists and the journal is gone.
pub(super) struct DrainRig {
    pub(super) live: Live,
    pub(super) session: DrainSession,
    /// The donor as seeded, before the handover flagged it.
    pub(super) donor: JournalV2,
}

/// One decided writer whose outcome is not yet delivered, bound to `live`'s log, then handed over.
pub(super) fn drain_rig(row: &str, edit: impl FnOnce(&mut JournalV2)) -> DrainRig {
    let live = Live::new();
    let mut donor = state(&live.resolved);
    decided(&mut donor);
    staged(&mut donor);
    donor.phase = Phase::Accepted;
    donor.binding = Some(live.log.log_id());
    edit(&mut donor);
    let mut session = live.seed(donor.clone(), row);
    assert_eq!(hand_over(&mut session), Ok(()), "{row}: fixture handover");
    DrainRig {
        live,
        session,
        donor,
    }
}

/// The rig's donor with the writer's intent undelivered and no counter: the drain must deliver
/// the intent, then freeze and deliver the terminal itself.
pub(super) fn unfrozen(donor: &mut JournalV2) {
    let writer = donor.writer.as_mut().expect("fixture writer");
    writer.intent_counter = None;
    writer.records.clear();
}

impl DrainRig {
    pub(super) fn drain(&mut self) -> Result<(), super::super::DrainError> {
        runtime(drain_abandoned(
            &mut self.session,
            Some(Arc::clone(&self.live.log)),
        ))
    }

    pub(super) fn file(&self) -> Option<Vec<u8>> {
        file_at(&self.live.path)
    }

    pub(super) fn journal(&self) -> Option<Vec<u8>> {
        std::fs::read(journal::journal_path(&self.live.path)).ok()
    }
}

pub(super) fn file_at(config: &Path) -> Option<Vec<u8>> {
    std::fs::read(abandoned_path(config)).ok()
}

/// The frames a handover of `donor` writes, encoded and joined: an independent reference file.
pub(super) fn reference_file(donor: &JournalV2) -> Vec<u8> {
    frames_of(&marked(donor))
        .expect("the donor is bound")
        .iter()
        .map(|frame| encode_frame(frame).expect("a frame fits"))
        .collect::<Vec<_>>()
        .concat()
}

/// The distinct terminal contents the log holds for `token`: result, reason, settled_by and the
/// intent counter. Equal repeats collapse; a second entry is a terminal frozen twice.
pub(super) fn terminal_contents(live: &Live, token: &str) -> std::collections::BTreeSet<String> {
    live.records()
        .iter()
        .filter(|r| {
            r["token"] == token
                && (r["event"] == "config_write_outcome" || r["event"] == "config_write_abandoned")
        })
        .map(|r| {
            format!(
                "{} {} {} {} {}",
                r["event"], r["result"], r["reason"], r["settled_by"], r["intent_counter"]
            )
        })
        .collect()
}

#[test]
fn drain_delivers_and_removes_the_file() {
    const ROW: &str = "drain_delivers_and_removes_the_file";
    let mut rig = drain_rig(ROW, unfrozen);
    assert!(rig.file().is_some(), "{ROW}: the handover left the file");
    assert_eq!(rig.drain(), Ok(()), "{ROW}");
    assert_eq!(rig.file(), None, "{ROW}: the drained file is gone");
    assert_eq!(rig.journal(), None, "{ROW}: no journal was recreated");
    let writer = &rig.donor.writer.as_ref().expect("fixture writer").intent_id.0;
    assert_eq!(
        terminal_contents(&rig.live, writer).len(),
        1,
        "{ROW}: exactly one terminal for the writer"
    );
    rig.live.verify(ROW);
}
