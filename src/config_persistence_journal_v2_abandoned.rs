// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The framed abandoned file: frame types, codec and read-side classification.
//!
//! Compiled for tests until startup gives the abandoned file a production
//! caller. Nothing here opens a file: it works on bytes the caller read.

use serde::{Deserialize, Serialize};

use super::{FrozenRecord, IntentId, JournalDecision, JournalV2};
use crate::security::transparency_log::identity::LogId;

/// Where a frozen record sits in its token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Slot {
    Intent,
    Record(usize),
}

/// The token-level state, carried on the intent frame only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnerFacts {
    pub(super) decision: Option<JournalDecision>,
    pub(super) handed_over: bool,
    pub(super) intent_counter: Option<u64>,
    pub(super) root: bool,
}

/// One frozen record of one token, as the abandoned file stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AbandonedFrame {
    pub(super) log_id: LogId,
    pub(super) token: IntentId,
    pub(super) slot: Slot,
    pub(super) record: FrozenRecord,
    pub(super) owner: Option<OwnerFacts>,
}

/// Why one frame or the file cannot be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameFault {
    Length,
    Checksum,
    Json,
    Field,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Tail {
    Clean,
    Incomplete { start: usize },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FrameRead {
    pub(super) frames: Vec<AbandonedFrame>,
    pub(super) tail: Tail,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cause {
    Wire(FrameFault),
    DonorMismatch,
    NotAPrefix,
    TailWithoutDonor,
    TailBeyondDonor,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Inspection {
    Structural,
    RepairableTail { start: usize },
    Corrupt { at: usize, cause: Cause },
}

pub(crate) fn encode_frame(_frame: &AbandonedFrame) -> Result<Vec<u8>, FrameFault> {
    Ok(Vec::new())
}

pub(crate) fn decode_frames(_bytes: &[u8]) -> Result<FrameRead, FrameFault> {
    Ok(FrameRead {
        frames: Vec::new(),
        tail: Tail::Clean,
    })
}

pub(crate) fn canonical_frames(_donor: &JournalV2) -> Vec<(IntentId, Slot)> {
    Vec::new()
}

pub(crate) fn inspect(_bytes: &[u8], _donor: Option<&JournalV2>) -> Inspection {
    Inspection::Structural
}

#[cfg(test)]
#[path = "config_persistence_journal_v2_abandoned_fixtures_tests.rs"]
mod fixtures;
#[cfg(test)]
#[path = "config_persistence_journal_v2_abandoned_tests.rs"]
mod tests;
