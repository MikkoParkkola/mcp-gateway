// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! The framed abandoned file: frame types, codec and read-side classification.
//!
//! Compiled for tests until startup gives the abandoned file a production
//! caller. Nothing here opens a file: it works on bytes the caller read.

use serde::{Deserialize, Serialize};

use super::{FrozenRecord, IntentId, JournalDecision, JournalV2, MAX_JOURNAL_BYTES, TokenState};
use crate::hashing::sha256_hex;
use crate::security::transparency_log::identity::LogId;

/// The only frame version this build writes and reads.
const VERSION: u32 = 1;

/// The JSON a frame carries. Fields are plain so serde does the validation the journal
/// already does for a record (role, attribution through the persisted-principal decoder).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameWire {
    log_id: String,
    owner: Option<OwnerFacts>,
    record: FrozenRecord,
    slot: Slot,
    token: IntentId,
    v: u32,
}

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
    pub(super) intent_id: IntentId,
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

/// One frame as the file stores it: declared length, tab, checksum, tab, JSON, newline.
/// The JSON goes through a value so its keys are sorted and the bytes are stable.
pub(crate) fn encode_frame(frame: &AbandonedFrame) -> Result<Vec<u8>, FrameFault> {
    let wire = FrameWire {
        log_id: frame.log_id.as_str().to_owned(),
        owner: frame.owner.clone(),
        record: frame.record.clone(),
        slot: frame.slot,
        token: frame.intent_id.clone(),
        v: VERSION,
    };
    let value = serde_json::to_value(&wire).map_err(|_| FrameFault::Json)?;
    let json = serde_json::to_vec(&value).map_err(|_| FrameFault::Json)?;
    if json.len() > MAX_JOURNAL_BYTES {
        return Err(FrameFault::Length);
    }
    let mut out = format!("{}\t{}\t", json.len(), sha256_hex(&json)).into_bytes();
    out.extend_from_slice(&json);
    out.push(b'\n');
    Ok(out)
}

/// What the bytes at one offset are.
enum Next {
    Frame(Box<AbandonedFrame>, usize),
    Incomplete,
    Fault(FrameFault),
}

/// The field before the first tab, and what follows it. A newline before the tab ends the
/// header line without a tab: there is no field, and `torn` then calls it corrupt.
fn field(rest: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = rest
        .iter()
        .position(|byte| matches!(*byte, b'\t' | b'\n'))?;
    if rest[at] == b'\n' {
        return None;
    }
    Some((&rest[..at], &rest[at + 1..]))
}

/// A header cut by the end of the file is a torn tail; one cut by a newline is corrupt.
fn torn(rest: &[u8]) -> Next {
    if rest.contains(&b'\n') {
        Next::Fault(FrameFault::Length)
    } else {
        Next::Incomplete
    }
}

/// The declared length: digits only, and within the cap, decided before any allocation.
fn declared(text: &[u8]) -> Option<usize> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let length: usize = std::str::from_utf8(text).ok()?.parse().ok()?;
    (length <= MAX_JOURNAL_BYTES).then_some(length)
}

fn next_frame(bytes: &[u8], at: usize) -> Next {
    let rest = &bytes[at..];
    let Some((length, after_length)) = field(rest) else {
        return torn(rest);
    };
    let Some(length) = declared(length) else {
        return Next::Fault(FrameFault::Length);
    };
    let Some((sum, body)) = field(after_length) else {
        return torn(after_length);
    };
    if body.len() <= length {
        // The bytes stop short of the declared JSON and its newline: a newline inside
        // the declared span is a corrupt frame, the end of the file is a torn tail.
        return match body.iter().position(|byte| *byte == b'\n') {
            Some(newline) if newline < length => Next::Fault(FrameFault::Length),
            _ => Next::Incomplete,
        };
    }
    let json = &body[..length];
    if body[length] != b'\n' || json.contains(&b'\n') {
        return Next::Fault(FrameFault::Length);
    }
    if sum != sha256_hex(json).as_bytes() {
        return Next::Fault(FrameFault::Checksum);
    }
    let end = at + (rest.len() - body.len()) + length + 1;
    match parse(json) {
        Ok(frame) => Next::Frame(Box::new(frame), end),
        Err(fault) => Next::Fault(fault),
    }
}

fn parse(json: &[u8]) -> Result<AbandonedFrame, FrameFault> {
    let value: serde_json::Value = serde_json::from_slice(json).map_err(|_| FrameFault::Json)?;
    let wire: FrameWire = serde_json::from_value(value).map_err(|_| FrameFault::Field)?;
    if wire.v != VERSION {
        return Err(FrameFault::Field);
    }
    Ok(AbandonedFrame {
        log_id: LogId::from_journal(wire.log_id).map_err(|_| FrameFault::Field)?,
        intent_id: wire.token,
        slot: wire.slot,
        record: wire.record,
        owner: wire.owner,
    })
}

/// Every complete frame, or the index of the first one that is corrupt.
fn read(bytes: &[u8]) -> Result<FrameRead, (usize, FrameFault)> {
    let mut frames = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        match next_frame(bytes, at) {
            Next::Frame(frame, end) => {
                frames.push(*frame);
                at = end;
            }
            Next::Incomplete => {
                let tail = Tail::Incomplete { start: at };
                return Ok(FrameRead { frames, tail });
            }
            Next::Fault(fault) => return Err((frames.len(), fault)),
        }
    }
    Ok(FrameRead {
        frames,
        tail: Tail::Clean,
    })
}

pub(crate) fn decode_frames(bytes: &[u8]) -> Result<FrameRead, FrameFault> {
    read(bytes).map_err(|(_, fault)| fault)
}

/// The donor's tokens in the order `hand_over` writes them: the writer first, then the
/// attempts in journal order.
fn tokens(donor: &JournalV2) -> impl Iterator<Item = &TokenState> {
    donor.writer.iter().chain(donor.attempts.iter())
}

/// The donor's frame sequence: per token the intent frame, then its records in order.
pub(crate) fn canonical_frames(donor: &JournalV2) -> Vec<(IntentId, Slot)> {
    let mut sequence = Vec::new();
    for token in tokens(donor) {
        sequence.push((token.intent_id.clone(), Slot::Intent));
        for index in 0..token.records.len() {
            sequence.push((token.intent_id.clone(), Slot::Record(index)));
        }
    }
    sequence
}

/// Whether the donor proves one frame: its token is handed over, the binding is the donor's,
/// and the whole record, and on an intent frame the owner facts, equal the donor's.
fn proves(donor: &JournalV2, frame: &AbandonedFrame) -> bool {
    let Some(token) = tokens(donor).find(|token| token.intent_id == frame.intent_id) else {
        return false;
    };
    let record = match frame.slot {
        Slot::Intent => Some(&token.intent),
        Slot::Record(index) => token.records.get(index),
    };
    let facts = match frame.slot {
        Slot::Intent => Some(OwnerFacts {
            decision: token.decision.clone(),
            handed_over: token.handed_over,
            intent_counter: token.intent_counter,
            root: donor.writer.is_none(),
        }),
        Slot::Record(_) => None,
    };
    token.handed_over
        && donor.binding.as_ref() == Some(&frame.log_id)
        && record == Some(&frame.record)
        && frame.owner == facts
}

/// What a torn tail is, given the donor: repairable only when the complete frames are exactly
/// the donor's leading frames and each is proven. Nothing here reads or writes a file.
fn tail_verdict(read: &FrameRead, start: usize, donor: Option<&JournalV2>) -> Inspection {
    let complete = read.frames.len();
    let Some(donor) = donor else {
        return Inspection::Corrupt {
            at: complete,
            cause: Cause::TailWithoutDonor,
        };
    };
    let canonical = canonical_frames(donor);
    if complete >= canonical.len() {
        return Inspection::Corrupt {
            at: complete,
            cause: Cause::TailBeyondDonor,
        };
    }
    for (index, frame) in read.frames.iter().enumerate() {
        if (frame.intent_id.clone(), frame.slot) != canonical[index] {
            return Inspection::Corrupt {
                at: index,
                cause: Cause::NotAPrefix,
            };
        }
        if !proves(donor, frame) {
            return Inspection::Corrupt {
                at: index,
                cause: Cause::DonorMismatch,
            };
        }
    }
    Inspection::RepairableTail { start }
}

/// Classify the bytes of an abandoned file without touching it. `Structural` is not donor
/// evidence: it says only that the frames parse and check out.
pub(crate) fn inspect(bytes: &[u8], donor: Option<&JournalV2>) -> Inspection {
    match read(bytes) {
        Err((at, fault)) => Inspection::Corrupt {
            at,
            cause: Cause::Wire(fault),
        },
        Ok(read) => match read.tail {
            Tail::Clean => Inspection::Structural,
            Tail::Incomplete { start } => tail_verdict(&read, start, donor),
        },
    }
}

#[cfg(test)]
#[path = "config_persistence_journal_v2_abandoned_fixtures_tests.rs"]
mod fixtures;
#[cfg(test)]
#[path = "config_persistence_journal_v2_abandoned_tests.rs"]
mod tests;
