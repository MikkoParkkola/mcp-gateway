// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Drain the framed abandoned file into its own log: deliver what the file still owes, freeze
//! the terminals it lacks, and remove the file once every token is complete. A refused file is
//! kept exactly as found.

use std::sync::Arc;

use std::path::Path;

use super::super::abandoned::{AbandonedFrame, MAX_ABANDONED_BYTES, Slot, Tail, decode_frames};
use super::super::{JournalSession, JournalV2, Phase, TokenState};
use super::fault::{self, At};
use super::handover::{HandoverError, abandoned_path, hand_over, open_existing};
use super::{DrainError, DrainSession, SettleSink, deliver_all};
use crate::config_persistence::sync_dir_of;
use crate::security::transparency_log::TransparencyLogger;
use crate::security::transparency_log::settle::Role;

/// Deliver the abandoned file beside the session's config through `log`, with the config lock
/// held in `session` for the whole call. A handed-over journal beside the file is first finished
/// by the handover's own resume; a refused file is kept exactly as found.
pub(crate) async fn drain_abandoned(
    session: &mut DrainSession,
    log: Option<Arc<TransparencyLogger>>,
) -> Result<(), DrainError> {
    let target = session.locked.target.clone();
    let path = abandoned_path(&target);
    if let Some(journal) = &session.journal {
        let mut tokens = journal.state.writer.iter().chain(&journal.state.attempts);
        let first = tokens.next();
        if !first.is_some_and(|token| token.handed_over) || !tokens.all(|token| token.handed_over) {
            return Err(DrainError::Journal);
        }
        match hand_over(session) {
            Ok(()) => {}
            Err(HandoverError::Foreign) => {
                return Err(refused(&path, Refusal::ForeignDonor, DrainError::Journal));
            }
            Err(_) => return Err(DrainError::Journal),
        }
    }
    let Some((_handle, bytes)) = open_existing(&path, MAX_ABANDONED_BYTES).map_err(|_| {
        // The label only: the refusal is the same whatever the reason.
        let over = std::fs::symlink_metadata(&path)
            .is_ok_and(|meta| meta.is_file() && meta.len() > MAX_ABANDONED_BYTES as u64);
        let why = if over {
            Refusal::OverCap
        } else {
            Refusal::UnsafeHandle
        };
        refused(&path, why, DrainError::FileRefused)
    })?
    else {
        return Ok(());
    };
    if bytes.is_empty() {
        // A created-but-empty file holds no evidence, and no donor is left to complete it.
        return remove(&target, &path);
    }
    let read = decode_frames(&bytes)
        .map_err(|_| refused(&path, Refusal::Wire, DrainError::FileRefused))?;
    if matches!(read.tail, Tail::Incomplete { .. }) {
        // Only a handover with its donor may truncate a torn tail; there is no donor here.
        return Err(refused(&path, Refusal::TornTail, DrainError::FileRefused));
    }
    if read
        .frames
        .windows(2)
        .any(|pair| pair[0].log_id != pair[1].log_id)
    {
        return Err(refused(
            &path,
            Refusal::MixedBinding,
            DrainError::FileRefused,
        ));
    }
    let state = state_from_frames(read.frames)
        .ok_or_else(|| refused(&path, Refusal::Shape, DrainError::FileRefused))?;
    let logger = log.ok_or(DrainError::NoLogger)?;
    let binding = state.binding.clone().ok_or(DrainError::Journal)?;
    // Refreshed from the file on disk: a log replaced behind this handle is refused here.
    let current = logger.refreshed_log_id().map_err(|_| DrainError::Refused)?;
    if current != binding {
        return Err(DrainError::OtherLog);
    }
    let mut file = JournalSession::over_abandoned(target.clone(), state);
    let sink: &dyn SettleSink = &logger;
    deliver_all(&mut file, sink, &binding).await?;
    if !complete(&file.state) {
        return Err(refused(&path, Refusal::Shape, DrainError::FileRefused));
    }
    remove(&target, &path)
}

/// Remove the drained file whole, then sync its directory.
fn remove(target: &Path, path: &Path) -> Result<(), DrainError> {
    super::super::super::remove_if_present(path).map_err(|_| DrainError::Journal)?;
    fault::hit(target, At::FileUnlinked).map_err(|_| DrainError::Journal)?;
    sync_dir_of(path).map_err(|_| DrainError::Journal)
}

/// The file's tokens, rebuilt from its frames, or `None` when the frames are not one
/// handover's shape: one binding; per token an intent frame with its owner facts, then its
/// records in order; no token twice; every token handed over and decided; one root flag; and
/// every terminal already frozen agreeing with its decision.
pub(super) fn state_from_frames(frames: Vec<AbandonedFrame>) -> Option<JournalV2> {
    let binding = frames.first()?.log_id.clone();
    let mut tokens: Vec<TokenState> = Vec::new();
    let mut root = None;
    for frame in frames {
        if frame.log_id != binding {
            return None;
        }
        match (frame.slot, frame.owner) {
            (Slot::Intent, Some(owner)) => {
                let fresh = tokens.iter().all(|t| t.intent_id != frame.intent_id);
                if !fresh || !owner.handed_over || owner.decision.is_none() {
                    return None;
                }
                if *root.get_or_insert(owner.root) != owner.root {
                    return None;
                }
                tokens.push(TokenState {
                    intent_id: frame.intent_id,
                    intent: frame.record,
                    intent_counter: owner.intent_counter,
                    decision: owner.decision,
                    records: Vec::new(),
                    handed_over: true,
                });
            }
            (Slot::Record(index), None) => {
                let token = tokens.last_mut()?;
                if token.intent_id != frame.intent_id || token.records.len() != index {
                    return None;
                }
                token.records.push(frame.record);
            }
            _ => return None,
        }
    }
    let writer = if root? { None } else { Some(tokens.remove(0)) };
    if writer
        .iter()
        .chain(&tokens)
        .any(|token| !token.terminals_agree(&tokens))
    {
        return None;
    }
    let state = JournalV2 {
        version: 2,
        binding: Some(binding),
        phase: Phase::Accepted,
        original_revision: None,
        new_revision: None,
        pending: None,
        fact: None,
        writer,
        attempts: tokens,
    };
    completable(&state).then_some(state)
}

/// Whether the drain can finish this state from the file alone: no delivered intent without its
/// counter, and every terminal the drain may still freeze builds, at the widest counters, with
/// the drain's own builder (a `settled_by` names an attempt in the file). Checked before any
/// delivery, so an unfinishable file is refused as found instead of half delivered.
fn completable(state: &JournalV2) -> bool {
    let mut widest = state.clone();
    for token in widest.writer.iter_mut().chain(widest.attempts.iter_mut()) {
        if token.intent.delivered && token.intent_counter.is_none() {
            return false;
        }
        token.intent_counter.get_or_insert(u64::MAX);
    }
    widest.writer.iter().chain(&widest.attempts).all(|token| {
        // A terminal already frozen is never built again: the same skip as the size bound.
        token
            .records
            .iter()
            .any(|record| matches!(record.role, Role::Outcome | Role::Abandoned))
            || super::terminal_record(&widest, token).is_ok()
    })
}

/// Whether every token is settled (the journal's own per-token check, without its handed-over
/// shortcut) and every record delivered.
pub(super) fn complete(state: &JournalV2) -> bool {
    state
        .writer
        .iter()
        .chain(&state.attempts)
        .all(|token| token.settled(&state.attempts))
}

/// Why a file was refused. The name is the counter's label and the warning's reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    UnsafeHandle,
    OverCap,
    Wire,
    TornTail,
    Shape,
    MixedBinding,
    ForeignDonor,
}

impl Refusal {
    fn as_str(self) -> &'static str {
        match self {
            Self::UnsafeHandle => "unsafe_handle",
            Self::OverCap => "over_cap",
            Self::Wire => "wire",
            Self::TornTail => "torn_tail",
            Self::Shape => "shape",
            Self::MixedBinding => "mixed_binding",
            Self::ForeignDonor => "foreign_donor",
        }
    }
}

/// Report a refused file and leave it exactly as found: one WARN with the path and the reason,
/// one count. Nothing here touches the file.
fn refused(path: &Path, why: Refusal, error: DrainError) -> DrainError {
    tracing::warn!(
        path = %path.display(),
        reason = why.as_str(),
        "the abandoned config-write file is refused and kept as found"
    );
    telemetry_metrics::counter!("mcp_config_abandoned_refused_total", "reason" => why.as_str())
        .increment(1);
    error
}

// The success-path rows need a file that passes the owner check, which only exists on Unix.
#[cfg(all(test, unix))]
#[path = "config_persistence_journal_v2_drain_file_crash_tests.rs"]
mod crash_tests;
#[cfg(all(test, unix))]
#[path = "config_persistence_journal_v2_drain_file_refusal_tests.rs"]
mod refusal_tests;
#[cfg(all(test, unix))]
#[path = "config_persistence_journal_v2_drain_file_tests.rs"]
mod tests;
#[cfg(all(test, not(unix)))]
#[path = "config_persistence_journal_v2_drain_file_windows_tests.rs"]
mod windows_tests;
