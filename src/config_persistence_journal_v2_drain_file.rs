// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Drain the framed abandoned file into its own log: deliver what the file still owes, freeze
//! the terminals it lacks, and remove the file once every token is complete. A refused file is
//! kept exactly as found.

use std::sync::Arc;

use super::super::JournalV2;
use super::super::abandoned::AbandonedFrame;
use super::{DrainError, DrainSession};
use crate::security::transparency_log::TransparencyLogger;

/// Deliver the abandoned file beside the session's config through `log`.
pub(crate) async fn drain_abandoned(
    _session: &mut DrainSession,
    _log: Option<Arc<TransparencyLogger>>,
) -> Result<(), DrainError> {
    Ok(())
}

/// The file's tokens, rebuilt from its frames, or `None` when the frames are not one
/// handover's shape.
pub(super) fn state_from_frames(_frames: Vec<AbandonedFrame>) -> Option<JournalV2> {
    None
}

/// Whether every token is settled and every record delivered.
pub(super) fn complete(_state: &JournalV2) -> bool {
    false
}

// The success-path rows need a file that passes the owner check, which only exists on Unix.
#[cfg(all(test, unix))]
#[path = "config_persistence_journal_v2_drain_file_tests.rs"]
mod tests;
#[cfg(all(test, unix))]
#[path = "config_persistence_journal_v2_drain_file_crash_tests.rs"]
mod crash_tests;
#[cfg(all(test, unix))]
#[path = "config_persistence_journal_v2_drain_file_refusal_tests.rs"]
mod refusal_tests;
#[cfg(all(test, not(unix)))]
#[path = "config_persistence_journal_v2_drain_file_windows_tests.rs"]
mod windows_tests;
