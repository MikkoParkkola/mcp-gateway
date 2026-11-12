// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Hand a journal's frozen records over to the framed abandoned file: preflight proves the file
//! acceptable, then the flag, the frames, the syncs and the journal's removal follow in order.

use std::path::{Path, PathBuf};

use super::DrainSession;

/// Why a handover did not complete. The donor is byte-identical after `Foreign`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HandoverError {
    Journal,
    Write,
    Sync,
    Finish,
    Foreign,
}

/// `<config>.abandoned`, beside the resolved config, in the journal's own directory.
pub(crate) fn abandoned_path(target: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(target.file_name().unwrap_or_default());
    name.push(".abandoned");
    target.with_file_name(name)
}

pub(crate) fn hand_over(_session: &mut DrainSession) -> Result<(), HandoverError> {
    Err(HandoverError::Write)
}

#[cfg(test)]
#[path = "config_persistence_journal_v2_drain_handover_tests.rs"]
mod tests;
