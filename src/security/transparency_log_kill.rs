// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only crash boundaries for the logger. A child-process row arms one,
//! and the child aborts there: no destructor runs, so the lease is released
//! only by the process dying, as after a real kill. The page cache is kept.

use std::path::PathBuf;
use std::sync::Mutex;

/// A named boundary a child can be killed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum At {
    /// The logger is built: its `log_id` reused or minted and recorded.
    LoggerBuilt,
    /// Recovery wrote the genesis open record (and its first mark), and not
    /// yet the identified record that names its id.
    BeforeIdentified,
    /// The signing anchor is published, and this open has written no
    /// record yet (not even its open record).
    AfterSigstart,
    /// Segment recovery is done and the record the anchor owes is not yet
    /// written.
    BeforeAnnounce,
}

/// The armed boundary and the marker file written on reaching it. Global,
/// not thread-local: an armed child runs one row, and recovery may run on
/// any thread.
static ARMED: Mutex<Option<(At, PathBuf)>> = Mutex::new(None);

/// Abort the process at `at`, writing `marker` first so the parent can tell
/// a child that reached the boundary from one that ran nothing.
pub(crate) fn arm(at: At, marker: PathBuf) {
    *ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((at, marker));
}

/// The boundary `at`: abort here when it is armed, else nothing.
///
/// # Panics
///
/// The marker cannot be written: a row whose child cannot prove it reached
/// the boundary fails here, by name, rather than as a missing marker.
pub(crate) fn point(at: At) {
    let armed = ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some((want, marker)) = armed
        && want == at
    {
        // The marker is synced: it must outlive the abort like the log does.
        let written = std::fs::File::create(&marker).and_then(|f| f.sync_all());
        assert!(written.is_ok(), "kill marker not written: {written:?}");
        std::process::abort();
    }
}
