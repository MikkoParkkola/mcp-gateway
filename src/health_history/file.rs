// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! `health.json` on disk, and the process-wide history the request-path
//! recorders feed.

use std::path::Path;
use std::sync::{Arc, OnceLock};

use tracing::warn;

use super::HealthHistory;
use crate::gateway::health_metrics::ErrorKind;

/// The history this process records into, set once at startup.
static INSTALLED: OnceLock<Arc<HealthHistory>> = OnceLock::new();

/// Held from a save's snapshot through its rename, so two saves (the
/// periodic one and the shutdown one) cannot cross: the later save always
/// writes the newer snapshot.
static SAVES: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

/// Holds every save back while the guard lives (a test seam for the order).
#[cfg(test)]
pub(crate) fn hold_saves() -> parking_lot::MutexGuard<'static, ()> {
    SAVES.lock()
}

/// Make `history` the one the request path records into. A second call (a
/// second gateway in one test process) keeps the first.
pub(crate) fn install(history: Arc<HealthHistory>) {
    let _ = INSTALLED.set(history);
}

/// Record one call's added latency in the installed history, if any.
pub(crate) fn record_latency_now(secs: f64) {
    if let (Some(history), Ok(now)) = (INSTALLED.get(), crate::clock::unix_secs()) {
        history.record_latency(secs, now);
    }
}

/// Record one error a client received in the installed history, if any.
pub(crate) fn record_error_now(kind: ErrorKind) {
    if let (Some(history), Ok(now)) = (INSTALLED.get(), crate::clock::unix_secs()) {
        history.record_error(kind, now);
    }
}

/// `health.json`'s bytes: `None` when there is no file (a first start);
/// an unreadable file is returned as empty bytes, which the start sets aside.
pub(crate) fn read(path: &Path) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            warn!(error = %e, "health.json could not be read; the health history starts again");
            Some(Vec::new())
        }
    }
}

/// Why a save did not complete.
enum Unsaved {
    Encode,
    Dir(std::io::Error),
    Write(std::io::Error),
}

/// How a save meets another save in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wait {
    /// Wait for it (the startup and shutdown saves: each must land).
    Block,
    /// Skip this save (the periodic one: the next tick tries again, and a
    /// stalled write never piles up waiting threads).
    SkipIfBusy,
}

/// Save `history` to `path` at `now`: a temporary file, flushed, renamed over
/// the old one. Returns whether the rename completed (false for a
/// [`Wait::SkipIfBusy`] save that skipped, which leaves the flag alone); a failure marks the
/// run's history incomplete until a later save succeeds. The snapshot through
/// the rename runs under [`SAVES`]; the outcome is logged after it is released.
pub(crate) fn save(history: &HealthHistory, path: &Path, now: u64, wait: Wait) -> bool {
    let outcome = {
        let _one_at_a_time = match wait {
            Wait::Block => SAVES.lock(),
            Wait::SkipIfBusy => match SAVES.try_lock() {
                Some(guard) => guard,
                None => return false,
            },
        };
        let outcome = snapshot_and_write(history, path, now);
        // Under the lock, so two saves set the flag in the order they wrote.
        history.set_incomplete(outcome.is_err());
        outcome
    };
    let Err(why) = outcome else {
        return true;
    };
    match why {
        Unsaved::Encode => warn!(
            "Failed to encode the health history; this run's history is incomplete until a save succeeds"
        ),
        Unsaved::Dir(e) => warn!(error = %e, "Failed to create the health history directory"),
        Unsaved::Write(e) => warn!(
            error = %e,
            "Failed to save the health history; this run's history is incomplete until a save succeeds"
        ),
    }
    false
}

/// The snapshot and its atomic write; the caller holds [`SAVES`].
fn snapshot_and_write(history: &HealthHistory, path: &Path, now: u64) -> Result<(), Unsaved> {
    let bytes = history.encode(now).ok_or(Unsaved::Encode)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(Unsaved::Dir)?;
    }
    crate::config_persistence::write_atomic(
        path,
        &bytes,
        crate::config_persistence::FileMode::Private,
        crate::config_persistence::Symlink::Replace,
    )
    .map_err(Unsaved::Write)
}
