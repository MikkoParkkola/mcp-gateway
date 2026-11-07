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

/// Save `history` to `path` at `now`: a temporary file, flushed, renamed over
/// the old one. Returns whether the rename completed; a failure marks the
/// run's history incomplete until a later save succeeds.
pub(crate) fn save(history: &HealthHistory, path: &Path, now: u64) -> bool {
    let bytes = history.encode(now);
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        warn!(error = %e, "Failed to create the health history directory");
        history.set_incomplete(true);
        return false;
    }
    match crate::config_persistence::write_atomic(
        path,
        &bytes,
        crate::config_persistence::FileMode::Private,
        crate::config_persistence::Symlink::Replace,
    ) {
        Ok(()) => {
            history.set_incomplete(false);
            true
        }
        Err(e) => {
            warn!(error = %e, "Failed to save the health history; this run's history is incomplete until a save succeeds");
            history.set_incomplete(true);
            false
        }
    }
}
