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

/// The history this process records into, if one was installed.
#[cfg(any(test, feature = "webui"))]
pub(crate) fn installed() -> Option<Arc<HealthHistory>> {
    INSTALLED.get().cloned()
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

/// What one call to the save core did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SaveOutcome {
    /// The snapshot was written; the incomplete flag is cleared.
    Saved,
    /// Another save held SAVES (a [`Wait::SkipIfBusy`] save); nothing changed.
    Busy,
    /// The health floor's gate turned the periodic save away; nothing changed.
    GateSkipped,
    /// The checkpoint attempt this save belonged to ended first; nothing changed.
    Superseded,
    /// Encoding, the directory or the write failed; the flag is set, the cause logged.
    Failed,
}

/// The check a save runs under SAVES, before it snapshots.
#[derive(Clone, Copy)]
pub(crate) enum Check<'a> {
    /// The startup and shutdown saves: no check.
    None,
    /// The periodic save: the health floor's gate.
    Gate(&'a super::gate::HealthGate),
    /// The checkpoint worker: its attempt is still live.
    Live(&'a std::sync::atomic::AtomicBool),
}

/// Save `history` to `path` at `now`: a temporary file, flushed, renamed over
/// the old one. Returns whether the rename completed (false for a
/// [`Wait::SkipIfBusy`] save that skipped, which leaves the flag alone); a failure marks the
/// run's history incomplete until a later save succeeds. The snapshot through
/// the rename runs under [`SAVES`]; the outcome is logged after it is released.
pub(crate) fn save(history: &HealthHistory, path: &Path, now: u64, wait: Wait) -> bool {
    save_with(history, path, now, wait, Check::None) == SaveOutcome::Saved
}

/// A save behind the health floor's gate: the periodic one (`SkipIfBusy`) or
/// the adapter's resume replay (Block).
pub(crate) fn save_gated(
    history: &HealthHistory,
    path: &Path,
    now: u64,
    gate: &super::gate::HealthGate,
    wait: Wait,
) -> SaveOutcome {
    #[cfg(test)]
    super::pause_points::at(super::pause_points::Point::SaverBeforeLock, &path_key(path));
    save_with(history, path, now, wait, Check::Gate(gate))
}

/// The checkpoint worker's save: it waits for SAVES, then writes only while
/// its attempt is live.
pub(crate) fn checkpoint_save(
    history: &HealthHistory,
    path: &Path,
    now: u64,
    live: &std::sync::atomic::AtomicBool,
) -> SaveOutcome {
    #[cfg(test)]
    super::pause_points::at(super::pause_points::Point::WorkerWaiting, &path_key(path));
    save_with(history, path, now, Wait::Block, Check::Live(live))
}

/// The one save core: SAVES per `wait`, `check` under it, then the snapshot
/// and the write. Only a write attempt sets the incomplete flag (under SAVES,
/// so two saves set it in the order they wrote); a skip never touches it.
fn save_core(
    history: &HealthHistory,
    path: &Path,
    now: u64,
    wait: Wait,
    check: Check<'_>,
) -> SaveOutcome {
    let outcome = {
        let _one_at_a_time = match wait {
            Wait::Block => SAVES.lock(),
            Wait::SkipIfBusy => match SAVES.try_lock() {
                Some(guard) => guard,
                None => return SaveOutcome::Busy,
            },
        };
        match check {
            Check::None => {}
            Check::Gate(gate) => {
                let admitted = gate.admit(super::gate::Closure::Save, || {
                    #[cfg(test)]
                    super::pause_points::at(
                        super::pause_points::Point::AdmissionMark,
                        &path_key(path),
                    );
                });
                if admitted == super::gate::Admit::Skip {
                    return SaveOutcome::GateSkipped;
                }
            }
            Check::Live(live) => {
                if !live.load(std::sync::atomic::Ordering::SeqCst) {
                    return SaveOutcome::Superseded;
                }
            }
        }
        #[cfg(test)]
        super::pause_points::at(super::pause_points::Point::AfterLiveCheck, &path_key(path));
        let outcome = snapshot_and_write(history, path, now);
        history.set_incomplete(outcome.is_err());
        outcome
    };
    let Err(why) = outcome else {
        #[cfg(test)]
        count_write(path);
        return SaveOutcome::Saved;
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
    SaveOutcome::Failed
}

/// The save core with, under test, its outcome kept per path (rows tell a busy
/// skip from a gate skip).
fn save_with(
    history: &HealthHistory,
    path: &Path,
    now: u64,
    wait: Wait,
    check: Check<'_>,
) -> SaveOutcome {
    let outcome = save_core(history, path, now, wait, check);
    #[cfg(test)]
    outcomes().lock().insert(path_key(path), outcome);
    outcome
}

/// The snapshot and its atomic write; the caller holds [`SAVES`].
fn snapshot_and_write(history: &HealthHistory, path: &Path, now: u64) -> Result<(), Unsaved> {
    let bytes = history.encode(now).ok_or(Unsaved::Encode)?;
    #[cfg(test)]
    super::pause_points::at(super::pause_points::Point::AfterSnapshot, &path_key(path));
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

/// The key the pause points and the write count use for `path`.
#[cfg(test)]
pub(crate) fn path_key(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
fn writes() -> &'static parking_lot::Mutex<std::collections::HashMap<String, u64>> {
    static WRITES: OnceLock<parking_lot::Mutex<std::collections::HashMap<String, u64>>> =
        OnceLock::new();
    WRITES.get_or_init(Default::default)
}

#[cfg(test)]
fn count_write(path: &Path) {
    *writes().lock().entry(path_key(path)).or_default() += 1;
}

#[cfg(test)]
fn outcomes() -> &'static parking_lot::Mutex<std::collections::HashMap<String, SaveOutcome>> {
    static OUTCOMES: OnceLock<parking_lot::Mutex<std::collections::HashMap<String, SaveOutcome>>> =
        OnceLock::new();
    OUTCOMES.get_or_init(Default::default)
}

/// Forget `path`'s last outcome, so a row can wait for the next one.
#[cfg(test)]
pub(crate) fn forget_outcome(path: &Path) {
    outcomes().lock().remove(&path_key(path));
}

/// The last save outcome for `path` (a test probe).
#[cfg(test)]
pub(crate) fn last_outcome(path: &Path) -> Option<SaveOutcome> {
    outcomes().lock().get(&path_key(path)).copied()
}

/// Completed writes to `path` in this process (a test probe; rows assert deltas).
#[cfg(test)]
pub(crate) fn write_count(path: &Path) -> u64 {
    writes()
        .lock()
        .get(&path_key(path))
        .copied()
        .unwrap_or_default()
}

/// Serialises the rows that hold SAVES or count writes, so they never see
/// each other's saves (legacy saves elsewhere can still hold SAVES briefly).
/// An async-aware mutex, so an async row may hold it across its awaits.
#[cfg(test)]
static SAVES_TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The serialisation lock for a synchronous row.
#[cfg(test)]
pub(crate) fn saves_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    SAVES_TEST.blocking_lock()
}

/// The serialisation lock for an async row.
#[cfg(test)]
pub(crate) async fn saves_test_lock_async() -> tokio::sync::MutexGuard<'static, ()> {
    SAVES_TEST.lock().await
}
