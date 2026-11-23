// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! What a detached writer holds so a test's temp dir outlives its writes.
//!
//! A writer that runs detached (a thread or a blocking task its test does not
//! await) takes this when it is spawned, while the test still holds its share
//! of the dir, and drops it after its last write. Looked up later, on the
//! writer's own thread, the test's dir may already be gone. Test builds carry
//! the kept dirs; a release build carries nothing.

use std::path::Path;

/// The kind a shutdown save (`run_shutdown_saves`) reports as.
pub(crate) const SHUTDOWN_SAVE: &str = "shutdown save";

/// The kind a periodic saver (`spawn_periodic_save`) reports as, once at start.
pub(crate) const PERIODIC_SAVE: &str = "periodic save";

/// The kind the skills regen loop reports as, for its output dir and each
/// agent root.
pub(crate) const SKILL_BUNDLE: &str = "skill bundle";

/// The kind the package cache's detached deletes (a tombstone, the startup
/// sweep) report as.
pub(crate) const PACKAGE_CACHE: &str = "package cache";

/// The kind the config lock's detached thread reports as, for the config path.
#[cfg(test)]
pub(crate) const CONFIG_LOCK: &str = "config lock";

/// The temp dirs a detached writer keeps: test builds only.
#[cfg(test)]
pub(crate) type Kept = Vec<std::sync::Arc<tempfile::TempDir>>;
/// Nothing to keep in a release build. Clone, not Copy: a writer clones its
/// keep the same way in either build.
#[cfg(not(test))]
#[derive(Debug, Default, Clone)]
pub(crate) struct Kept;

/// Test-only holds by path, for writers handed a path and nothing else (the
/// package cache's deletes, the config lock's thread): a row arms the hold for
/// the exact path its writer will get, and the writer's closure pauses there
/// before it touches the file system. Parallel rows use distinct paths.
#[cfg(test)]
static HOLDS: parking_lot::Mutex<
    Vec<(std::path::PathBuf, std::sync::Arc<crate::test_pause::Slot>)>,
> = parking_lot::Mutex::new(Vec::new());

/// Arm a one-shot hold for the writer handed `path`.
#[cfg(test)]
pub(crate) fn hold_for(path: &Path) -> std::sync::Arc<crate::test_pause::Slot> {
    let slot = std::sync::Arc::new(crate::test_pause::Slot::default());
    HOLDS
        .lock()
        .push((path.to_path_buf(), std::sync::Arc::clone(&slot)));
    slot
}

/// The key a row arms with [`hold_for`] to stop a held writer once its work
/// is done: `path` with ".returned" appended, so it never matches the hold
/// before the work.
#[cfg(test)]
pub(crate) fn after_work(path: &Path) -> std::path::PathBuf {
    let mut key = path.as_os_str().to_owned();
    key.push(".returned");
    key.into()
}

/// Pause here if a row armed a hold for `path` (bounded: see
/// `Slot::pause_on_thread`). The first statement of a held writer's closure.
#[cfg(test)]
pub(crate) fn pause_if_held(path: &Path) {
    let slot = HOLDS
        .lock()
        .iter()
        .find(|(held, _)| held == path)
        .map(|(_, slot)| std::sync::Arc::clone(slot));
    if let Some(slot) = slot {
        slot.pause_on_thread();
    }
}

// A keep carries no data in a release build, so taking one costs nothing there.
// Written as a statement inside a block, the form Kani's nightly accepts.
#[cfg(not(test))]
const _: () = {
    assert!(std::mem::size_of::<Kept>() == 0);
};

/// The kept dirs holding `path`, taken at spawn, with no report: for a writer
/// whose own open already reports an unkept dir, or one that is awaited.
#[cfg(test)]
pub(crate) fn kept_dirs_at_spawn(path: &Path) -> Kept {
    crate::test_dir_keep::kept_dirs_for(path)
}

/// Nothing to keep in a release build.
#[cfg(not(test))]
pub(crate) fn kept_dirs_at_spawn(_path: &Path) -> Kept {
    Kept
}

/// [`kept_dirs_at_spawn`], reporting `kind` at `path` when no test kept the
/// dir: the line CI fails a shard on. It is reported at spawn, so it fires on
/// every run, whether or not a late write races the dir's removal.
#[cfg(test)]
pub(crate) fn kept_at_spawn(kind: &'static str, path: &Path) -> Kept {
    let kept = kept_dirs_at_spawn(path);
    if kept.is_empty() {
        crate::test_dir_keep::report_unkept(kind, path);
    }
    kept
}

/// Nothing to keep or report in a release build.
#[cfg(not(test))]
pub(crate) fn kept_at_spawn(_kind: &'static str, _path: &Path) -> Kept {
    Kept
}

/// Run `work` on a detached writer's thread with `kept` held until it
/// returns. Taking the keep as an argument moves it into the thread without
/// a binding nobody reads.
#[cfg(test)]
pub(crate) fn holding<R>(kept: Kept, work: impl FnOnce() -> R) -> R {
    let result = work();
    drop(kept);
    result
}

/// A release build holds nothing: `work` just runs.
#[cfg(not(test))]
pub(crate) fn holding<R>(Kept: Kept, work: impl FnOnce() -> R) -> R {
    work()
}

/// One keep holding every dir `parts` keeps.
#[cfg(test)]
pub(crate) fn union(parts: impl IntoIterator<Item = Kept>) -> Kept {
    parts.into_iter().flatten().collect()
}

/// Nothing to keep in a release build.
#[cfg(not(test))]
pub(crate) fn union(_parts: impl IntoIterator<Item = Kept>) -> Kept {
    Kept
}
