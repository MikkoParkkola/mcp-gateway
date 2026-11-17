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

/// The temp dirs a detached writer keeps: test builds only.
#[cfg(test)]
pub(crate) type Kept = Vec<std::sync::Arc<tempfile::TempDir>>;
/// Nothing to keep in a release build.
#[cfg(not(test))]
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Kept;

// A keep carries no data in a release build, so taking one costs nothing there.
#[cfg(not(test))]
const _: () = assert!(std::mem::size_of::<Kept>() == 0);

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
