// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A store's test-only share of the temporary directory it lives in, so the
//! directory is removed only after the store's last handle drops: a write
//! still in flight when its test ends lands before the directory goes.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

/// Held as a store field; set once, by [`Self::keep`].
#[derive(Debug, Default)]
pub(crate) struct TestDirKeep {
    dir: OnceLock<Arc<tempfile::TempDir>>,
    /// Set by the gateway's own openers: a test that builds a gateway never
    /// holds the store, so it has nothing to keep it with.
    opened_by_gateway: AtomicBool,
}

impl TestDirKeep {
    /// The gateway opened this store, not a test.
    pub(crate) fn opened_by_gateway(&self) {
        self.opened_by_gateway.store(true, Ordering::Relaxed);
    }

    /// A worker is about to start on this store. A store a test opened
    /// itself must keep its directory first, or a late write from the worker
    /// can land while the directory is being removed.
    pub(crate) fn assert_kept(&self, worker: &str) {
        assert!(
            self.dir.get().is_some() || self.opened_by_gateway.load(Ordering::Relaxed),
            "{worker} started on a store whose test never kept its directory; call keep_test_dir"
        );
    }

    /// Keep `dir` for a store living at `store_path`. The store must live
    /// inside `dir`, and a second call must name the same directory: keeping
    /// another one would leave this store's directory unowned.
    pub(crate) fn keep(&self, dir: Arc<tempfile::TempDir>, store_path: &Path) {
        assert!(
            store_path.starts_with(dir.path()),
            "a store at {} keeps {}, a directory it does not live in",
            store_path.display(),
            dir.path().display()
        );
        if let Err(other) = self.dir.set(dir) {
            let kept = self.dir.get().expect("set");
            assert!(
                Arc::ptr_eq(kept, &other),
                "a store keeps one test directory"
            );
        }
    }
}

// The registry of kept temp dirs (MIK-8986 part 2). A transparency log opened
// inside a dir from `kept_tempdir()` keeps that dir, and every registered dir
// containing it, until its last handle drops; a log opened in an unregistered
// temp dir is reported. The registry holds only `Weak`s, so it never keeps a
// dir alive by itself.
// STUB (red commit): every function below is a placeholder the rows fail on.

/// A short-lived dir outside the process temp dir, in the crate root, for
/// rows that need a path a raw comparison would not place under it.
pub(crate) fn outside_temp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("kept-dir-alias-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("a dir outside the temp dir")
}

/// A temp dir that any transparency log opened inside it keeps.
pub(crate) fn kept_tempdir() -> Arc<tempfile::TempDir> {
    Arc::new(tempfile::tempdir().expect("a temp dir"))
}

/// [`kept_tempdir`], created inside `parent`.
pub(crate) fn kept_tempdir_in(parent: &Path) -> Arc<tempfile::TempDir> {
    Arc::new(tempfile::tempdir_in(parent).expect("a temp dir"))
}

/// Every live registered dir that contains `path`.
pub(crate) fn kept_dirs_for(_path: &Path) -> Vec<Arc<tempfile::TempDir>> {
    Vec::new()
}

/// `path` with its deepest existing ancestor canonicalised.
pub(crate) fn norm(path: &Path) -> std::path::PathBuf {
    path.to_path_buf()
}

/// Whether `dir` contains `path`, compared per path component.
pub(crate) fn contains(_dir: &Path, _path: &Path) -> bool {
    false
}

/// Whether `path` lies under the process temp dir.
pub(crate) fn under_temp_root(_path: &Path) -> bool {
    false
}

/// The dirs a parent test process keeps, from `MCP_GATEWAY_TEST_KEPT_DIRS`'s format.
pub(crate) fn parse_external(_list: &std::ffi::OsStr) -> Vec<std::path::PathBuf> {
    Vec::new()
}

/// Whether one of `external` contains `path`.
pub(crate) fn is_external_in(_external: &[std::path::PathBuf], _path: &Path) -> bool {
    false
}

/// Report a log opened at `path` that keeps no registered dir.
pub(crate) fn report_unkept(_path: &Path) {}

/// While held, an unkept open on this thread is recorded here instead of
/// reported, for a row that opens one on purpose.
pub(crate) struct ExpectUnkept(());

pub(crate) fn expect_unkept() -> ExpectUnkept {
    ExpectUnkept(())
}

impl ExpectUnkept {
    /// The unkept opens recorded so far, in order: each path and the test
    /// it is attributed to.
    pub(crate) fn recorded(&self) -> Vec<(std::path::PathBuf, String)> {
        Vec::new()
    }
}

/// The normalised paths of the registry's entries, live or not yet pruned.
pub(crate) fn registered_paths() -> Vec<std::path::PathBuf> {
    Vec::new()
}

/// A row's checkpoint: `f` runs once, on this thread, inside the next log
/// open after its kept-dir lookup and before any filesystem call.
pub(crate) fn before_first_fs_call(_f: impl FnOnce() + 'static) {}

/// Run and clear this thread's checkpoint, if one is set.
pub(crate) fn run_before_first_fs_call() {}

#[path = "test_dir_keep_registry_tests.rs"]
mod registry_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_store_outside_the_kept_directory_is_refused() {
        let kept = Arc::new(tempfile::tempdir().expect("a directory"));
        let elsewhere = tempfile::tempdir().expect("another directory");
        let refused = std::panic::catch_unwind(|| {
            TestDirKeep::default().keep(Arc::clone(&kept), elsewhere.path());
        });
        assert!(refused.is_err(), "a keep of the wrong directory must fail");
    }

    #[test]
    fn a_second_different_directory_is_refused() {
        let first = Arc::new(tempfile::tempdir().expect("a directory"));
        let second = Arc::new(tempfile::tempdir().expect("another directory"));
        let keep = TestDirKeep::default();
        keep.keep(Arc::clone(&first), &first.path().join("tasks"));
        keep.keep(Arc::clone(&first), &first.path().join("tasks"));
        let refused = std::panic::catch_unwind(|| {
            keep.keep(Arc::clone(&second), &first.path().join("tasks"));
        });
        assert!(refused.is_err(), "a second, different directory must fail");
    }

    #[test]
    fn a_worker_on_an_unkept_test_store_is_refused() {
        let refused = std::panic::catch_unwind(|| TestDirKeep::default().assert_kept("a worker"));
        assert!(refused.is_err(), "an unkept store must not start a worker");
        let kept = Arc::new(tempfile::tempdir().expect("a directory"));
        let keep = TestDirKeep::default();
        keep.keep(Arc::clone(&kept), &kept.path().join("tasks"));
        keep.assert_kept("a worker");
        let gateway = TestDirKeep::default();
        gateway.opened_by_gateway();
        gateway.assert_kept("a worker");
    }
}
