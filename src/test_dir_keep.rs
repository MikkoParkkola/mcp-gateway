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
