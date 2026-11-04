// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A store's test-only share of the temporary directory it lives in, so the
//! directory is removed only after the store's last handle drops: a write
//! still in flight when its test ends lands before the directory goes.

use std::path::Path;
use std::sync::{Arc, OnceLock};

/// Held as a store field; set once, by [`Self::keep`].
#[derive(Debug, Default)]
pub(crate) struct TestDirKeep(OnceLock<Arc<tempfile::TempDir>>);

impl TestDirKeep {
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
        if let Err(other) = self.0.set(dir) {
            let kept = self.0.get().expect("set");
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
}
