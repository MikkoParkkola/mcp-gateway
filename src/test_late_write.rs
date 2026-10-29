// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Test-only attribution for a write that lands after its test's temporary
//! directory was removed (the "left in TMPDIR" leftovers the shard guard in
//! `scripts/ci/shard_tests.py` counts).
//!
//! A writer records the test that built it ([`Creator`], from the thread name
//! libtest gives each test) and, before each write, checks a witness file that
//! exists only while its directory is live. A missing witness means the
//! directory is being removed under the writer: one line naming the test goes
//! straight to the process's stderr. It is written with `std::io::Write`, not
//! `eprintln!`, because libtest captures the print macros per test and a late
//! writer's test has already finished. The write itself is unchanged, and the
//! check races it: this names the leaker, it does not prevent the leak.
//!
//! A log opened at a file directly in the temp root is named when its lease is
//! taken ([`Creator::beside_temp_root`]): its `.lock` and `.hwm` sit beside
//! that file, so whatever removes the file leaves both behind.

use std::io::Write as _;
use std::path::Path;

/// The test that built a writer: its thread name, or `unnamed thread` when the
/// writer was built off a test thread (`main`, no name, or a runtime worker).
#[derive(Debug)]
pub(crate) struct Creator(String);

impl Default for Creator {
    fn default() -> Self {
        let name = std::thread::current().name().map(str::to_owned);
        Self(attributed(name.as_deref()))
    }
}

impl Creator {
    /// Report a `kind` write about to land while `witness` is gone.
    pub(crate) fn witness(&self, kind: &str, witness: &Path) {
        let gone = matches!(
            std::fs::symlink_metadata(witness),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound
        );
        if !gone {
            return;
        }
        let line = format!(
            "late {kind} write after its directory was removed; created by {}\n",
            self.0
        );
        report(&line);
    }

    /// Report a log opened at a file directly in the temp root: its `.lock`
    /// and `.hwm` sidecars sit beside the file, so removing the file (a
    /// `NamedTempFile`, or a `TempDir` reused as a file path) leaves both.
    /// Checked when the lease is taken, so it names the test on every run,
    /// not only when a late write races the removal.
    pub(crate) fn beside_temp_root(&self, kind: &str, path: &Path) {
        if !in_temp_root(path) {
            return;
        }
        report(&format!(
            "{kind} at {} sits in the temp root, so its sidecars outlive it; created by {}\n",
            path.display(),
            self.0
        ));
    }
}

/// Best effort: attribution must never fail the write it describes.
fn report(line: &str) {
    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}

/// Whether `path`'s directory is the process temp root itself.
fn in_temp_root(path: &Path) -> bool {
    let canonical = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    path.parent()
        .is_some_and(|parent| canonical(parent) == canonical(&std::env::temp_dir()))
}

/// The name a writer is attributed to.
fn attributed(thread: Option<&str>) -> String {
    match thread {
        Some(name) if name != "main" && !name.starts_with("tokio-runtime-worker") => {
            name.to_owned()
        }
        _ => "unnamed thread".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_thread_names_its_test() {
        assert_eq!(
            Creator::default().0,
            "test_late_write::tests::a_test_thread_names_its_test"
        );
    }

    #[test]
    fn main_unnamed_and_runtime_workers_are_unnamed() {
        for thread in [None, Some("main"), Some("tokio-runtime-worker")] {
            assert_eq!(attributed(thread), "unnamed thread", "{thread:?}");
        }
        assert_eq!(attributed(Some("a::b")), "a::b");
    }

    #[test]
    fn a_live_witness_reports_nothing_and_a_missing_one_is_seen() {
        let dir = tempfile::tempdir().unwrap();
        let live = dir.path().join("audit.jsonl");
        std::fs::write(&live, b"").unwrap();
        // Neither call may panic or create the witness.
        Creator::default().witness("probe", &live);
        let gone = dir.path().join("gone");
        Creator::default().witness("probe", &gone);
        assert!(!gone.exists(), "the check creates nothing");
    }

    #[test]
    fn only_a_file_directly_in_the_temp_root_is_flagged() {
        let root = std::env::temp_dir();
        assert!(in_temp_root(&root.join(".tmpAbC123")));
        let dir = tempfile::tempdir().unwrap();
        assert!(!in_temp_root(&dir.path().join("audit.jsonl")));
    }
}
