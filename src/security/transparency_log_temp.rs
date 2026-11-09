// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A transparency log path for tests, inside its own temporary directory.

use std::path::{Path, PathBuf};

/// An empty log file inside its own temporary directory.
///
/// The log writes sidecars beside its path (`<path>.hwm`, `<path>.lock`), and
/// a bare `NamedTempFile` removes only the log file itself, so every test run
/// left the sidecars behind. Dropping this removes the directory and all of
/// them. Keep it alive until the logger is dropped: declare it after the
/// field holding the logger, since fields drop in declaration order and a
/// directory with an open `.lock` inside cannot be removed on Windows.
pub(crate) struct TempLog {
    path: PathBuf,
    _dir: std::sync::Arc<tempfile::TempDir>,
}

impl TempLog {
    /// A new, empty log file, as `NamedTempFile::new` would create.
    pub(crate) fn new() -> Self {
        // A name of its own, so a leaked log directory never passes as one of
        // the plain temp dirs the CI shard guard still tolerates.
        let dir = crate::test_dir_keep::kept_tempdir_prefixed("audit-log-");
        let path = dir.path().join("audit.jsonl");
        std::fs::File::create(&path).expect("log file");
        Self { path, _dir: dir }
    }

    /// The log file's path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::TempLog;
    use crate::security::TransparencyLogger;
    use crate::security::transparency_log::TransparencyLogConfig;

    /// A logger opened at a `TempLog` path is in a kept dir: no unkept open is
    /// recorded, so the logger holds the dir past the `TempLog` itself.
    /// Mutant: `TempLog` back to an unregistered `tempfile::Builder` dir.
    #[test]
    fn a_log_in_a_temp_log_is_kept() {
        let log = TempLog::new();
        let unkept = crate::test_dir_keep::expect_unkept();
        let logger = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: log.path().to_string_lossy().to_string(),
            key_id: "temp-log".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("the log opens");
        assert_eq!(unkept.recorded(), vec![]);
        let folder = log.path().parent().expect("a parent").to_path_buf();
        drop(log);
        logger
            .log_invocation("s", "c", "srv", "kept", "sha256:aa", "sha256:bb")
            .expect("an append after the TempLog dropped");
        assert!(folder.exists(), "the logger did not keep the folder");
        drop(logger);
        assert!(!folder.exists(), "the folder did not go with the logger");
    }

    /// A logger and its `TempLog`, dropped in that order, leave nothing behind:
    /// the log, its sidecars and their folder all go. On Windows this fails if
    /// the logger still holds its `.lock` open when the folder is removed.
    #[test]
    fn dropping_logger_then_log_leaves_nothing() {
        let log = TempLog::new();
        let folder = log.path().parent().expect("a parent").to_path_buf();
        let logger = TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: log.path().to_string_lossy().to_string(),
            key_id: "temp-log".to_string(),
            ..TransparencyLogConfig::default()
        }))
        .expect("logger opens");
        logger
            .log_invocation("s", "c", "srv", "tool", "sha256:rr", "sha256:pp")
            .expect("one record");
        assert!(
            folder.join("audit.jsonl.hwm").exists(),
            "the log wrote its sidecar"
        );
        drop(logger);
        drop(log);
        assert!(!folder.exists(), "the log folder outlived its TempLog");
    }
}
