// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! A log that keeps its test directory is removed only after its last
//! handle: a late append (a worker its test left running) lands first, and a
//! runtime that drops its detached workers still lets the directory go.

use std::sync::Arc;

use super::{TransparencyLogConfig, TransparencyLogger};
use crate::security::audit::AuditEnvelope;

/// A log at the root of a kept temporary directory, and that directory's path.
fn kept_log() -> (Arc<TransparencyLogger>, std::path::PathBuf) {
    let dir = Arc::new(tempfile::tempdir().expect("a temp dir"));
    let root = dir.path().to_owned();
    // Unregistered on purpose: only keep_test_dir may keep this dir alive.
    let unkept = crate::test_dir_keep::expect_unkept();
    let log = Arc::new(
        TransparencyLogger::open(Arc::new(TransparencyLogConfig {
            enabled: true,
            path: root.join("audit.jsonl").to_string_lossy().into_owned(),
            ..TransparencyLogConfig::default()
        }))
        .expect("the log opens"),
    );
    drop(unkept);
    log.keep_test_dir(dir);
    (log, root)
}

pub(super) fn note(log: &TransparencyLogger) {
    let fields: serde_json::Map<String, serde_json::Value> =
        [("kind".to_owned(), serde_json::Value::from("keep_dir_probe"))]
            .into_iter()
            .collect();
    log.append_event(fields, &AuditEnvelope::gateway())
        .expect("the record is written");
}

/// The test's own share is gone; a late append still lands in the directory,
/// and the directory goes with the log's last handle.
/// Mutant: the keep dropped: the directory goes with the test's share and the
/// append recreates part of it.
#[test]
fn a_late_append_lands_and_the_directory_goes_with_the_last_handle() {
    let (log, root) = kept_log();
    // The test body ends: nothing of its own holds the directory now.
    note(&log);
    assert!(root.join("audit.jsonl").is_file(), "the late append landed");
    drop(log);
    assert!(
        !root.exists(),
        "the directory outlived the log's last handle"
    );
}

/// A detached task that never ends holds the log; dropping its runtime drops
/// the task, the task's handle, and with the last handle the directory.
/// Mutant: a keep that outlived its log (a leaked share): the directory stays.
#[test]
fn a_dropped_runtime_lets_the_directory_go() {
    let (log, root) = kept_log();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .build()
        .expect("a runtime");
    let held = Arc::clone(&log);
    runtime.spawn(async move {
        note(&held);
        std::future::pending::<()>().await;
    });
    drop(log);
    // Every detached task is dropped with its runtime.
    drop(runtime);
    assert!(
        !root.exists(),
        "the directory outlived the runtime that held its last handle"
    );
}
