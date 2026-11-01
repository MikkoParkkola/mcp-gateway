// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! LOG.4: transparency-log records have their own writer. With every tracing
//! line on this thread dropped by a stalled stderr, a record still reaches
//! the log's file. The control plane's audit.jsonl is one of these loggers.

use super::rotation_tests::{cfg, event, lines, log_path};
use super::*;
use crate::log_writer::test_sinks::stalled_log;

#[test]
fn l3_a_transparency_record_reaches_its_file_while_stderr_is_stalled() {
    let dir = tempfile::tempdir().expect("a directory");
    let path = log_path(&dir);
    let logger = TransparencyLogger::open(cfg(&path, 2, false)).expect("logger opens");
    let stalled = stalled_log();
    tracing::warn!("probe");
    assert_eq!(
        stalled.writer.dropped_lines(),
        1,
        "tracing on this thread is stalled"
    );
    let mut record = serde_json::Map::new();
    record.insert("event".into(), "lossy-probe".into());
    logger
        .append_event_synced(record, &AuditEnvelope::gateway())
        .expect("the record is written");
    drop(stalled);
    assert!(
        lines(&path).iter().any(|v| event(v) == Some("lossy-probe")),
        "the record is not in its file"
    );
}
