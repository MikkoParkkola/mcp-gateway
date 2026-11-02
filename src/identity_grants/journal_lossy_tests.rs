// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! LOG.4: the identity-grant journal has its own writer. With every tracing
//! line on this thread dropped by a stalled stderr, a line still reaches it.

use super::append_line;
use crate::log_writer::test_sinks::stalled_log;

#[test]
fn l3_a_journal_line_reaches_its_file_while_stderr_is_stalled() {
    let dir = tempfile::tempdir().expect("a directory");
    let journal = dir.path().join("grants.journal.jsonl");
    let stalled = stalled_log();
    tracing::warn!("probe");
    assert_eq!(
        stalled.writer.dropped_lines(),
        1,
        "tracing on this thread is stalled"
    );
    append_line(&journal, b"{\"probe\":\"lossy\"}\n").expect("the line is written");
    drop(stalled);
    let text = std::fs::read_to_string(&journal).expect("the journal");
    assert!(
        text.contains("\"probe\":\"lossy\""),
        "the line is not in its file: {text:?}"
    );
}
